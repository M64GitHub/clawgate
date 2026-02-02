//! Agent daemon for ClawGate E2E connections.
//!
//! Listens on TCP for resource daemon connections, performs handshake,
//! and maintains encrypted sessions. Also listens on a Unix socket for
//! IPC from CLI commands and MCP server.

const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const unix = @import("../transport/unix.zig");
const handshake = @import("../protocol/handshake.zig");
const e2e = @import("../capability/e2e.zig");
const tokens = @import("tokens.zig");
const path_mod = @import("../path.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

const DEFAULT_LISTEN_ADDR = "0.0.0.0";
const DEFAULT_TOKEN_DIR = "~/.clawgate/tokens";
const KEEPALIVE_INTERVAL_MS: u64 = 30000;
const IPC_POLL_INTERVAL_MS: u64 = 100;

pub const DaemonError = error{
    TokenDirNotFound,
    BindFailed,
    HandshakeFailed,
    NotConnected,
    ConnectionClosed,
    OutOfMemory,
    IpcBindFailed,
};

/// Configuration for the agent daemon.
pub const Config = struct {
    listen_addr: []const u8 = DEFAULT_LISTEN_ADDR,
    listen_port: u16 = tcp.DEFAULT_PORT,
    token_dir: []const u8 = DEFAULT_TOKEN_DIR,
    socket_path: ?[]const u8 = null,
    environ: std.process.Environ = .empty,
};

/// Encapsulates daemon state for the active E2E connection.
pub const DaemonState = struct {
    active_connection: ?*handshake.EncryptedConnection = null,
    ipc_server: ?*unix.Server = null,

    /// Clears the active connection state.
    pub fn clearConnection(self: *DaemonState) void {
        self.active_connection = null;
    }

    /// Sets a new active connection.
    pub fn setConnection(
        self: *DaemonState,
        conn: *handshake.EncryptedConnection,
    ) void {
        self.active_connection = conn;
    }

    /// Returns true if connected.
    pub fn isConnected(self: *const DaemonState) bool {
        return self.active_connection != null;
    }
};

/// Module-level daemon state (singleton for the daemon process).
var state: DaemonState = .{};

/// Sends a request through the active E2E connection.
/// Returns the decrypted response. Caller owns returned memory.
pub fn sendRequest(
    allocator: Allocator,
    conn_alloc: Allocator,
    request: []const u8,
) DaemonError![]u8 {
    const conn = state.active_connection orelse return DaemonError.NotConnected;

    conn.sendEncrypted(conn_alloc, request) catch {
        return DaemonError.ConnectionClosed;
    };

    const response = conn.recvEncrypted(conn_alloc) catch {
        return DaemonError.ConnectionClosed;
    };

    if (conn_alloc.ptr == allocator.ptr) {
        return response;
    }

    const owned = allocator.dupe(u8, response) catch {
        conn_alloc.free(response);
        return DaemonError.OutOfMemory;
    };
    conn_alloc.free(response);
    return owned;
}

/// Returns true if there is an active connection.
pub fn isConnected() bool {
    return state.isConnected();
}

/// Runs the agent daemon with the given configuration.
/// Blocks indefinitely, accepting connections and handling requests.
pub fn run(allocator: Allocator, config: Config) DaemonError!void {
    var threaded: Io.Threaded = .init(allocator, .{
        .environ = config.environ,
    });
    defer threaded.deinit();

    const home = threaded.environString("HOME") orelse "/tmp";

    runWithIo(allocator, threaded.io(), config, home) catch |err| {
        return err;
    };
}

/// Internal entry point that accepts an Io instance for testing.
pub fn runWithIo(
    allocator: Allocator,
    io: Io,
    config: Config,
    home: []const u8,
) DaemonError!void {
    const token_dir = path_mod.expand(allocator, config.token_dir, home) catch {
        return DaemonError.OutOfMemory;
    };
    defer allocator.free(token_dir);

    std.log.info("Loading tokens from {s}", .{token_dir});
    var store = tokens.TokenStore.loadFromDir(allocator, io, token_dir) catch {
        std.log.err("Token directory not found: {s}", .{token_dir});
        std.log.info("Create it with: mkdir -p {s}", .{token_dir});
        return DaemonError.TokenDirNotFound;
    };
    defer store.deinit(allocator);

    std.log.info("Loaded {d} token(s)", .{store.tokens.len});

    std.log.info(
        "Binding TCP listener on {s}:{d}",
        .{ config.listen_addr, config.listen_port },
    );

    var listener = tcp.Listener.bind(
        io,
        config.listen_addr,
        config.listen_port,
    ) catch {
        std.log.err("Failed to bind to {s}:{d}", .{
            config.listen_addr,
            config.listen_port,
        });
        return DaemonError.BindFailed;
    };
    defer listener.close();

    const socket_path = if (config.socket_path) |sp|
        allocator.dupe(u8, sp) catch return DaemonError.OutOfMemory
    else
        unix.getSocketPath(allocator, config.environ) catch {
            return DaemonError.OutOfMemory;
        };
    defer allocator.free(socket_path);

    std.log.info("Binding IPC socket on {s}", .{socket_path});

    var ipc = unix.Server.bind(allocator, io, socket_path) catch {
        std.log.err("Failed to bind IPC socket: {s}", .{socket_path});
        return DaemonError.IpcBindFailed;
    };
    defer ipc.close(allocator, io);

    state.ipc_server = &ipc;
    defer {
        state.ipc_server = null;
    }

    std.log.info("Agent daemon ready, waiting for connections", .{});

    while (true) {
        acceptAndHandle(
            allocator,
            io,
            &listener,
            &ipc,
            &store,
        ) catch |err| {
            std.log.warn("Connection error: {}", .{err});
            continue;
        };
    }
}

/// Accepts a connection and handles the handshake.
fn acceptAndHandle(
    allocator: Allocator,
    io: Io,
    listener: *tcp.Listener,
    ipc: *unix.Server,
    store: *const tokens.TokenStore,
) !void {
    _ = store;
    var conn = listener.accept() catch {
        return DaemonError.BindFailed;
    };
    errdefer conn.close();

    std.log.info("Accepted connection from resource daemon", .{});

    var keypair = e2e.KeyPair.generate(io);
    defer keypair.deinit();

    const request_json = tcp.recvWithTimeout(
        &conn,
        allocator,
        tcp.HANDSHAKE_TIMEOUT_MS,
    ) catch |err| {
        if (err == tcp.TcpError.Timeout) {
            std.log.warn("Handshake timeout", .{});
        } else {
            std.log.warn("Failed to receive handshake request", .{});
        }
        return DaemonError.HandshakeFailed;
    };
    defer allocator.free(request_json);

    var parsed_request = handshake.HandshakeRequest.parse(
        allocator,
        request_json,
    ) catch {
        std.log.warn("Invalid handshake request", .{});
        sendErrorResponse(allocator, &conn, "invalid handshake request");
        return DaemonError.HandshakeFailed;
    };
    defer parsed_request.deinit();

    std.log.info(
        "Handshake from resource: {s}",
        .{parsed_request.value.resource_id},
    );

    const resource_pubkey = e2e.decodePublicKey(
        parsed_request.value.resource_pubkey,
    ) catch {
        std.log.warn("Invalid resource public key", .{});
        sendErrorResponse(allocator, &conn, "invalid public key");
        return DaemonError.HandshakeFailed;
    };

    const session_id = handshake.generateSessionId(io);
    const agent_pubkey_b64 = e2e.encodePublicKey(keypair.public_key);

    const response = handshake.HandshakeResponse{
        .ok = true,
        .agent_pubkey = &agent_pubkey_b64,
        .session_id = &session_id,
    };

    const response_json = response.serialize(allocator) catch {
        return DaemonError.OutOfMemory;
    };
    defer allocator.free(response_json);

    conn.send(response_json) catch {
        std.log.warn("Failed to send handshake response", .{});
        return DaemonError.HandshakeFailed;
    };

    const session = e2e.Session.establish(
        allocator,
        keypair.secret_key,
        resource_pubkey,
        &session_id,
    ) catch {
        std.log.warn("Failed to establish session", .{});
        return DaemonError.HandshakeFailed;
    };

    var enc_conn = allocator.create(handshake.EncryptedConnection) catch {
        var s = session;
        s.deinit(allocator);
        return DaemonError.OutOfMemory;
    };
    enc_conn.* = .{
        .conn = &conn,
        .session = session,
    };

    state.setConnection(enc_conn);

    std.log.info("E2E session established: {s}", .{&session_id});

    ipcServiceLoop(allocator, io, ipc);

    state.clearConnection();
    enc_conn.deinit(allocator);
    allocator.destroy(enc_conn);
    conn.close();

    std.log.info("Connection closed", .{});
}

/// Handles IPC requests while the E2E connection is active.
fn ipcServiceLoop(
    conn_alloc: Allocator,
    io: Io,
    ipc: *unix.Server,
) void {
    while (state.isConnected()) {
        var ipc_conn = ipc.accept() catch {
            io.sleep(.fromMilliseconds(IPC_POLL_INTERVAL_MS), .awake) catch {
                break;
            };
            continue;
        };
        defer ipc_conn.close();

        handleIpcRequest(conn_alloc, &ipc_conn);
    }
}

/// Handles a single IPC request.
fn handleIpcRequest(conn_alloc: Allocator, ipc_conn: *unix.Connection) void {
    const request = ipc_conn.recv(conn_alloc) catch |err| {
        std.log.warn("Failed to receive IPC request: {}", .{err});
        return;
    };
    defer conn_alloc.free(request);

    const response = sendRequest(conn_alloc, conn_alloc, request) catch |err| {
        std.log.warn("Failed to forward IPC request: {}", .{err});
        const error_response = buildErrorResponse(conn_alloc, err) catch return;
        defer conn_alloc.free(error_response);
        ipc_conn.send(error_response) catch {};
        return;
    };
    defer conn_alloc.free(response);

    ipc_conn.send(response) catch |err| {
        std.log.warn("Failed to send IPC response: {}", .{err});
    };
}

/// Builds a JSON error response for IPC errors.
fn buildErrorResponse(allocator: Allocator, err: DaemonError) ![]u8 {
    const code = switch (err) {
        DaemonError.NotConnected => "NOT_CONNECTED",
        DaemonError.ConnectionClosed => "CONNECTION_CLOSED",
        else => "INTERNAL_ERROR",
    };
    const message = switch (err) {
        DaemonError.NotConnected => "Not connected to resource daemon",
        DaemonError.ConnectionClosed => "Connection to resource closed",
        else => "Internal error",
    };

    return std.fmt.allocPrint(
        allocator,
        "{{\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ code, message },
    );
}

/// Sends an error response during handshake.
fn sendErrorResponse(
    allocator: Allocator,
    conn: *tcp.Connection,
    message: []const u8,
) void {
    const response = handshake.HandshakeResponse{
        .ok = false,
        .@"error" = message,
    };

    const json = response.serialize(allocator) catch return;
    defer allocator.free(json);

    conn.send(json) catch {};
}

// Tests

test "sendRequest errors when not connected" {
    state.clearConnection();

    const allocator = std.testing.allocator;
    const result = sendRequest(allocator, allocator, "test request");
    try std.testing.expectError(DaemonError.NotConnected, result);
}

test "isConnected returns false when no connection" {
    state.clearConnection();
    try std.testing.expect(!isConnected());
}

test "handshake request parsing" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var resource_kp = e2e.KeyPair.generate(io);
    defer resource_kp.deinit();

    const resource_pubkey_b64 = e2e.encodePublicKey(resource_kp.public_key);

    const request = handshake.HandshakeRequest{
        .version = 1,
        .resource_pubkey = &resource_pubkey_b64,
        .resource_id = "test-resource",
    };

    const request_json = try request.serialize(allocator);
    defer allocator.free(request_json);

    var parsed = try handshake.HandshakeRequest.parse(allocator, request_json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 1), parsed.value.version);
    try std.testing.expectEqualStrings("test-resource", parsed.value.resource_id);

    const decoded = try e2e.decodePublicKey(parsed.value.resource_pubkey);
    try std.testing.expectEqualSlices(u8, &resource_kp.public_key, &decoded);
}

test "handshake response generation" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var agent_kp = e2e.KeyPair.generate(io);
    defer agent_kp.deinit();

    const agent_pubkey_b64 = e2e.encodePublicKey(agent_kp.public_key);
    const session_id = handshake.generateSessionId(io);

    const response = handshake.HandshakeResponse{
        .ok = true,
        .agent_pubkey = &agent_pubkey_b64,
        .session_id = &session_id,
    };

    const response_json = try response.serialize(allocator);
    defer allocator.free(response_json);

    var parsed = try handshake.HandshakeResponse.parse(allocator, response_json);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.ok);
    try std.testing.expect(parsed.value.agent_pubkey != null);
    try std.testing.expect(parsed.value.session_id != null);
    try std.testing.expect(parsed.value.@"error" == null);
}

test "error response generation" {
    const allocator = std.testing.allocator;

    const response = handshake.HandshakeResponse{
        .ok = false,
        .@"error" = "invalid request",
    };

    const response_json = try response.serialize(allocator);
    defer allocator.free(response_json);

    var parsed = try handshake.HandshakeResponse.parse(allocator, response_json);
    defer parsed.deinit();

    try std.testing.expect(!parsed.value.ok);
    try std.testing.expectEqualStrings("invalid request", parsed.value.@"error".?);
}

test "full handshake simulation" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var resource_kp = e2e.KeyPair.generate(io);
    defer resource_kp.deinit();

    var agent_kp = e2e.KeyPair.generate(io);
    defer agent_kp.deinit();

    const resource_pubkey_b64 = e2e.encodePublicKey(resource_kp.public_key);

    const request = handshake.HandshakeRequest{
        .version = 1,
        .resource_pubkey = &resource_pubkey_b64,
        .resource_id = "test-resource",
    };

    const request_json = try request.serialize(allocator);
    defer allocator.free(request_json);

    var parsed_req = try handshake.HandshakeRequest.parse(allocator, request_json);
    defer parsed_req.deinit();

    const decoded_pubkey = try e2e.decodePublicKey(parsed_req.value.resource_pubkey);
    try std.testing.expectEqualSlices(u8, &resource_kp.public_key, &decoded_pubkey);

    const session_id = handshake.generateSessionId(io);
    const agent_pubkey_b64 = e2e.encodePublicKey(agent_kp.public_key);

    const response = handshake.HandshakeResponse{
        .ok = true,
        .agent_pubkey = &agent_pubkey_b64,
        .session_id = &session_id,
    };

    const response_json = try response.serialize(allocator);
    defer allocator.free(response_json);

    var parsed_resp = try handshake.HandshakeResponse.parse(
        allocator,
        response_json,
    );
    defer parsed_resp.deinit();

    try std.testing.expect(parsed_resp.value.ok);

    const agent_pubkey = try e2e.decodePublicKey(parsed_resp.value.agent_pubkey.?);

    var resource_session = try e2e.Session.establish(
        allocator,
        resource_kp.secret_key,
        agent_pubkey,
        parsed_resp.value.session_id.?,
    );
    defer resource_session.deinit(allocator);

    var agent_session = try e2e.Session.establish(
        allocator,
        agent_kp.secret_key,
        decoded_pubkey,
        &session_id,
    );
    defer agent_session.deinit(allocator);

    try std.testing.expectEqualSlices(
        u8,
        &resource_session.shared_secret,
        &agent_session.shared_secret,
    );
}

test "buildErrorResponse" {
    const allocator = std.testing.allocator;

    const response = try buildErrorResponse(allocator, DaemonError.NotConnected);
    defer allocator.free(response);

    try std.testing.expect(
        std.mem.indexOf(u8, response, "NOT_CONNECTED") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, response, "\"ok\":false") != null);
}

//! Resource daemon for ClawGate E2E connections.
//!
//! Connects to the agent daemon via TCP, performs handshake, and handles
//! encrypted file operation requests in the main loop.

const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const handshake = @import("../protocol/handshake.zig");
const e2e = @import("../capability/e2e.zig");
const handlers = @import("handlers.zig");
const crypto = @import("../capability/crypto.zig");
const protocol = @import("../protocol/json.zig");
const paths = @import("../path.zig");
const audit_log = @import("audit_log.zig");
const AuditLog = audit_log.AuditLog;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const RECONNECT_DELAY_MS: u64 = 5000;

pub const DaemonError = error{
    KeyLoadFailed,
    ConnectionFailed,
    HandshakeFailed,
    OutOfMemory,
};

/// Configuration for the resource daemon.
pub const Config = struct {
    connect_addr: []const u8,
    connect_port: u16 = tcp.DEFAULT_PORT,
    public_key_path: []const u8,
    resource_id: []const u8 = "clawgate-resource",
    /// Expected token issuer (if set, tokens with different iss are rejected).
    expected_issuer: ?[]const u8 = null,
    /// Expected token subject (if set, tokens with different sub are rejected).
    expected_subject: ?[]const u8 = null,
    environ: std.process.Environ = .empty,
};

/// Runs the resource daemon with the given configuration.
/// Blocks indefinitely, processing requests from the agent.
pub fn run(allocator: Allocator, config: Config) DaemonError!void {
    var threaded: Io.Threaded = .init(allocator, .{
        .environ = config.environ,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const home = threaded.environString("HOME") orelse "/tmp";

    runWithIo(allocator, io, config, home) catch |err| {
        return switch (err) {
            crypto.CryptoError.FileNotFound,
            crypto.CryptoError.ReadError,
            crypto.CryptoError.InvalidKeyLength,
            => DaemonError.KeyLoadFailed,
            else => DaemonError.ConnectionFailed,
        };
    };
}

/// Internal entry point that accepts an Io instance for testing.
pub fn runWithIo(
    allocator: Allocator,
    io: Io,
    config: Config,
    home: []const u8,
) !void {
    const key_path = try paths.expand(allocator, config.public_key_path, home);
    defer allocator.free(key_path);

    std.log.info("Loading public key from {s}", .{key_path});
    const public_key = try crypto.loadPublicKey(io, key_path);

    std.log.info(
        "Resource daemon starting, will connect to {s}:{d}",
        .{ config.connect_addr, config.connect_port },
    );

    const alog = AuditLog.init(allocator, io, home) catch |err| {
        std.log.warn(
            "Failed to init audit log: {}, continuing without",
            .{err},
        );
        return error.AuditLogInitFailed;
    };
    defer alog.deinit(io);

    while (true) {
        connectAndServe(
            allocator,
            io,
            config,
            public_key,
            &alog,
        ) catch |err| {
            std.log.warn(
                "Connection error: {}, reconnecting...",
                .{err},
            );
        };

        io.sleep(
            .fromMilliseconds(RECONNECT_DELAY_MS),
            .awake,
        ) catch {};
    }
}

/// Connects to agent, performs handshake, and runs main loop.
fn connectAndServe(
    allocator: Allocator,
    io: Io,
    config: Config,
    public_key: crypto.PublicKey,
    alog: *const AuditLog,
) !void {
    std.log.info(
        "Connecting to agent at {s}:{d}",
        .{ config.connect_addr, config.connect_port },
    );

    var conn = tcp.connectWithTimeout(
        io,
        config.connect_addr,
        config.connect_port,
        tcp.CONNECT_TIMEOUT_MS,
    ) catch |err| {
        if (err == tcp.TcpError.Timeout) {
            std.log.warn("Connection timeout", .{});
        }
        return DaemonError.ConnectionFailed;
    };
    defer conn.close();

    std.log.info("Connected, performing handshake", .{});

    var keypair = e2e.KeyPair.generate(io);
    defer keypair.deinit();

    const resource_pubkey_b64 = e2e.encodePublicKey(keypair.public_key);

    const request = handshake.HandshakeRequest{
        .version = handshake.PROTOCOL_VERSION,
        .resource_pubkey = &resource_pubkey_b64,
        .resource_id = config.resource_id,
    };

    const request_json = request.serialize(allocator) catch {
        return DaemonError.OutOfMemory;
    };
    defer allocator.free(request_json);

    conn.send(request_json) catch {
        std.log.warn("Failed to send handshake request", .{});
        return DaemonError.HandshakeFailed;
    };

    const response_json = tcp.recvWithTimeout(
        &conn,
        allocator,
        tcp.HANDSHAKE_TIMEOUT_MS,
    ) catch |err| {
        if (err == tcp.TcpError.Timeout) {
            std.log.warn("Handshake timeout", .{});
        } else {
            std.log.warn("Failed to receive handshake response", .{});
        }
        return DaemonError.HandshakeFailed;
    };
    defer allocator.free(response_json);

    var parsed_response = handshake.HandshakeResponse.parse(
        allocator,
        response_json,
    ) catch {
        std.log.warn("Invalid handshake response", .{});
        return DaemonError.HandshakeFailed;
    };
    defer parsed_response.deinit();

    if (!parsed_response.value.ok) {
        const err_msg = parsed_response.value.@"error" orelse "unknown error";
        std.log.warn("Handshake rejected: {s}", .{err_msg});
        return DaemonError.HandshakeFailed;
    }

    const agent_pubkey_b64 = parsed_response.value.agent_pubkey orelse {
        std.log.warn("Missing agent public key in response", .{});
        return DaemonError.HandshakeFailed;
    };

    const session_id = parsed_response.value.session_id orelse {
        std.log.warn("Missing session ID in response", .{});
        return DaemonError.HandshakeFailed;
    };

    const agent_pubkey = e2e.decodePublicKey(agent_pubkey_b64) catch {
        std.log.warn("Invalid agent public key", .{});
        return DaemonError.HandshakeFailed;
    };

    var session = e2e.Session.establish(
        allocator,
        keypair.secret_key,
        agent_pubkey,
        session_id,
    ) catch {
        std.log.warn("Failed to establish E2E session", .{});
        return DaemonError.HandshakeFailed;
    };
    defer session.deinit(allocator);

    var enc_conn = handshake.EncryptedConnection{
        .conn = &conn,
        .session = session,
    };

    std.log.info("E2E session established: {s}", .{session_id});

    mainLoop(allocator, io, &enc_conn, public_key, config, alog);
}

/// Main request processing loop. Runs until connection closes.
fn mainLoop(
    allocator: Allocator,
    io: Io,
    enc_conn: *handshake.EncryptedConnection,
    public_key: crypto.PublicKey,
    config: Config,
    alog: *const AuditLog,
) void {
    while (true) {
        const request_json = enc_conn.recvEncrypted(allocator) catch |err| {
            std.log.warn("Connection closed: {}", .{err});
            return;
        };
        defer allocator.free(request_json);

        std.log.debug("Received request ({d} bytes)", .{request_json.len});

        const response_json = handlers.handleRequest(
            allocator,
            io,
            request_json,
            public_key,
            .{
                .expected_issuer = config.expected_issuer,
                .expected_subject = config.expected_subject,
            },
        ) catch |err| {
            std.log.err("Handler error: {}", .{err});
            sendErrorResponse(allocator, enc_conn);
            continue;
        };
        defer allocator.free(response_json);

        enc_conn.sendEncrypted(allocator, response_json) catch |err| {
            std.log.warn("Failed to send response: {}", .{err});
            return;
        };

        alog.logEvent(
            allocator,
            io,
            request_json,
            response_json,
        );
    }
}

/// Sends a generic error response when request handling fails.
fn sendErrorResponse(
    allocator: Allocator,
    enc_conn: *handshake.EncryptedConnection,
) void {
    const error_json = protocol.formatError(
        allocator,
        "unknown",
        handlers.ErrorCode.INTERNAL_ERROR,
        "Internal error processing request",
    ) catch return;
    defer allocator.free(error_json);

    enc_conn.sendEncrypted(allocator, error_json) catch {};
}

// Tests

test "handshake request serialization" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var keypair = e2e.KeyPair.generate(io);
    defer keypair.deinit();

    const pubkey_b64 = e2e.encodePublicKey(keypair.public_key);

    const request = handshake.HandshakeRequest{
        .version = 1,
        .resource_pubkey = &pubkey_b64,
        .resource_id = "test-resource",
    };

    const json = try request.serialize(allocator);
    defer allocator.free(json);

    var parsed = try handshake.HandshakeRequest.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 1), parsed.value.version);
    try std.testing.expectEqualStrings("test-resource", parsed.value.resource_id);
}

test "handshake response parsing" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var keypair = e2e.KeyPair.generate(io);
    defer keypair.deinit();

    const pubkey_b64 = e2e.encodePublicKey(keypair.public_key);
    const session_id = handshake.generateSessionId(io);

    const response = handshake.HandshakeResponse{
        .ok = true,
        .agent_pubkey = &pubkey_b64,
        .session_id = &session_id,
    };

    const json = try response.serialize(allocator);
    defer allocator.free(json);

    var parsed = try handshake.HandshakeResponse.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.ok);
    try std.testing.expect(parsed.value.agent_pubkey != null);
    try std.testing.expect(parsed.value.session_id != null);

    const decoded = try e2e.decodePublicKey(parsed.value.agent_pubkey.?);
    try std.testing.expectEqualSlices(u8, &keypair.public_key, &decoded);
}

test "error response parsing" {
    const allocator = std.testing.allocator;

    const response = handshake.HandshakeResponse{
        .ok = false,
        .@"error" = "connection refused",
    };

    const json = try response.serialize(allocator);
    defer allocator.free(json);

    var parsed = try handshake.HandshakeResponse.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(!parsed.value.ok);
    try std.testing.expectEqualStrings(
        "connection refused",
        parsed.value.@"error".?,
    );
}

test "full E2E session establishment" {
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

    const decoded_resource_pubkey = try e2e.decodePublicKey(
        parsed_req.value.resource_pubkey,
    );

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

    const decoded_agent_pubkey = try e2e.decodePublicKey(
        parsed_resp.value.agent_pubkey.?,
    );

    var resource_session = try e2e.Session.establish(
        allocator,
        resource_kp.secret_key,
        decoded_agent_pubkey,
        parsed_resp.value.session_id.?,
    );
    defer resource_session.deinit(allocator);

    var agent_session = try e2e.Session.establish(
        allocator,
        agent_kp.secret_key,
        decoded_resource_pubkey,
        &session_id,
    );
    defer agent_session.deinit(allocator);

    try std.testing.expectEqualSlices(
        u8,
        &resource_session.shared_secret,
        &agent_session.shared_secret,
    );

    const test_msg = "Hello from resource!";
    const encrypted = try resource_session.encrypt(allocator, test_msg);
    defer allocator.free(encrypted);

    const decrypted = try agent_session.decrypt(allocator, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(test_msg, decrypted);
}

test "audit logging via AuditLog" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const Dir = Io.Dir;
    const tmp_path = Dir.realPathFileAlloc(
        tmp.dir,
        io,
        ".",
        allocator,
    ) catch unreachable;
    defer allocator.free(tmp_path);

    const alog = try AuditLog.init(allocator, io, tmp_path);
    defer alog.deinit(io);

    const request_json =
        \\{"id":"req123","token":"t","op":"read",
    ++
        \\"params":{"path":"/tmp/test"}}
    ;
    const response_json =
        "{\"id\":\"req123\",\"ok\":true,\"result\":{}}";

    alog.logEvent(allocator, io, request_json, response_json);
}

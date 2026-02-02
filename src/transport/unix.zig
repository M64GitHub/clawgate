//! Unix domain socket transport for IPC.
//!
//! Provides Server and Connection abstractions for local IPC between
//! CLI/MCP processes and the agent daemon. Uses the same 4-byte
//! big-endian length-prefixed framing as the TCP transport.

const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

/// Maximum message size (100 MB, same as TCP).
pub const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Length prefix size (4 bytes, big-endian).
const LENGTH_PREFIX_SIZE: usize = 4;

/// Read/write buffer size.
const BUFFER_SIZE: usize = 64 * 1024;

/// Maximum path length for Unix socket.
const MAX_PATH_LEN: usize = 107;

pub const UnixError = error{
    MessageTooLarge,
    ConnectionClosed,
    InvalidLengthPrefix,
    PathTooLong,
    BindFailed,
    ConnectFailed,
    AcceptFailed,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
    SocketNotFound,
    PermissionDenied,
};

/// A Unix domain socket connection with length-prefixed message framing.
pub const Connection = struct {
    fd: linux.fd_t,
    read_buffer: [BUFFER_SIZE]u8,
    read_pos: usize,
    read_end: usize,

    /// Creates a Connection from an existing file descriptor.
    pub fn init(fd: linux.fd_t) Connection {
        return .{
            .fd = fd,
            .read_buffer = undefined,
            .read_pos = 0,
            .read_end = 0,
        };
    }

    /// Sends a length-prefixed message.
    pub fn send(self: *Connection, data: []const u8) UnixError!void {
        if (data.len > MAX_MESSAGE_SIZE) {
            return UnixError.MessageTooLarge;
        }

        const len: u32 = @intCast(data.len);
        var len_bytes: [LENGTH_PREFIX_SIZE]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, len, .big);

        writeAll(self.fd, &len_bytes) catch return UnixError.WriteFailed;
        writeAll(self.fd, data) catch return UnixError.WriteFailed;
    }

    /// Receives a length-prefixed message.
    pub fn recv(self: *Connection, allocator: Allocator) UnixError![]u8 {
        var len_bytes: [LENGTH_PREFIX_SIZE]u8 = undefined;
        self.readExact(&len_bytes) catch return UnixError.ConnectionClosed;

        const message_len = std.mem.readInt(u32, &len_bytes, .big);

        if (message_len > MAX_MESSAGE_SIZE) {
            return UnixError.MessageTooLarge;
        }

        if (message_len == 0) {
            return allocator.alloc(u8, 0) catch {
                return UnixError.OutOfMemory;
            };
        }

        const buffer = allocator.alloc(u8, message_len) catch {
            return UnixError.OutOfMemory;
        };
        errdefer allocator.free(buffer);

        self.readExact(buffer) catch {
            allocator.free(buffer);
            return UnixError.ConnectionClosed;
        };

        return buffer;
    }

    /// Reads exactly `buf.len` bytes from the connection.
    fn readExact(self: *Connection, buf: []u8) !void {
        var total: usize = 0;
        while (total < buf.len) {
            if (self.read_pos < self.read_end) {
                const available = self.read_end - self.read_pos;
                const to_copy = @min(available, buf.len - total);
                const src = self.read_buffer[self.read_pos..][0..to_copy];
                @memcpy(buf[total..][0..to_copy], src);
                self.read_pos += to_copy;
                total += to_copy;
            } else {
                const rc = linux.read(self.fd, &self.read_buffer, BUFFER_SIZE);
                const err = linux.errno(rc);
                if (err != .SUCCESS) return error.ReadFailed;
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                self.read_pos = 0;
                self.read_end = n;
            }
        }
    }

    /// Closes the connection.
    pub fn close(self: *Connection) void {
        _ = linux.close(self.fd);
    }
};

/// A Unix domain socket server.
pub const Server = struct {
    fd: linux.fd_t,
    path: []const u8,
    path_owned: bool,

    /// Binds to a Unix socket path.
    pub fn bind(
        allocator: Allocator,
        io: Io,
        path: []const u8,
    ) UnixError!Server {
        if (path.len > MAX_PATH_LEN) {
            return UnixError.PathTooLong;
        }

        const path_owned = allocator.dupe(u8, path) catch {
            return UnixError.OutOfMemory;
        };
        errdefer allocator.free(path_owned);

        removeStaleSocket(io, path);

        const rc_socket = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        const socket_err = linux.errno(rc_socket);
        if (socket_err != .SUCCESS) return UnixError.BindFailed;

        const fd: linux.fd_t = @intCast(rc_socket);
        errdefer _ = linux.close(fd);

        var addr: linux.sockaddr.un = .{
            .family = linux.AF.UNIX,
            .path = undefined,
        };
        @memset(&addr.path, 0);
        @memcpy(addr.path[0..path.len], path);

        const rc_bind = linux.bind(
            fd,
            @ptrCast(&addr),
            @sizeOf(linux.sockaddr.un),
        );
        const bind_err = linux.errno(rc_bind);
        if (bind_err != .SUCCESS) return UnixError.BindFailed;

        const rc_listen = linux.listen(fd, 128);
        const listen_err = linux.errno(rc_listen);
        if (listen_err != .SUCCESS) return UnixError.BindFailed;

        setSocketPermissions(io, path);

        return .{
            .fd = fd,
            .path = path_owned,
            .path_owned = true,
        };
    }

    /// Accepts a new connection.
    pub fn accept(self: *Server) UnixError!Connection {
        const rc = linux.accept(self.fd, null, null);
        const err = linux.errno(rc);
        if (err != .SUCCESS) return UnixError.AcceptFailed;
        const client_fd: linux.fd_t = @intCast(rc);
        return Connection.init(client_fd);
    }

    /// Closes the server and removes the socket file.
    pub fn close(self: *Server, allocator: Allocator, io: Io) void {
        _ = linux.close(self.fd);
        Dir.deleteFile(.cwd(), io, self.path) catch {};
        if (self.path_owned) {
            allocator.free(self.path);
        }
    }
};

/// Connects to a Unix domain socket.
pub fn connect(path: []const u8) UnixError!Connection {
    if (path.len > MAX_PATH_LEN) {
        return UnixError.PathTooLong;
    }

    const rc_socket = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    const socket_err = linux.errno(rc_socket);
    if (socket_err != .SUCCESS) return UnixError.ConnectFailed;

    const fd: linux.fd_t = @intCast(rc_socket);
    errdefer _ = linux.close(fd);

    var addr: linux.sockaddr.un = .{
        .family = linux.AF.UNIX,
        .path = undefined,
    };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);

    const rc_connect = linux.connect(
        fd,
        @ptrCast(&addr),
        @sizeOf(linux.sockaddr.un),
    );
    const connect_err = linux.errno(rc_connect);
    if (connect_err != .SUCCESS) {
        return switch (connect_err) {
            .NOENT => UnixError.SocketNotFound,
            .ACCES => UnixError.PermissionDenied,
            else => UnixError.ConnectFailed,
        };
    }

    return Connection.init(fd);
}

/// Returns the default socket path for ClawGate IPC.
/// Uses $XDG_RUNTIME_DIR/clawgate.sock if available, otherwise
/// /tmp/clawgate-$UID.sock.
pub fn getSocketPath(
    allocator: Allocator,
    environ: std.process.Environ,
) ![]const u8 {
    if (environ.getPosix("XDG_RUNTIME_DIR")) |dir| {
        return std.fmt.allocPrint(allocator, "{s}/clawgate.sock", .{dir});
    }

    const uid = linux.getuid();
    return std.fmt.allocPrint(allocator, "/tmp/clawgate-{d}.sock", .{uid});
}

/// Removes a stale socket file if it exists.
fn removeStaleSocket(io: Io, path: []const u8) void {
    Dir.deleteFile(.cwd(), io, path) catch {};
}

/// Sets socket file permissions to 0600 (owner only).
fn setSocketPermissions(io: Io, path: []const u8) void {
    _ = io;
    var path_buf: [108]u8 = undefined;
    if (path.len >= path_buf.len) return;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&path_buf);
    _ = linux.chmod(cpath, 0o600);
}

/// Writes all bytes to a file descriptor.
fn writeAll(fd: linux.fd_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const rc = linux.write(fd, data[written..].ptr, data.len - written);
        const err = linux.errno(rc);
        if (err != .SUCCESS) return error.WriteFailed;
        const n: usize = @intCast(rc);
        if (n == 0) return error.WriteFailed;
        written += n;
    }
}

// Tests

test "length prefix encode/decode" {
    const len: u32 = 0x12345678;
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, len, .big);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56, 0x78 }, &buf);

    const decoded = std.mem.readInt(u32, &buf, .big);
    try std.testing.expectEqual(len, decoded);
}

test "getSocketPath fallback" {
    const allocator = std.testing.allocator;

    const path = try getSocketPath(allocator, .empty);
    defer allocator.free(path);

    try std.testing.expect(std.mem.startsWith(u8, path, "/tmp/clawgate-"));
    try std.testing.expect(std.mem.endsWith(u8, path, ".sock"));
}

test "path too long" {
    const long_path = "x" ** 200;
    const result = connect(long_path);
    try std.testing.expectError(UnixError.PathTooLong, result);
}

test "connect to nonexistent socket" {
    const result = connect("/tmp/nonexistent-clawgate-test.sock");
    try std.testing.expectError(UnixError.SocketNotFound, result);
}

test "server bind and accept" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-bind.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    const rc_socket = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    const socket_err = linux.errno(rc_socket);
    if (socket_err != .SUCCESS) return;
    const client_fd: linux.fd_t = @intCast(rc_socket);
    defer _ = linux.close(client_fd);

    var addr: linux.sockaddr.un = .{
        .family = linux.AF.UNIX,
        .path = undefined,
    };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);

    const rc_connect = linux.connect(
        client_fd,
        @ptrCast(&addr),
        @sizeOf(linux.sockaddr.un),
    );
    const connect_err = linux.errno(rc_connect);
    if (connect_err != .SUCCESS) return;

    var server_conn = try server.accept();
    defer server_conn.close();
}

test "send and receive message" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-send.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    var client = try connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();

    const msg = "Hello, ClawGate!";
    try client.send(msg);

    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqualStrings(msg, received);
}

test "bidirectional communication" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-bidir.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    var client = try connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();

    try client.send("REQUEST");

    const request = try server_conn.recv(allocator);
    defer allocator.free(request);
    try std.testing.expectEqualStrings("REQUEST", request);

    try server_conn.send("RESPONSE");

    const response = try client.recv(allocator);
    defer allocator.free(response);
    try std.testing.expectEqualStrings("RESPONSE", response);
}

test "empty message" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-empty.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    var client = try connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();

    try client.send("");

    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqual(@as(usize, 0), received.len);
}

test "multiple messages" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-multi.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    var client = try connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();

    const messages = [_][]const u8{
        "First message",
        "Second message with more content",
        "Third",
        "Fourth message is here",
    };

    for (messages) |msg| {
        try client.send(msg);
    }

    for (messages) |expected| {
        const received = try server_conn.recv(allocator);
        defer allocator.free(received);
        try std.testing.expectEqualStrings(expected, received);
    }
}

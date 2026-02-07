//! Unix domain socket transport for IPC.
//!
//! Provides Server and Connection abstractions for local IPC between
//! CLI/MCP processes and the agent daemon. Uses the same 4-byte
//! big-endian length-prefixed framing as the TCP transport.
//! Cross-platform: works on Linux and macOS.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const system = posix.system;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

/// Maximum message size (100 MB, same as TCP).
pub const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Length prefix size (4 bytes, big-endian).
const LENGTH_PREFIX_SIZE: usize = 4;

/// Read/write buffer size.
const BUFFER_SIZE: usize = 64 * 1024;

/// Maximum path length for Unix socket (platform-dependent).
const MAX_PATH_LEN: usize = @typeInfo(
    std.meta.fieldInfo(posix.sockaddr.un, .path).type,
).array.len - 1;

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

/// A Unix domain socket connection with length-prefixed framing.
pub const Connection = struct {
    fd: posix.fd_t,
    read_buffer: [BUFFER_SIZE]u8,
    read_pos: usize,
    read_end: usize,

    /// Creates a Connection from an existing file descriptor.
    pub fn init(fd: posix.fd_t) Connection {
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

        sysWriteAll(self.fd, &len_bytes) catch
            return UnixError.WriteFailed;
        sysWriteAll(self.fd, data) catch
            return UnixError.WriteFailed;
    }

    /// Receives a length-prefixed message.
    pub fn recv(
        self: *Connection,
        allocator: Allocator,
    ) UnixError![]u8 {
        var len_bytes: [LENGTH_PREFIX_SIZE]u8 = undefined;
        self.readExact(&len_bytes) catch
            return UnixError.ConnectionClosed;

        const message_len = std.mem.readInt(
            u32,
            &len_bytes,
            .big,
        );

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
                const to_copy = @min(
                    available,
                    buf.len - total,
                );
                const src = self.read_buffer[self.read_pos..][0..to_copy];
                @memcpy(buf[total..][0..to_copy], src);
                self.read_pos += to_copy;
                total += to_copy;
            } else {
                const n = posix.read(
                    self.fd,
                    &self.read_buffer,
                ) catch return error.ReadFailed;
                if (n == 0) return error.ConnectionClosed;
                self.read_pos = 0;
                self.read_end = n;
            }
        }
    }

    /// Closes the connection.
    pub fn close(self: *Connection) void {
        posix.close(self.fd);
    }
};

/// A Unix domain socket server.
pub const Server = struct {
    fd: posix.fd_t,
    path: []const u8,
    path_owned: bool,

    /// Binds to a Unix socket path (non-blocking accept).
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

        const fd = sysSocket(
            posix.AF.UNIX,
            posix.SOCK.STREAM,
            0,
        ) orelse return UnixError.BindFailed;
        errdefer posix.close(fd);

        setNonBlocking(fd) catch
            return UnixError.BindFailed;

        var addr = makeUnixAddr(path);
        sysBind(
            fd,
            @ptrCast(&addr),
            @sizeOf(posix.sockaddr.un),
        ) orelse return UnixError.BindFailed;

        sysListen(fd, 128) orelse
            return UnixError.BindFailed;

        sysChmod(path);

        return .{
            .fd = fd,
            .path = path_owned,
            .path_owned = true,
        };
    }

    /// Accepts a new connection (non-blocking).
    pub fn accept(self: *Server) UnixError!Connection {
        const fd = sysAccept(self.fd) orelse
            return UnixError.AcceptFailed;
        return Connection.init(fd);
    }

    /// Closes the server and removes the socket file.
    pub fn close(
        self: *Server,
        allocator: Allocator,
        io: Io,
    ) void {
        posix.close(self.fd);
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

    const fd = sysSocket(
        posix.AF.UNIX,
        posix.SOCK.STREAM,
        0,
    ) orelse return UnixError.ConnectFailed;
    errdefer posix.close(fd);

    var addr = makeUnixAddr(path);

    posix.connect(
        fd,
        @ptrCast(&addr),
        @sizeOf(posix.sockaddr.un),
    ) catch |err| {
        return switch (err) {
            error.FileNotFound => UnixError.SocketNotFound,
            error.AccessDenied => UnixError.PermissionDenied,
            else => UnixError.ConnectFailed,
        };
    };

    return Connection.init(fd);
}

/// Returns the default socket path for ClawGate IPC.
pub fn getSocketPath(
    allocator: Allocator,
    environ: std.process.Environ,
) ![]const u8 {
    if (environ.getPosix("XDG_RUNTIME_DIR")) |dir| {
        return std.fmt.allocPrint(
            allocator,
            "{s}/clawgate.sock",
            .{dir},
        );
    }

    const uid = sysGetuid();
    return std.fmt.allocPrint(
        allocator,
        "/tmp/clawgate-{d}.sock",
        .{uid},
    );
}

// -- Cross-platform syscall helpers --

/// Creates a Unix socket addr from a path.
fn makeUnixAddr(path: []const u8) posix.sockaddr.un {
    var addr: posix.sockaddr.un = .{
        .family = posix.AF.UNIX,
        .path = undefined,
    };
    // macOS sockaddr.un has a len field
    if (@hasField(posix.sockaddr.un, "len")) {
        addr.len = @sizeOf(posix.sockaddr.un);
    }
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);
    return addr;
}

/// Sets a file descriptor to non-blocking mode via fcntl.
fn setNonBlocking(fd: posix.fd_t) !void {
    var fl = posix.fcntl(fd, posix.F.GETFL, 0) catch
        return error.FcntlFailed;
    fl |= 1 << @bitOffsetOf(posix.O, "NONBLOCK");
    _ = posix.fcntl(fd, posix.F.SETFL, fl) catch
        return error.FcntlFailed;
}

/// Cross-platform socket().
fn sysSocket(
    domain: u32,
    sock_type: u32,
    protocol: u32,
) ?posix.fd_t {
    const rc = system.socket(domain, sock_type, protocol);
    return sysToFd(rc);
}

/// Cross-platform bind().
fn sysBind(
    fd: posix.fd_t,
    addr: *const posix.sockaddr,
    len: posix.socklen_t,
) ?void {
    const rc = system.bind(fd, addr, len);
    return if (sysIsSuccess(rc)) {} else null;
}

/// Cross-platform listen().
fn sysListen(fd: posix.fd_t, backlog: u32) ?void {
    const rc = system.listen(fd, @intCast(backlog));
    return if (sysIsSuccess(rc)) {} else null;
}

/// Cross-platform accept().
fn sysAccept(fd: posix.fd_t) ?posix.fd_t {
    const rc = system.accept(fd, null, null);
    return sysToFd(rc);
}

/// Cross-platform write(). Returns bytes written.
fn sysWrite(
    fd: posix.fd_t,
    data: []const u8,
) ?usize {
    const rc = system.write(fd, data.ptr, data.len);
    const T = @TypeOf(rc);
    if (T == usize) {
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return rc;
    } else {
        if (rc < 0) return null;
        return @intCast(rc);
    }
}

/// Cross-platform chmod on a path.
fn sysChmod(path: []const u8) void {
    var path_buf: [108]u8 = undefined;
    if (path.len >= path_buf.len) return;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&path_buf);
    _ = system.chmod(cpath, 0o600);
}

/// Cross-platform getuid().
fn sysGetuid() u32 {
    const rc = system.getuid();
    const T = @TypeOf(rc);
    if (T == u32) return rc;
    return @intCast(rc);
}

/// Checks if a raw syscall return value indicates success.
fn sysIsSuccess(rc: anytype) bool {
    const T = @TypeOf(rc);
    if (T == usize) {
        return std.os.linux.errno(rc) == .SUCCESS;
    } else {
        return rc >= 0;
    }
}

/// Converts a raw syscall return value to an fd.
fn sysToFd(rc: anytype) ?posix.fd_t {
    if (!sysIsSuccess(rc)) return null;
    return @intCast(rc);
}

/// Writes all bytes to a file descriptor.
fn sysWriteAll(fd: posix.fd_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = sysWrite(fd, data[written..]) orelse
            return error.WriteFailed;
        if (n == 0) return error.WriteFailed;
        written += n;
    }
}

/// Removes a stale socket file if it exists.
fn removeStaleSocket(io: Io, path: []const u8) void {
    Dir.deleteFile(.cwd(), io, path) catch {};
}

// Tests

test "length prefix encode/decode" {
    const len: u32 = 0x12345678;
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, len, .big);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x12, 0x34, 0x56, 0x78 },
        &buf,
    );

    const decoded = std.mem.readInt(u32, &buf, .big);
    try std.testing.expectEqual(len, decoded);
}

test "getSocketPath fallback" {
    const allocator = std.testing.allocator;

    const path = try getSocketPath(allocator, .empty);
    defer allocator.free(path);

    try std.testing.expect(
        std.mem.startsWith(u8, path, "/tmp/clawgate-"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, path, ".sock"),
    );
}

test "path too long" {
    const long_path = "x" ** 200;
    const result = connect(long_path);
    try std.testing.expectError(UnixError.PathTooLong, result);
}

test "connect to nonexistent socket" {
    const result = connect(
        "/tmp/nonexistent-clawgate-test.sock",
    );
    try std.testing.expectError(UnixError.SocketNotFound, result);
}

test "server bind and accept" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-test-bind.sock";
    defer Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    var client = try connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();
}

test "send and receive message" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
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

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
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

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
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

    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
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

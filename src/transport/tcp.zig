//! TCP transport layer with length-prefixed message framing.
//!
//! Provides Connection and Listener abstractions for reliable
//! bidirectional communication. All messages are framed with a
//! 4-byte big-endian length prefix.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

/// Maximum message size (100 MB).
pub const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Default ClawGate TCP port.
pub const DEFAULT_PORT: u16 = 53280;

/// Length prefix size (4 bytes, big-endian).
const LENGTH_PREFIX_SIZE: usize = 4;

/// Read/write buffer size.
const BUFFER_SIZE: usize = 64 * 1024;

pub const TcpError = error{
    MessageTooLarge,
    ConnectionClosed,
    InvalidLengthPrefix,
    AddressParseError,
    BindFailed,
    ConnectFailed,
    AcceptFailed,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
    Timeout,
};

/// Timeout constants for DoS protection.
pub const CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 30_000;
pub const MESSAGE_TIMEOUT_MS: u64 = 60_000;

/// A TCP connection with length-prefixed message framing.
pub const Connection = struct {
    stream: net.Stream,
    io: Io,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    read_buffer: [BUFFER_SIZE]u8,
    write_buffer: [BUFFER_SIZE]u8,

    /// Creates a Connection from an existing stream.
    pub fn init(stream: net.Stream, io: Io) Connection {
        var conn: Connection = .{
            .stream = stream,
            .io = io,
            .reader = undefined,
            .writer = undefined,
            .read_buffer = undefined,
            .write_buffer = undefined,
        };
        conn.reader = net.Stream.Reader.init(stream, io, &conn.read_buffer);
        conn.writer = net.Stream.Writer.init(stream, io, &conn.write_buffer);
        return conn;
    }

    /// Sends a length-prefixed message.
    pub fn send(self: *Connection, data: []const u8) TcpError!void {
        if (data.len > MAX_MESSAGE_SIZE) {
            return TcpError.MessageTooLarge;
        }

        // Write 4-byte big-endian length prefix
        const len: u32 = @intCast(data.len);
        var len_bytes: [LENGTH_PREFIX_SIZE]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, len, .big);

        self.writer.interface.writeAll(&len_bytes) catch {
            return TcpError.WriteFailed;
        };

        // Write payload
        self.writer.interface.writeAll(data) catch {
            return TcpError.WriteFailed;
        };

        // Flush to ensure data is sent
        self.writer.interface.flush() catch {
            return TcpError.WriteFailed;
        };
    }

    /// Receives a length-prefixed message.
    pub fn recv(self: *Connection, allocator: Allocator) TcpError![]u8 {
        // Read 4-byte length prefix
        const len_bytes = self.reader.interface.take(LENGTH_PREFIX_SIZE) catch {
            return TcpError.ConnectionClosed;
        };

        const message_len = std.mem.readInt(u32, len_bytes[0..4], .big);

        if (message_len > MAX_MESSAGE_SIZE) {
            return TcpError.MessageTooLarge;
        }

        if (message_len == 0) {
            return allocator.alloc(u8, 0) catch {
                return TcpError.OutOfMemory;
            };
        }

        // Allocate buffer for message
        const buffer = allocator.alloc(u8, message_len) catch {
            return TcpError.OutOfMemory;
        };
        errdefer allocator.free(buffer);

        // Read message in chunks
        var total_read: usize = 0;
        while (total_read < message_len) {
            const remaining = message_len - total_read;
            const chunk = self.reader.interface.peekGreedy(1) catch {
                allocator.free(buffer);
                return TcpError.ConnectionClosed;
            };

            if (chunk.len == 0) {
                allocator.free(buffer);
                return TcpError.ConnectionClosed;
            }

            const to_copy = @min(chunk.len, remaining);
            @memcpy(buffer[total_read..][0..to_copy], chunk[0..to_copy]);
            self.reader.interface.toss(to_copy);
            total_read += to_copy;
        }

        return buffer;
    }

    /// Closes the connection.
    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
    }
};

/// A TCP server listener.
pub const Listener = struct {
    server: net.Server,
    io: Io,

    /// Binds to an address and port.
    pub fn bind(io: Io, address: []const u8, port: u16) TcpError!Listener {
        const addr = net.IpAddress.parse(address, port) catch {
            return TcpError.AddressParseError;
        };

        const server = net.IpAddress.listen(addr, io, .{
            .kernel_backlog = 128,
            .reuse_address = true,
            .mode = .stream,
            .protocol = .tcp,
        }) catch {
            return TcpError.BindFailed;
        };

        return .{
            .server = server,
            .io = io,
        };
    }

    /// Accepts a new connection.
    pub fn accept(self: *Listener) TcpError!Connection {
        const stream = self.server.accept(self.io) catch {
            return TcpError.AcceptFailed;
        };
        return Connection.init(stream, self.io);
    }

    /// Closes the listener.
    pub fn close(self: *Listener) void {
        self.server.deinit(self.io);
    }
};

/// Connects to a remote host.
pub fn connectTo(io: Io, host: []const u8, port: u16) TcpError!Connection {
    // Convert "localhost" to numeric IP (IpAddress.parse only handles numeric)
    const resolved_host = if (std.mem.eql(u8, host, "localhost"))
        "127.0.0.1"
    else
        host;

    const addr = net.IpAddress.parse(resolved_host, port) catch {
        return TcpError.AddressParseError;
    };

    const stream = net.IpAddress.connect(addr, io, .{
        .mode = .stream,
        .protocol = .tcp,
    }) catch {
        return TcpError.ConnectFailed;
    };

    return Connection.init(stream, io);
}

/// Connects to a remote host with a timeout.
pub fn connectWithTimeout(
    io: Io,
    host: []const u8,
    port: u16,
    timeout_ms: u64,
) TcpError!Connection {
    var conn_future = io.async(doConnect, .{ io, host, port });

    var timeout_future = io.async(sleepForTimeout, .{ io, timeout_ms });

    const result = io.select(.{
        .conn = &conn_future,
        .timeout = &timeout_future,
    }) catch {
        _ = conn_future.cancel(io) catch {};
        timeout_future.cancel(io);
        return TcpError.ConnectFailed;
    };

    switch (result) {
        .conn => |conn_result| {
            timeout_future.cancel(io);
            return conn_result;
        },
        .timeout => {
            _ = conn_future.cancel(io) catch {};
            return TcpError.Timeout;
        },
    }
}

/// Helper for async connect.
fn doConnect(io: Io, host: []const u8, port: u16) TcpError!Connection {
    return connectTo(io, host, port);
}

/// Helper for timeout sleep.
fn sleepForTimeout(io: Io, ms: u64) void {
    io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

/// Receives a message with timeout. Returns Timeout error if exceeded.
pub fn recvWithTimeout(
    conn: *Connection,
    allocator: Allocator,
    timeout_ms: u64,
) TcpError![]u8 {
    const io = conn.io;

    var recv_future = io.async(doRecv, .{ conn, allocator });

    var timeout_future = io.async(sleepForTimeout, .{ io, timeout_ms });

    const result = io.select(.{
        .data = &recv_future,
        .timeout = &timeout_future,
    }) catch {
        if (recv_future.cancel(io)) |data| allocator.free(data) else |_| {}
        timeout_future.cancel(io);
        return TcpError.ConnectionClosed;
    };

    switch (result) {
        .data => |recv_result| {
            timeout_future.cancel(io);
            return recv_result;
        },
        .timeout => {
            if (recv_future.cancel(io)) |data| allocator.free(data) else |_| {}
            return TcpError.Timeout;
        },
    }
}

/// Helper for async recv.
fn doRecv(conn: *Connection, allocator: Allocator) TcpError![]u8 {
    return conn.recv(allocator);
}

test "length prefix encode/decode" {
    // Test encoding
    const len: u32 = 0x12345678;
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, len, .big);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56, 0x78 }, &buf);

    // Test decoding
    const decoded = std.mem.readInt(u32, &buf, .big);
    try std.testing.expectEqual(len, decoded);
}

test "length prefix zero" {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, 0, .big);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &buf);
}

test "length prefix max message size" {
    var buf: [4]u8 = undefined;
    const max: u32 = @intCast(MAX_MESSAGE_SIZE);
    std.mem.writeInt(u32, &buf, max, .big);
    const decoded = std.mem.readInt(u32, &buf, .big);
    try std.testing.expectEqual(max, decoded);
}

test "loopback server client communication" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    // Bind server
    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    // Get the actual bound port
    const port = listener.server.socket.address.getPort();

    // Connect client in same thread (for test simplicity, real use is async)
    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    // Accept server-side connection
    var server_conn = try listener.accept();
    defer server_conn.close();

    // Client sends message
    const msg = "Hello, ClawGate!";
    try client.send(msg);

    // Server receives
    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqualStrings(msg, received);
}

test "send and recv small message" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // Small message (< 1KB)
    const small_msg = "x" ** 100;
    try client.send(small_msg);

    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqual(@as(usize, 100), received.len);
    try std.testing.expectEqualStrings(small_msg, received);
}

test "send and recv large message (1MB)" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // 1MB message
    const large_msg = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(large_msg);
    @memset(large_msg, 'A');

    try client.send(large_msg);

    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqual(large_msg.len, received.len);
    for (received) |byte| {
        try std.testing.expectEqual(@as(u8, 'A'), byte);
    }
}

test "reject oversized message on send" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    // Try to send message larger than MAX_MESSAGE_SIZE
    const oversized = try allocator.alloc(u8, MAX_MESSAGE_SIZE + 1);
    defer allocator.free(oversized);

    const result = client.send(oversized);
    try std.testing.expectError(TcpError.MessageTooLarge, result);
}

test "multiple messages on same connection" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // Send multiple messages
    const messages = [_][]const u8{
        "First message",
        "Second message with more content",
        "Third",
        "Fourth message is here",
    };

    for (messages) |msg| {
        try client.send(msg);
    }

    // Receive all messages
    for (messages) |expected| {
        const received = try server_conn.recv(allocator);
        defer allocator.free(received);
        try std.testing.expectEqualStrings(expected, received);
    }
}

test "bidirectional communication" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // Client sends request
    try client.send("REQUEST");

    const request = try server_conn.recv(allocator);
    defer allocator.free(request);
    try std.testing.expectEqualStrings("REQUEST", request);

    // Server sends response
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

    var listener = try Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client = try connectTo(io, "127.0.0.1", port);
    defer client.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // Send empty message
    try client.send("");

    const received = try server_conn.recv(allocator);
    defer allocator.free(received);

    try std.testing.expectEqual(@as(usize, 0), received.len);
}

test "connect to invalid address fails" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    // Invalid address format
    const result = connectTo(io, "not-an-ip", 53280);
    try std.testing.expectError(TcpError.AddressParseError, result);
}

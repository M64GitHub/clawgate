//! IPC client for communicating with the agent daemon.
//!
//! Provides a simple interface for CLI commands and MCP server to send
//! requests to the agent daemon via Unix domain socket. The daemon then
//! forwards requests to the resource daemon over the E2E encrypted TCP
//! connection.

const std = @import("std");
const unix = @import("../transport/unix.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const IpcError = error{
    DaemonNotRunning,
    ConnectionFailed,
    RequestFailed,
    ResponseError,
    OutOfMemory,
    Timeout,
};

/// Sends a request to the agent daemon and returns the response.
/// Caller owns the returned memory.
pub fn sendRequest(
    allocator: Allocator,
    environ: std.process.Environ,
    request: []const u8,
) IpcError![]u8 {
    const socket_path = unix.getSocketPath(allocator, environ) catch {
        return IpcError.OutOfMemory;
    };
    defer allocator.free(socket_path);

    return sendRequestToPath(allocator, socket_path, request);
}

/// Sends a request to a specific socket path.
/// Caller owns the returned memory.
pub fn sendRequestToPath(
    allocator: Allocator,
    socket_path: []const u8,
    request: []const u8,
) IpcError![]u8 {
    var conn = unix.connect(socket_path) catch |err| {
        return switch (err) {
            unix.UnixError.SocketNotFound => IpcError.DaemonNotRunning,
            unix.UnixError.PermissionDenied => IpcError.ConnectionFailed,
            else => IpcError.ConnectionFailed,
        };
    };
    defer conn.close();

    conn.send(request) catch {
        return IpcError.RequestFailed;
    };

    const response = conn.recv(allocator) catch |err| {
        return switch (err) {
            unix.UnixError.ConnectionClosed => IpcError.ResponseError,
            unix.UnixError.OutOfMemory => IpcError.OutOfMemory,
            else => IpcError.ResponseError,
        };
    };

    return response;
}

/// Checks if the agent daemon is running by attempting to connect.
pub fn isDaemonRunning(environ: std.process.Environ) bool {
    var buf: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const socket_path = unix.getSocketPath(fba.allocator(), environ) catch {
        return false;
    };

    var conn = unix.connect(socket_path) catch {
        return false;
    };
    conn.close();
    return true;
}

/// Returns the socket path used for IPC.
/// Caller owns returned memory.
pub fn getSocketPath(
    allocator: Allocator,
    environ: std.process.Environ,
) ![]const u8 {
    return unix.getSocketPath(allocator, environ);
}

// Tests

test "sendRequest to nonexistent daemon" {
    const allocator = std.testing.allocator;

    const result = sendRequestToPath(
        allocator,
        "/tmp/nonexistent-clawgate-ipc-test.sock",
        "test request",
    );

    try std.testing.expectError(IpcError.DaemonNotRunning, result);
}

test "isDaemonRunning returns false when no daemon" {
    const running = isDaemonRunning(.empty);
    try std.testing.expect(!running);
}

test "getSocketPath returns valid path" {
    const allocator = std.testing.allocator;

    const path = try getSocketPath(allocator, .empty);
    defer allocator.free(path);

    try std.testing.expect(std.mem.startsWith(u8, path, "/tmp/clawgate-"));
    try std.testing.expect(std.mem.endsWith(u8, path, ".sock"));
}

test "roundtrip with mock server" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/clawgate-ipc-test.sock";
    defer Io.Dir.deleteFile(.cwd(), io, path) catch {};

    var server = try unix.Server.bind(allocator, io, path);
    defer server.close(allocator, io);

    const request_data = "{\"op\":\"test\",\"params\":{}}";
    const response_data = "{\"ok\":true,\"result\":{}}";

    var client = try unix.connect(path);
    defer client.close();

    var server_conn = try server.accept();
    defer server_conn.close();

    try client.send(request_data);

    const received_request = try server_conn.recv(allocator);
    defer allocator.free(received_request);
    try std.testing.expectEqualStrings(request_data, received_request);

    try server_conn.send(response_data);

    const received_response = try client.recv(allocator);
    defer allocator.free(received_response);
    try std.testing.expectEqualStrings(response_data, received_response);
}

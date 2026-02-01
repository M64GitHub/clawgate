//! Resource daemon main loop.
//!
//! Connects to NATS, subscribes to file operation requests,
//! validates tokens, executes operations, and publishes audit events.

const std = @import("std");
const nats = @import("nats");
const handlers = @import("handlers.zig");
const crypto = @import("../capability/crypto.zig");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_NATS_URL = "nats://localhost:4222";
const REQUEST_TIMEOUT_MS: u32 = 30000;

pub const DaemonError = error{
    KeyLoadFailed,
    ConnectionFailed,
    SubscribeFailed,
    OutOfMemory,
};

/// Configuration for the resource daemon.
pub const Config = struct {
    nats_url: []const u8 = DEFAULT_NATS_URL,
    public_key_path: []const u8,
};

/// Runs the resource daemon with the given configuration.
/// This function blocks indefinitely, processing requests.
pub fn run(allocator: Allocator, config: Config) DaemonError!void {
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    runWithIo(allocator, io, config) catch |err| {
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
fn runWithIo(allocator: Allocator, io: Io, config: Config) !void {
    std.log.info("Loading public key from {s}", .{config.public_key_path});
    const public_key = try crypto.loadPublicKey(io, config.public_key_path);

    std.log.info("Connecting to NATS at {s}", .{config.nats_url});
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-resource" },
    ) catch {
        std.log.err("Failed to connect to NATS server", .{});
        return DaemonError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    const sub = client.subscribe(allocator, "clawgate.req.files.>") catch {
        std.log.err("Failed to subscribe", .{});
        return DaemonError.SubscribeFailed;
    };
    defer sub.deinit(allocator);

    client.flush(allocator) catch {
        std.log.err("Failed to flush subscription", .{});
        return DaemonError.ConnectionFailed;
    };

    std.log.info("Resource daemon listening on clawgate.req.files.>", .{});

    mainLoop(allocator, io, client, sub, public_key);
}

/// Main request processing loop. Blocks indefinitely.
fn mainLoop(
    allocator: Allocator,
    io: Io,
    client: *nats.Client,
    sub: *nats.Client.Sub,
    public_key: crypto.PublicKey,
) void {
    while (true) {
        const timeout = REQUEST_TIMEOUT_MS;
        const msg = sub.nextWithTimeout(allocator, timeout) catch |err| {
            std.log.warn("Error receiving message: {}", .{err});
            continue;
        };

        if (msg) |m| {
            defer m.deinit(allocator);
            handleMessage(allocator, io, client, m, public_key);
        }
    }
}

/// Processes a single request message.
fn handleMessage(
    allocator: Allocator,
    io: Io,
    client: *nats.Client,
    msg: nats.Client.Message,
    public_key: crypto.PublicKey,
) void {
    std.log.debug(
        "Received request on {s} ({d} bytes)",
        .{ msg.subject, msg.data.len },
    );

    const response = handlers.handleRequest(
        allocator,
        io,
        msg.data,
        public_key,
    ) catch |err| {
        std.log.err("Handler error: {}", .{err});
        sendErrorResponse(allocator, client, msg.reply_to);
        return;
    };
    defer allocator.free(response);

    if (msg.reply_to) |reply_to| {
        client.publish(reply_to, response) catch |err| {
            std.log.err("Failed to send response: {}", .{err});
            return;
        };
        client.flush(allocator) catch |err| {
            std.log.err("Failed to flush response: {}", .{err});
        };
    }

    publishAuditEvent(allocator, client, msg, response);
}

/// Sends a generic error response when request handling fails.
fn sendErrorResponse(
    allocator: Allocator,
    client: *nats.Client,
    reply_to: ?[]const u8,
) void {
    const error_json = protocol.formatError(
        allocator,
        "unknown",
        handlers.ErrorCode.INTERNAL_ERROR,
        "Internal error processing request",
    ) catch return;
    defer allocator.free(error_json);

    if (reply_to) |rt| {
        client.publish(rt, error_json) catch return;
        client.flush(allocator) catch {};
    }
}

/// Publishes an audit event for a completed request.
fn publishAuditEvent(
    allocator: Allocator,
    client: *nats.Client,
    request_msg: nats.Client.Message,
    response_json: []const u8,
) void {
    const audit_json = formatAuditEvent(
        allocator,
        request_msg,
        response_json,
    ) catch return;
    defer allocator.free(audit_json);

    client.publish("clawgate.audit.files", audit_json) catch |err| {
        std.log.warn("Failed to publish audit event: {}", .{err});
    };
}

/// Formats an audit event as JSON.
fn formatAuditEvent(
    allocator: Allocator,
    request_msg: nats.Client.Message,
    response_json: []const u8,
) ![]const u8 {
    const instant = std.time.Instant.now() catch {
        return error.TimerUnavailable;
    };
    const secs: i64 = @intCast(instant.timestamp.sec);

    var req_id: []const u8 = "unknown";
    var op: []const u8 = "unknown";
    var path: []const u8 = "unknown";

    var parsed_req = protocol.parseRequest(
        allocator,
        request_msg.data,
    ) catch null;
    defer if (parsed_req) |*pr| pr.deinit();

    if (parsed_req) |pr| {
        req_id = pr.value.id;
        op = pr.value.op;
        path = pr.value.params.path;
    }

    const success = std.mem.indexOf(u8, response_json, "\"ok\":true") != null;

    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();

    const writer = &output.writer;

    try writer.print(
        "{{\"timestamp\":{d},\"request_id\":\"{s}\",\"op\":\"{s}\"," ++
            "\"path\":\"{s}\",\"success\":{s}}}",
        .{
            secs,
            req_id,
            op,
            path,
            if (success) "true" else "false",
        },
    );

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

// Tests

test "format audit event" {
    const allocator = std.testing.allocator;

    const request_data =
        \\{"id":"req123","token":"t","op":"read",
        \\"params":{"path":"/tmp/test.txt"}}
    ;

    const msg = nats.Client.Message{
        .subject = "clawgate.req.files.read",
        .data = request_data,
        .reply_to = null,
        .headers = null,
        .sid = 1,
        .owned = false,
    };

    const response = "{\"id\":\"req123\",\"ok\":true,\"result\":{}}";

    const audit = try formatAuditEvent(allocator, msg, response);
    defer allocator.free(audit);

    const has_req_id = std.mem.indexOf(u8, audit, "\"request_id\":\"req123\"");
    const has_op = std.mem.indexOf(u8, audit, "\"op\":\"read\"");
    const has_success = std.mem.indexOf(u8, audit, "\"success\":true");
    try std.testing.expect(has_req_id != null);
    try std.testing.expect(has_op != null);
    try std.testing.expect(has_success != null);
}

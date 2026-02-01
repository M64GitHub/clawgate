//! Audit log viewer for ClawGate.
//!
//! Subscribes to audit events from the resource daemon and
//! displays them in real-time.

const std = @import("std");
const nats = @import("nats");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const AuditError = error{
    InvalidArgs,
    ConnectionFailed,
    SubscriptionFailed,
    OutOfMemory,
};

/// Configuration for audit command.
pub const AuditConfig = struct {
    nats_url: []const u8 = "nats://localhost:4222",
    json_output: bool = false,
    filter: ?[]const u8 = null,
};

/// Runs the audit log viewer.
/// Subscribes to clawgate.audit.> and displays events.
pub fn run(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
) AuditError!void {
    var config = AuditConfig{};

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--nats") or std.mem.eql(u8, arg, "-n")) {
            if (i + 1 >= args.len) {
                printAuditUsage();
                return AuditError.InvalidArgs;
            }
            i += 1;
            config.nats_url = args[i];
        } else if (std.mem.eql(u8, arg, "--json") or
            std.mem.eql(u8, arg, "-j"))
        {
            config.json_output = true;
        } else if (std.mem.eql(u8, arg, "--filter") or
            std.mem.eql(u8, arg, "-f"))
        {
            if (i + 1 >= args.len) {
                printAuditUsage();
                return AuditError.InvalidArgs;
            }
            i += 1;
            config.filter = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printAuditUsage();
            return;
        } else {
            std.debug.print("Error: Unknown option: {s}\n", .{arg});
            return AuditError.InvalidArgs;
        }
    }

    std.debug.print("Connecting to {s}...\n", .{config.nats_url});

    // Connect to NATS
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-audit" },
    ) catch {
        std.debug.print("Error: Failed to connect to NATS\n", .{});
        return AuditError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    // Subscribe to audit events
    const subject = if (config.filter) |f|
        std.fmt.allocPrint(allocator, "clawgate.audit.{s}", .{f}) catch {
            return AuditError.OutOfMemory;
        }
    else
        "clawgate.audit.>";

    defer if (config.filter != null) allocator.free(subject);

    const sub = client.subscribe(allocator, subject) catch {
        std.debug.print("Error: Failed to subscribe\n", .{});
        return AuditError.SubscriptionFailed;
    };
    defer sub.deinit(allocator);

    client.flush(allocator) catch {};

    std.debug.print("Listening for audit events on {s}\n", .{subject});
    std.debug.print("Press Ctrl+C to stop.\n\n", .{});

    // Main loop - read and display events
    while (true) {
        const msg = sub.nextWithTimeout(allocator, 1000) catch |err| {
            if (err == error.Cancelled) break;
            continue;
        };

        if (msg) |m| {
            defer m.deinit(allocator);

            if (config.json_output) {
                // Raw JSON output
                std.debug.print("{s}\n", .{m.data});
            } else {
                // Parse and format nicely
                displayAuditEvent(allocator, m.subject, m.data);
            }
        }
    }
}

/// Parses and displays an audit event.
fn displayAuditEvent(
    allocator: Allocator,
    subject: []const u8,
    data: []const u8,
) void {
    // Try to parse the JSON
    const parsed = std.json.parseFromSlice(
        struct {
            timestamp: ?[]const u8 = null,
            request_id: ?[]const u8 = null,
            op: ?[]const u8 = null,
            path: ?[]const u8 = null,
            token_id: ?[]const u8 = null,
            issuer: ?[]const u8 = null,
            result: ?[]const u8 = null,
            error_code: ?[]const u8 = null,
            bytes: ?usize = null,
        },
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        // Can't parse, just show raw
        std.debug.print("[{s}] {s}\n", .{ subject, data });
        return;
    };
    defer parsed.deinit();

    const event = parsed.value;

    // Format timestamp or use subject
    const ts = event.timestamp orelse "unknown";

    // Build output line
    var buf: [512]u8 = undefined;
    var writer = Io.Writer.fixed(&buf);

    writer.print("[{s}] ", .{ts}) catch {};

    if (event.op) |op| {
        writer.print("{s} ", .{op}) catch {};
    }

    if (event.path) |path| {
        writer.print("{s} ", .{path}) catch {};
    }

    if (event.result) |result| {
        if (std.mem.eql(u8, result, "ok")) {
            writer.writeAll("OK") catch {};
        } else {
            writer.print("FAILED", .{}) catch {};
            if (event.error_code) |code| {
                writer.print(" ({s})", .{code}) catch {};
            }
        }
    }

    if (event.bytes) |bytes| {
        writer.print(" [{d} bytes]", .{bytes}) catch {};
    }

    if (event.token_id) |tid| {
        // Show abbreviated token ID
        const abbrev_len = @min(tid.len, 16);
        writer.print(" token:{s}...", .{tid[0..abbrev_len]}) catch {};
    }

    std.debug.print("{s}\n", .{writer.buffered()});
}

/// Prints audit command usage.
fn printAuditUsage() void {
    const usage =
        \\Usage: clawgate audit [options]
        \\
        \\Watch the audit log for file access events.
        \\
        \\Options:
        \\  -n, --nats <url>      NATS server URL
        \\                        (default: nats://localhost:4222)
        \\  -j, --json            Output raw JSON events
        \\  -f, --filter <type>   Filter by event type
        \\                        (e.g., files.read, files.write)
        \\  -h, --help            Show this help
        \\
        \\Examples:
        \\  clawgate audit
        \\  clawgate audit --json
        \\  clawgate audit --filter files.read
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "config defaults" {
    const config = AuditConfig{};
    try std.testing.expectEqualStrings(
        "nats://localhost:4222",
        config.nats_url,
    );
    try std.testing.expect(!config.json_output);
    try std.testing.expect(config.filter == null);
}

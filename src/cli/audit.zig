//! Audit log viewer for ClawGate.
//!
//! Displays audit events from local resource daemon logs.
//! Audit events are logged to stdout by the resource daemon.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const AuditError = error{
    InvalidArgs,
    OutOfMemory,
};

/// Configuration for audit command.
pub const AuditConfig = struct {
    json_output: bool = false,
    filter: ?[]const u8 = null,
};

/// Runs the audit log viewer.
/// In the current architecture, audit events are logged locally by the
/// resource daemon. This command provides usage information.
pub fn run(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
) AuditError!void {
    _ = allocator;
    _ = io;

    var config = AuditConfig{};

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "-j")) {
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

    printAuditInfo();
}

/// Prints information about audit logging.
fn printAuditInfo() void {
    const info =
        \\Audit Log Information
        \\
        \\ClawGate audit events are logged locally by the resource daemon.
        \\Events are written to stderr with the prefix "AUDIT:".
        \\
        \\To view audit logs on the resource machine:
        \\
        \\  # Run resource daemon and capture audit logs
        \\  clawgate --mode resource 2>&1 | grep AUDIT
        \\
        \\  # Or redirect to a file for later analysis
        \\  clawgate --mode resource 2>&1 | tee clawgate.log
        \\
        \\Audit log format:
        \\  AUDIT: req=<id> op=<operation> path=<path> success=<true|false>
        \\
        \\Operations logged:
        \\  - read:  File read requests
        \\  - write: File write requests
        \\  - list:  Directory listing requests
        \\  - stat:  File/directory stat requests
        \\
    ;
    std.debug.print("{s}", .{info});
}

/// Prints audit command usage.
fn printAuditUsage() void {
    const usage =
        \\Usage: clawgate audit [options]
        \\
        \\Display audit log information.
        \\
        \\In the E2E architecture, audit events are logged locally by the
        \\resource daemon on the primary machine. This command provides
        \\information about accessing those logs.
        \\
        \\Options:
        \\  -j, --json            (reserved for future use)
        \\  -f, --filter <type>   (reserved for future use)
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "config defaults" {
    const config = AuditConfig{};
    try std.testing.expect(!config.json_output);
    try std.testing.expect(config.filter == null);
}

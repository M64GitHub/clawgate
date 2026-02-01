//! ClawGate - Secure file access for isolated AI agents
//!
//! A capability-based, auditable bridge that enables isolated AI agents
//! to access files on a user's primary machine through NATS messaging.

const std = @import("std");

pub const version = "0.1.0";

/// Main entry point using Zig 0.16's std.process.Init.
pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Parse command line arguments
    var args_iter = std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    ) catch |err| {
        std.debug.print("Failed to init args: {}\n", .{err});
        return;
    };
    defer args_iter.deinit();

    // Collect args into a list for easier handling
    var args_list: std.ArrayListUnmanaged([:0]const u8) = .empty;
    defer args_list.deinit(allocator);

    while (args_iter.next()) |arg| {
        args_list.append(allocator, arg) catch |err| {
            std.debug.print("Failed to collect args: {}\n", .{err});
            return;
        };
    }

    const args = args_list.items;

    if (args.len < 2) {
        printUsage();
        return;
    }

    const cmd = args[1];
    const cmd_args = if (args.len > 2) args[2..] else &[_][:0]const u8{};

    if (std.mem.eql(u8, cmd, "--mode")) {
        try handleModeCommand(cmd_args);
    } else if (std.mem.eql(u8, cmd, "mcp-server")) {
        try handleMcpServer();
    } else if (std.mem.eql(u8, cmd, "grant")) {
        try handleGrant(cmd_args);
    } else if (std.mem.eql(u8, cmd, "audit")) {
        try handleAudit(cmd_args);
    } else if (std.mem.eql(u8, cmd, "cat")) {
        try handleCat(cmd_args);
    } else if (std.mem.eql(u8, cmd, "ls")) {
        try handleLs(cmd_args);
    } else if (std.mem.eql(u8, cmd, "write")) {
        try handleWrite(cmd_args);
    } else if (std.mem.eql(u8, cmd, "stat")) {
        try handleStat(cmd_args);
    } else if (std.mem.eql(u8, cmd, "keygen")) {
        try handleKeygen(cmd_args);
    } else if (std.mem.eql(u8, cmd, "token")) {
        try handleToken(cmd_args);
    } else if (std.mem.eql(u8, cmd, "version") or
        std.mem.eql(u8, cmd, "--version") or
        std.mem.eql(u8, cmd, "-v"))
    {
        printVersion();
    } else if (std.mem.eql(u8, cmd, "help") or
        std.mem.eql(u8, cmd, "--help") or
        std.mem.eql(u8, cmd, "-h"))
    {
        printUsage();
    } else {
        std.debug.print("Unknown command: {s}\n\n", .{cmd});
        printUsage();
    }
}

fn handleModeCommand(args: []const [:0]const u8) !void {
    if (args.len == 0) {
        std.debug.print(
            "Error: --mode requires argument (resource|agent)\n",
            .{},
        );
        return;
    }
    const mode = args[0];
    if (std.mem.eql(u8, mode, "resource")) {
        std.debug.print("Resource daemon not yet implemented\n", .{});
    } else if (std.mem.eql(u8, mode, "agent")) {
        std.debug.print("Agent daemon not yet implemented\n", .{});
    } else {
        std.debug.print("Unknown mode: {s}\n", .{mode});
    }
}

fn handleMcpServer() !void {
    std.debug.print("MCP server not yet implemented\n", .{});
}

fn handleGrant(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Grant command not yet implemented\n", .{});
}

fn handleAudit(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Audit command not yet implemented\n", .{});
}

fn handleCat(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Cat command not yet implemented\n", .{});
}

fn handleLs(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Ls command not yet implemented\n", .{});
}

fn handleWrite(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Write command not yet implemented\n", .{});
}

fn handleStat(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Stat command not yet implemented\n", .{});
}

fn handleKeygen(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Keygen command not yet implemented\n", .{});
}

fn handleToken(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Token command not yet implemented\n", .{});
}

fn printVersion() void {
    std.debug.print("ClawGate v{s}\n", .{version});
}

fn printUsage() void {
    const usage =
        \\ClawGate - Secure file access for isolated AI agents
        \\
        \\Usage:
        \\  clawgate --mode <resource|agent>  Run daemon
        \\  clawgate mcp-server               Run MCP server (stdio)
        \\
        \\Capability Management (primary machine):
        \\  clawgate grant [opts] <path>      Grant access to path
        \\    --read                          Allow read operations
        \\    --write                         Allow write operations
        \\    --ttl <duration>                Token lifetime (2h, 24h, 7d)
        \\  clawgate keygen                   Generate Ed25519 keypair
        \\
        \\Token Management (agent machine):
        \\  clawgate token add <token>        Add a capability token
        \\  clawgate token list               List stored tokens
        \\  clawgate token remove <id>        Remove a token
        \\
        \\File Operations (agent machine):
        \\  clawgate cat <path>               Read file
        \\  clawgate ls <path>                List directory
        \\  clawgate write <path>             Write file (stdin or --content)
        \\  clawgate stat <path>              Get file info
        \\
        \\Monitoring:
        \\  clawgate audit                    Watch audit log
        \\  clawgate audit --json             Output as JSON
        \\
        \\Options:
        \\  --nats <url>                      NATS server URL
        \\  --help, -h                        Show this help
        \\  --version, -v                     Show version
        \\
        \\https://clawgate.io
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "version string is valid" {
    try std.testing.expect(version.len > 0);
    try std.testing.expect(std.mem.eql(u8, version, "0.1.0"));
}

test {
    // Reference modules to include their tests
    _ = @import("capability/scope.zig");
    _ = @import("capability/crypto.zig");
    _ = @import("capability/token.zig");
    _ = @import("protocol/json.zig");
}

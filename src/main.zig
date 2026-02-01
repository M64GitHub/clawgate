//! ClawGate - Secure file access for isolated AI agents
//!
//! A capability-based, auditable bridge that enables isolated AI agents
//! to access files on a user's primary machine through NATS messaging.

const std = @import("std");
const resource_daemon = @import("resource/daemon.zig");

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
        try handleModeCommand(allocator, cmd_args);
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

/// Handles --mode command to start resource or agent daemon.
fn handleModeCommand(
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) !void {
    if (args.len == 0) {
        std.debug.print(
            "Error: --mode requires argument (resource|agent)\n",
            .{},
        );
        return;
    }

    const mode = args[0];
    const remaining_args = if (args.len > 1) args[1..] else &[_][:0]const u8{};

    if (std.mem.eql(u8, mode, "resource")) {
        var public_key_path: []const u8 = "/tmp/clawgate_test_public.key";
        var nats_url: []const u8 = "nats://localhost:4222";

        var i: usize = 0;
        while (i < remaining_args.len) : (i += 1) {
            const arg = remaining_args[i];
            const has_next = i + 1 < remaining_args.len;
            if (std.mem.eql(u8, arg, "--public-key") and has_next) {
                i += 1;
                public_key_path = remaining_args[i];
            } else if (std.mem.eql(u8, arg, "--nats") and has_next) {
                i += 1;
                nats_url = remaining_args[i];
            }
        }

        resource_daemon.run(allocator, .{
            .nats_url = nats_url,
            .public_key_path = public_key_path,
        }) catch |err| {
            std.debug.print("Resource daemon error: {}\n", .{err});
            return;
        };
    } else if (std.mem.eql(u8, mode, "agent")) {
        std.debug.print("Agent daemon not yet implemented\n", .{});
    } else {
        std.debug.print("Unknown mode: {s}\n", .{mode});
    }
}

/// Starts MCP server for agent-side AI tool integration.
fn handleMcpServer() !void {
    std.debug.print("MCP server not yet implemented\n", .{});
}

/// Grants a capability token for file access.
fn handleGrant(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Grant command not yet implemented\n", .{});
}

/// Displays audit log of file access events.
fn handleAudit(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Audit command not yet implemented\n", .{});
}

/// Reads and outputs file content.
fn handleCat(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Cat command not yet implemented\n", .{});
}

/// Lists directory contents.
fn handleLs(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Ls command not yet implemented\n", .{});
}

/// Writes content to a file.
fn handleWrite(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Write command not yet implemented\n", .{});
}

/// Returns file or directory metadata.
fn handleStat(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Stat command not yet implemented\n", .{});
}

/// Generates Ed25519 keypair for token signing.
fn handleKeygen(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Keygen command not yet implemented\n", .{});
}

/// Manages stored capability tokens.
fn handleToken(args: []const [:0]const u8) !void {
    _ = args;
    std.debug.print("Token command not yet implemented\n", .{});
}

/// Prints version information.
fn printVersion() void {
    std.debug.print("ClawGate v{s}\n", .{version});
}

/// Prints CLI usage help.
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
    _ = @import("resource/files.zig");
    _ = @import("resource/handlers.zig");
    _ = @import("resource/daemon.zig");
}

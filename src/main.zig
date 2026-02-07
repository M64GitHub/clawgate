//! ClawGate - Secure file access for isolated AI agents
//!
//! A capability-based, auditable bridge that enables isolated AI agents
//! to access files on a user's primary machine through direct TCP with
//! end-to-end encryption.

const std = @import("std");
const resource_daemon = @import("resource/daemon.zig");
const agent_daemon = @import("agent/daemon.zig");
const mcp = @import("agent/mcp.zig");
const setup = @import("cli/setup.zig");
const grant_cmd = @import("cli/grant.zig");
const token_cmd = @import("cli/token.zig");
const file_cmds = @import("cli/file_cmds.zig");
const git_cmd = @import("cli/git_cmd.zig");
const audit_cmd = @import("cli/audit.zig");

pub const version = "0.2.2";

/// Main entry point using Zig 0.16's std.process.Init.
pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // Get HOME from environment
    const home: ?[]const u8 = init.environ_map.get("HOME");

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
        try handleModeCommand(allocator, cmd_args, init.minimal.environ);
    } else if (std.mem.eql(u8, cmd, "mcp-server")) {
        try handleMcpServer(allocator, cmd_args, init.minimal.environ);
    } else if (std.mem.eql(u8, cmd, "grant")) {
        grant_cmd.grant(allocator, io, cmd_args, home) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "audit")) {
        audit_cmd.run(allocator, io, cmd_args) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "cat")) {
        file_cmds.cat(
            allocator,
            io,
            cmd_args,
            home,
            init.minimal.environ,
        ) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "ls")) {
        file_cmds.ls(
            allocator,
            io,
            cmd_args,
            home,
            init.minimal.environ,
        ) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "write")) {
        file_cmds.write(
            allocator,
            io,
            cmd_args,
            home,
            init.minimal.environ,
        ) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "stat")) {
        file_cmds.stat(
            allocator,
            io,
            cmd_args,
            home,
            init.minimal.environ,
        ) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "git")) {
        git_cmd.git(
            allocator,
            io,
            cmd_args,
            home,
            init.minimal.environ,
        ) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "keygen")) {
        setup.keygen(allocator, io, cmd_args, home) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, cmd, "token")) {
        token_cmd.run(allocator, io, cmd_args, home) catch {
            std.process.exit(1);
        };
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
    environ: std.process.Environ,
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
        var public_key_path: []const u8 = "~/.clawgate/keys/public.key";
        var connect_addr: []const u8 = "localhost";
        var connect_port: u16 = 4223;
        var resource_id: []const u8 = "clawgate-resource";

        var i: usize = 0;
        while (i < remaining_args.len) : (i += 1) {
            const arg = remaining_args[i];
            const has_next = i + 1 < remaining_args.len;
            if (std.mem.eql(u8, arg, "--public-key") and has_next) {
                i += 1;
                public_key_path = remaining_args[i];
            } else if (std.mem.eql(u8, arg, "--connect") and has_next) {
                i += 1;
                const addr_port = remaining_args[i];
                if (std.mem.lastIndexOfScalar(u8, addr_port, ':')) |idx| {
                    connect_addr = addr_port[0..idx];
                    connect_port = std.fmt.parseInt(
                        u16,
                        addr_port[idx + 1 ..],
                        10,
                    ) catch 4223;
                } else {
                    connect_addr = addr_port;
                }
            } else if (std.mem.eql(u8, arg, "--resource-id") and has_next) {
                i += 1;
                resource_id = remaining_args[i];
            }
        }

        resource_daemon.run(allocator, .{
            .connect_addr = connect_addr,
            .connect_port = connect_port,
            .public_key_path = public_key_path,
            .resource_id = resource_id,
            .environ = environ,
        }) catch |err| {
            std.debug.print("Resource daemon error: {}\n", .{err});
            return;
        };
    } else if (std.mem.eql(u8, mode, "agent")) {
        var token_dir: []const u8 = "~/.clawgate/tokens";
        var listen_addr: []const u8 = "0.0.0.0";
        var listen_port: u16 = 4223;

        var i: usize = 0;
        while (i < remaining_args.len) : (i += 1) {
            const arg = remaining_args[i];
            const has_next = i + 1 < remaining_args.len;
            if (std.mem.eql(u8, arg, "--token-dir") and has_next) {
                i += 1;
                token_dir = remaining_args[i];
            } else if (std.mem.eql(u8, arg, "--listen") and has_next) {
                i += 1;
                const addr_port = remaining_args[i];
                if (std.mem.lastIndexOfScalar(u8, addr_port, ':')) |idx| {
                    listen_addr = addr_port[0..idx];
                    listen_port = std.fmt.parseInt(
                        u16,
                        addr_port[idx + 1 ..],
                        10,
                    ) catch 4223;
                }
            }
        }

        agent_daemon.run(allocator, .{
            .listen_addr = listen_addr,
            .listen_port = listen_port,
            .token_dir = token_dir,
            .environ = environ,
        }) catch |err| {
            std.debug.print("Agent daemon error: {}\n", .{err});
            return;
        };
    } else {
        std.debug.print("Unknown mode: {s}\n", .{mode});
    }
}

/// Starts MCP server for agent-side AI tool integration.
fn handleMcpServer(
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
    environ: std.process.Environ,
) !void {
    var token_dir: []const u8 = "~/.clawgate/tokens";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const has_next = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--token-dir") and has_next) {
            i += 1;
            token_dir = args[i];
        }
    }

    mcp.run(allocator, .{
        .token_dir = token_dir,
        .environ = environ,
    }) catch |err| {
        std.debug.print("MCP server error: {}\n", .{err});
        return;
    };
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
        \\  clawgate --mode agent             Run agent daemon (listens for connections)
        \\  clawgate --mode resource          Run resource daemon (connects to agent)
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
        \\  clawgate git <repo> <args...>     Run git command
        \\
        \\Monitoring:
        \\  clawgate audit                    Watch audit log
        \\  clawgate audit --json             Output as JSON
        \\
        \\Daemon Options:
        \\  --listen <addr:port>              Listen address (agent mode, default 0.0.0.0:4223)
        \\  --connect <host:port>             Connect address (resource mode)
        \\  --public-key <path>               Public key path (resource mode)
        \\  --token-dir <path>                Token directory (agent mode)
        \\
        \\General Options:
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
    try std.testing.expect(std.mem.eql(u8, version, "0.2.2"));
}

test {
    // Reference modules to include their tests
    _ = @import("capability/scope.zig");
    _ = @import("capability/crypto.zig");
    _ = @import("capability/e2e.zig");
    _ = @import("capability/token.zig");
    _ = @import("transport/tcp.zig");
    _ = @import("transport/unix.zig");
    _ = @import("protocol/json.zig");
    _ = @import("protocol/handshake.zig");
    _ = @import("resource/files.zig");
    _ = @import("resource/handlers.zig");
    _ = @import("resource/git.zig");
    _ = @import("resource/daemon.zig");
    _ = @import("agent/tokens.zig");
    _ = @import("agent/daemon.zig");
    _ = @import("agent/mcp.zig");
    _ = @import("agent/ipc_client.zig");
    _ = @import("cli/setup.zig");
    _ = @import("cli/grant.zig");
    _ = @import("cli/token.zig");
    _ = @import("cli/file_cmds.zig");
    _ = @import("cli/git_cmd.zig");
    _ = @import("cli/audit.zig");
    _ = @import("config/config.zig");
}

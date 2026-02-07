//! Token management commands for ClawGate.
//!
//! Manages capability tokens on the agent machine:
//! - add: Add a token from stdin or argument
//! - list: List all stored tokens
//! - remove: Remove a token by ID

const std = @import("std");
const tokens_mod = @import("../agent/tokens.zig");
const token_mod = @import("../capability/token.zig");
const audit_log = @import("../resource/audit_log.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;

pub const TokenCmdError = error{
    InvalidArgs,
    InvalidSubcommand,
    TokenNotFound,
    TokenStoreFailed,
    ReadFailed,
    OutOfMemory,
};

/// Dispatches token subcommands.
pub fn run(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) TokenCmdError!void {
    if (args.len == 0) {
        printTokenUsage();
        return TokenCmdError.InvalidArgs;
    }

    const subcmd = args[0];
    const subcmd_args = if (args.len > 1) args[1..] else &[_][:0]const u8{};

    if (std.mem.eql(u8, subcmd, "add")) {
        return tokenAdd(allocator, io, subcmd_args, home);
    } else if (std.mem.eql(u8, subcmd, "list") or
        std.mem.eql(u8, subcmd, "ls"))
    {
        return tokenList(allocator, io, subcmd_args, home);
    } else if (std.mem.eql(u8, subcmd, "remove") or
        std.mem.eql(u8, subcmd, "rm"))
    {
        return tokenRemove(allocator, io, subcmd_args, home);
    } else if (std.mem.eql(u8, subcmd, "show")) {
        return tokenShow(allocator, io, subcmd_args, home);
    } else if (std.mem.eql(u8, subcmd, "--help") or
        std.mem.eql(u8, subcmd, "-h"))
    {
        printTokenUsage();
        return;
    } else {
        std.debug.print("Error: Unknown subcommand: {s}\n\n", .{subcmd});
        printTokenUsage();
        return TokenCmdError.InvalidSubcommand;
    }
}

/// Adds a token to the store.
fn tokenAdd(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) TokenCmdError!void {
    var token_dir: ?[]const u8 = null;
    var token_data: ?[]const u8 = null;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) {
                printTokenUsage();
                return TokenCmdError.InvalidArgs;
            }
            i += 1;
            token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printTokenAddUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            token_data = arg;
        }
    }

    // Get token directory
    const dir = token_dir orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return TokenCmdError.TokenStoreFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return TokenCmdError.OutOfMemory;
    };
    defer if (token_dir == null) allocator.free(dir);

    // Ensure directory exists
    const clawgate_dir = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate",
        .{home orelse "."},
    ) catch return TokenCmdError.OutOfMemory;
    defer allocator.free(clawgate_dir);

    Dir.createDir(.cwd(), io, clawgate_dir, .default_dir) catch {};
    Dir.createDir(.cwd(), io, dir, .default_dir) catch {};

    // Get token from arg or stdin
    const jwt: []const u8 = if (token_data) |td|
        td
    else blk: {
        // Read from stdin
        std.debug.print("Paste token (then press Enter):\n", .{});
        var buf: [16384]u8 = undefined;
        const stdin = std.posix.STDIN_FILENO;
        const n = std.posix.read(stdin, &buf) catch {
            std.debug.print("Error: Failed to read from stdin\n", .{});
            return TokenCmdError.ReadFailed;
        };
        if (n == 0) {
            std.debug.print("Error: No token provided\n", .{});
            return TokenCmdError.InvalidArgs;
        }
        break :blk std.mem.trim(u8, buf[0..n], " \t\r\n");
    };

    // Load or create store
    var store = tokens_mod.TokenStore.loadFromDir(allocator, io, dir) catch {
        // Create empty store if directory is empty/new
        const owned_dir = allocator.dupe(u8, dir) catch {
            return TokenCmdError.OutOfMemory;
        };
        var s: tokens_mod.TokenStore = .{
            .tokens = &.{},
            .token_dir = owned_dir,
        };
        s.addToken(allocator, io, jwt) catch |err| {
            allocator.free(owned_dir);
            std.debug.print("Error: Failed to add token: {}\n", .{err});
            return TokenCmdError.TokenStoreFailed;
        };

        // Parse to show ID
        var parsed = token_mod.Token.parse(allocator, jwt) catch {
            std.debug.print("Token added successfully.\n", .{});
            s.deinit(allocator);
            return;
        };
        defer parsed.deinit(allocator);

        std.debug.print("Token added: {s}\n", .{parsed.getId()});
        s.deinit(allocator);
        return;
    };
    defer store.deinit(allocator);

    // Add token
    store.addToken(allocator, io, jwt) catch |err| {
        std.debug.print("Error: Failed to add token: {}\n", .{err});
        return TokenCmdError.TokenStoreFailed;
    };

    // Parse to show ID
    var parsed = token_mod.Token.parse(allocator, jwt) catch {
        std.debug.print("Token added successfully.\n", .{});
        return;
    };
    defer parsed.deinit(allocator);

    std.debug.print("Token added: {s}\n", .{parsed.getId()});
}

/// Lists all stored tokens.
fn tokenList(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) TokenCmdError!void {
    var token_dir: ?[]const u8 = null;
    var show_json = false;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return TokenCmdError.InvalidArgs;
            i += 1;
            token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--json")) {
            show_json = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printTokenListUsage();
            return;
        }
    }

    // Get token directory
    const dir = token_dir orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return TokenCmdError.TokenStoreFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return TokenCmdError.OutOfMemory;
    };
    defer if (token_dir == null) allocator.free(dir);

    // Load store
    var store = tokens_mod.TokenStore.loadFromDir(allocator, io, dir) catch {
        std.debug.print("No tokens found.\n", .{});
        return;
    };
    defer store.deinit(allocator);

    const stored_tokens = store.list();
    if (stored_tokens.len == 0) {
        std.debug.print("No tokens found.\n", .{});
        return;
    }

    if (show_json) {
        // Output as JSON
        std.debug.print("[\n", .{});
        for (stored_tokens, 0..) |*tok, idx| {
            const payload = tok.parsed.payload;
            std.debug.print(
                "  {{\"id\":\"{s}\",\"iss\":\"{s}\",\"sub\":\"{s}\"," ++
                    "\"exp\":{d}}}",
                .{ payload.jti, payload.iss, payload.sub, payload.exp },
            );
            if (idx < stored_tokens.len - 1) {
                std.debug.print(",\n", .{});
            } else {
                std.debug.print("\n", .{});
            }
        }
        std.debug.print("]\n", .{});
    } else {
        // Human-readable output
        std.debug.print("Stored tokens ({d}):\n\n", .{stored_tokens.len});

        for (stored_tokens) |*tok| {
            const payload = tok.parsed.payload;
            const expired = tok.parsed.isExpired();

            std.debug.print("  ID:      {s}\n", .{payload.jti});
            std.debug.print("  Issuer:  {s}\n", .{payload.iss});
            std.debug.print("  Subject: {s}\n", .{payload.sub});

            // Show capabilities
            for (payload.cg.cap) |cap| {
                std.debug.print("  Scope:   {s} ", .{cap.s});
                std.debug.print("[", .{});
                for (cap.o, 0..) |op, j| {
                    if (j > 0) std.debug.print(", ", .{});
                    std.debug.print("{s}", .{op});
                }
                std.debug.print("]\n", .{});
            }

            var exp_buf: [20]u8 = undefined;
            if (payload.exp >= 0) {
                const exp_str = audit_log.formatEpochBuf(
                    &exp_buf,
                    @intCast(payload.exp),
                );
                std.debug.print(
                    "  Expires: {s}\n",
                    .{exp_str},
                );
            }

            if (expired) {
                std.debug.print("  Status:  EXPIRED\n", .{});
            } else {
                std.debug.print("  Status:  Valid\n", .{});
            }
            std.debug.print("\n", .{});
        }
    }
}

/// Removes a token by ID.
fn tokenRemove(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) TokenCmdError!void {
    var token_dir: ?[]const u8 = null;
    var token_id: ?[]const u8 = null;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return TokenCmdError.InvalidArgs;
            i += 1;
            token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printTokenRemoveUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            token_id = arg;
        }
    }

    if (token_id == null) {
        std.debug.print("Error: Token ID required\n\n", .{});
        printTokenRemoveUsage();
        return TokenCmdError.InvalidArgs;
    }

    // Get token directory
    const dir = token_dir orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return TokenCmdError.TokenStoreFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return TokenCmdError.OutOfMemory;
    };
    defer if (token_dir == null) allocator.free(dir);

    // Load store
    var store = tokens_mod.TokenStore.loadFromDir(allocator, io, dir) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return TokenCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    // Remove token
    store.removeToken(allocator, io, token_id.?) catch {
        std.debug.print("Error: Token not found: {s}\n", .{token_id.?});
        return TokenCmdError.TokenNotFound;
    };

    std.debug.print("Token removed: {s}\n", .{token_id.?});
}

/// Shows details of a specific token.
fn tokenShow(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) TokenCmdError!void {
    var token_dir: ?[]const u8 = null;
    var token_id: ?[]const u8 = null;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return TokenCmdError.InvalidArgs;
            i += 1;
            token_dir = args[i];
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            token_id = arg;
        }
    }

    if (token_id == null) {
        std.debug.print("Error: Token ID required\n", .{});
        return TokenCmdError.InvalidArgs;
    }

    // Get token directory
    const dir = token_dir orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return TokenCmdError.TokenStoreFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return TokenCmdError.OutOfMemory;
    };
    defer if (token_dir == null) allocator.free(dir);

    // Load store
    var store = tokens_mod.TokenStore.loadFromDir(allocator, io, dir) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return TokenCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    // Find token
    for (store.list()) |*tok| {
        if (std.mem.eql(u8, tok.parsed.getId(), token_id.?)) {
            const payload = tok.parsed.payload;
            std.debug.print("Token: {s}\n\n", .{payload.jti});
            std.debug.print("  Issuer:  {s}\n", .{payload.iss});
            std.debug.print("  Subject: {s}\n", .{payload.sub});
            var iat_buf: [20]u8 = undefined;
            var exp_buf: [20]u8 = undefined;
            if (payload.iat >= 0) {
                std.debug.print("  Issued:  {s}\n", .{
                    audit_log.formatEpochBuf(
                        &iat_buf,
                        @intCast(payload.iat),
                    ),
                });
            } else {
                std.debug.print(
                    "  Issued:  {d}\n",
                    .{payload.iat},
                );
            }
            if (payload.exp >= 0) {
                std.debug.print("  Expires: {s}\n", .{
                    audit_log.formatEpochBuf(
                        &exp_buf,
                        @intCast(payload.exp),
                    ),
                });
            } else {
                std.debug.print(
                    "  Expires: {d}\n",
                    .{payload.exp},
                );
            }
            std.debug.print("\n  Capabilities:\n", .{});
            for (payload.cg.cap) |cap| {
                std.debug.print("    - {s}: {s} [", .{ cap.r, cap.s });
                for (cap.o, 0..) |op, j| {
                    if (j > 0) std.debug.print(", ", .{});
                    std.debug.print("{s}", .{op});
                }
                std.debug.print("]\n", .{});
            }
            std.debug.print("\n  Status: ", .{});
            if (tok.parsed.isExpired()) {
                std.debug.print("EXPIRED\n", .{});
            } else {
                std.debug.print("Valid\n", .{});
            }
            return;
        }
    }

    std.debug.print("Error: Token not found: {s}\n", .{token_id.?});
    return TokenCmdError.TokenNotFound;
}

fn printTokenUsage() void {
    const usage =
        \\Usage: clawgate token <command> [options]
        \\
        \\Manage capability tokens on the agent machine.
        \\
        \\Commands:
        \\  add [token]           Add a token (from arg or stdin)
        \\  list, ls              List all stored tokens
        \\  show <id>             Show token details
        \\  remove, rm <id>       Remove a token by ID
        \\
        \\Options:
        \\  -d, --token-dir <dir> Token directory
        \\                        (default: ~/.clawgate/tokens)
        \\  -h, --help            Show this help
        \\
        \\Examples:
        \\  clawgate token add eyJhbGc...
        \\  cat token.txt | clawgate token add
        \\  clawgate token list
        \\  clawgate token remove cg_abc123def456
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printTokenAddUsage() void {
    const usage =
        \\Usage: clawgate token add [options] [token]
        \\
        \\Add a capability token to the local store.
        \\
        \\If no token is provided as argument, reads from stdin.
        \\
        \\Options:
        \\  -d, --token-dir <dir> Token directory
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printTokenListUsage() void {
    const usage =
        \\Usage: clawgate token list [options]
        \\
        \\List all stored capability tokens.
        \\
        \\Options:
        \\  -d, --token-dir <dir> Token directory
        \\      --json            Output as JSON
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printTokenRemoveUsage() void {
    const usage =
        \\Usage: clawgate token remove <id>
        \\
        \\Remove a capability token by its ID.
        \\
        \\Use 'clawgate token list' to see token IDs.
        \\
        \\Options:
        \\  -d, --token-dir <dir> Token directory
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "token cmd error" {
    // Simple test to verify module compiles
    try std.testing.expect(
        TokenCmdError.InvalidArgs != TokenCmdError.TokenNotFound,
    );
}

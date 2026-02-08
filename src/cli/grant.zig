//! Grant command for creating capability tokens.
//!
//! Creates JWT capability tokens signed with Ed25519.
//! Tokens grant access to specific paths with specific operations.

const std = @import("std");
const crypto = @import("../capability/crypto.zig");
const token = @import("../capability/token.zig");
const tools_mod = @import("../resource/tools.zig");
const issuance = @import("../resource/issuance.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const GrantError = error{
    InvalidArgs,
    MissingPath,
    MissingOperations,
    KeyLoadFailed,
    TokenCreateFailed,
    InvalidTtl,
    OutOfMemory,
};

/// Configuration for grant command.
pub const GrantConfig = struct {
    /// Path to grant access to
    path: ?[]const u8 = null,
    /// Allow read operations
    read: bool = false,
    /// Allow write operations
    write: bool = false,
    /// Allow list operations (implied by read)
    list: bool = false,
    /// Allow stat operations (implied by read)
    stat: bool = false,
    /// Allow git read-only operations
    git: bool = false,
    /// Allow git write operations
    git_write: bool = false,
    /// Allow git remote operations
    git_full: bool = false,
    /// Tool names to grant access to
    tool_names: [16][]const u8 = undefined,
    /// Number of tool names
    tool_count: usize = 0,
    /// Grant access to all registered tools
    tools_all: bool = false,
    /// Token TTL in seconds (default: 24h)
    ttl_seconds: i64 = 24 * 60 * 60,
    /// Path to secret key
    secret_key_path: ?[]const u8 = null,
    /// Issuer identity
    issuer: []const u8 = "clawgate:resource",
    /// Subject identity
    subject: []const u8 = "clawgate:agent",
};

/// Creates and outputs a capability token.
pub fn grant(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) GrantError!void {
    var config = GrantConfig{};

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--read") or std.mem.eql(u8, arg, "-r")) {
            config.read = true;
            config.list = true;
            config.stat = true;
        } else if (std.mem.eql(u8, arg, "--write") or
            std.mem.eql(u8, arg, "-w"))
        {
            config.write = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            config.list = true;
        } else if (std.mem.eql(u8, arg, "--stat")) {
            config.stat = true;
        } else if (std.mem.eql(u8, arg, "--ttl") or
            std.mem.eql(u8, arg, "-t"))
        {
            if (i + 1 >= args.len) {
                printGrantUsage();
                return GrantError.InvalidArgs;
            }
            i += 1;
            config.ttl_seconds = parseTtl(args[i]) orelse {
                std.debug.print("Error: Invalid TTL: {s}\n", .{args[i]});
                return GrantError.InvalidTtl;
            };
        } else if (std.mem.eql(u8, arg, "--key") or
            std.mem.eql(u8, arg, "-k"))
        {
            if (i + 1 >= args.len) {
                printGrantUsage();
                return GrantError.InvalidArgs;
            }
            i += 1;
            config.secret_key_path = args[i];
        } else if (std.mem.eql(u8, arg, "--issuer")) {
            if (i + 1 >= args.len) {
                printGrantUsage();
                return GrantError.InvalidArgs;
            }
            i += 1;
            config.issuer = args[i];
        } else if (std.mem.eql(u8, arg, "--subject")) {
            if (i + 1 >= args.len) {
                printGrantUsage();
                return GrantError.InvalidArgs;
            }
            i += 1;
            config.subject = args[i];
        } else if (std.mem.eql(u8, arg, "--git")) {
            config.git = true;
            config.read = true;
            config.list = true;
            config.stat = true;
        } else if (std.mem.eql(u8, arg, "--git-write")) {
            config.git = true;
            config.git_write = true;
            config.read = true;
            config.write = true;
            config.list = true;
            config.stat = true;
        } else if (std.mem.eql(u8, arg, "--git-full")) {
            config.git = true;
            config.git_write = true;
            config.git_full = true;
            config.read = true;
            config.write = true;
            config.list = true;
            config.stat = true;
        } else if (std.mem.eql(u8, arg, "--tool")) {
            if (i + 1 >= args.len) {
                printGrantUsage();
                return GrantError.InvalidArgs;
            }
            i += 1;
            if (config.tool_count >= 16) {
                std.debug.print(
                    "Error: Max 16 tools\n",
                    .{},
                );
                return GrantError.InvalidArgs;
            }
            config.tool_names[config.tool_count] = args[i];
            config.tool_count += 1;
        } else if (std.mem.eql(u8, arg, "--tools-all")) {
            config.tools_all = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printGrantUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            config.path = arg;
        } else {
            std.debug.print("Error: Unknown option: {s}\n", .{arg});
            return GrantError.InvalidArgs;
        }
    }

    // Validate required arguments
    const has_tools = config.tool_count > 0 or config.tools_all;
    const has_file_ops = config.read or config.write or
        config.list or config.stat or config.git;

    if (config.path == null and !has_tools) {
        std.debug.print(
            "Error: Path or --tool required\n\n",
            .{},
        );
        printGrantUsage();
        return GrantError.MissingPath;
    }

    if (config.path != null and !has_file_ops and !has_tools) {
        std.debug.print(
            "Error: At least one operation required\n\n",
            .{},
        );
        printGrantUsage();
        return GrantError.MissingOperations;
    }

    // Determine secret key path
    const key_path = config.secret_key_path orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return GrantError.KeyLoadFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/keys/secret.key",
            .{home_dir},
        ) catch return GrantError.OutOfMemory;
    };
    defer if (config.secret_key_path == null) allocator.free(key_path);

    // Load secret key
    var secret_key = crypto.loadSecretKey(io, key_path) catch {
        std.debug.print("Error: Failed to load secret key from {s}\n", .{
            key_path,
        });
        std.debug.print("Run 'clawgate keygen' first.\n", .{});
        return GrantError.KeyLoadFailed;
    };
    defer std.crypto.secureZero(u8, &secret_key);

    // Build operations list
    var ops_buf: [7][]const u8 = undefined;
    var ops_count: usize = 0;
    if (config.read) {
        ops_buf[ops_count] = "read";
        ops_count += 1;
    }
    if (config.write) {
        ops_buf[ops_count] = "write";
        ops_count += 1;
    }
    if (config.list) {
        ops_buf[ops_count] = "list";
        ops_count += 1;
    }
    if (config.stat) {
        ops_buf[ops_count] = "stat";
        ops_count += 1;
    }
    if (config.git) {
        ops_buf[ops_count] = "git";
        ops_count += 1;
    }
    if (config.git_write) {
        ops_buf[ops_count] = "git_write";
        ops_count += 1;
    }
    if (config.git_full) {
        ops_buf[ops_count] = "git_remote";
        ops_count += 1;
    }

    // Build capabilities array (file + tool caps)
    // Max: 1 file + 16 tools = 17
    var caps_buf: [17]token.Capability = undefined;
    var caps_count: usize = 0;

    // File capability (if path given and file ops requested)
    if (config.path != null and ops_count > 0) {
        caps_buf[caps_count] = .{
            .r = "files",
            .o = ops_buf[0..ops_count],
            .s = config.path.?,
        };
        caps_count += 1;
    }

    // Tool capabilities
    if (config.tools_all) {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return GrantError.KeyLoadFailed;
        };
        var reg = tools_mod.ToolRegistry.load(
            allocator,
            io,
            home_dir,
        ) catch {
            std.debug.print(
                "Error: Failed to load tool registry\n",
                .{},
            );
            return GrantError.InvalidArgs;
        };
        defer reg.deinit(allocator);

        const names = reg.listNames(allocator) catch
            return GrantError.OutOfMemory;
        defer allocator.free(names);

        const invoke_op = [_][]const u8{"invoke"};
        for (names) |name| {
            if (caps_count >= caps_buf.len) break;
            caps_buf[caps_count] = .{
                .r = "tools",
                .o = &invoke_op,
                .s = name,
            };
            caps_count += 1;
        }
    } else {
        const invoke_op = [_][]const u8{"invoke"};
        for (
            config.tool_names[0..config.tool_count],
        ) |name| {
            if (caps_count >= caps_buf.len) break;
            caps_buf[caps_count] = .{
                .r = "tools",
                .o = &invoke_op,
                .s = name,
            };
            caps_count += 1;
        }
    }

    if (caps_count == 0) {
        std.debug.print(
            "Error: No capabilities to grant\n\n",
            .{},
        );
        printGrantUsage();
        return GrantError.MissingOperations;
    }

    // Create token
    const jwt = token.createToken(
        allocator,
        io,
        secret_key,
        config.issuer,
        config.subject,
        caps_buf[0..caps_count],
        config.ttl_seconds,
    ) catch {
        std.debug.print("Error: Failed to create token\n", .{});
        return GrantError.TokenCreateFailed;
    };
    defer allocator.free(jwt);

    // Record issuance (non-fatal)
    recordIssuance(allocator, io, jwt, home) catch {};

    // Output token to stdout (not stderr)
    const stdout = std.Io.File.stdout();
    stdout.writeStreamingAll(io, jwt) catch return GrantError.OutOfMemory;
    stdout.writeStreamingAll(io, "\n") catch return GrantError.OutOfMemory;
}

/// Parses a TTL string like "1h", "24h", "7d", "3600".
fn parseTtl(s: []const u8) ?i64 {
    if (s.len == 0) return null;

    // Check for suffix
    const last = s[s.len - 1];
    if (last == 'h' or last == 'H') {
        const hours = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch {
            return null;
        };
        return hours * 60 * 60;
    } else if (last == 'd' or last == 'D') {
        const days = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch {
            return null;
        };
        return days * 24 * 60 * 60;
    } else if (last == 'm' or last == 'M') {
        const minutes = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch {
            return null;
        };
        return minutes * 60;
    } else if (last == 's' or last == 'S') {
        return std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch null;
    } else {
        return std.fmt.parseInt(i64, s, 10) catch null;
    }
}

/// Records token issuance in the issuance log.
fn recordIssuance(
    allocator: Allocator,
    io: Io,
    jwt: []const u8,
    home: ?[]const u8,
) !void {
    const home_dir = home orelse return;
    var tok = token.Token.parse(allocator, jwt) catch return;
    defer tok.deinit(allocator);

    var log = issuance.IssuanceLog.load(
        allocator,
        io,
        home_dir,
    ) catch return;
    defer log.deinit(allocator);

    log.record(allocator, io, .{
        .id = tok.getId(),
        .scope = "",
        .issued_at = "",
        .expires_at = "",
    }) catch {};
}

/// Prints grant command usage.
fn printGrantUsage() void {
    const usage =
        \\Usage: clawgate grant [options] <path>
        \\
        \\Create a capability token granting access to a path.
        \\
        \\Arguments:
        \\  <path>                Path or glob pattern to grant access to
        \\                        Examples: /home/user/project/**
        \\                                  /tmp/*
        \\                                  /data/file.txt
        \\
        \\Operations:
        \\  -r, --read            Allow read operations (includes list, stat)
        \\  -w, --write           Allow write operations
        \\      --list            Allow list operations only
        \\      --stat            Allow stat operations only
        \\      --git             Git read-only (+ read, list, stat)
        \\      --git-write       Git read+write (+ file write)
        \\      --git-full        Git full access (+ push/pull/fetch)
        \\      --tool <name>     Grant tool access (repeatable)
        \\      --tools-all       Grant access to all registered tools
        \\
        \\Options:
        \\  -t, --ttl <duration>  Token lifetime (default: 24h)
        \\                        Examples: 1h, 24h, 7d, 3600
        \\  -k, --key <path>      Path to secret key
        \\                        (default: ~/.clawgate/keys/secret.key)
        \\      --issuer <id>     Issuer identity
        \\      --subject <id>    Subject identity
        \\  -h, --help            Show this help
        \\
        \\Output:
        \\  The JWT token is printed to stdout.
        \\  Copy it to the agent machine and add with 'clawgate token add'.
        \\
        \\Examples:
        \\  clawgate grant --read /home/mario/projects/**
        \\  clawgate grant --read --write --ttl 1h /tmp/shared/*
        \\  clawgate grant -r -t 7d /data/** > token.txt
        \\  clawgate grant --git ~/projects/**
        \\  clawgate grant --tool calc --ttl 1h
        \\  clawgate grant --read --tool calc /tmp/**
        \\  clawgate grant --tools-all --ttl 4h
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "parseTtl with hours" {
    try std.testing.expectEqual(@as(?i64, 3600), parseTtl("1h"));
    try std.testing.expectEqual(@as(?i64, 86400), parseTtl("24h"));
    try std.testing.expectEqual(@as(?i64, 7200), parseTtl("2H"));
}

test "parseTtl with days" {
    try std.testing.expectEqual(@as(?i64, 86400), parseTtl("1d"));
    try std.testing.expectEqual(@as(?i64, 604800), parseTtl("7d"));
}

test "parseTtl with minutes" {
    try std.testing.expectEqual(@as(?i64, 60), parseTtl("1m"));
    try std.testing.expectEqual(@as(?i64, 1800), parseTtl("30m"));
}

test "parseTtl with seconds" {
    try std.testing.expectEqual(@as(?i64, 3600), parseTtl("3600"));
    try std.testing.expectEqual(@as(?i64, 3600), parseTtl("3600s"));
}

test "parseTtl invalid" {
    try std.testing.expect(parseTtl("") == null);
    try std.testing.expect(parseTtl("abc") == null);
    try std.testing.expect(parseTtl("12x") == null);
}

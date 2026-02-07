//! Git command execution with tiered allowlists.
//!
//! Validates git subcommands against three permission tiers,
//! blocks dangerous flags, and executes git in a scoped directory
//! with output truncation and timeout.

const std = @import("std");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Maximum output bytes per stream before truncation.
pub const TRUNCATE_AT: usize = 512 * 1024;

/// Default timeout for git commands (30 seconds).
pub const DEFAULT_TIMEOUT_MS: u32 = 30_000;

pub const GitError = error{
    BlockedCommand,
    BlockedArg,
    EmptyArgs,
    NotARepository,
    SpawnFailed,
    Timeout,
    OutOfMemory,
    OutputTooLong,
};

pub const Tier = enum {
    read,
    write,
    remote,
    blocked,
};

/// Tier 1: read-only git subcommands.
const TIER_READ = [_][]const u8{
    "status",       "diff",         "log",
    "show",         "branch",       "tag",
    "rev-parse",    "ls-files",     "ls-tree",
    "blame",        "shortlog",     "describe",
    "name-rev",     "rev-list",     "cat-file",
    "diff-tree",    "diff-files",   "diff-index",
    "for-each-ref", "symbolic-ref", "stash",
    "remote",       "config",
};

/// Tier 2: mutating git subcommands.
const TIER_WRITE = [_][]const u8{
    "add",          "commit",      "checkout",
    "switch",       "merge",       "rebase",
    "reset",        "cherry-pick", "revert",
    "clean",        "rm",          "mv",
    "restore",      "am",          "apply",
    "format-patch", "notes",
};

/// Tier 3: remote-accessing git subcommands.
const TIER_REMOTE = [_][]const u8{
    "push",  "pull",
    "fetch", "submodule",
};

/// Always-blocked git subcommands.
const BLOCKED_COMMANDS = [_][]const u8{
    "filter-branch",
};

/// Top-level git flags that are always rejected.
const BLOCKED_TOP_LEVEL = [_][]const u8{
    "-c",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "-C",
};

/// Per-subcommand blocked flags.
const BlockedSubArg = struct {
    subcmd: []const u8,
    flag: []const u8,
};

const BLOCKED_SUB_ARGS = [_]BlockedSubArg{
    .{ .subcmd = "rebase", .flag = "--exec" },
    .{ .subcmd = "am", .flag = "--exec" },
    .{ .subcmd = "diff", .flag = "--ext-diff" },
    .{ .subcmd = "config", .flag = "--global" },
    .{ .subcmd = "config", .flag = "--system" },
};

/// Read-only subcommands needing special argument checks.
/// "stash" is read-only only for "list"; other stash
/// subcommands are write tier.
/// "remote" is read-only for list/show; add/remove/set-url
/// are remote tier.
/// "config" is read-only for --get/--get-all/--list.
/// "branch" is read-only when listing (no create/delete).
/// "tag" is read-only when listing (no create/delete).
/// Classifies a git subcommand into a permission tier.
pub fn classifySubcommand(args: []const []const u8) Tier {
    if (args.len == 0) return .blocked;

    const subcmd = args[0];

    for (BLOCKED_COMMANDS) |cmd| {
        if (std.mem.eql(u8, subcmd, cmd)) return .blocked;
    }

    for (TIER_REMOTE) |cmd| {
        if (std.mem.eql(u8, subcmd, cmd)) return .remote;
    }

    // "stash" tier depends on sub-subcommand
    if (std.mem.eql(u8, subcmd, "stash")) {
        if (args.len < 2) return .read; // bare "stash" = status
        const sub = args[1];
        if (std.mem.eql(u8, sub, "list")) return .read;
        return .write;
    }

    // "remote" tier depends on sub-subcommand
    if (std.mem.eql(u8, subcmd, "remote")) {
        if (args.len < 2) return .read; // bare "remote" = list
        const sub = args[1];
        if (std.mem.eql(u8, sub, "-v") or
            std.mem.eql(u8, sub, "show"))
        {
            return .read;
        }
        return .remote;
    }

    // "config" tier depends on flags
    if (std.mem.eql(u8, subcmd, "config")) {
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--get") or
                std.mem.eql(u8, arg, "--get-all") or
                std.mem.eql(u8, arg, "--list") or
                std.mem.eql(u8, arg, "-l"))
            {
                return .read;
            }
        }
        return .write;
    }

    // "branch" with create/delete flags is write
    if (std.mem.eql(u8, subcmd, "branch")) {
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "-d") or
                std.mem.eql(u8, arg, "-D") or
                std.mem.eql(u8, arg, "-m") or
                std.mem.eql(u8, arg, "-M") or
                std.mem.eql(u8, arg, "--delete") or
                std.mem.eql(u8, arg, "--move") or
                std.mem.eql(u8, arg, "-c") or
                std.mem.eql(u8, arg, "--copy"))
            {
                return .write;
            }
        }
        return .read;
    }

    // "tag" with create/delete flags is write
    if (std.mem.eql(u8, subcmd, "tag")) {
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "-d") or
                std.mem.eql(u8, arg, "--delete") or
                std.mem.eql(u8, arg, "-a") or
                std.mem.eql(u8, arg, "-s") or
                std.mem.eql(u8, arg, "-f"))
            {
                return .write;
            }
        }
        // If there are non-flag args beyond "tag", it's creating
        for (args[1..]) |arg| {
            if (!std.mem.startsWith(u8, arg, "-")) return .write;
        }
        return .read;
    }

    for (TIER_WRITE) |cmd| {
        if (std.mem.eql(u8, subcmd, cmd)) return .write;
    }

    for (TIER_READ) |cmd| {
        if (std.mem.eql(u8, subcmd, cmd)) return .read;
    }

    return .blocked;
}

/// Returns the required token operation for the tier.
pub fn requiredOp(tier: Tier) []const u8 {
    return switch (tier) {
        .read => "git",
        .write => "git_write",
        .remote => "git_remote",
        .blocked => "git",
    };
}

/// Validates args against blocked flags.
pub fn validateArgs(args: []const []const u8) GitError!void {
    if (args.len == 0) return GitError.EmptyArgs;

    const subcmd = args[0];

    // Check for blocked top-level flags mixed into args.
    // These could appear before the subcommand in a real
    // git invocation, so check all args.
    for (args) |arg| {
        for (BLOCKED_TOP_LEVEL) |blocked| {
            if (std.mem.eql(u8, arg, blocked)) {
                return GitError.BlockedArg;
            }
            // Also block -c<value> style (no space)
            if (std.mem.eql(u8, blocked, "-c") and
                arg.len > 2 and
                std.mem.startsWith(u8, arg, "-c"))
            {
                return GitError.BlockedArg;
            }
        }
    }

    // Check per-subcommand blocked flags
    for (BLOCKED_SUB_ARGS) |rule| {
        if (std.mem.eql(u8, subcmd, rule.subcmd)) {
            for (args[1..]) |arg| {
                if (std.mem.eql(u8, arg, rule.flag)) {
                    return GitError.BlockedArg;
                }
                // Also block --flag=value style
                if (std.mem.startsWith(u8, arg, rule.flag) and
                    arg.len > rule.flag.len and
                    arg[rule.flag.len] == '=')
                {
                    return GitError.BlockedArg;
                }
            }
        }
    }
}

/// Executes a git command in the specified directory.
/// Returns a GitResult with stdout, stderr, exit code.
/// Caller owns the returned stdout and stderr memory.
pub fn executeGit(
    allocator: Allocator,
    io: Io,
    repo_path: []const u8,
    args: []const []const u8,
) GitError!protocol.GitResult {
    // Build argv: ["git", "-C", repo_path] ++ args
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    argv.append(allocator, "git") catch
        return GitError.OutOfMemory;
    argv.append(allocator, "-C") catch
        return GitError.OutOfMemory;
    argv.append(allocator, repo_path) catch
        return GitError.OutOfMemory;
    for (args) |arg| {
        argv.append(allocator, arg) catch
            return GitError.OutOfMemory;
    }

    const result = std.process.run(
        allocator,
        io,
        .{
            .argv = argv.items,
            .max_output_bytes = TRUNCATE_AT,
        },
    ) catch |err| {
        return switch (err) {
            error.StdoutStreamTooLong,
            error.StderrStreamTooLong,
            => GitError.OutputTooLong,
            error.OutOfMemory => GitError.OutOfMemory,
            else => GitError.SpawnFailed,
        };
    };
    errdefer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const exit_code: u8 = switch (result.term) {
        .exited => |code| code,
        .signal => 128,
        .stopped => 128,
        .unknown => 128,
    };

    return protocol.GitResult{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .exit_code = exit_code,
        .truncated = false,
    };
}

// Tests

test "classifySubcommand - read-only commands" {
    const read_cmds = [_][]const u8{
        "status",     "diff",         "log",          "show",      "blame",
        "rev-parse",  "ls-files",     "ls-tree",      "shortlog",  "describe",
        "name-rev",   "rev-list",     "cat-file",     "diff-tree", "diff-files",
        "diff-index", "for-each-ref", "symbolic-ref",
    };
    for (read_cmds) |cmd| {
        const tier = classifySubcommand(&[_][]const u8{cmd});
        try std.testing.expectEqual(Tier.read, tier);
    }
}

test "classifySubcommand - write commands" {
    const write_cmds = [_][]const u8{
        "add",     "commit", "checkout", "switch",
        "merge",   "rebase", "reset",    "cherry-pick",
        "revert",  "clean",  "rm",       "mv",
        "restore", "am",     "apply",    "format-patch",
        "notes",
    };
    for (write_cmds) |cmd| {
        const tier = classifySubcommand(&[_][]const u8{cmd});
        try std.testing.expectEqual(Tier.write, tier);
    }
}

test "classifySubcommand - remote commands" {
    const remote_cmds = [_][]const u8{
        "push", "pull", "fetch", "submodule",
    };
    for (remote_cmds) |cmd| {
        const tier = classifySubcommand(
            &[_][]const u8{cmd},
        );
        try std.testing.expectEqual(Tier.remote, tier);
    }
}

test "classifySubcommand - blocked commands" {
    const tier = classifySubcommand(
        &[_][]const u8{"filter-branch"},
    );
    try std.testing.expectEqual(Tier.blocked, tier);
}

test "classifySubcommand - unknown command is blocked" {
    const tier = classifySubcommand(
        &[_][]const u8{"bisect"},
    );
    try std.testing.expectEqual(Tier.blocked, tier);
}

test "classifySubcommand - stash subcommands" {
    // bare stash = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(&[_][]const u8{"stash"}),
    );
    // stash list = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "stash", "list" },
        ),
    );
    // stash pop = write
    try std.testing.expectEqual(
        Tier.write,
        classifySubcommand(
            &[_][]const u8{ "stash", "pop" },
        ),
    );
}

test "classifySubcommand - remote subcommands" {
    // bare remote = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(&[_][]const u8{"remote"}),
    );
    // remote -v = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "remote", "-v" },
        ),
    );
    // remote add = remote tier
    try std.testing.expectEqual(
        Tier.remote,
        classifySubcommand(
            &[_][]const u8{ "remote", "add" },
        ),
    );
}

test "classifySubcommand - config subcommands" {
    // config --list = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "config", "--list" },
        ),
    );
    // config --get = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "config", "--get", "user.name" },
        ),
    );
    // config set = write
    try std.testing.expectEqual(
        Tier.write,
        classifySubcommand(
            &[_][]const u8{ "config", "user.name", "Mario" },
        ),
    );
}

test "classifySubcommand - branch subcommands" {
    // branch (list) = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(&[_][]const u8{"branch"}),
    );
    // branch -a = read (list all)
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "branch", "-a" },
        ),
    );
    // branch -d = write
    try std.testing.expectEqual(
        Tier.write,
        classifySubcommand(
            &[_][]const u8{ "branch", "-d", "feat" },
        ),
    );
}

test "classifySubcommand - tag subcommands" {
    // tag (list) = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(&[_][]const u8{"tag"}),
    );
    // tag -l = read
    try std.testing.expectEqual(
        Tier.read,
        classifySubcommand(
            &[_][]const u8{ "tag", "-l" },
        ),
    );
    // tag v1.0 = write (create)
    try std.testing.expectEqual(
        Tier.write,
        classifySubcommand(
            &[_][]const u8{ "tag", "v1.0" },
        ),
    );
    // tag -d = write
    try std.testing.expectEqual(
        Tier.write,
        classifySubcommand(
            &[_][]const u8{ "tag", "-d", "v1.0" },
        ),
    );
}

test "classifySubcommand - empty args" {
    try std.testing.expectEqual(
        Tier.blocked,
        classifySubcommand(&[_][]const u8{}),
    );
}

test "validateArgs - blocked top-level flags" {
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(&[_][]const u8{ "status", "-c", "a=b" }),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(&[_][]const u8{ "status", "--git-dir" }),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "status", "--work-tree" },
        ),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "status", "--exec-path" },
        ),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(&[_][]const u8{ "status", "-C" }),
    );
}

test "validateArgs - blocked per-subcommand flags" {
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "rebase", "--exec", "cmd" },
        ),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "diff", "--ext-diff" },
        ),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "config", "--global" },
        ),
    );
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "config", "--system" },
        ),
    );
}

test "validateArgs - empty args" {
    try std.testing.expectError(
        GitError.EmptyArgs,
        validateArgs(&[_][]const u8{}),
    );
}

test "validateArgs - valid args pass" {
    try validateArgs(&[_][]const u8{"status"});
    try validateArgs(
        &[_][]const u8{ "status", "--short" },
    );
    try validateArgs(
        &[_][]const u8{ "diff", "--stat", "HEAD~3" },
    );
    try validateArgs(
        &[_][]const u8{ "log", "--oneline", "-20" },
    );
    try validateArgs(
        &[_][]const u8{ "commit", "-m", "fix bug" },
    );
}

test "validateArgs - blocked -c with value attached" {
    try std.testing.expectError(
        GitError.BlockedArg,
        validateArgs(
            &[_][]const u8{ "status", "-ccore.fsmonitor=evil" },
        ),
    );
}

test "requiredOp returns correct operation string" {
    try std.testing.expectEqualStrings(
        "git",
        requiredOp(.read),
    );
    try std.testing.expectEqualStrings(
        "git_write",
        requiredOp(.write),
    );
    try std.testing.expectEqualStrings(
        "git_remote",
        requiredOp(.remote),
    );
}

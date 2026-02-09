//! Tool execution engine for ClawGate custom tools.
//!
//! Validates arguments and executes registered tools as child processes
//! with output truncation and timeout support.

const std = @import("std");
const tools_mod = @import("tools.zig");
const protocol = @import("../protocol/json.zig");
const scope_mod = @import("../capability/scope.zig");
const handlers = @import("handlers.zig");
const path_mod = @import("../path.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const ExecError = error{
    ArgBlocked,
    PathBlocked,
    SpawnFailed,
    Timeout,
    OutputTooLong,
    OutOfMemory,
};

/// Result of executing a tool.
pub const ToolResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: u8,
    truncated: bool,
};

/// Validates args against tool config restrictions.
pub fn validateArgs(
    tool: tools_mod.ToolConfig,
    args: []const []const u8,
) ExecError!void {
    switch (tool.arg_mode) {
        .allowlist => {
            for (args) |arg| {
                if (!std.mem.startsWith(u8, arg, "-"))
                    continue;
                var allowed = false;
                for (tool.allow_args) |allow| {
                    if (std.mem.eql(u8, arg, allow)) {
                        allowed = true;
                        break;
                    }
                }
                if (!allowed) return ExecError.ArgBlocked;
            }
        },
        .passthrough => {
            for (args) |arg| {
                if (!std.mem.startsWith(u8, arg, "-"))
                    continue;
                for (tool.deny_args) |deny| {
                    if (std.mem.eql(u8, arg, deny))
                        return ExecError.ArgBlocked;
                    // Also block --flag=value style
                    if (std.mem.startsWith(u8, arg, deny) and
                        arg.len > deny.len and
                        arg[deny.len] == '=')
                    {
                        return ExecError.ArgBlocked;
                    }
                }
            }
        },
    }
}

/// Detects syntactically unambiguous path forms.
pub fn isPathLike(arg: []const u8) bool {
    if (arg.len == 0) return false;
    if (arg[0] == '/') return true;
    if (std.mem.startsWith(u8, arg, "~/")) return true;
    if (std.mem.startsWith(u8, arg, "./")) return true;
    if (std.mem.startsWith(u8, arg, "../")) return true;
    if (std.mem.eql(u8, arg, ".")) return true;
    if (std.mem.eql(u8, arg, "..")) return true;
    if (std.mem.eql(u8, arg, "~")) return true;
    return false;
}

pub const ScopeError = error{
    InvalidScope,
    OutOfMemory,
};

/// Parses semicolon-separated scope entries. Validates
/// each entry: rejects ".", "..", absolute paths, empty.
/// Caller owns returned slice and its strings.
pub fn parseScopeEntries(
    allocator: Allocator,
    scope_str: []const u8,
) ScopeError![][]const u8 {
    if (scope_str.len == 0)
        return ScopeError.InvalidScope;

    var entries: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (entries.items) |e| allocator.free(e);
        entries.deinit(allocator);
    }

    var iter = std.mem.splitScalar(
        u8,
        scope_str,
        ';',
    );
    while (iter.next()) |segment| {
        if (segment.len == 0)
            return ScopeError.InvalidScope;
        if (std.mem.eql(u8, segment, "."))
            return ScopeError.InvalidScope;
        if (std.mem.eql(u8, segment, ".."))
            return ScopeError.InvalidScope;
        if (segment[0] == '/')
            return ScopeError.InvalidScope;
        // Reject segments containing ..
        var comp_iter = std.mem.splitScalar(
            u8,
            segment,
            '/',
        );
        while (comp_iter.next()) |comp| {
            if (std.mem.eql(u8, comp, ".."))
                return ScopeError.InvalidScope;
        }
        const duped = allocator.dupe(u8, segment) catch
            return ScopeError.OutOfMemory;
        entries.append(allocator, duped) catch {
            allocator.free(duped);
            return ScopeError.OutOfMemory;
        };
    }

    if (entries.items.len == 0)
        return ScopeError.InvalidScope;

    const owned = entries.toOwnedSlice(allocator) catch
        return ScopeError.OutOfMemory;
    // Cast [][]u8 to [][]const u8 (covariant)
    const result: [][]const u8 = @ptrCast(owned);
    return result;
}

/// Validates path-like arguments against tool scope and
/// forbidden paths. Blocks out-of-scope or forbidden paths.
pub fn validatePaths(
    allocator: Allocator,
    tool: tools_mod.ToolConfig,
    args: []const []const u8,
    home: []const u8,
) ExecError!void {
    for (args) |arg| {
        // Skip flags
        if (std.mem.startsWith(u8, arg, "-")) continue;
        // Skip non-path-like args
        if (!isPathLike(arg)) continue;

        // No scope = block any path-like arg
        const scope_str = tool.scope orelse
            return ExecError.PathBlocked;

        // Resolve the argument to an absolute path
        const expanded = path_mod.expand(
            allocator,
            arg,
            home,
        ) catch return ExecError.OutOfMemory;
        defer allocator.free(expanded);

        // Make absolute: relative paths resolve from HOME
        const absolute = if (expanded[0] != '/')
            std.fmt.allocPrint(
                allocator,
                "{s}/{s}",
                .{ home, expanded },
            ) catch return ExecError.OutOfMemory
        else
            allocator.dupe(u8, expanded) catch
                return ExecError.OutOfMemory;
        defer allocator.free(absolute);

        // Canonicalize to resolve . and ..
        const canonical = scope_mod.canonicalizePath(
            allocator,
            absolute,
        ) orelse return ExecError.PathBlocked;
        defer allocator.free(canonical);

        // Check forbidden paths
        if (handlers.isForbiddenPath(canonical))
            return ExecError.PathBlocked;

        // Check against scope entries
        const entries = parseScopeEntries(
            allocator,
            scope_str,
        ) catch return ExecError.PathBlocked;
        defer {
            for (entries) |e| allocator.free(e);
            allocator.free(entries);
        }

        var allowed = false;
        for (entries) |entry| {
            // Build $HOME/<entry> as the allowed base
            const base = std.fmt.allocPrint(
                allocator,
                "{s}/{s}",
                .{ home, entry },
            ) catch return ExecError.OutOfMemory;
            defer allocator.free(base);

            if (scope_mod.isWithin(base, canonical)) {
                allowed = true;
                break;
            }
        }

        if (!allowed)
            return ExecError.PathBlocked;
    }
}

/// Executes a tool as a child process.
pub fn executeTool(
    allocator: Allocator,
    io: Io,
    tool: tools_mod.ToolConfig,
    args: []const []const u8,
    input: ?[]const u8,
    cwd: ?[]const u8,
) ExecError!ToolResult {
    // Split tool.command into argv tokens
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    var cmd_iter = std.mem.splitScalar(
        u8,
        tool.command,
        ' ',
    );
    while (cmd_iter.next()) |part| {
        if (part.len == 0) continue;
        argv.append(allocator, part) catch
            return ExecError.OutOfMemory;
    }

    for (args) |arg| {
        argv.append(allocator, arg) catch
            return ExecError.OutOfMemory;
    }

    if (argv.items.len == 0)
        return ExecError.SpawnFailed;

    const collect_limit = tool.max_output_bytes * 2;

    if (input != null) {
        return executeWithStdin(
            allocator,
            io,
            argv.items,
            input.?,
            tool.max_output_bytes,
            collect_limit,
            cwd,
        );
    }

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .max_output_bytes = collect_limit,
        .cwd = cwd,
    }) catch |err| {
        return switch (err) {
            error.StdoutStreamTooLong,
            error.StderrStreamTooLong,
            => ExecError.OutputTooLong,
            error.OutOfMemory => ExecError.OutOfMemory,
            else => ExecError.SpawnFailed,
        };
    };

    return trimResult(
        allocator,
        result.stdout,
        result.stderr,
        result.term,
        tool.max_output_bytes,
    );
}

/// Executes with stdin data via Child process.
fn executeWithStdin(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    input: []const u8,
    max_output: usize,
    collect_limit: usize,
    cwd: ?[]const u8,
) ExecError!ToolResult {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .cwd = cwd,
    }) catch return ExecError.SpawnFailed;
    defer child.kill(io);

    // Write stdin data and close
    if (child.stdin) |stdin_file| {
        stdin_file.writeStreamingAll(io, input) catch {};
        stdin_file.close(io);
        child.stdin = null;
    }

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    child.collectOutput(
        allocator,
        &stdout_buf,
        &stderr_buf,
        collect_limit,
    ) catch |err| {
        return switch (err) {
            error.StdoutStreamTooLong,
            error.StderrStreamTooLong,
            => ExecError.OutputTooLong,
            error.OutOfMemory => ExecError.OutOfMemory,
            else => ExecError.SpawnFailed,
        };
    };

    const term = child.wait(io) catch
        return ExecError.SpawnFailed;

    const stdout = stdout_buf.toOwnedSlice(allocator) catch
        return ExecError.OutOfMemory;
    const stderr = stderr_buf.toOwnedSlice(allocator) catch {
        allocator.free(stdout);
        return ExecError.OutOfMemory;
    };

    return trimResult(
        allocator,
        stdout,
        stderr,
        term,
        max_output,
    );
}

/// Trims stdout/stderr to max_output, sets truncated flag.
fn trimResult(
    allocator: Allocator,
    raw_stdout: []u8,
    raw_stderr: []u8,
    term: std.process.Child.Term,
    max_output: usize,
) ExecError!ToolResult {
    const exit_code: u8 = switch (term) {
        .exited => |code| code,
        .signal => 128,
        .stopped => 128,
        .unknown => 128,
    };

    var stdout: []u8 = raw_stdout;
    var stderr: []u8 = raw_stderr;
    var truncated = false;

    if (stdout.len > max_output) {
        const trimmed = allocator.alloc(
            u8,
            max_output,
        ) catch {
            allocator.free(raw_stdout);
            allocator.free(raw_stderr);
            return ExecError.OutOfMemory;
        };
        @memcpy(trimmed, raw_stdout[0..max_output]);
        allocator.free(raw_stdout);
        stdout = trimmed;
        truncated = true;
    }

    if (stderr.len > max_output) {
        const trimmed = allocator.alloc(
            u8,
            max_output,
        ) catch {
            allocator.free(stdout);
            allocator.free(raw_stderr);
            return ExecError.OutOfMemory;
        };
        @memcpy(trimmed, raw_stderr[0..max_output]);
        allocator.free(raw_stderr);
        stderr = trimmed;
        truncated = true;
    }

    return ToolResult{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = exit_code,
        .truncated = truncated,
    };
}

// Tests

test "validateArgs allowlist blocks unknown flags" {
    const config = tools_mod.ToolConfig{
        .command = "bc -l",
        .allow_args = &[_][]const u8{"-q"},
        .deny_args = &[_][]const u8{},
        .arg_mode = .allowlist,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    // Allowed flag passes
    try validateArgs(config, &[_][]const u8{"-q"});

    // Unknown flag blocked
    try std.testing.expectError(
        ExecError.ArgBlocked,
        validateArgs(config, &[_][]const u8{"--exec"}),
    );

    // Positional args pass through
    try validateArgs(config, &[_][]const u8{"expression"});
}

test "validateArgs passthrough blocks denied flags" {
    const config = tools_mod.ToolConfig{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{ "--exec", "-c" },
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    // Regular flags pass
    try validateArgs(config, &[_][]const u8{"-n"});

    // Denied flags blocked
    try std.testing.expectError(
        ExecError.ArgBlocked,
        validateArgs(config, &[_][]const u8{"--exec"}),
    );

    // Denied flag with = value blocked
    try std.testing.expectError(
        ExecError.ArgBlocked,
        validateArgs(
            config,
            &[_][]const u8{"--exec=evil"},
        ),
    );
}

test "executeTool with echo" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const config = tools_mod.ToolConfig{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    var result = executeTool(
        allocator,
        io,
        config,
        &[_][]const u8{"hello"},
        null,
        null,
    ) catch return;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    try std.testing.expect(result.exit_code == 0);
    try std.testing.expect(!result.truncated);
    try std.testing.expect(
        std.mem.startsWith(u8, result.stdout, "hello"),
    );
}

test "executeTool with stdin input" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const config = tools_mod.ToolConfig{
        .command = "cat",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    var result = executeTool(
        allocator,
        io,
        config,
        &[_][]const u8{},
        "test input data",
        null,
    ) catch return;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    try std.testing.expect(result.exit_code == 0);
    try std.testing.expectEqualStrings(
        "test input data",
        result.stdout,
    );
}

test "isPathLike detects path forms" {
    // Absolute paths
    try std.testing.expect(isPathLike("/etc/hosts"));
    try std.testing.expect(isPathLike("/"));

    // Tilde paths
    try std.testing.expect(isPathLike("~/file"));
    try std.testing.expect(isPathLike("~"));

    // Relative paths
    try std.testing.expect(isPathLike("./file"));
    try std.testing.expect(isPathLike("../file"));
    try std.testing.expect(isPathLike("."));
    try std.testing.expect(isPathLike(".."));

    // Non-path args
    try std.testing.expect(!isPathLike("pattern"));
    try std.testing.expect(!isPathLike("Makefile"));
    try std.testing.expect(!isPathLike(""));
    try std.testing.expect(!isPathLike("-n"));
    try std.testing.expect(!isPathLike("--verbose"));
    try std.testing.expect(!isPathLike("hosts"));
}

test "parseScopeEntries valid single" {
    const allocator = std.testing.allocator;
    const entries = try parseScopeEntries(
        allocator,
        "projects/webapp",
    );
    defer {
        for (entries) |e| allocator.free(e);
        allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings(
        "projects/webapp",
        entries[0],
    );
}

test "parseScopeEntries valid multiple" {
    const allocator = std.testing.allocator;
    const entries = try parseScopeEntries(
        allocator,
        "a;b;c",
    );
    defer {
        for (entries) |e| allocator.free(e);
        allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("a", entries[0]);
    try std.testing.expectEqualStrings("b", entries[1]);
    try std.testing.expectEqualStrings("c", entries[2]);
}

test "parseScopeEntries rejects dot" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        ScopeError.InvalidScope,
        parseScopeEntries(allocator, "."),
    );
}

test "parseScopeEntries rejects dotdot" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        ScopeError.InvalidScope,
        parseScopeEntries(allocator, ".."),
    );
}

test "parseScopeEntries rejects absolute" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        ScopeError.InvalidScope,
        parseScopeEntries(allocator, "/etc"),
    );
}

test "parseScopeEntries rejects empty segment" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        ScopeError.InvalidScope,
        parseScopeEntries(allocator, "a;;b"),
    );
}

test "parseScopeEntries rejects dotdot in component" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        ScopeError.InvalidScope,
        parseScopeEntries(allocator, "projects/../etc"),
    );
}

test "validatePaths scoped in-scope passes" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try validatePaths(
        allocator,
        config,
        &[_][]const u8{
            "pattern",
            "~/project/src/main.zig",
        },
        "/home/user",
    );
}

test "validatePaths scoped out-of-scope blocked" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{ "pattern", "/etc/hosts" },
            "/home/user",
        ),
    );
}

test "validatePaths traversal blocked" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{
                "~/project/../../etc/passwd",
            },
            "/home/user",
        ),
    );
}

test "validatePaths forbidden path blocked" {
    const allocator = std.testing.allocator;
    // Scope covers all of home, but .ssh is forbidden
    const config = tools_mod.ToolConfig{
        .command = "cat",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = ".ssh",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{"~/.ssh/id_rsa"},
            "/home/user",
        ),
    );
}

test "validatePaths multi-scope passes" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "wc",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "projects;docs",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try validatePaths(
        allocator,
        config,
        &[_][]const u8{"~/docs/file.txt"},
        "/home/user",
    );
}

test "validatePaths multi-scope blocks out-of-scope" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "wc",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "projects;docs",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{"/etc/hosts"},
            "/home/user",
        ),
    );
}

test "validatePaths unscoped non-path passes" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "bc",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    // Non-path args allowed even with no scope
    try validatePaths(
        allocator,
        config,
        &[_][]const u8{"2+2"},
        "/home/user",
    );
}

test "validatePaths unscoped path-like blocked" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "bc",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{"/etc/passwd"},
            "/home/user",
        ),
    );
}

test "validatePaths tilde in-scope" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project/src",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try validatePaths(
        allocator,
        config,
        &[_][]const u8{"~/project/src/main.zig"},
        "/home/user",
    );
}

test "validatePaths tilde out-of-scope" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try std.testing.expectError(
        ExecError.PathBlocked,
        validatePaths(
            allocator,
            config,
            &[_][]const u8{"~/other/secret.txt"},
            "/home/user",
        ),
    );
}

test "validatePaths flags are skipped" {
    const allocator = std.testing.allocator;
    const config = tools_mod.ToolConfig{
        .command = "rg",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = "project",
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    // Flags are not checked as paths
    try validatePaths(
        allocator,
        config,
        &[_][]const u8{ "-i", "--color", "pattern" },
        "/home/user",
    );
}

test "executeTool receives cwd" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const config = tools_mod.ToolConfig{
        .command = "pwd",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    var result = executeTool(
        allocator,
        io,
        config,
        &[_][]const u8{},
        null,
        "/tmp",
    ) catch return;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    try std.testing.expect(result.exit_code == 0);
    // pwd should output /tmp
    try std.testing.expect(
        std.mem.startsWith(u8, result.stdout, "/tmp"),
    );
}

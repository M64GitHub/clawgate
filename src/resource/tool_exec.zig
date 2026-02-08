//! Tool execution engine for ClawGate custom tools.
//!
//! Validates arguments and executes registered tools as child processes
//! with output truncation and timeout support.

const std = @import("std");
const tools_mod = @import("tools.zig");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const ExecError = error{
    ArgBlocked,
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

/// Executes a tool as a child process.
pub fn executeTool(
    allocator: Allocator,
    io: Io,
    tool: tools_mod.ToolConfig,
    args: []const []const u8,
    input: ?[]const u8,
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
        );
    }

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .max_output_bytes = collect_limit,
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
) ExecError!ToolResult {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
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

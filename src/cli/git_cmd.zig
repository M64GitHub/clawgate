//! Git command for ClawGate.
//!
//! Agent-side command that sends git requests to the resource daemon
//! via IPC to the agent daemon's E2E encrypted connection.

const std = @import("std");
const ipc_client = @import("../agent/ipc_client.zig");
const tokens_mod = @import("../agent/tokens.zig");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const GitCmdError = error{
    InvalidArgs,
    MissingPath,
    MissingGitArgs,
    TokenNotFound,
    NotConnected,
    RequestFailed,
    ResponseError,
    OutOfMemory,
};

/// Executes a git command via the agent daemon.
pub fn git(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
    environ: std.process.Environ,
) GitCmdError!void {
    var token_dir_override: []const u8 = "";
    var repo_path: ?[]const u8 = null;
    var git_args_start: ?usize = null;

    // Parse: [--token-dir <dir>] <repo-path> <git-args...>
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return GitCmdError.InvalidArgs;
            i += 1;
            token_dir_override = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printGitUsage();
            return;
        } else if (repo_path == null) {
            repo_path = arg;
            git_args_start = i + 1;
            break;
        }
    }

    if (repo_path == null) {
        std.debug.print("Error: Repository path required\n\n", .{});
        printGitUsage();
        return GitCmdError.MissingPath;
    }

    const git_start = git_args_start orelse args.len;
    if (git_start >= args.len) {
        std.debug.print("Error: Git arguments required\n\n", .{});
        printGitUsage();
        return GitCmdError.MissingGitArgs;
    }

    const git_args = args[git_start..];

    // Get token directory
    const token_dir = if (token_dir_override.len > 0)
        token_dir_override
    else blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return GitCmdError.TokenNotFound;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return GitCmdError.OutOfMemory;
    };
    defer if (token_dir_override.len == 0)
        allocator.free(token_dir);

    // Load tokens and find matching one
    var store = tokens_mod.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return GitCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    const token = store.findForPath(
        "files",
        "git",
        repo_path.?,
    ) orelse {
        std.debug.print(
            "Error: No token grants git access to {s}\n",
            .{repo_path.?},
        );
        return GitCmdError.TokenNotFound;
    };

    // Build request with args array
    const request = buildGitRequest(
        allocator,
        io,
        token.raw,
        repo_path.?,
        git_args,
    ) catch return GitCmdError.OutOfMemory;
    defer allocator.free(request);

    // Send request via IPC to agent daemon
    const response = ipc_client.sendRequest(
        allocator,
        environ,
        request,
    ) catch |err| {
        switch (err) {
            ipc_client.IpcError.DaemonNotRunning => {
                std.debug.print(
                    "Error: Agent daemon not running\n",
                    .{},
                );
                std.debug.print(
                    "Start it first: clawgate --mode agent\n",
                    .{},
                );
                return GitCmdError.NotConnected;
            },
            ipc_client.IpcError.OutOfMemory => {
                return GitCmdError.OutOfMemory;
            },
            else => {
                std.debug.print("Error: Request failed\n", .{});
                return GitCmdError.RequestFailed;
            },
        }
    };
    defer allocator.free(response);

    // Parse response
    const parsed = std.json.parseFromSlice(
        struct {
            ok: bool,
            result: ?struct {
                stdout: []const u8,
                stderr: []const u8,
                exit_code: u8,
                truncated: bool,
            } = null,
            @"error": ?struct {
                code: []const u8,
                message: []const u8,
            } = null,
        },
        allocator,
        response,
        .{ .ignore_unknown_fields = true },
    ) catch {
        std.debug.print("Error: Invalid response\n", .{});
        return GitCmdError.ResponseError;
    };
    defer parsed.deinit();

    if (!parsed.value.ok) {
        if (parsed.value.@"error") |err| {
            std.debug.print(
                "Error: {s}: {s}\n",
                .{ err.code, err.message },
            );
        }
        return GitCmdError.ResponseError;
    }

    if (parsed.value.result) |result| {
        const stdout = Io.File.stdout();
        const stderr = Io.File.stderr();

        if (result.stdout.len > 0) {
            stdout.writeStreamingAll(io, result.stdout) catch {};
        }
        if (result.stderr.len > 0) {
            stderr.writeStreamingAll(io, result.stderr) catch {};
        }
        if (result.truncated) {
            stderr.writeStreamingAll(
                io,
                "\n[output truncated]\n",
            ) catch {};
        }

        // Exit with git's exit code
        if (result.exit_code != 0) {
            std.process.exit(result.exit_code);
        }
    }
}

/// Builds a JSON request with git args.
fn buildGitRequest(
    allocator: Allocator,
    io: Io,
    jwt: []const u8,
    path: []const u8,
    git_args: []const [:0]const u8,
) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    // Generate request ID
    var id_bytes: [8]u8 = undefined;
    io.random(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);

    try writer.writeAll("{\"id\":\"req_");
    try writer.writeAll(&id_hex);
    try writer.writeAll("\",\"token\":\"");
    try writer.writeAll(jwt);
    try writer.writeAll("\",\"op\":\"git\",\"params\":{\"path\":\"");
    try writeJsonEscaped(writer, path);
    try writer.writeAll("\",\"args\":[");

    for (git_args, 0..) |arg, idx| {
        if (idx > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try writeJsonEscaped(writer, arg);
        try writer.writeAll("\"");
    }

    try writer.writeAll("]}}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Writes JSON-escaped string.
fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

fn printGitUsage() void {
    const usage =
        \\Usage: clawgate git [options] <repo-path> <git-args...>
        \\
        \\Run git commands on the primary machine.
        \\
        \\Requires the agent daemon to be running and connected
        \\to a resource daemon.
        \\
        \\Options:
        \\  -d, --token-dir <dir> Token directory
        \\  -h, --help            Show this help
        \\
        \\Examples:
        \\  clawgate git ~/projects/myapp status
        \\  clawgate git ~/projects/myapp diff HEAD~3
        \\  clawgate git ~/projects/myapp log --oneline -20
        \\  clawgate git ~/projects/myapp commit -m "fix"
        \\  clawgate git ~/projects/myapp push origin main
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "buildGitRequest creates valid JSON" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    const req = try buildGitRequest(
        allocator,
        io,
        "test_token",
        "/tmp/repo",
        &[_][:0]const u8{ "status", "--short" },
    );
    defer allocator.free(req);

    // Verify it parses as valid JSON
    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            token: []const u8,
            op: []const u8,
            params: struct {
                path: []const u8,
                args: []const []const u8,
            },
        },
        allocator,
        req,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "test_token",
        parsed.value.token,
    );
    try std.testing.expectEqualStrings("git", parsed.value.op);
    try std.testing.expectEqualStrings(
        "/tmp/repo",
        parsed.value.params.path,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        parsed.value.params.args.len,
    );
    try std.testing.expectEqualStrings(
        "status",
        parsed.value.params.args[0],
    );
    try std.testing.expectEqualStrings(
        "--short",
        parsed.value.params.args[1],
    );
}

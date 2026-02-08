//! Tool management and invocation CLI commands.
//!
//! Management (resource-side):
//!   clawgate tool register <name> [opts]
//!   clawgate tool ls
//!   clawgate tool info <name>
//!   clawgate tool update <name> [opts]
//!   clawgate tool remove <name>
//!   clawgate tool test <name> [args...]
//!
//! Remote Discovery (agent-side):
//!   clawgate tool remote-list
//!
//! Invocation (agent-side):
//!   clawgate tool <name> [args...]

const std = @import("std");
const tools_mod = @import("../resource/tools.zig");
const tool_exec = @import("../resource/tool_exec.zig");
const skills = @import("../resource/skills.zig");
const ipc_client = @import("../agent/ipc_client.zig");
const tokens = @import("../agent/tokens.zig");
const protocol = @import("../protocol/json.zig");
const audit_log = @import("../resource/audit_log.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = Io.File;

pub const ToolCmdError = error{
    InvalidArgs,
    LoadFailed,
    ExecFailed,
    OutOfMemory,
    NotFound,
};

const MANAGEMENT_SUBCMDS = [_][]const u8{
    "register",    "ls",     "list",   "info",
    "update",      "remove", "test",   "--help",
    "-h",          "help",   "generate",
    "remote-list",
};

/// Main entry point for `clawgate tool` commands.
pub fn run(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
    environ: std.process.Environ,
) ToolCmdError!void {
    if (args.len == 0) {
        printUsage();
        return ToolCmdError.InvalidArgs;
    }

    const subcmd = args[0];

    // remote-list needs environ for IPC (handleManagement
    // doesn't receive it), so intercept here.
    if (std.mem.eql(u8, subcmd, "remote-list")) {
        return handleRemoteList(
            allocator,
            io,
            environ,
        );
    }

    // Check if it's a management subcommand
    for (MANAGEMENT_SUBCMDS) |mgmt| {
        if (std.mem.eql(u8, subcmd, mgmt)) {
            return handleManagement(
                allocator,
                io,
                args,
                home,
            );
        }
    }

    // Otherwise, treat as tool invocation
    return handleInvocation(
        allocator,
        io,
        args,
        home,
        environ,
    );
}

fn handleManagement(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) ToolCmdError!void {
    const home_dir = home orelse {
        std.debug.print("Error: HOME not set\n", .{});
        return ToolCmdError.InvalidArgs;
    };

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "register")) {
        return handleRegister(allocator, io, args[1..], home_dir);
    } else if (std.mem.eql(u8, subcmd, "ls") or
        std.mem.eql(u8, subcmd, "list"))
    {
        return handleList(allocator, io, home_dir);
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (args.len < 2) {
            std.debug.print(
                "Error: Tool name required\n",
                .{},
            );
            return ToolCmdError.InvalidArgs;
        }
        return handleInfo(allocator, io, args[1], home_dir);
    } else if (std.mem.eql(u8, subcmd, "update")) {
        return handleUpdate(allocator, io, args[1..], home_dir);
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (args.len < 2) {
            std.debug.print(
                "Error: Tool name required\n",
                .{},
            );
            return ToolCmdError.InvalidArgs;
        }
        return handleRemove(allocator, io, args[1], home_dir);
    } else if (std.mem.eql(u8, subcmd, "test")) {
        return handleTest(allocator, io, args[1..], home_dir);
    } else if (std.mem.eql(u8, subcmd, "generate")) {
        return handleGenerate(allocator, io, home_dir);
    } else {
        printUsage();
    }
}

fn handleRegister(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: []const u8,
) ToolCmdError!void {
    if (args.len == 0) {
        std.debug.print("Error: Tool name required\n", .{});
        return ToolCmdError.InvalidArgs;
    }

    const name = args[0];
    var command: ?[]const u8 = null;
    var allow_args_list: [32][]const u8 = undefined;
    var allow_count: usize = 0;
    var deny_args_list: [32][]const u8 = undefined;
    var deny_count: usize = 0;
    var timeout: u32 = 30;
    var max_output: usize = 65536;
    var description: []const u8 = "";
    var example_list: [16][]const u8 = undefined;
    var example_count: usize = 0;
    var arg_mode: tools_mod.ArgMode = .passthrough;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const has_next = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--command") and has_next) {
            i += 1;
            command = args[i];
        } else if (std.mem.eql(u8, arg, "--allow-args") and
            has_next)
        {
            i += 1;
            if (allow_count < allow_args_list.len) {
                allow_args_list[allow_count] = args[i];
                allow_count += 1;
            }
            arg_mode = .allowlist;
        } else if (std.mem.eql(u8, arg, "--deny-args") and
            has_next)
        {
            i += 1;
            if (deny_count < deny_args_list.len) {
                deny_args_list[deny_count] = args[i];
                deny_count += 1;
            }
        } else if (std.mem.eql(u8, arg, "--timeout") and
            has_next)
        {
            i += 1;
            timeout = std.fmt.parseInt(
                u32,
                args[i],
                10,
            ) catch 30;
        } else if (std.mem.eql(u8, arg, "--max-output") and
            has_next)
        {
            i += 1;
            max_output = std.fmt.parseInt(
                usize,
                args[i],
                10,
            ) catch 65536;
        } else if (std.mem.eql(u8, arg, "--description") and
            has_next)
        {
            i += 1;
            description = args[i];
        } else if (std.mem.eql(u8, arg, "--example") and
            has_next)
        {
            i += 1;
            if (example_count < example_list.len) {
                example_list[example_count] = args[i];
                example_count += 1;
            }
        }
    }

    if (command == null) {
        std.debug.print("Error: --command required\n", .{});
        return ToolCmdError.InvalidArgs;
    }

    var ts_buf: [20]u8 = undefined;
    const now = std.posix.clock_gettime(.REALTIME) catch
        return ToolCmdError.ExecFailed;
    const ts = audit_log.formatEpochBuf(
        &ts_buf,
        @intCast(now.sec),
    );

    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    reg.register(allocator, io, name, .{
        .command = command.?,
        .allow_args = allow_args_list[0..allow_count],
        .deny_args = deny_args_list[0..deny_count],
        .arg_mode = arg_mode,
        .scope = null,
        .timeout_seconds = timeout,
        .max_output_bytes = max_output,
        .description = description,
        .examples = example_list[0..example_count],
        .created = ts,
    }) catch |err| {
        if (err == tools_mod.ToolError.DuplicateName) {
            std.debug.print(
                "Error: Tool '{s}' already exists\n",
                .{name},
            );
        } else {
            std.debug.print(
                "Error: Failed to register tool\n",
                .{},
            );
        }
        return ToolCmdError.ExecFailed;
    };

    const stdout = File.stdout();
    stdout.writeStreamingAll(
        io,
        "Tool registered\n",
    ) catch {};
}

fn handleList(
    allocator: Allocator,
    io: Io,
    home: []const u8,
) ToolCmdError!void {
    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    const stdout = File.stdout();
    if (reg.entries.len == 0) {
        stdout.writeStreamingAll(
            io,
            "No tools registered\n",
        ) catch {};
        return;
    }

    for (reg.entries) |entry| {
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &buf,
            "{s}\t{s}\t{s}\n",
            .{
                entry.name,
                entry.config.command,
                entry.config.description,
            },
        ) catch continue;
        stdout.writeStreamingAll(io, line) catch {};
    }
}

fn handleInfo(
    allocator: Allocator,
    io: Io,
    name: [:0]const u8,
    home: []const u8,
) ToolCmdError!void {
    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    const config = reg.get(name) orelse {
        std.debug.print(
            "Error: Tool '{s}' not found\n",
            .{name},
        );
        return ToolCmdError.NotFound;
    };

    const stdout = File.stdout();
    var buf: [512]u8 = undefined;
    const info = std.fmt.bufPrint(&buf,
        \\Name:        {s}
        \\Command:     {s}
        \\Arg mode:    {s}
        \\Timeout:     {d}s
        \\Max output:  {d} bytes
        \\Description: {s}
        \\
    , .{
        name,
        config.command,
        @as([]const u8, switch (config.arg_mode) {
            .allowlist => "allowlist",
            .passthrough => "passthrough",
        }),
        config.timeout_seconds,
        config.max_output_bytes,
        config.description,
    }) catch "Tool info\n";
    stdout.writeStreamingAll(io, info) catch {};
}

fn handleUpdate(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: []const u8,
) ToolCmdError!void {
    if (args.len == 0) {
        std.debug.print("Error: Tool name required\n", .{});
        return ToolCmdError.InvalidArgs;
    }

    const name = args[0];

    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    const existing = reg.get(name) orelse {
        std.debug.print(
            "Error: Tool '{s}' not found\n",
            .{name},
        );
        return ToolCmdError.NotFound;
    };

    // Start with existing config, override with provided args
    var command: []const u8 = existing.command;
    var timeout: u32 = existing.timeout_seconds;
    var max_output: usize = existing.max_output_bytes;
    var description: []const u8 = existing.description;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const has_next = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--command") and has_next) {
            i += 1;
            command = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout") and
            has_next)
        {
            i += 1;
            timeout = std.fmt.parseInt(
                u32,
                args[i],
                10,
            ) catch timeout;
        } else if (std.mem.eql(u8, arg, "--max-output") and
            has_next)
        {
            i += 1;
            max_output = std.fmt.parseInt(
                usize,
                args[i],
                10,
            ) catch max_output;
        } else if (std.mem.eql(u8, arg, "--description") and
            has_next)
        {
            i += 1;
            description = args[i];
        }
    }

    reg.update(allocator, io, name, .{
        .command = command,
        .allow_args = existing.allow_args,
        .deny_args = existing.deny_args,
        .arg_mode = existing.arg_mode,
        .scope = existing.scope,
        .timeout_seconds = timeout,
        .max_output_bytes = max_output,
        .description = description,
        .examples = existing.examples,
        .created = existing.created,
    }) catch {
        std.debug.print("Error: Failed to update tool\n", .{});
        return ToolCmdError.ExecFailed;
    };

    const stdout = File.stdout();
    stdout.writeStreamingAll(io, "Tool updated\n") catch {};
}

fn handleRemove(
    allocator: Allocator,
    io: Io,
    name: [:0]const u8,
    home: []const u8,
) ToolCmdError!void {
    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    reg.remove(allocator, io, name) catch |err| {
        if (err == tools_mod.ToolError.NotFound) {
            std.debug.print(
                "Error: Tool '{s}' not found\n",
                .{name},
            );
            return ToolCmdError.NotFound;
        }
        std.debug.print(
            "Error: Failed to remove tool\n",
            .{},
        );
        return ToolCmdError.ExecFailed;
    };

    const stdout = File.stdout();
    stdout.writeStreamingAll(io, "Tool removed\n") catch {};
}

fn handleTest(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: []const u8,
) ToolCmdError!void {
    if (args.len == 0) {
        std.debug.print("Error: Tool name required\n", .{});
        return ToolCmdError.InvalidArgs;
    }

    const name = args[0];
    const tool_args = if (args.len > 1) args[1..] else &[_][:0]const u8{};

    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    const config = reg.get(name) orelse {
        std.debug.print(
            "Error: Tool '{s}' not found\n",
            .{name},
        );
        return ToolCmdError.NotFound;
    };

    // Convert [:0]const u8 to []const u8 for tool_exec
    var exec_args: [64][]const u8 = undefined;
    const n = @min(tool_args.len, exec_args.len);
    for (tool_args[0..n], 0..) |a, j| {
        exec_args[j] = a;
    }

    // Read stdin if not a TTY
    var stdin_data: ?[]const u8 = null;
    defer if (stdin_data) |d| allocator.free(d);

    const stdin_file = File.stdin();
    if (!(stdin_file.isTty(io) catch false)) {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(allocator);
        var read_buf: [4096]u8 = undefined;
        var reader = stdin_file.reader(io, &read_buf);
        while (true) {
            const data = reader.interface.peekGreedy(1) catch
                break;
            if (data.len == 0) break;
            buf.appendSlice(allocator, data) catch break;
            reader.interface.toss(data.len);
        }
        if (buf.items.len > 0) {
            stdin_data = allocator.dupe(
                u8,
                buf.items,
            ) catch null;
        }
    }

    tool_exec.validateArgs(config.*, exec_args[0..n]) catch {
        std.debug.print("Error: Blocked argument\n", .{});
        return ToolCmdError.ExecFailed;
    };

    var result = tool_exec.executeTool(
        allocator,
        io,
        config.*,
        exec_args[0..n],
        stdin_data,
    ) catch |err| {
        std.debug.print("Error: {}\n", .{err});
        return ToolCmdError.ExecFailed;
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const stdout = File.stdout();
    if (result.stdout.len > 0)
        stdout.writeStreamingAll(io, result.stdout) catch {};
    const stderr_file = File.stderr();
    if (result.stderr.len > 0)
        stderr_file.writeStreamingAll(
            io,
            result.stderr,
        ) catch {};
}

fn handleInvocation(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
    environ: std.process.Environ,
) ToolCmdError!void {
    const name = args[0];
    const tool_args = if (args.len > 1) args[1..] else &[_][:0]const u8{};

    // Load token store and find matching token
    const home_dir = home orelse {
        std.debug.print("Error: HOME not set\n", .{});
        return ToolCmdError.InvalidArgs;
    };
    const token_dir = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/tokens",
        .{home_dir},
    ) catch return ToolCmdError.OutOfMemory;
    defer allocator.free(token_dir);

    var store = tokens.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return ToolCmdError.ExecFailed;
    };
    defer store.deinit(allocator);

    const token = store.findForPath(
        "tools",
        "invoke",
        name,
    ) orelse {
        std.debug.print(
            "Error: No token grants invoke access" ++
                " to tool '{s}'\n",
            .{name},
        );
        return ToolCmdError.ExecFailed;
    };

    // Read stdin if not a TTY
    var stdin_data: ?[]const u8 = null;
    defer if (stdin_data) |d| allocator.free(d);

    const stdin_file = File.stdin();
    if (!(stdin_file.isTty(io) catch false)) {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(allocator);
        var read_buf: [4096]u8 = undefined;
        var reader = stdin_file.reader(io, &read_buf);
        while (true) {
            const data = reader.interface.peekGreedy(1) catch
                break;
            if (data.len == 0) break;
            buf.appendSlice(allocator, data) catch break;
            reader.interface.toss(data.len);
        }
        if (buf.items.len > 0) {
            stdin_data = allocator.dupe(
                u8,
                buf.items,
            ) catch null;
        }
    }

    // Convert args
    var exec_args: [64][]const u8 = undefined;
    const n = @min(tool_args.len, exec_args.len);
    for (tool_args[0..n], 0..) |a, j| {
        exec_args[j] = a;
    }

    // Generate random request ID
    var id_bytes: [8]u8 = undefined;
    io.random(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);

    // Build request JSON
    var request_json: Io.Writer.Allocating = .init(allocator);
    defer request_json.deinit();
    const pw = &request_json.writer;

    pw.writeAll("{\"id\":\"req_") catch
        return ToolCmdError.OutOfMemory;
    pw.writeAll(&id_hex) catch
        return ToolCmdError.OutOfMemory;
    pw.writeAll("\",\"token\":\"") catch
        return ToolCmdError.OutOfMemory;
    pw.writeAll(token.raw) catch
        return ToolCmdError.OutOfMemory;
    pw.writeAll(
        "\",\"op\":\"tool\",\"params\":{\"tool_name\":\"",
    ) catch return ToolCmdError.OutOfMemory;
    pw.writeAll(name) catch return ToolCmdError.OutOfMemory;
    pw.writeAll("\",\"tool_args\":[") catch
        return ToolCmdError.OutOfMemory;

    for (exec_args[0..n], 0..) |arg, idx| {
        if (idx > 0) pw.writeAll(",") catch
            return ToolCmdError.OutOfMemory;
        pw.writeAll("\"") catch
            return ToolCmdError.OutOfMemory;
        pw.writeAll(arg) catch
            return ToolCmdError.OutOfMemory;
        pw.writeAll("\"") catch
            return ToolCmdError.OutOfMemory;
    }

    pw.writeAll("]") catch return ToolCmdError.OutOfMemory;

    if (stdin_data) |data| {
        pw.writeAll(",\"input\":\"") catch
            return ToolCmdError.OutOfMemory;
        protocol.writeBase64Encoded(pw, data) catch
            return ToolCmdError.OutOfMemory;
        pw.writeAll("\"") catch
            return ToolCmdError.OutOfMemory;
    }

    pw.writeAll("}}") catch return ToolCmdError.OutOfMemory;

    // Send via IPC
    const response_data = ipc_client.sendRequest(
        allocator,
        environ,
        request_json.written(),
    ) catch |err| {
        std.debug.print(
            "Error: Failed to connect to daemon: {}\n",
            .{err},
        );
        return ToolCmdError.ExecFailed;
    };
    defer allocator.free(response_data);

    // Parse and display response
    const parsed = std.json.parseFromSlice(
        struct {
            ok: bool,
            result: ?struct {
                tool_name: []const u8 = "",
                stdout: []const u8 = "",
                stderr: []const u8 = "",
                exit_code: u8 = 0,
                truncated: bool = false,
            } = null,
            @"error": ?struct {
                code: []const u8,
                message: []const u8,
            } = null,
        },
        allocator,
        response_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        std.debug.print("Error: Invalid response\n", .{});
        return ToolCmdError.ExecFailed;
    };
    defer parsed.deinit();

    if (!parsed.value.ok) {
        if (parsed.value.@"error") |e| {
            std.debug.print(
                "Error: {s}: {s}\n",
                .{ e.code, e.message },
            );
        }
        return ToolCmdError.ExecFailed;
    }

    if (parsed.value.result) |result| {
        const stdout = File.stdout();
        if (result.stdout.len > 0)
            stdout.writeStreamingAll(
                io,
                result.stdout,
            ) catch {};
        const stderr_out = File.stderr();
        if (result.stderr.len > 0)
            stderr_out.writeStreamingAll(
                io,
                result.stderr,
            ) catch {};
    }
}

fn handleGenerate(
    allocator: Allocator,
    io: Io,
    home: []const u8,
) ToolCmdError!void {
    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return ToolCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    const out_dir = std.fmt.allocPrint(
        allocator,
        "skills/clawgate",
        .{},
    ) catch return ToolCmdError.OutOfMemory;
    defer allocator.free(out_dir);

    skills.generateAll(allocator, io, &reg, out_dir) catch {
        std.debug.print(
            "Error: Failed to generate skills\n",
            .{},
        );
        return ToolCmdError.ExecFailed;
    };

    const stdout = File.stdout();
    stdout.writeStreamingAll(
        io,
        "Skills generated\n",
    ) catch {};
}

/// Discover available tools on the resource daemon.
/// Sends a tokenless request; the agent daemon handles
/// token lookup and aggregation internally.
fn handleRemoteList(
    allocator: Allocator,
    io: Io,
    environ: std.process.Environ,
) ToolCmdError!void {
    const request =
        "{\"op\":\"tool_list\",\"params\":{}}";

    // Send via IPC — daemon handles token lookup
    const response_data = ipc_client.sendRequest(
        allocator,
        environ,
        request,
    ) catch |err| {
        std.debug.print(
            "Error: Failed to connect to daemon:" ++
                " {}\n",
            .{err},
        );
        return ToolCmdError.ExecFailed;
    };
    defer allocator.free(response_data);

    // Parse response
    const parsed = std.json.parseFromSlice(
        struct {
            ok: bool,
            result: ?struct {
                tools: []const struct {
                    name: []const u8,
                    description: []const u8,
                },
            } = null,
            @"error": ?struct {
                code: []const u8,
                message: []const u8,
            } = null,
        },
        allocator,
        response_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        std.debug.print(
            "Error: Invalid response\n",
            .{},
        );
        return ToolCmdError.ExecFailed;
    };
    defer parsed.deinit();

    if (!parsed.value.ok) {
        if (parsed.value.@"error") |e| {
            std.debug.print(
                "Error: {s}: {s}\n",
                .{ e.code, e.message },
            );
        }
        return ToolCmdError.ExecFailed;
    }

    const stdout = File.stdout();
    if (parsed.value.result) |result| {
        if (result.tools.len == 0) {
            stdout.writeStreamingAll(
                io,
                "No tools available\n",
            ) catch {};
            return;
        }
        for (result.tools) |tool| {
            var buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(
                &buf,
                "{s}\t{s}\n",
                .{ tool.name, tool.description },
            ) catch continue;
            stdout.writeStreamingAll(
                io,
                line,
            ) catch {};
        }
    }
}

fn printUsage() void {
    const usage =
        \\Usage: clawgate tool <subcommand|name> [args...]
        \\
        \\Tool Management (resource-side):
        \\  register <name> [opts]  Register a new tool
        \\    --command <cmd>       Command to execute (required)
        \\    --allow-args <arg>    Allowed flag (repeatable)
        \\    --deny-args <arg>     Denied flag (repeatable)
        \\    --timeout <secs>      Timeout in seconds (default: 30)
        \\    --max-output <bytes>  Max output bytes (default: 65536)
        \\    --description <text>  Tool description
        \\    --example <text>      Usage example (repeatable)
        \\  ls                      List registered tools
        \\  info <name>             Show tool details
        \\  update <name> [opts]    Update tool configuration
        \\  remove <name>           Remove a tool
        \\  test <name> [args]      Test tool locally
        \\  generate                Generate skill files
        \\
        \\Remote Discovery (agent-side):
        \\  remote-list             List tools via daemon
        \\
        \\Tool Invocation (agent-side):
        \\  <name> [args...]        Invoke tool via daemon
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "MANAGEMENT_SUBCMDS are defined" {
    try std.testing.expect(MANAGEMENT_SUBCMDS.len > 0);
}

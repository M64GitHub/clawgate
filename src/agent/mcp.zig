//! MCP server for OpenClaw integration.
//!
//! Implements JSON-RPC 2.0 over stdio with the following methods:
//! - initialize: Return server capabilities
//! - tools/list: List available tools
//! - tools/call: Execute a tool (file operation via E2E connection)

const std = @import("std");
const ipc_client = @import("ipc_client.zig");
const tokens = @import("tokens.zig");
const paths = @import("../path.zig");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = std.Io.File;

const DEFAULT_TOKEN_DIR = "~/.clawgate/tokens";

/// MCP error codes (JSON-RPC 2.0 compliant).
pub const McpError = struct {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // Application-specific errors
    pub const NO_TOKEN: i32 = -32001;
    pub const TOKEN_EXPIRED: i32 = -32002;
    pub const SCOPE_VIOLATION: i32 = -32003;
    pub const CONN_TIMEOUT: i32 = -32004;
    pub const CONN_ERROR: i32 = -32005;
    pub const NOT_CONNECTED: i32 = -32006;
    pub const FILE_NOT_FOUND: i32 = -32010;
    pub const ACCESS_DENIED: i32 = -32011;
};

/// MCP server configuration.
pub const Config = struct {
    token_dir: []const u8 = DEFAULT_TOKEN_DIR,
    environ: std.process.Environ = .empty,
};

/// Runs the MCP server, reading from stdin and writing to stdout.
/// This function blocks until stdin is closed.
pub fn run(allocator: Allocator, config: Config) !void {
    var threaded: std.Io.Threaded = .init(allocator, .{
        .environ = config.environ,
    });
    defer threaded.deinit();

    const home = threaded.environString("HOME") orelse "/tmp";

    try runWithIo(allocator, threaded.io(), config, home);
}

/// Internal entry point with Io for testing.
fn runWithIo(
    allocator: Allocator,
    io: Io,
    config: Config,
    home: []const u8,
) !void {
    const environ = config.environ;
    const token_dir = try paths.expand(allocator, config.token_dir, home);
    defer allocator.free(token_dir);

    var store = tokens.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch |err| {
        std.log.err("Failed to load tokens from {s}: {}", .{ token_dir, err });
        const stderr = File.stderr();
        const msg = "Error: Token directory not found\n";
        stderr.writeStreamingAll(io, msg) catch {};
        return;
    };
    defer store.deinit(allocator);

    const stdin = File.stdin();
    const stdout = File.stdout();

    var read_buf: [65536]u8 = undefined;
    var reader = stdin.reader(io, &read_buf);

    var write_buf: [4096]u8 = undefined;
    var writer = stdout.writer(io, &write_buf);
    const out = &writer.interface;

    while (true) {
        const line = readLine(&reader.interface) catch |err| {
            if (err == error.EndOfStream) break;
            continue;
        };

        if (line.len == 0) continue;

        const response = handleRequest(
            allocator,
            environ,
            line,
            &store,
        ) catch |err| {
            const error_response = formatError(
                allocator,
                null,
                McpError.INTERNAL_ERROR,
                @errorName(err),
            ) catch continue;
            defer allocator.free(error_response);
            out.writeAll(error_response) catch continue;
            out.writeByte('\n') catch continue;
            out.flush() catch continue;
            continue;
        };
        defer allocator.free(response);

        out.writeAll(response) catch continue;
        out.writeByte('\n') catch continue;
        out.flush() catch continue;
    }
}

/// Reads a line from the reader interface.
fn readLine(reader: *Io.Reader) ![]const u8 {
    const data = try reader.peekGreedy(1);
    if (data.len == 0) return error.EndOfStream;

    const newline_pos = std.mem.indexOfScalar(u8, data, '\n');
    if (newline_pos) |pos| {
        const line = data[0..pos];
        reader.toss(pos + 1);
        return line;
    }

    const line = data;
    reader.tossBuffered();
    return line;
}

/// Handles a single JSON-RPC request.
fn handleRequest(
    allocator: Allocator,
    environ: std.process.Environ,
    line: []const u8,
    store: *tokens.TokenStore,
) ![]const u8 {
    const parsed = std.json.parseFromSlice(
        struct {
            jsonrpc: []const u8 = "2.0",
            method: []const u8,
            id: ?std.json.Value = null,
            params: ?std.json.Value = null,
        },
        allocator,
        line,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return formatError(
            allocator,
            null,
            McpError.PARSE_ERROR,
            "Invalid JSON",
        );
    };
    defer parsed.deinit();

    const req = parsed.value;

    if (std.mem.eql(u8, req.method, "initialize")) {
        return handleInitialize(allocator, req.id);
    } else if (std.mem.eql(u8, req.method, "tools/list")) {
        return handleToolsList(allocator, req.id);
    } else if (std.mem.eql(u8, req.method, "tools/call")) {
        return handleToolsCall(allocator, environ, req.id, req.params, store);
    } else if (std.mem.eql(u8, req.method, "notifications/initialized")) {
        return allocator.dupe(u8, "");
    } else {
        return formatError(
            allocator,
            req.id,
            McpError.METHOD_NOT_FOUND,
            "Method not found",
        );
    }
}

/// Handles 'initialize' method.
fn handleInitialize(allocator: Allocator, id: ?std.json.Value) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    try writer.writeAll("{\"jsonrpc\":\"2.0\",");
    try writeId(writer, id);
    try writer.writeAll(",\"result\":{");
    try writer.writeAll("\"protocolVersion\":\"2024-11-05\",");
    try writer.writeAll("\"capabilities\":{\"tools\":{}},");
    try writer.writeAll("\"serverInfo\":{");
    try writer.writeAll("\"name\":\"clawgate\",");
    try writer.writeAll("\"version\":\"0.3.0\"");
    try writer.writeAll("}}}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Handles 'tools/list' method.
fn handleToolsList(allocator: Allocator, id: ?std.json.Value) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    try writer.writeAll("{\"jsonrpc\":\"2.0\",");
    try writeId(writer, id);
    try writer.writeAll(",\"result\":{\"tools\":[");

    // clawgate_read_file
    try writer.writeAll("{\"name\":\"clawgate_read_file\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"Read file content from the primary machine\",");
    try writer.writeAll("\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{\"path\":{\"type\":\"string\",");
    try writer.writeAll("\"description\":\"Absolute path to the file\"}},");
    try writer.writeAll("\"required\":[\"path\"]}}");

    try writer.writeAll(",");

    // clawgate_write_file
    try writer.writeAll("{\"name\":\"clawgate_write_file\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"Write content to a file on the primary machine\",");
    try writer.writeAll("\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{");
    try writer.writeAll("\"path\":{\"type\":\"string\",");
    try writer.writeAll("\"description\":\"Absolute path to the file\"},");
    try writer.writeAll("\"content\":{\"type\":\"string\",");
    try writer.writeAll("\"description\":\"Content to write\"}},");
    try writer.writeAll("\"required\":[\"path\",\"content\"]}}");

    try writer.writeAll(",");

    // clawgate_list_directory
    try writer.writeAll("{\"name\":\"clawgate_list_directory\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"List directory contents on the primary machine\",");
    try writer.writeAll("\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{\"path\":{\"type\":\"string\",");
    try writer.writeAll("\"description\":\"Absolute path to directory\"}},");
    try writer.writeAll("\"required\":[\"path\"]}}");

    try writer.writeAll(",");

    // clawgate_stat
    try writer.writeAll("{\"name\":\"clawgate_stat\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"Get file/directory metadata from primary machine\"");
    try writer.writeAll(",\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{\"path\":{\"type\":\"string\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"Absolute path to file or directory\"");
    try writer.writeAll("}},\"required\":[\"path\"]}}");

    try writer.writeAll(",");

    // clawgate_git
    try writer.writeAll("{\"name\":\"clawgate_git\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll(
        "\"Run git commands on the primary machine\",",
    );
    try writer.writeAll("\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{");
    try writer.writeAll("\"path\":{\"type\":\"string\",");
    try writer.writeAll(
        "\"description\":\"Repository path\"},",
    );
    try writer.writeAll("\"args\":{\"type\":\"array\",");
    try writer.writeAll("\"items\":{\"type\":\"string\"},");
    try writer.writeAll("\"description\":");
    try writer.writeAll("\"Git arguments (e.g. ");
    try writer.writeAll("[\\\"status\\\", \\\"--short\\\"])\"");
    try writer.writeAll("}},\"required\":[\"path\",\"args\"]}}");

    try writer.writeAll(",");

    // clawgate_tool
    try writer.writeAll("{\"name\":\"clawgate_tool\",");
    try writer.writeAll("\"description\":");
    try writer.writeAll(
        "\"Run a registered tool on the primary machine\",",
    );
    try writer.writeAll("\"inputSchema\":{\"type\":\"object\",");
    try writer.writeAll("\"properties\":{");
    try writer.writeAll("\"tool\":{\"type\":\"string\",");
    try writer.writeAll(
        "\"description\":\"Tool name\"},",
    );
    try writer.writeAll("\"args\":{\"type\":\"array\",");
    try writer.writeAll("\"items\":{\"type\":\"string\"},");
    try writer.writeAll(
        "\"description\":\"Arguments\"},",
    );
    try writer.writeAll("\"input\":{\"type\":\"string\",");
    try writer.writeAll(
        "\"description\":\"Stdin data for the tool\"}",
    );
    try writer.writeAll("},\"required\":[\"tool\"]}}");

    try writer.writeAll("]}}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Handles 'tools/call' method.
fn handleToolsCall(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    params: ?std.json.Value,
    store: *tokens.TokenStore,
) ![]const u8 {
    const p = params orelse {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Missing params",
        );
    };

    const params_obj = switch (p) {
        .object => |obj| obj,
        else => return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Params must be object",
        ),
    };

    const name_val = params_obj.get("name") orelse {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Missing name",
        );
    };
    const name = switch (name_val) {
        .string => |s| s,
        else => return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "name must be string",
        ),
    };

    const args_val = params_obj.get("arguments") orelse {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Missing arguments",
        );
    };
    const args = switch (args_val) {
        .object => |obj| obj,
        else => return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "arguments must be object",
        ),
    };

    // Handle clawgate_tool before path extraction (no path needed)
    if (std.mem.eql(u8, name, "clawgate_tool")) {
        return executeToolCall(
            allocator,
            environ,
            id,
            args,
            store,
        );
    }

    const path_val = args.get("path") orelse {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Missing path",
        );
    };
    const path = switch (path_val) {
        .string => |s| s,
        else => return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "path must be string",
        ),
    };

    if (std.mem.eql(u8, name, "clawgate_read_file")) {
        return executeReadFile(allocator, environ, id, path, store);
    } else if (std.mem.eql(u8, name, "clawgate_write_file")) {
        const content_val = args.get("content") orelse {
            return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "Missing content",
            );
        };
        const content = switch (content_val) {
            .string => |s| s,
            else => return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "content must be string",
            ),
        };
        return executeWriteFile(allocator, environ, id, path, content, store);
    } else if (std.mem.eql(u8, name, "clawgate_list_directory")) {
        return executeListDirectory(allocator, environ, id, path, store);
    } else if (std.mem.eql(u8, name, "clawgate_stat")) {
        return executeStat(allocator, environ, id, path, store);
    } else if (std.mem.eql(u8, name, "clawgate_git")) {
        // Extract args array
        const git_args_val = args.get("args") orelse {
            return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "Missing args",
            );
        };
        const git_args_arr = switch (git_args_val) {
            .array => |a| a,
            else => return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "args must be array",
            ),
        };
        return executeGitTool(
            allocator,
            environ,
            id,
            path,
            git_args_arr,
            store,
        );
    } else {
        return formatError(
            allocator,
            id,
            McpError.METHOD_NOT_FOUND,
            "Unknown tool",
        );
    }
}

/// Executes clawgate_read_file tool.
fn executeReadFile(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    path: []const u8,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tok = store.findForPath("files", "read", path) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for path",
        );
    };

    const response = sendRequest(
        allocator,
        environ,
        "read",
        path,
        tok.raw,
        null,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };
    defer {
        if (response.result) |r| {
            switch (r) {
                .read => |rr| allocator.free(rr.content),
                else => {},
            }
        }
    }

    if (!response.ok) {
        if (response.err) |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    const result = response.result orelse {
        return formatError(allocator, id, McpError.INTERNAL_ERROR, "No result");
    };

    const read_result = switch (result) {
        .read => |r| r,
        else => return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unexpected result",
        ),
    };

    return formatToolResult(allocator, id, read_result.content);
}

/// Executes clawgate_write_file tool.
fn executeWriteFile(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    path: []const u8,
    content: []const u8,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tok = store.findForPath("files", "write", path) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for path",
        );
    };

    const response = sendRequest(
        allocator,
        environ,
        "write",
        path,
        tok.raw,
        content,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };

    if (!response.ok) {
        if (response.err) |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    const result = response.result orelse {
        return formatError(allocator, id, McpError.INTERNAL_ERROR, "No result");
    };

    const write_result = switch (result) {
        .write => |w| w,
        else => return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unexpected result",
        ),
    };

    var msg_buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &msg_buf,
        "Wrote {d} bytes",
        .{write_result.bytes_written},
    ) catch "Write successful";

    return formatToolResult(allocator, id, msg);
}

/// Executes clawgate_list_directory tool.
fn executeListDirectory(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    path: []const u8,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tok = store.findForPath("files", "list", path) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for path",
        );
    };

    const response = sendRequest(
        allocator,
        environ,
        "list",
        path,
        tok.raw,
        null,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };
    defer {
        if (response.result) |r| {
            switch (r) {
                .list => |l| {
                    for (l.entries) |entry| {
                        allocator.free(entry.name);
                    }
                    allocator.free(l.entries);
                },
                else => {},
            }
        }
    }

    if (!response.ok) {
        if (response.err) |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    const result = response.result orelse {
        return formatError(allocator, id, McpError.INTERNAL_ERROR, "No result");
    };

    const list_result = switch (result) {
        .list => |l| l,
        else => return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unexpected result",
        ),
    };

    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    for (list_result.entries) |entry| {
        try writer.print("{s}\t{s}", .{ entry.type, entry.name });
        if (entry.size) |sz| {
            try writer.print("\t{d}", .{sz});
        }
        try writer.writeByte('\n');
    }

    const text = output.written();
    const text_copy = try allocator.dupe(u8, text);
    defer allocator.free(text_copy);
    output.deinit();

    return formatToolResult(allocator, id, text_copy);
}

/// Executes clawgate_stat tool.
fn executeStat(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    path: []const u8,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tok = store.findForPath("files", "stat", path) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for path",
        );
    };

    const response = sendRequest(
        allocator,
        environ,
        "stat",
        path,
        tok.raw,
        null,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };
    defer {
        if (response.result) |r| {
            switch (r) {
                .stat => |s| allocator.free(s.modified),
                else => {},
            }
        }
    }

    if (!response.ok) {
        if (response.err) |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    const result = response.result orelse {
        return formatError(allocator, id, McpError.INTERNAL_ERROR, "No result");
    };

    const stat_result = switch (result) {
        .stat => |s| s,
        else => return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unexpected result",
        ),
    };

    var buf: [256]u8 = undefined;
    const fmt = "exists: {}\ntype: {s}\nsize: {d}\nmodified: {s}";
    const text = std.fmt.bufPrint(&buf, fmt, .{
        stat_result.exists,
        stat_result.type,
        stat_result.size,
        stat_result.modified,
    }) catch "stat result";

    return formatToolResult(allocator, id, text);
}

/// Executes clawgate_git tool.
fn executeGitTool(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    path: []const u8,
    git_args_arr: std.json.Array,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tok = store.findForPath(
        "files",
        "git",
        path,
    ) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for path",
        );
    };

    // Extract string args from JSON array
    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);

    for (git_args_arr.items) |item| {
        const s = switch (item) {
            .string => |s| s,
            else => return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "args must be strings",
            ),
        };
        args_list.append(allocator, s) catch {
            return formatError(
                allocator,
                id,
                McpError.INTERNAL_ERROR,
                "Out of memory",
            );
        };
    }

    if (args_list.items.len == 0) {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "args must not be empty",
        );
    }

    const response = sendGitRequest(
        allocator,
        environ,
        path,
        tok.raw,
        args_list.items,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };
    defer allocator.free(response);

    // Parse the response to check ok/error
    const parsed = std.json.parseFromSlice(
        struct {
            ok: bool,
            result: ?struct {
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
        response,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Invalid response from daemon",
        );
    };
    defer parsed.deinit();

    if (!parsed.value.ok) {
        if (parsed.value.@"error") |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    if (parsed.value.result) |result| {
        // Build output text: stdout + stderr if non-empty
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;

        if (result.stdout.len > 0) {
            try writer.writeAll(result.stdout);
        }
        if (result.stderr.len > 0) {
            if (result.stdout.len > 0) {
                try writer.writeAll("\n--- stderr ---\n");
            }
            try writer.writeAll(result.stderr);
        }
        if (result.exit_code != 0) {
            try writer.print(
                "\n[exit code: {d}]",
                .{result.exit_code},
            );
        }
        if (result.truncated) {
            try writer.writeAll("\n[output truncated]");
        }

        const text = output.written();
        const text_copy = try allocator.dupe(u8, text);
        defer allocator.free(text_copy);
        output.deinit();

        return formatToolResult(allocator, id, text_copy);
    }

    return formatToolResult(allocator, id, "");
}

/// Executes clawgate_tool.
fn executeToolCall(
    allocator: Allocator,
    environ: std.process.Environ,
    id: ?std.json.Value,
    args: std.json.ObjectMap,
    store: *tokens.TokenStore,
) ![]const u8 {
    const tool_val = args.get("tool") orelse {
        return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "Missing tool",
        );
    };
    const tool_name = switch (tool_val) {
        .string => |s| s,
        else => return formatError(
            allocator,
            id,
            McpError.INVALID_PARAMS,
            "tool must be string",
        ),
    };

    const tok = store.findForPath(
        "tools",
        "invoke",
        tool_name,
    ) orelse {
        return formatError(
            allocator,
            id,
            McpError.NO_TOKEN,
            "No capability token for tool",
        );
    };

    // Extract optional args array
    var tool_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer tool_args.deinit(allocator);

    if (args.get("args")) |args_val| {
        const arr = switch (args_val) {
            .array => |a| a,
            else => return formatError(
                allocator,
                id,
                McpError.INVALID_PARAMS,
                "args must be array",
            ),
        };
        for (arr.items) |item| {
            const s = switch (item) {
                .string => |s| s,
                else => return formatError(
                    allocator,
                    id,
                    McpError.INVALID_PARAMS,
                    "args must be strings",
                ),
            };
            tool_args.append(allocator, s) catch {
                return formatError(
                    allocator,
                    id,
                    McpError.INTERNAL_ERROR,
                    "Out of memory",
                );
            };
        }
    }

    // Extract optional input
    var input: ?[]const u8 = null;
    if (args.get("input")) |input_val| {
        input = switch (input_val) {
            .string => |s| s,
            else => null,
        };
    }

    const response = sendToolRequest(
        allocator,
        environ,
        tool_name,
        tok.raw,
        tool_args.items,
        input,
    ) catch |err| {
        return mapConnectionError(allocator, id, err);
    };
    defer allocator.free(response);

    // Parse response
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
        response,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Invalid response from daemon",
        );
    };
    defer parsed.deinit();

    if (!parsed.value.ok) {
        if (parsed.value.@"error") |e| {
            return formatError(
                allocator,
                id,
                mapProtocolError(e.code),
                e.message,
            );
        }
        return formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Unknown error",
        );
    }

    if (parsed.value.result) |result| {
        var output: std.Io.Writer.Allocating = .init(
            allocator,
        );
        errdefer output.deinit();
        const writer = &output.writer;

        if (result.stdout.len > 0) {
            try writer.writeAll(result.stdout);
        }
        if (result.stderr.len > 0) {
            if (result.stdout.len > 0) {
                try writer.writeAll(
                    "\n--- stderr ---\n",
                );
            }
            try writer.writeAll(result.stderr);
        }
        if (result.exit_code != 0) {
            try writer.print(
                "\n[exit code: {d}]",
                .{result.exit_code},
            );
        }
        if (result.truncated) {
            try writer.writeAll("\n[output truncated]");
        }

        const text = output.written();
        const text_copy = try allocator.dupe(u8, text);
        defer allocator.free(text_copy);
        output.deinit();

        return formatToolResult(allocator, id, text_copy);
    }

    return formatToolResult(allocator, id, "");
}

/// Sends a tool request via IPC to the agent daemon.
fn sendToolRequest(
    allocator: Allocator,
    environ: std.process.Environ,
    tool_name: []const u8,
    token_raw: []const u8,
    tool_args: []const []const u8,
    input: ?[]const u8,
) ![]const u8 {
    var id_buf: [16]u8 = undefined;
    @memset(&id_buf, 't');
    const id_str = &id_buf;

    var request_json: std.Io.Writer.Allocating = .init(
        allocator,
    );
    defer request_json.deinit();
    const pw = &request_json.writer;

    try pw.writeAll("{\"id\":\"");
    try pw.writeAll(id_str);
    try pw.writeAll("\",\"token\":\"");
    try writeJsonEscaped(pw, token_raw);
    try pw.writeAll("\",\"op\":\"tool\"");
    try pw.writeAll(",\"params\":{\"tool_name\":\"");
    try writeJsonEscaped(pw, tool_name);
    try pw.writeAll("\"");

    if (tool_args.len > 0) {
        try pw.writeAll(",\"tool_args\":[");
        for (tool_args, 0..) |arg, idx| {
            if (idx > 0) try pw.writeAll(",");
            try pw.writeAll("\"");
            try writeJsonEscaped(pw, arg);
            try pw.writeAll("\"");
        }
        try pw.writeAll("]");
    }

    if (input) |inp| {
        try pw.writeAll(",\"input\":\"");
        try writeJsonEscaped(pw, inp);
        try pw.writeAll("\"");
    }

    try pw.writeAll("}}");

    const response_data = ipc_client.sendRequest(
        allocator,
        environ,
        request_json.written(),
    ) catch |err| {
        return switch (err) {
            ipc_client.IpcError.DaemonNotRunning => {
                return error.NotConnected;
            },
            ipc_client.IpcError.ConnectionFailed => {
                return error.ConnectionClosed;
            },
            ipc_client.IpcError.OutOfMemory => {
                return error.OutOfMemory;
            },
            else => error.ConnectionError,
        };
    };

    return response_data;
}

/// Sends a git request via IPC to the agent daemon.
fn sendGitRequest(
    allocator: Allocator,
    environ: std.process.Environ,
    path: []const u8,
    token_raw: []const u8,
    git_args: []const []const u8,
) ![]const u8 {
    // Generate request ID
    var id_buf: [16]u8 = undefined;
    @memset(&id_buf, 'g');
    const id_str = &id_buf;

    // Build request JSON
    var request_json: std.Io.Writer.Allocating = .init(
        allocator,
    );
    defer request_json.deinit();
    const pw = &request_json.writer;

    try pw.writeAll("{\"id\":\"");
    try pw.writeAll(id_str);
    try pw.writeAll("\",\"token\":\"");
    try writeJsonEscaped(pw, token_raw);
    try pw.writeAll("\",\"op\":\"git\"");
    try pw.writeAll(",\"params\":{\"path\":\"");
    try writeJsonEscaped(pw, path);
    try pw.writeAll("\",\"args\":[");

    for (git_args, 0..) |arg, idx| {
        if (idx > 0) try pw.writeAll(",");
        try pw.writeAll("\"");
        try writeJsonEscaped(pw, arg);
        try pw.writeAll("\"");
    }

    try pw.writeAll("]}}");

    // Send via IPC
    const response_data = ipc_client.sendRequest(
        allocator,
        environ,
        request_json.written(),
    ) catch |err| {
        return switch (err) {
            ipc_client.IpcError.DaemonNotRunning => {
                return error.NotConnected;
            },
            ipc_client.IpcError.ConnectionFailed => {
                return error.ConnectionClosed;
            },
            ipc_client.IpcError.OutOfMemory => {
                return error.OutOfMemory;
            },
            else => error.ConnectionError,
        };
    };

    return response_data;
}

/// Sends a request via IPC to the agent daemon and parses the response.
fn sendRequest(
    allocator: Allocator,
    environ: std.process.Environ,
    op: []const u8,
    path: []const u8,
    token_raw: []const u8,
    content: ?[]const u8,
) !protocol.Response {
    // Generate request ID
    var id_buf: [16]u8 = undefined;
    @memset(&id_buf, 'a');
    const id_str = &id_buf;

    // Build request JSON
    var request_json: std.Io.Writer.Allocating = .init(allocator);
    defer request_json.deinit();
    const pw = &request_json.writer;

    try pw.writeAll("{\"id\":\"");
    try pw.writeAll(id_str);
    try pw.writeAll("\",\"token\":\"");
    try writeJsonEscaped(pw, token_raw);
    try pw.writeAll("\",\"op\":\"");
    try pw.writeAll(op);
    try pw.writeAll("\",\"params\":{\"path\":\"");
    try writeJsonEscaped(pw, path);
    try pw.writeAll("\"");

    if (content) |c| {
        try pw.writeAll(",\"content\":\"");
        try protocol.writeBase64Encoded(pw, c);
        try pw.writeAll("\"");
    }

    try pw.writeAll("}}");

    // Send request via IPC to agent daemon
    const response_data = ipc_client.sendRequest(
        allocator,
        environ,
        request_json.written(),
    ) catch |err| {
        return switch (err) {
            ipc_client.IpcError.DaemonNotRunning => error.NotConnected,
            ipc_client.IpcError.ConnectionFailed => error.ConnectionClosed,
            ipc_client.IpcError.OutOfMemory => error.OutOfMemory,
            else => error.ConnectionError,
        };
    };
    defer allocator.free(response_data);

    // Parse response
    return parseResponse(allocator, response_data);
}

/// Parses response JSON into protocol.Response.
fn parseResponse(allocator: Allocator, data: []const u8) !protocol.Response {
    const parsed = std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: ?std.json.Value = null,
            @"error": ?struct {
                code: []const u8,
                message: []const u8,
            } = null,
        },
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const resp = parsed.value;

    if (!resp.ok) {
        if (resp.@"error") |e| {
            const code = try allocator.dupe(u8, e.code);
            errdefer allocator.free(code);
            const message = try allocator.dupe(u8, e.message);
            return protocol.Response{
                .id = "",
                .ok = false,
                .err = .{ .code = code, .message = message },
            };
        }
        return protocol.Response{ .id = "", .ok = false };
    }

    if (resp.result) |result_val| {
        switch (result_val) {
            .object => |obj| {
                if (obj.get("content") != null) {
                    const encoded = switch (obj.get("content").?) {
                        .string => |s| s,
                        else => return error.InvalidResponse,
                    };
                    const content_str = protocol.decodeBase64(
                        allocator,
                        encoded,
                    ) catch return error.InvalidResponse;
                    const size_val = obj.get("size") orelse {
                        allocator.free(content_str);
                        return error.InvalidResponse;
                    };
                    const size: usize = switch (size_val) {
                        .integer => |i| @intCast(i),
                        else => {
                            allocator.free(content_str);
                            return error.InvalidResponse;
                        },
                    };
                    const truncated_val = obj.get("truncated") orelse {
                        allocator.free(content_str);
                        return error.InvalidResponse;
                    };
                    const truncated = switch (truncated_val) {
                        .bool => |b| b,
                        else => false,
                    };
                    return protocol.Response{
                        .id = "",
                        .ok = true,
                        .result = .{
                            .read = .{
                                .content = content_str,
                                .size = size,
                                .truncated = truncated,
                            },
                        },
                    };
                } else if (obj.get("bytes_written") != null) {
                    const bw_val = obj.get("bytes_written").?;
                    const bytes_written: usize = switch (bw_val) {
                        .integer => |i| @intCast(i),
                        else => return error.InvalidResponse,
                    };
                    return protocol.Response{
                        .id = "",
                        .ok = true,
                        .result = .{
                            .write = .{ .bytes_written = bytes_written },
                        },
                    };
                } else if (obj.get("entries") != null) {
                    const entries_val = obj.get("entries").?;
                    const entries_arr = switch (entries_val) {
                        .array => |a| a,
                        else => return error.InvalidResponse,
                    };
                    var entries: std.ArrayListUnmanaged(protocol.Entry) =
                        .empty;
                    errdefer {
                        for (entries.items) |e| allocator.free(e.name);
                        entries.deinit(allocator);
                    }
                    for (entries_arr.items) |item| {
                        const item_obj = switch (item) {
                            .object => |o| o,
                            else => continue,
                        };
                        const name_val = item_obj.get("name") orelse continue;
                        const name = switch (name_val) {
                            .string => |s| try allocator.dupe(u8, s),
                            else => continue,
                        };
                        const type_val = item_obj.get("type") orelse {
                            allocator.free(name);
                            continue;
                        };
                        const entry_type = switch (type_val) {
                            .string => |s| s,
                            else => {
                                allocator.free(name);
                                continue;
                            },
                        };
                        const size_val = item_obj.get("size");
                        const size: ?usize = if (size_val) |sv|
                            switch (sv) {
                                .integer => |i| @intCast(i),
                                else => null,
                            }
                        else
                            null;
                        try entries.append(allocator, .{
                            .name = name,
                            .type = entry_type,
                            .size = size,
                        });
                    }
                    return protocol.Response{
                        .id = "",
                        .ok = true,
                        .result = .{
                            .list = .{
                                .entries = try entries.toOwnedSlice(allocator),
                            },
                        },
                    };
                } else if (obj.get("exists") != null) {
                    const exists = switch (obj.get("exists").?) {
                        .bool => |b| b,
                        else => return error.InvalidResponse,
                    };
                    const file_type = switch (obj.get("type") orelse {
                        return error.InvalidResponse;
                    }) {
                        .string => |s| s,
                        else => return error.InvalidResponse,
                    };
                    const size: usize = switch (obj.get("size") orelse {
                        return error.InvalidResponse;
                    }) {
                        .integer => |i| @intCast(i),
                        else => return error.InvalidResponse,
                    };
                    const modified = switch (obj.get("modified") orelse {
                        return error.InvalidResponse;
                    }) {
                        .string => |s| try allocator.dupe(u8, s),
                        else => return error.InvalidResponse,
                    };
                    return protocol.Response{
                        .id = "",
                        .ok = true,
                        .result = .{
                            .stat = .{
                                .exists = exists,
                                .type = file_type,
                                .size = size,
                                .modified = modified,
                            },
                        },
                    };
                }
            },
            else => {},
        }
    }

    return error.InvalidResponse;
}

/// Writes a string with JSON escaping.
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

/// Writes the id field to JSON output.
fn writeId(writer: anytype, id: ?std.json.Value) !void {
    try writer.writeAll("\"id\":");
    if (id) |v| {
        switch (v) {
            .integer => |i| try writer.print("{d}", .{i}),
            .string => |s| {
                try writer.writeByte('"');
                try writeJsonEscaped(writer, s);
                try writer.writeByte('"');
            },
            .null => try writer.writeAll("null"),
            else => try writer.writeAll("null"),
        }
    } else {
        try writer.writeAll("null");
    }
}

/// Formats a JSON-RPC error response.
pub fn formatError(
    allocator: Allocator,
    id: ?std.json.Value,
    code: i32,
    message: []const u8,
) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    try writer.writeAll("{\"jsonrpc\":\"2.0\",");
    try writeId(writer, id);
    try writer.writeAll(",\"error\":{\"code\":");
    try writer.print("{d}", .{code});
    try writer.writeAll(",\"message\":\"");
    try writeJsonEscaped(writer, message);
    try writer.writeAll("\"}}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Formats a successful tool call result.
pub fn formatToolResult(
    allocator: Allocator,
    id: ?std.json.Value,
    text: []const u8,
) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;

    try writer.writeAll("{\"jsonrpc\":\"2.0\",");
    try writeId(writer, id);
    try writer.writeAll(
        ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"",
    );
    try writeJsonEscaped(writer, text);
    try writer.writeAll("\"}]}}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Maps connection errors to MCP error responses.
fn mapConnectionError(
    allocator: Allocator,
    id: ?std.json.Value,
    err: anyerror,
) ![]const u8 {
    return switch (err) {
        error.NotConnected => formatError(
            allocator,
            id,
            McpError.NOT_CONNECTED,
            "Not connected to resource daemon",
        ),
        error.ConnectionClosed => formatError(
            allocator,
            id,
            McpError.CONN_ERROR,
            "Connection closed",
        ),
        else => formatError(
            allocator,
            id,
            McpError.INTERNAL_ERROR,
            "Internal error",
        ),
    };
}

/// Maps protocol error codes to MCP error codes.
fn mapProtocolError(code: []const u8) i32 {
    const not_found = std.mem.eql(u8, code, "FILE_NOT_FOUND");
    if (not_found) return McpError.FILE_NOT_FOUND;
    if (std.mem.eql(u8, code, "ACCESS_DENIED")) return McpError.ACCESS_DENIED;
    const scope_viol = std.mem.eql(u8, code, "SCOPE_VIOLATION");
    if (scope_viol) return McpError.SCOPE_VIOLATION;
    if (std.mem.eql(u8, code, "INVALID_TOKEN")) return McpError.NO_TOKEN;
    if (std.mem.eql(u8, code, "TOKEN_EXPIRED")) return McpError.TOKEN_EXPIRED;
    if (std.mem.eql(u8, code, "TOKEN_REVOKED")) return McpError.NO_TOKEN;
    if (std.mem.eql(u8, code, "TOOL_DENIED")) return McpError.ACCESS_DENIED;
    if (std.mem.eql(u8, code, "TOOL_ERROR")) return McpError.INTERNAL_ERROR;
    if (std.mem.eql(u8, code, "ARG_BLOCKED")) return McpError.ACCESS_DENIED;
    return McpError.INTERNAL_ERROR;
}

// Tests

test "formatError creates valid JSON-RPC error" {
    const allocator = std.testing.allocator;

    const result = try formatError(
        allocator,
        null,
        McpError.PARSE_ERROR,
        "Invalid JSON",
    );
    defer allocator.free(result);

    const parsed = try std.json.parseFromSlice(
        struct {
            jsonrpc: []const u8,
            id: ?i32,
            @"error": struct {
                code: i32,
                message: []const u8,
            },
        },
        allocator,
        result,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("2.0", parsed.value.jsonrpc);
    try std.testing.expect(parsed.value.id == null);
    const err = parsed.value.@"error";
    try std.testing.expectEqual(McpError.PARSE_ERROR, err.code);
    try std.testing.expectEqualStrings("Invalid JSON", err.message);
}

test "handleInitialize returns capabilities" {
    const allocator = std.testing.allocator;

    const result = try handleInitialize(allocator, null);
    defer allocator.free(result);

    const parsed = try std.json.parseFromSlice(
        struct {
            jsonrpc: []const u8,
            result: struct {
                protocolVersion: []const u8,
                serverInfo: struct {
                    name: []const u8,
                    version: []const u8,
                },
            },
        },
        allocator,
        result,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("2.0", parsed.value.jsonrpc);
    const info = parsed.value.result.serverInfo;
    try std.testing.expectEqualStrings("clawgate", info.name);
    try std.testing.expectEqualStrings("0.3.0", info.version);
}

test "handleToolsList returns all tools" {
    const allocator = std.testing.allocator;

    const result = try handleToolsList(allocator, null);
    defer allocator.free(result);

    const parsed = try std.json.parseFromSlice(
        struct {
            jsonrpc: []const u8,
            result: struct {
                tools: []const struct {
                    name: []const u8,
                    description: []const u8,
                },
            },
        },
        allocator,
        result,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 6), parsed.value.result.tools.len);
    try std.testing.expectEqualStrings(
        "clawgate_read_file",
        parsed.value.result.tools[0].name,
    );
    try std.testing.expectEqualStrings(
        "clawgate_write_file",
        parsed.value.result.tools[1].name,
    );
    try std.testing.expectEqualStrings(
        "clawgate_list_directory",
        parsed.value.result.tools[2].name,
    );
    try std.testing.expectEqualStrings(
        "clawgate_stat",
        parsed.value.result.tools[3].name,
    );
    try std.testing.expectEqualStrings(
        "clawgate_git",
        parsed.value.result.tools[4].name,
    );
    try std.testing.expectEqualStrings(
        "clawgate_tool",
        parsed.value.result.tools[5].name,
    );
}

test "formatToolResult creates valid response" {
    const allocator = std.testing.allocator;

    const result = try formatToolResult(allocator, null, "Hello, World!");
    defer allocator.free(result);

    const parsed = try std.json.parseFromSlice(
        struct {
            jsonrpc: []const u8,
            result: struct {
                content: []const struct {
                    type: []const u8,
                    text: []const u8,
                },
            },
        },
        allocator,
        result,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.result.content.len);
    try std.testing.expectEqualStrings(
        "text",
        parsed.value.result.content[0].type,
    );
    try std.testing.expectEqualStrings(
        "Hello, World!",
        parsed.value.result.content[0].text,
    );
}

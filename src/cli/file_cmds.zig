//! File operation commands for ClawGate.
//!
//! Agent-side commands that send requests to the resource daemon
//! via NATS and display results.

const std = @import("std");
const nats = @import("nats");
const tokens_mod = @import("../agent/tokens.zig");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const FileCmdError = error{
    InvalidArgs,
    MissingPath,
    TokenNotFound,
    ConnectionFailed,
    RequestFailed,
    RequestTimeout,
    ResponseError,
    OutOfMemory,
};

/// Common configuration for file commands.
pub const FileConfig = struct {
    nats_url: []const u8 = "nats://localhost:4222",
    token_dir: []const u8 = "",
    path: ?[]const u8 = null,
};

/// Reads and outputs file content (cat command).
pub fn cat(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) FileCmdError!void {
    var config = FileConfig{};
    var offset: ?usize = null;
    var length: ?usize = null;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--nats") or std.mem.eql(u8, arg, "-n")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.nats_url = args[i];
        } else if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--offset")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            offset = std.fmt.parseInt(usize, args[i], 10) catch {
                return FileCmdError.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--length")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            length = std.fmt.parseInt(usize, args[i], 10) catch {
                return FileCmdError.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printCatUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            config.path = arg;
        }
    }

    if (config.path == null) {
        std.debug.print("Error: Path required\n\n", .{});
        printCatUsage();
        return FileCmdError.MissingPath;
    }

    // Get token directory
    const token_dir = if (config.token_dir.len > 0)
        config.token_dir
    else blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return FileCmdError.TokenNotFound;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return FileCmdError.OutOfMemory;
    };
    defer if (config.token_dir.len == 0) allocator.free(token_dir);

    // Load tokens and find matching one
    var store = tokens_mod.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return FileCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    const token = store.findForPath("files", "read", config.path.?) orelse {
        std.debug.print(
            "Error: No token grants read access to {s}\n",
            .{config.path.?},
        );
        return FileCmdError.TokenNotFound;
    };

    // Connect to NATS
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-cli" },
    ) catch {
        std.debug.print("Error: Failed to connect to NATS\n", .{});
        return FileCmdError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    // Build request
    const request = buildRequest(allocator, io, token.raw, "read", .{
        .path = config.path.?,
        .offset = offset,
        .length = length,
    }) catch return FileCmdError.OutOfMemory;
    defer allocator.free(request);

    // Send request
    const reply = client.request(
        allocator,
        "clawgate.req.files.read",
        request,
        5000,
    ) catch {
        std.debug.print("Error: Request failed\n", .{});
        return FileCmdError.RequestFailed;
    };

    if (reply) |r| {
        defer r.deinit(allocator);

        // Parse response
        const parsed = std.json.parseFromSlice(
            struct {
                ok: bool,
                result: ?struct { content: []const u8, truncated: bool } = null,
                @"error": ?struct {
                    code: []const u8,
                    message: []const u8,
                } = null,
            },
            allocator,
            r.data,
            .{ .ignore_unknown_fields = true },
        ) catch {
            std.debug.print("Error: Invalid response\n", .{});
            return FileCmdError.ResponseError;
        };
        defer parsed.deinit();

        if (!parsed.value.ok) {
            if (parsed.value.@"error") |err| {
                std.debug.print(
                    "Error: {s}: {s}\n",
                    .{ err.code, err.message },
                );
            }
            return FileCmdError.ResponseError;
        }

        if (parsed.value.result) |result| {
            // Output content to stdout
            const stdout = std.posix.STDOUT_FILENO;
            _ = std.posix.write(stdout, result.content) catch {};
            if (result.truncated) {
                std.debug.print("\n[truncated]\n", .{});
            }
        }
    } else {
        std.debug.print("Error: Request timed out\n", .{});
        return FileCmdError.RequestTimeout;
    }
}

/// Lists directory contents (ls command).
pub fn ls(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) FileCmdError!void {
    var config = FileConfig{};
    var depth: u8 = 1;
    var long_format = false;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--nats") or std.mem.eql(u8, arg, "-n")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.nats_url = args[i];
        } else if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--depth")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            depth = std.fmt.parseInt(u8, args[i], 10) catch 1;
        } else if (std.mem.eql(u8, arg, "-l")) {
            long_format = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printLsUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            config.path = arg;
        }
    }

    if (config.path == null) {
        std.debug.print("Error: Path required\n\n", .{});
        printLsUsage();
        return FileCmdError.MissingPath;
    }

    // Get token directory
    const token_dir = if (config.token_dir.len > 0)
        config.token_dir
    else blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return FileCmdError.TokenNotFound;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return FileCmdError.OutOfMemory;
    };
    defer if (config.token_dir.len == 0) allocator.free(token_dir);

    // Load tokens
    var store = tokens_mod.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return FileCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    const token = store.findForPath("files", "list", config.path.?) orelse {
        std.debug.print(
            "Error: No token grants list access to {s}\n",
            .{config.path.?},
        );
        return FileCmdError.TokenNotFound;
    };

    // Connect to NATS
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-cli" },
    ) catch {
        std.debug.print("Error: Failed to connect to NATS\n", .{});
        return FileCmdError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    // Build request
    const request = buildRequest(allocator, io, token.raw, "list", .{
        .path = config.path.?,
        .depth = depth,
    }) catch return FileCmdError.OutOfMemory;
    defer allocator.free(request);

    // Send request
    const reply = client.request(
        allocator,
        "clawgate.req.files.list",
        request,
        5000,
    ) catch {
        std.debug.print("Error: Request failed\n", .{});
        return FileCmdError.RequestFailed;
    };

    if (reply) |r| {
        defer r.deinit(allocator);

        // Parse response
        const parsed = std.json.parseFromSlice(
            struct {
                ok: bool,
                result: ?struct {
                    entries: []const struct {
                        name: []const u8,
                        type: []const u8,
                        size: ?usize = null,
                    },
                } = null,
                @"error": ?struct {
                    code: []const u8,
                    message: []const u8,
                } = null,
            },
            allocator,
            r.data,
            .{ .ignore_unknown_fields = true },
        ) catch {
            std.debug.print("Error: Invalid response\n", .{});
            return FileCmdError.ResponseError;
        };
        defer parsed.deinit();

        if (!parsed.value.ok) {
            if (parsed.value.@"error") |err| {
                std.debug.print(
                    "Error: {s}: {s}\n",
                    .{ err.code, err.message },
                );
            }
            return FileCmdError.ResponseError;
        }

        if (parsed.value.result) |result| {
            for (result.entries) |entry| {
                if (long_format) {
                    const type_char: u8 = if (std.mem.eql(
                        u8,
                        entry.type,
                        "dir",
                    )) 'd' else '-';
                    if (entry.size) |sz| {
                        std.debug.print(
                            "{c} {:>10} {s}\n",
                            .{ type_char, sz, entry.name },
                        );
                    } else {
                        std.debug.print(
                            "{c} {:>10} {s}\n",
                            .{ type_char, @as(usize, 0), entry.name },
                        );
                    }
                } else {
                    std.debug.print("{s}\n", .{entry.name});
                }
            }
        }
    } else {
        std.debug.print("Error: Request timed out\n", .{});
        return FileCmdError.RequestTimeout;
    }
}

/// Writes content to a file (write command).
pub fn write(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) FileCmdError!void {
    var config = FileConfig{};
    var content: ?[]const u8 = null;
    var mode: []const u8 = "overwrite";

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--nats") or std.mem.eql(u8, arg, "-n")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.nats_url = args[i];
        } else if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--content") or
            std.mem.eql(u8, arg, "-c"))
        {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            content = args[i];
        } else if (std.mem.eql(u8, arg, "--append") or
            std.mem.eql(u8, arg, "-a"))
        {
            mode = "append";
        } else if (std.mem.eql(u8, arg, "--create")) {
            mode = "create";
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printWriteUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            config.path = arg;
        }
    }

    if (config.path == null) {
        std.debug.print("Error: Path required\n\n", .{});
        printWriteUsage();
        return FileCmdError.MissingPath;
    }

    // Read content from stdin if not provided
    var stdin_content: ?[]u8 = null;
    defer if (stdin_content) |c| allocator.free(c);

    if (content == null) {
        var list: std.ArrayListUnmanaged(u8) = .empty;
        defer list.deinit(allocator);

        var buf: [4096]u8 = undefined;
        const stdin = std.posix.STDIN_FILENO;
        while (true) {
            const n = std.posix.read(stdin, &buf) catch break;
            if (n == 0) break;
            list.appendSlice(allocator, buf[0..n]) catch {
                return FileCmdError.OutOfMemory;
            };
        }
        stdin_content = list.toOwnedSlice(allocator) catch {
            return FileCmdError.OutOfMemory;
        };
        content = stdin_content;
    }

    // Get token directory
    const token_dir = if (config.token_dir.len > 0)
        config.token_dir
    else blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return FileCmdError.TokenNotFound;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return FileCmdError.OutOfMemory;
    };
    defer if (config.token_dir.len == 0) allocator.free(token_dir);

    // Load tokens
    var store = tokens_mod.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return FileCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    const token = store.findForPath("files", "write", config.path.?) orelse {
        std.debug.print(
            "Error: No token grants write access to {s}\n",
            .{config.path.?},
        );
        return FileCmdError.TokenNotFound;
    };

    // Connect to NATS
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-cli" },
    ) catch {
        std.debug.print("Error: Failed to connect to NATS\n", .{});
        return FileCmdError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    // Build request
    const request = buildRequest(allocator, io, token.raw, "write", .{
        .path = config.path.?,
        .content = content,
        .mode = mode,
    }) catch return FileCmdError.OutOfMemory;
    defer allocator.free(request);

    // Send request
    const reply = client.request(
        allocator,
        "clawgate.req.files.write",
        request,
        5000,
    ) catch {
        std.debug.print("Error: Request failed\n", .{});
        return FileCmdError.RequestFailed;
    };

    if (reply) |r| {
        defer r.deinit(allocator);

        // Parse response
        const parsed = std.json.parseFromSlice(
            struct {
                ok: bool,
                result: ?struct { bytes_written: usize } = null,
                @"error": ?struct {
                    code: []const u8,
                    message: []const u8,
                } = null,
            },
            allocator,
            r.data,
            .{ .ignore_unknown_fields = true },
        ) catch {
            std.debug.print("Error: Invalid response\n", .{});
            return FileCmdError.ResponseError;
        };
        defer parsed.deinit();

        if (!parsed.value.ok) {
            if (parsed.value.@"error") |err| {
                std.debug.print(
                    "Error: {s}: {s}\n",
                    .{ err.code, err.message },
                );
            }
            return FileCmdError.ResponseError;
        }

        if (parsed.value.result) |result| {
            std.debug.print(
                "Wrote {d} bytes to {s}\n",
                .{ result.bytes_written, config.path.? },
            );
        }
    } else {
        std.debug.print("Error: Request timed out\n", .{});
        return FileCmdError.RequestTimeout;
    }
}

/// Gets file or directory metadata (stat command).
pub fn stat(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) FileCmdError!void {
    var config = FileConfig{};
    var show_json = false;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--nats") or std.mem.eql(u8, arg, "-n")) {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.nats_url = args[i];
        } else if (std.mem.eql(u8, arg, "--token-dir") or
            std.mem.eql(u8, arg, "-d"))
        {
            if (i + 1 >= args.len) return FileCmdError.InvalidArgs;
            i += 1;
            config.token_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--json")) {
            show_json = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printStatUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            config.path = arg;
        }
    }

    if (config.path == null) {
        std.debug.print("Error: Path required\n\n", .{});
        printStatUsage();
        return FileCmdError.MissingPath;
    }

    // Get token directory
    const token_dir = if (config.token_dir.len > 0)
        config.token_dir
    else blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return FileCmdError.TokenNotFound;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tokens",
            .{home_dir},
        ) catch return FileCmdError.OutOfMemory;
    };
    defer if (config.token_dir.len == 0) allocator.free(token_dir);

    // Load tokens
    var store = tokens_mod.TokenStore.loadFromDir(
        allocator,
        io,
        token_dir,
    ) catch {
        std.debug.print("Error: No tokens found\n", .{});
        return FileCmdError.TokenNotFound;
    };
    defer store.deinit(allocator);

    const token = store.findForPath("files", "stat", config.path.?) orelse {
        std.debug.print(
            "Error: No token grants stat access to {s}\n",
            .{config.path.?},
        );
        return FileCmdError.TokenNotFound;
    };

    // Connect to NATS
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-cli" },
    ) catch {
        std.debug.print("Error: Failed to connect to NATS\n", .{});
        return FileCmdError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    // Build request
    const request = buildRequest(
        allocator,
        io,
        token.raw,
        "stat",
        .{ .path = config.path.? },
    ) catch return FileCmdError.OutOfMemory;
    defer allocator.free(request);

    // Send request
    const reply = client.request(
        allocator,
        "clawgate.req.files.stat",
        request,
        5000,
    ) catch {
        std.debug.print("Error: Request failed\n", .{});
        return FileCmdError.RequestFailed;
    };

    if (reply) |r| {
        defer r.deinit(allocator);

        // Parse response
        const parsed = std.json.parseFromSlice(
            struct {
                ok: bool,
                result: ?struct {
                    exists: bool,
                    type: []const u8,
                    size: usize,
                    modified: []const u8,
                } = null,
                @"error": ?struct {
                    code: []const u8,
                    message: []const u8,
                } = null,
            },
            allocator,
            r.data,
            .{ .ignore_unknown_fields = true },
        ) catch {
            std.debug.print("Error: Invalid response\n", .{});
            return FileCmdError.ResponseError;
        };
        defer parsed.deinit();

        if (!parsed.value.ok) {
            if (parsed.value.@"error") |err| {
                std.debug.print(
                    "Error: {s}: {s}\n",
                    .{ err.code, err.message },
                );
            }
            return FileCmdError.ResponseError;
        }

        if (parsed.value.result) |result| {
            if (show_json) {
                std.debug.print("{s}\n", .{r.data});
            } else {
                std.debug.print("  Path:     {s}\n", .{config.path.?});
                std.debug.print("  Exists:   {}\n", .{result.exists});
                std.debug.print("  Type:     {s}\n", .{result.type});
                std.debug.print("  Size:     {d}\n", .{result.size});
                std.debug.print("  Modified: {s}\n", .{result.modified});
            }
        }
    } else {
        std.debug.print("Error: Request timed out\n", .{});
        return FileCmdError.RequestTimeout;
    }
}

/// Builds a JSON request.
fn buildRequest(
    allocator: Allocator,
    io: Io,
    jwt: []const u8,
    op: []const u8,
    params: anytype,
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
    try writer.print("\",\"op\":\"{s}\",\"params\":{{\"path\":\"", .{op});
    try writeJsonEscaped(writer, params.path);
    try writer.writeAll("\"");

    if (@hasField(@TypeOf(params), "offset")) {
        if (params.offset) |off| {
            try writer.print(",\"offset\":{d}", .{off});
        }
    }
    if (@hasField(@TypeOf(params), "length")) {
        if (params.length) |len| {
            try writer.print(",\"length\":{d}", .{len});
        }
    }
    if (@hasField(@TypeOf(params), "depth")) {
        if (@as(?u8, params.depth)) |d| {
            try writer.print(",\"depth\":{d}", .{d});
        }
    }
    if (@hasField(@TypeOf(params), "content")) {
        if (params.content) |c| {
            try writer.writeAll(",\"content\":\"");
            try writeJsonEscaped(writer, c);
            try writer.writeAll("\"");
        }
    }
    if (@hasField(@TypeOf(params), "mode")) {
        if (@as(?[]const u8, params.mode)) |m| {
            try writer.print(",\"mode\":\"{s}\"", .{m});
        }
    }

    try writer.writeAll("}}");

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

fn printCatUsage() void {
    const usage =
        \\Usage: clawgate cat [options] <path>
        \\
        \\Read and output file content.
        \\
        \\Options:
        \\  -n, --nats <url>      NATS server URL
        \\  -d, --token-dir <dir> Token directory
        \\      --offset <n>      Start reading at byte offset
        \\      --length <n>      Maximum bytes to read
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printLsUsage() void {
    const usage =
        \\Usage: clawgate ls [options] <path>
        \\
        \\List directory contents.
        \\
        \\Options:
        \\  -n, --nats <url>      NATS server URL
        \\  -d, --token-dir <dir> Token directory
        \\      --depth <n>       Listing depth (default: 1)
        \\  -l                    Long format with sizes
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printWriteUsage() void {
    const usage =
        \\Usage: clawgate write [options] <path>
        \\
        \\Write content to a file. Content from stdin if not specified.
        \\
        \\Options:
        \\  -n, --nats <url>      NATS server URL
        \\  -d, --token-dir <dir> Token directory
        \\  -c, --content <text>  Content to write
        \\  -a, --append          Append to file
        \\      --create          Fail if file exists
        \\  -h, --help            Show this help
        \\
        \\Examples:
        \\  echo "hello" | clawgate write /tmp/file.txt
        \\  clawgate write --content "hello" /tmp/file.txt
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printStatUsage() void {
    const usage =
        \\Usage: clawgate stat [options] <path>
        \\
        \\Get file or directory metadata.
        \\
        \\Options:
        \\  -n, --nats <url>      NATS server URL
        \\  -d, --token-dir <dir> Token directory
        \\      --json            Output as JSON
        \\  -h, --help            Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "buildRequest creates valid JSON" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const req = try buildRequest(
        allocator,
        io,
        "test_token",
        "read",
        .{ .path = "/tmp/test.txt" },
    );
    defer allocator.free(req);

    // Verify it parses as valid JSON
    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            token: []const u8,
            op: []const u8,
            params: struct { path: []const u8 },
        },
        allocator,
        req,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("test_token", parsed.value.token);
    try std.testing.expectEqualStrings("read", parsed.value.op);
    try std.testing.expectEqualStrings(
        "/tmp/test.txt",
        parsed.value.params.path,
    );
}

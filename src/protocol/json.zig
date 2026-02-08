//! JSON protocol types for ClawGate E2E messages.
//!
//! Defines request and response structures for file operations
//! between agent and resource daemons.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ProtocolError = error{
    InvalidJson,
    InvalidOperation,
    MissingField,
    InvalidBase64,
    OutOfMemory,
};

/// Request parameters for file operations.
pub const Params = struct {
    /// File or directory path (required for file/git ops)
    path: []const u8 = "",
    /// Read offset in bytes
    offset: ?usize = null,
    /// Maximum bytes to read
    length: ?usize = null,
    /// Content to write
    content: ?[]const u8 = null,
    /// Write mode: "create", "overwrite", "append"
    mode: ?[]const u8 = null,
    /// Directory listing depth
    depth: ?u8 = null,
    /// Git command arguments (for op="git")
    args: ?[]const []const u8 = null,
    /// Tool name (for op="tool")
    tool_name: ?[]const u8 = null,
    /// Tool arguments (for op="tool")
    tool_args: ?[]const []const u8 = null,
    /// Stdin data for tool (for op="tool")
    input: ?[]const u8 = null,
};

/// A file operation request.
pub const Request = struct {
    /// Unique request identifier
    id: []const u8,
    /// JWT capability token
    token: []const u8,
    /// Operation: "read", "write", "list", "stat"
    op: []const u8,
    /// Operation-specific parameters
    params: Params,
};

/// Result of a read operation.
pub const ReadResult = struct {
    /// File content (may be base64 for binary)
    content: []const u8,
    /// Total file size in bytes
    size: usize,
    /// True if content was truncated
    truncated: bool,
};

/// Result of a write operation.
pub const WriteResult = struct {
    /// Number of bytes written
    bytes_written: usize,
};

/// A single directory entry.
pub const Entry = struct {
    /// File or directory name
    name: []const u8,
    /// Type: "file" or "dir"
    type: []const u8,
    /// Size in bytes (null for directories)
    size: ?usize = null,
};

/// Result of a list operation.
pub const ListResult = struct {
    /// Directory entries
    entries: []const Entry,
};

/// Result of a stat operation.
pub const StatResult = struct {
    /// Whether file exists
    exists: bool,
    /// Type: "file" or "dir"
    type: []const u8,
    /// Size in bytes
    size: usize,
    /// Last modified timestamp (ISO 8601)
    modified: []const u8,
};

/// Result of a git operation.
pub const GitResult = struct {
    /// Git stdout output
    stdout: []const u8,
    /// Git stderr output
    stderr: []const u8,
    /// Git process exit code
    exit_code: u8,
    /// True if output was truncated
    truncated: bool,
};

/// Result of a tool execution.
pub const ToolResult = struct {
    /// Tool name
    tool_name: []const u8,
    /// Tool stdout output
    stdout: []const u8,
    /// Tool stderr output
    stderr: []const u8,
    /// Tool process exit code
    exit_code: u8,
    /// True if output was truncated
    truncated: bool,
};

/// A single entry in a tool list response.
pub const ToolListEntry = struct {
    /// Tool name
    name: []const u8,
    /// Human-readable description
    description: []const u8,
    /// Argument validation mode
    arg_mode: []const u8,
    /// Allowed arguments (allowlist mode)
    allow_args: []const []const u8,
    /// Usage examples
    examples: []const []const u8,
};

/// Result of a tool_list operation.
pub const ToolListResult = struct {
    /// Tools the token is authorized to invoke
    tools: []const ToolListEntry,
};

/// Union of all possible result types.
pub const Result = union(enum) {
    read: ReadResult,
    write: WriteResult,
    list: ListResult,
    stat: StatResult,
    git: GitResult,
    tool: ToolResult,
    tool_list: ToolListResult,
};

/// Error details in a response.
pub const Error = struct {
    /// Error code (e.g., "INVALID_TOKEN", "SCOPE_VIOLATION")
    code: []const u8,
    /// Human-readable error message
    message: []const u8,
};

/// A file operation response.
pub const Response = struct {
    /// Matching request identifier
    id: []const u8,
    /// True if operation succeeded
    ok: bool,
    /// Operation result (when ok=true)
    result: ?Result = null,
    /// Error details (when ok=false)
    err: ?Error = null,
};

/// Parsed request with cleanup handle.
pub const ParsedRequest = struct {
    value: Request,
    parsed: std.json.Parsed(Request),

    pub fn deinit(self: *ParsedRequest) void {
        self.parsed.deinit();
    }
};

/// Valid operations.
const valid_operations = [_][]const u8{
    "read",  "write", "list", "stat",
    "git",   "tool",  "tool_list",
};

/// Parses JSON bytes into a Request.
pub fn parseRequest(
    allocator: Allocator,
    json: []const u8,
) ProtocolError!ParsedRequest {
    const parsed = std.json.parseFromSlice(
        Request,
        allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return ProtocolError.InvalidJson;
    };

    // Validate operation is allowed
    var valid = false;
    for (valid_operations) |op| {
        if (std.mem.eql(u8, parsed.value.op, op)) {
            valid = true;
            break;
        }
    }
    if (!valid) {
        parsed.deinit();
        return ProtocolError.InvalidOperation;
    }

    return ParsedRequest{
        .value = parsed.value,
        .parsed = parsed,
    };
}

/// Formats a Response to JSON bytes. Caller owns returned memory.
pub fn formatResponse(allocator: Allocator, response: Response) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();

    const writer = &output.writer;

    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(response.id);
    try writer.writeAll("\",\"ok\":");
    try writer.writeAll(if (response.ok) "true" else "false");

    if (response.result) |result| {
        try writer.writeAll(",\"result\":");
        switch (result) {
            .read => |r| {
                try writer.writeAll("{\"content\":\"");
                try writeBase64Encoded(writer, r.content);
                try writer.print(
                    "\",\"size\":{d},\"truncated\":{s}}}",
                    .{ r.size, if (r.truncated) "true" else "false" },
                );
            },
            .write => |w| {
                try writer.print(
                    "{{\"bytes_written\":{d}}}",
                    .{w.bytes_written},
                );
            },
            .list => |l| {
                try writer.writeAll("{\"entries\":[");
                for (l.entries, 0..) |entry, i| {
                    if (i > 0) try writer.writeAll(",");
                    try writer.writeAll("{\"name\":\"");
                    try writeJsonEscaped(writer, entry.name);
                    try writer.print("\",\"type\":\"{s}\"", .{entry.type});
                    if (entry.size) |sz| {
                        try writer.print(",\"size\":{d}", .{sz});
                    }
                    try writer.writeAll("}");
                }
                try writer.writeAll("]}");
            },
            .stat => |s| {
                try writer.print(
                    "{{\"exists\":{s},\"type\":\"{s}\",\"size\":{d}," ++
                        "\"modified\":\"{s}\"}}",
                    .{
                        if (s.exists) "true" else "false",
                        s.type,
                        s.size,
                        s.modified,
                    },
                );
            },
            .git => |g| {
                try writer.writeAll("{\"stdout\":\"");
                try writeJsonEscaped(writer, g.stdout);
                try writer.writeAll("\",\"stderr\":\"");
                try writeJsonEscaped(writer, g.stderr);
                try writer.print(
                    "\",\"exit_code\":{d},\"truncated\":{s}}}",
                    .{
                        g.exit_code,
                        if (g.truncated) "true" else "false",
                    },
                );
            },
            .tool => |t| {
                try writer.writeAll("{\"tool_name\":\"");
                try writeJsonEscaped(writer, t.tool_name);
                try writer.writeAll("\",\"stdout\":\"");
                try writeJsonEscaped(writer, t.stdout);
                try writer.writeAll("\",\"stderr\":\"");
                try writeJsonEscaped(writer, t.stderr);
                try writer.print(
                    "\",\"exit_code\":{d},\"truncated\":{s}}}",
                    .{
                        t.exit_code,
                        if (t.truncated) "true" else "false",
                    },
                );
            },
            .tool_list => |tl| {
                try writer.writeAll("{\"tools\":[");
                for (tl.tools, 0..) |tool, i| {
                    if (i > 0) try writer.writeAll(",");
                    try writer.writeAll("{\"name\":\"");
                    try writeJsonEscaped(writer, tool.name);
                    try writer.writeAll("\",\"description\":\"");
                    try writeJsonEscaped(
                        writer,
                        tool.description,
                    );
                    try writer.writeAll("\",\"arg_mode\":\"");
                    try writer.writeAll(tool.arg_mode);
                    try writer.writeAll("\",\"allow_args\":[");
                    for (tool.allow_args, 0..) |arg, j| {
                        if (j > 0) try writer.writeAll(",");
                        try writer.writeAll("\"");
                        try writeJsonEscaped(writer, arg);
                        try writer.writeAll("\"");
                    }
                    try writer.writeAll("],\"examples\":[");
                    for (tool.examples, 0..) |ex, j| {
                        if (j > 0) try writer.writeAll(",");
                        try writer.writeAll("\"");
                        try writeJsonEscaped(writer, ex);
                        try writer.writeAll("\"");
                    }
                    try writer.writeAll("]}");
                }
                try writer.writeAll("]}");
            },
        }
    }

    if (response.err) |e| {
        try writer.writeAll(",\"error\":{\"code\":\"");
        try writer.writeAll(e.code);
        try writer.writeAll("\",\"message\":\"");
        try writeJsonEscaped(writer, e.message);
        try writer.writeAll("\"}");
    }

    try writer.writeAll("}");

    const result = output.written();
    const owned = try allocator.dupe(u8, result);
    output.deinit();
    return owned;
}

/// Creates an error response JSON. Caller owns returned memory.
pub fn formatError(
    allocator: Allocator,
    id: []const u8,
    code: []const u8,
    message: []const u8,
) ![]const u8 {
    return formatResponse(allocator, .{
        .id = id,
        .ok = false,
        .err = .{ .code = code, .message = message },
    });
}

/// Creates a success response JSON. Caller owns returned memory.
pub fn formatSuccess(
    allocator: Allocator,
    id: []const u8,
    result: Result,
) ![]const u8 {
    return formatResponse(allocator, .{
        .id = id,
        .ok = true,
        .result = result,
    });
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

/// Encodes binary content to base64 and writes to the writer.
pub fn writeBase64Encoded(writer: anytype, content: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    try encoder.encodeWriter(writer, content);
}

/// Decodes base64 content to binary. Caller owns returned memory.
pub fn decodeBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch {
        return ProtocolError.InvalidBase64;
    };
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    decoder.decode(buf, encoded) catch {
        allocator.free(buf);
        return ProtocolError.InvalidBase64;
    };
    return buf;
}

// Tests

test "parse read request" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"r1","token":"t","op":"read",
    ++
        \\  "params":{"path":"/t","offset":0,"length":1024}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("r1", parsed.value.id);
    try std.testing.expectEqualStrings("t", parsed.value.token);
    try std.testing.expectEqualStrings("read", parsed.value.op);
    try std.testing.expectEqualStrings("/t", parsed.value.params.path);
    try std.testing.expectEqual(@as(?usize, 0), parsed.value.params.offset);
    try std.testing.expectEqual(@as(?usize, 1024), parsed.value.params.length);
}

test "parse write request" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"r2","token":"t","op":"write",
    ++
        \\"params":{"path":"/o","content":"Hi","mode":"create"}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("r2", parsed.value.id);
    try std.testing.expectEqualStrings("write", parsed.value.op);
    try std.testing.expectEqualStrings("/o", parsed.value.params.path);
    try std.testing.expectEqualStrings("Hi", parsed.value.params.content.?);
    try std.testing.expectEqualStrings("create", parsed.value.params.mode.?);
}

test "parse minimal request" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"req_3","token":"tok","op":"stat","params":{"path":"/tmp"}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("req_3", parsed.value.id);
    try std.testing.expectEqualStrings("stat", parsed.value.op);
    try std.testing.expect(parsed.value.params.offset == null);
    try std.testing.expect(parsed.value.params.content == null);
}

test "parse invalid json" {
    const allocator = std.testing.allocator;

    const result = parseRequest(allocator, "not valid json");
    try std.testing.expectError(ProtocolError.InvalidJson, result);
}

test "format read response" {
    const allocator = std.testing.allocator;

    const response = Response{
        .id = "req_1",
        .ok = true,
        .result = .{
            .read = .{
                .content = "file content",
                .size = 12,
                .truncated = false,
            },
        },
    };

    const json = try formatResponse(allocator, response);
    defer allocator.free(json);

    // Parse it back to verify structure
    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: struct {
                content: []const u8,
                size: usize,
                truncated: bool,
            },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("req_1", parsed.value.id);
    try std.testing.expect(parsed.value.ok);
    const result = parsed.value.result;

    // Content is base64 encoded, decode before comparing
    const decoded = try decodeBase64(allocator, result.content);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("file content", decoded);

    try std.testing.expectEqual(@as(usize, 12), result.size);
    try std.testing.expect(!result.truncated);
}

test "format write response" {
    const allocator = std.testing.allocator;

    const json = try formatSuccess(allocator, "req_2", .{
        .write = .{ .bytes_written = 256 },
    });
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: struct { bytes_written: usize },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("req_2", parsed.value.id);
    try std.testing.expect(parsed.value.ok);
    const written = parsed.value.result.bytes_written;
    try std.testing.expectEqual(@as(usize, 256), written);
}

test "format list response" {
    const allocator = std.testing.allocator;

    const input = [_]Entry{
        .{ .name = "file.txt", .type = "file", .size = 100 },
        .{ .name = "subdir", .type = "dir" },
    };

    const json = try formatSuccess(allocator, "req_3", .{
        .list = .{ .entries = &input },
    });
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: struct {
                entries: []const struct {
                    name: []const u8,
                    type: []const u8,
                    size: ?usize = null,
                },
            },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    const entries = parsed.value.result.entries;
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("file.txt", entries[0].name);
    try std.testing.expectEqual(@as(?usize, 100), entries[0].size);
    try std.testing.expectEqualStrings("subdir", entries[1].name);
    try std.testing.expect(entries[1].size == null);
}

test "format stat response" {
    const allocator = std.testing.allocator;

    const json = try formatSuccess(allocator, "req_4", .{
        .stat = .{
            .exists = true,
            .type = "file",
            .size = 4096,
            .modified = "2026-01-31T10:00:00Z",
        },
    });
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: struct {
                exists: bool,
                type: []const u8,
                size: usize,
                modified: []const u8,
            },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expect(parsed.value.result.exists);
    try std.testing.expectEqualStrings("file", parsed.value.result.type);
    try std.testing.expectEqual(@as(usize, 4096), parsed.value.result.size);
    try std.testing.expectEqualStrings(
        "2026-01-31T10:00:00Z",
        parsed.value.result.modified,
    );
}

test "format error response" {
    const allocator = std.testing.allocator;

    const json = try formatError(
        allocator,
        "req_5",
        "SCOPE_VIOLATION",
        "Path not in granted scope",
    );
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            @"error": struct {
                code: []const u8,
                message: []const u8,
            },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("req_5", parsed.value.id);
    try std.testing.expect(!parsed.value.ok);
    const err = parsed.value.@"error";
    try std.testing.expectEqualStrings("SCOPE_VIOLATION", err.code);
    const expected_msg = "Path not in granted scope";
    try std.testing.expectEqualStrings(expected_msg, err.message);
}

test "base64 encoding special characters in content" {
    const allocator = std.testing.allocator;

    const original = "line1\nline2\twith \"quotes\"";
    const json = try formatSuccess(allocator, "req_6", .{
        .read = .{
            .content = original,
            .size = 25,
            .truncated = false,
        },
    });
    defer allocator.free(json);

    // Verify it parses correctly with base64 encoded content
    const parsed = try std.json.parseFromSlice(
        struct {
            result: struct { content: []const u8 },
        },
        allocator,
        json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    // Content is base64 encoded, decode before comparing
    const decoded = try decodeBase64(allocator, parsed.value.result.content);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}

test "round-trip request" {
    const allocator = std.testing.allocator;

    const original_json =
        \\{"id":"rt","token":"tok","op":"read","params":{"path":"/test"}}
    ;

    var parsed = try parseRequest(allocator, original_json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("rt", parsed.value.id);
    try std.testing.expectEqualStrings("tok", parsed.value.token);
    try std.testing.expectEqualStrings("read", parsed.value.op);
    try std.testing.expectEqualStrings("/test", parsed.value.params.path);
}

test "base64 encode/decode round trip" {
    const allocator = std.testing.allocator;

    const text = "Hello, ClawGate!";
    var buf: [64]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&buf, text);

    const decoded = try decodeBase64(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(text, decoded);
}

test "base64 encode/decode binary content" {
    const allocator = std.testing.allocator;

    // Binary content including null bytes
    const binary = &[_]u8{ 0x00, 0x01, 0xFF, 0xFE, 0x00, 0x7F };
    var buf: [16]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&buf, binary);

    const decoded = try decodeBase64(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, binary, decoded);
}

test "base64 invalid input" {
    const allocator = std.testing.allocator;

    const result = decodeBase64(allocator, "!!!invalid!!!");
    try std.testing.expectError(ProtocolError.InvalidBase64, result);
}

// Protocol boundary and edge case tests

test "parse request - invalid operation rejected" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"r1","token":"t","op":"delete","params":{"path":"/tmp"}}
    ;

    const result = parseRequest(allocator, json);
    try std.testing.expectError(ProtocolError.InvalidOperation, result);
}

test "parse request - operation case sensitive" {
    const allocator = std.testing.allocator;

    // "Read" instead of "read" - should fail
    const json =
        \\{"id":"r1","token":"t","op":"Read","params":{"path":"/tmp"}}
    ;

    const result = parseRequest(allocator, json);
    try std.testing.expectError(ProtocolError.InvalidOperation, result);
}

test "parse request - missing required fields" {
    const allocator = std.testing.allocator;

    // Missing "op" field
    const json1 =
        \\{"id":"r1","token":"t","params":{"path":"/tmp"}}
    ;
    try std.testing.expectError(ProtocolError.InvalidJson, parseRequest(allocator, json1));

    // Missing "params" field
    const json2 =
        \\{"id":"r1","token":"t","op":"read"}
    ;
    try std.testing.expectError(ProtocolError.InvalidJson, parseRequest(allocator, json2));

    // Empty params now valid (path defaults to "")
    const json3 =
        \\{"id":"r1","token":"t","op":"read","params":{}}
    ;
    var parsed3 = try parseRequest(allocator, json3);
    defer parsed3.deinit();
    try std.testing.expectEqualStrings("", parsed3.value.params.path);
}

test "parse request - empty strings accepted" {
    const allocator = std.testing.allocator;

    // Empty id and token are technically valid (validation happens elsewhere)
    const json =
        \\{"id":"","token":"","op":"read","params":{"path":""}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("", parsed.value.id);
    try std.testing.expectEqualStrings("", parsed.value.token);
}

test "parse request - extra fields ignored" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"r1","token":"t","op":"read","params":{"path":"/tmp"},
    ++
        \\"extra":"ignored","nested":{"also":"ignored"}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("r1", parsed.value.id);
}

test "writeJsonEscaped - control characters" {
    const allocator = std.testing.allocator;

    // Test string with various control characters
    const test_str = "null:\x00 bell:\x07 formfeed:\x0c";

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try writeJsonEscaped(&output.writer, test_str);

    const result = output.written();
    // Control characters should be escaped as \uXXXX
    try std.testing.expect(std.mem.indexOf(u8, result, "\\u0000") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\\u0007") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\\u000c") != null);
}

test "writeJsonEscaped - quotes and backslash" {
    const allocator = std.testing.allocator;

    const test_str = "path with \"quotes\" and \\backslash";

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try writeJsonEscaped(&output.writer, test_str);

    const result = output.written();
    try std.testing.expect(std.mem.indexOf(u8, result, "\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\\\\") != null);
}

test "base64 decode - empty string" {
    const allocator = std.testing.allocator;

    const decoded = try decodeBase64(allocator, "");
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "base64 decode - padding variations" {
    const allocator = std.testing.allocator;

    // Standard base64 with padding
    const d1 = try decodeBase64(allocator, "YQ==");
    defer allocator.free(d1);
    try std.testing.expectEqualStrings("a", d1);

    const d2 = try decodeBase64(allocator, "YWI=");
    defer allocator.free(d2);
    try std.testing.expectEqualStrings("ab", d2);

    const d3 = try decodeBase64(allocator, "YWJj");
    defer allocator.free(d3);
    try std.testing.expectEqualStrings("abc", d3);
}

test "parse tool request" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"t1","token":"tok","op":"tool",
    ++
        \\"params":{"tool_name":"calc","input":"2+2"}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("tool", parsed.value.op);
    try std.testing.expectEqualStrings(
        "calc",
        parsed.value.params.tool_name.?,
    );
    try std.testing.expectEqualStrings(
        "2+2",
        parsed.value.params.input.?,
    );
}

test "format tool response" {
    const allocator = std.testing.allocator;

    const json = try formatSuccess(allocator, "req_t", .{
        .tool = .{
            .tool_name = "calc",
            .stdout = "4\n",
            .stderr = "",
            .exit_code = 0,
            .truncated = false,
        },
    });
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            id: []const u8,
            ok: bool,
            result: struct {
                tool_name: []const u8,
                stdout: []const u8,
                stderr: []const u8,
                exit_code: u8,
                truncated: bool,
            },
        },
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("req_t", parsed.value.id);
    try std.testing.expect(parsed.value.ok);
    const r = parsed.value.result;
    try std.testing.expectEqualStrings("calc", r.tool_name);
    try std.testing.expectEqualStrings("4\n", r.stdout);
    try std.testing.expectEqual(@as(u8, 0), r.exit_code);
    try std.testing.expect(!r.truncated);
}

test "parse tool_list request" {
    const allocator = std.testing.allocator;

    const json =
        \\{"id":"tl1","token":"tok","op":"tool_list",
    ++
        \\"params":{}}
    ;

    var parsed = try parseRequest(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "tool_list",
        parsed.value.op,
    );
}

test "format tool_list response" {
    const allocator = std.testing.allocator;

    const tools = [_]ToolListEntry{
        .{
            .name = "calc",
            .description = "Calculator (bc)",
            .arg_mode = "allowlist",
            .allow_args = &[_][]const u8{"-q"},
            .examples = &[_][]const u8{
                "echo \"2+2\" | clawgate tool calc",
            },
        },
        .{
            .name = "grep",
            .description = "Safe grep",
            .arg_mode = "passthrough",
            .allow_args = &[_][]const u8{},
            .examples = &[_][]const u8{},
        },
    };

    const json = try formatSuccess(allocator, "req_tl", .{
        .tool_list = .{ .tools = &tools },
    });
    defer allocator.free(json);

    const ParsedTools = struct {
        id: []const u8,
        ok: bool,
        result: struct {
            tools: []const struct {
                name: []const u8,
                description: []const u8,
                arg_mode: []const u8,
                allow_args: []const []const u8,
                examples: []const []const u8,
            },
        },
    };

    const parsed = try std.json.parseFromSlice(
        ParsedTools,
        allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "req_tl",
        parsed.value.id,
    );
    try std.testing.expect(parsed.value.ok);
    const t = parsed.value.result.tools;
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("calc", t[0].name);
    try std.testing.expectEqualStrings(
        "Calculator (bc)",
        t[0].description,
    );
    try std.testing.expectEqualStrings(
        "allowlist",
        t[0].arg_mode,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        t[0].allow_args.len,
    );
    try std.testing.expectEqualStrings("-q", t[0].allow_args[0]);
    try std.testing.expectEqual(
        @as(usize, 1),
        t[0].examples.len,
    );
    try std.testing.expectEqualStrings("grep", t[1].name);
    try std.testing.expectEqual(
        @as(usize, 0),
        t[1].allow_args.len,
    );
}

test "format tool_list empty response" {
    const allocator = std.testing.allocator;

    const json = try formatSuccess(allocator, "req_e", .{
        .tool_list = .{ .tools = &[_]ToolListEntry{} },
    });
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(
        struct {
            ok: bool,
            result: struct {
                tools: []const struct { name: []const u8 },
            },
        },
        allocator,
        json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqual(
        @as(usize, 0),
        parsed.value.result.tools.len,
    );
}

test "format response - filenames with special chars" {
    const allocator = std.testing.allocator;

    const entries = [_]Entry{
        .{ .name = "file\"with\"quotes.txt", .type = "file", .size = 10 },
        .{ .name = "file\\with\\backslash.txt", .type = "file", .size = 20 },
        .{ .name = "file\twith\ttab.txt", .type = "file", .size = 30 },
    };

    const json = try formatSuccess(allocator, "req", .{
        .list = .{ .entries = &entries },
    });
    defer allocator.free(json);

    // Verify JSON is valid (can be parsed)
    const parsed = std.json.parseFromSlice(
        struct {
            result: struct {
                entries: []const struct {
                    name: []const u8,
                    type: []const u8,
                    size: ?usize = null,
                },
            },
        },
        allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch |err| {
        std.debug.print("Failed to parse: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 3), parsed.value.result.entries.len);
}

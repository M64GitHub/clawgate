//! Request handlers for the resource daemon.
//!
//! Parses requests, validates tokens, checks permissions, executes
//! file operations, and formats responses.

const std = @import("std");
const protocol = @import("../protocol/json.zig");
const token_mod = @import("../capability/token.zig");
const crypto = @import("../capability/crypto.zig");
const scope = @import("../capability/scope.zig");
const files = @import("files.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const ErrorCode = struct {
    pub const INVALID_TOKEN = "INVALID_TOKEN";
    pub const TOKEN_EXPIRED = "TOKEN_EXPIRED";
    pub const SCOPE_VIOLATION = "SCOPE_VIOLATION";
    pub const INVALID_OP = "INVALID_OP";
    pub const INVALID_PATH = "INVALID_PATH";
    pub const FILE_NOT_FOUND = "FILE_NOT_FOUND";
    pub const ACCESS_DENIED = "ACCESS_DENIED";
    pub const FILE_TOO_LARGE = "FILE_TOO_LARGE";
    pub const NOT_A_FILE = "NOT_A_FILE";
    pub const NOT_A_DIRECTORY = "NOT_A_DIRECTORY";
    pub const IS_SYMLINK = "IS_SYMLINK";
    pub const INTERNAL_ERROR = "INTERNAL_ERROR";
};

pub const HandlerError = error{
    OutOfMemory,
    IoError,
};

/// Handles a file operation request.
/// Parses request JSON, validates token, checks permissions, executes op.
/// Returns JSON response (success or error). Caller owns returned memory.
pub fn handleRequest(
    allocator: Allocator,
    io: Io,
    request_json: []const u8,
    public_key: crypto.PublicKey,
) HandlerError![]const u8 {
    var parsed_req = protocol.parseRequest(
        allocator,
        request_json,
    ) catch |err| {
        return switch (err) {
            protocol.ProtocolError.InvalidJson => {
                return protocol.formatError(
                    allocator,
                    "unknown",
                    ErrorCode.INVALID_TOKEN,
                    "Invalid request JSON",
                ) catch return HandlerError.OutOfMemory;
            },
            protocol.ProtocolError.InvalidOperation => {
                return protocol.formatError(
                    allocator,
                    "unknown",
                    ErrorCode.INVALID_OP,
                    "Invalid operation",
                ) catch return HandlerError.OutOfMemory;
            },
            else => {
                return protocol.formatError(
                    allocator,
                    "unknown",
                    ErrorCode.INTERNAL_ERROR,
                    "Failed to parse request",
                ) catch return HandlerError.OutOfMemory;
            },
        };
    };
    defer parsed_req.deinit();

    const req = parsed_req.value;

    var tok = token_mod.Token.parse(allocator, req.token) catch {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_TOKEN,
            "Failed to parse token",
        ) catch return HandlerError.OutOfMemory;
    };
    defer tok.deinit(allocator);

    if (!tok.verify(public_key)) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_TOKEN,
            "Token signature invalid",
        ) catch return HandlerError.OutOfMemory;
    }

    if (tok.isExpired()) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.TOKEN_EXPIRED,
            "Token has expired",
        ) catch return HandlerError.OutOfMemory;
    }

    // Canonicalize path to prevent traversal attacks (e.g., /../)
    const canonical_path = scope.canonicalizePath(
        allocator,
        req.params.path,
    ) orelse {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_PATH,
            "Invalid path",
        ) catch return HandlerError.OutOfMemory;
    };
    defer allocator.free(canonical_path);

    // Check against forbidden paths (security-critical files)
    if (isForbiddenPath(canonical_path)) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.ACCESS_DENIED,
            "Access to this path is forbidden",
        ) catch return HandlerError.OutOfMemory;
    }

    if (!tok.allows("files", req.op, canonical_path)) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.SCOPE_VIOLATION,
            "Path not in granted scope",
        ) catch return HandlerError.OutOfMemory;
    }

    // Create request with canonicalized path for dispatch
    var canonical_req = req;
    canonical_req.params.path = canonical_path;

    return dispatchOperation(allocator, io, canonical_req) catch |err| {
        return mapFileError(allocator, req.id, err) catch {
            return HandlerError.OutOfMemory;
        };
    };
}

/// Routes request to appropriate operation handler.
fn dispatchOperation(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
) ![]const u8 {
    if (std.mem.eql(u8, req.op, "read")) {
        return executeRead(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "write")) {
        return executeWrite(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "list")) {
        return executeList(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "stat")) {
        return executeStat(allocator, io, req);
    } else {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_OP,
            "Unknown operation",
        );
    }
}

/// Executes a file read operation.
fn executeRead(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
) ![]const u8 {
    const offset = req.params.offset orelse 0;
    const max_len = req.params.length;

    var result = try files.readFile(
        allocator,
        io,
        req.params.path,
        offset,
        max_len,
    );
    defer files.freeReadResult(allocator, &result);

    return protocol.formatSuccess(allocator, req.id, .{
        .read = result,
    });
}

/// Executes a file write operation.
fn executeWrite(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
) ![]const u8 {
    const content = req.params.content orelse "";
    const mode = files.WriteMode.fromString(req.params.mode);

    const bytes_written = try files.writeFile(
        io,
        req.params.path,
        content,
        mode,
    );

    return protocol.formatSuccess(allocator, req.id, .{
        .write = .{ .bytes_written = bytes_written },
    });
}

/// Executes a directory list operation.
fn executeList(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
) ![]const u8 {
    const depth = req.params.depth orelse 1;

    const entries = try files.listDir(allocator, io, req.params.path, depth);
    defer files.freeListResult(allocator, entries);

    return protocol.formatSuccess(allocator, req.id, .{
        .list = .{ .entries = entries },
    });
}

/// Executes a file stat operation.
fn executeStat(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
) ![]const u8 {
    var result = try files.statFile(allocator, io, req.params.path);
    defer files.freeStatResult(allocator, &result);

    return protocol.formatSuccess(allocator, req.id, .{
        .stat = result,
    });
}

/// Forbidden path patterns that must never be accessed regardless of token.
const FORBIDDEN_PATTERNS = [_][]const u8{
    "/.ssh/",
    "/.gnupg/",
    "/.clawgate/keys/",
    "/.aws/",
    "/.config/gcloud/",
    "/.kube/",
};

/// Checks if a path matches any forbidden pattern.
fn isForbiddenPath(path: []const u8) bool {
    for (FORBIDDEN_PATTERNS) |pattern| {
        if (std.mem.indexOf(u8, path, pattern) != null) {
            return true;
        }
    }
    return false;
}

/// Maps file operation errors to protocol error responses.
fn mapFileError(
    allocator: Allocator,
    req_id: []const u8,
    err: anyerror,
) ![]const u8 {
    const code_msg = switch (err) {
        files.FileError.FileNotFound => .{
            ErrorCode.FILE_NOT_FOUND,
            "File not found",
        },
        files.FileError.AccessDenied => .{
            ErrorCode.ACCESS_DENIED,
            "Access denied",
        },
        files.FileError.FileTooLarge => .{
            ErrorCode.FILE_TOO_LARGE,
            "File exceeds size limit",
        },
        files.FileError.NotAFile => .{
            ErrorCode.NOT_A_FILE,
            "Not a file",
        },
        files.FileError.NotADirectory => .{
            ErrorCode.NOT_A_DIRECTORY,
            "Not a directory",
        },
        files.FileError.IsSymlink => .{
            ErrorCode.IS_SYMLINK,
            "Symlinks are not allowed",
        },
        files.FileError.OutOfMemory => .{
            ErrorCode.INTERNAL_ERROR,
            "Out of memory",
        },
        else => .{
            ErrorCode.INTERNAL_ERROR,
            "Internal error",
        },
    };

    return protocol.formatError(allocator, req_id, code_msg[0], code_msg[1]);
}

// Tests

test "handle valid read request" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_handler_test.txt";
    const test_content = "test content";

    {
        const file = try std.Io.Dir.createFile(.cwd(), io, test_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, test_content);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const kp = crypto.generateKeypair(io);

    const tok = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "test-issuer",
        "test-subject",
        &[_]token_mod.Capability{.{
            .r = "files",
            .o = &[_][]const u8{"read"},
            .s = "/tmp/**",
        }},
        3600,
    );
    defer allocator.free(tok);

    var req_json_buf: [2048]u8 = undefined;
    const req_json = std.fmt.bufPrint(
        &req_json_buf,
        "{{\"id\":\"req1\",\"token\":\"{s}\",\"op\":\"read\"," ++
            "\"params\":{{\"path\":\"{s}\"}}}}",
        .{ tok, test_path },
    ) catch unreachable;

    const response = try handleRequest(allocator, io, req_json, kp.public_key);
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":true");
    const has_content = std.mem.indexOf(u8, response, test_content);
    try std.testing.expect(has_ok != null);
    try std.testing.expect(has_content != null);
}

test "handle invalid token signature" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const kp1 = crypto.generateKeypair(io);
    const kp2 = crypto.generateKeypair(io);

    const tok = try token_mod.createToken(
        allocator,
        io,
        kp1.secret_key,
        "issuer",
        "subject",
        &[_]token_mod.Capability{.{
            .r = "files",
            .o = &[_][]const u8{"read"},
            .s = "/tmp/**",
        }},
        3600,
    );
    defer allocator.free(tok);

    var req_json_buf: [2048]u8 = undefined;
    const req_json = std.fmt.bufPrint(
        &req_json_buf,
        "{{\"id\":\"req1\",\"token\":\"{s}\",\"op\":\"read\"," ++
            "\"params\":{{\"path\":\"/tmp/test.txt\"}}}}",
        .{tok},
    ) catch unreachable;

    const response = try handleRequest(allocator, io, req_json, kp2.public_key);
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":false");
    const has_err = std.mem.indexOf(u8, response, "INVALID_TOKEN");
    try std.testing.expect(has_ok != null);
    try std.testing.expect(has_err != null);
}

test "handle scope violation" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const kp = crypto.generateKeypair(io);

    const tok = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "issuer",
        "subject",
        &[_]token_mod.Capability{.{
            .r = "files",
            .o = &[_][]const u8{"read"},
            .s = "/home/allowed/**",
        }},
        3600,
    );
    defer allocator.free(tok);

    var req_json_buf: [2048]u8 = undefined;
    const req_json = std.fmt.bufPrint(
        &req_json_buf,
        "{{\"id\":\"req1\",\"token\":\"{s}\",\"op\":\"read\"," ++
            "\"params\":{{\"path\":\"/etc/passwd\"}}}}",
        .{tok},
    ) catch unreachable;

    const response = try handleRequest(allocator, io, req_json, kp.public_key);
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":false");
    const has_err = std.mem.indexOf(u8, response, "SCOPE_VIOLATION");
    try std.testing.expect(has_ok != null);
    try std.testing.expect(has_err != null);
}

test "handle file not found" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const kp = crypto.generateKeypair(io);

    const tok = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "issuer",
        "subject",
        &[_]token_mod.Capability{.{
            .r = "files",
            .o = &[_][]const u8{"read"},
            .s = "/tmp/**",
        }},
        3600,
    );
    defer allocator.free(tok);

    var req_json_buf: [2048]u8 = undefined;
    const req_json = std.fmt.bufPrint(
        &req_json_buf,
        "{{\"id\":\"req1\",\"token\":\"{s}\",\"op\":\"read\"," ++
            "\"params\":{{\"path\":\"/tmp/nonexistent_xyz_123.txt\"}}}}",
        .{tok},
    ) catch unreachable;

    const response = try handleRequest(allocator, io, req_json, kp.public_key);
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":false");
    const has_err = std.mem.indexOf(u8, response, "FILE_NOT_FOUND");
    try std.testing.expect(has_ok != null);
    try std.testing.expect(has_err != null);
}

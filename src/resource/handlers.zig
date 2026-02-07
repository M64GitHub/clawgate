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
const git_mod = @import("git.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const ErrorCode = struct {
    pub const INVALID_TOKEN = "INVALID_TOKEN";
    pub const TOKEN_EXPIRED = "TOKEN_EXPIRED";
    pub const SCOPE_VIOLATION = "SCOPE_VIOLATION";
    pub const INVALID_OP = "INVALID_OP";
    pub const INVALID_PATH = "INVALID_PATH";
    pub const INVALID_REQUEST = "INVALID_REQUEST";
    pub const FILE_NOT_FOUND = "FILE_NOT_FOUND";
    pub const ACCESS_DENIED = "ACCESS_DENIED";
    pub const FILE_TOO_LARGE = "FILE_TOO_LARGE";
    pub const NOT_A_FILE = "NOT_A_FILE";
    pub const NOT_A_DIRECTORY = "NOT_A_DIRECTORY";
    pub const IS_SYMLINK = "IS_SYMLINK";
    pub const INTERNAL_ERROR = "INTERNAL_ERROR";
    pub const GIT_ERROR = "GIT_ERROR";
    pub const GIT_BLOCKED = "GIT_BLOCKED";
    pub const GIT_NOT_REPO = "GIT_NOT_REPO";
    pub const GIT_TIMEOUT = "GIT_TIMEOUT";
};

pub const HandlerError = error{
    OutOfMemory,
    IoError,
};

/// Optional identity validation parameters.
pub const IdentityOptions = struct {
    expected_issuer: ?[]const u8 = null,
    expected_subject: ?[]const u8 = null,
};

/// Handles a file operation request.
/// Parses request JSON, validates token, checks permissions, executes op.
/// Returns JSON response (success or error). Caller owns returned memory.
pub fn handleRequest(
    allocator: Allocator,
    io: Io,
    request_json: []const u8,
    public_key: crypto.PublicKey,
    identity: IdentityOptions,
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

    // Validate issuer identity if configured
    if (identity.expected_issuer) |expected| {
        if (!std.mem.eql(u8, tok.getIssuer(), expected)) {
            return protocol.formatError(
                allocator,
                req.id,
                ErrorCode.INVALID_TOKEN,
                "Token issuer mismatch",
            ) catch return HandlerError.OutOfMemory;
        }
    }

    // Validate subject identity if configured
    if (identity.expected_subject) |expected| {
        if (!std.mem.eql(u8, tok.getSubject(), expected)) {
            return protocol.formatError(
                allocator,
                req.id,
                ErrorCode.INVALID_TOKEN,
                "Token subject mismatch",
            ) catch return HandlerError.OutOfMemory;
        }
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

    return dispatchOperation(
        allocator,
        io,
        canonical_req,
        &tok,
    ) catch |err| {
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
    tok: *const token_mod.Token,
) ![]const u8 {
    if (std.mem.eql(u8, req.op, "read")) {
        return executeRead(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "write")) {
        return executeWrite(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "list")) {
        return executeList(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "stat")) {
        return executeStat(allocator, io, req);
    } else if (std.mem.eql(u8, req.op, "git")) {
        return executeGitOp(allocator, io, req, tok);
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
    const encoded_content = req.params.content orelse "";
    const mode = files.WriteMode.fromString(req.params.mode);

    // Decode base64 content
    const content = if (encoded_content.len > 0)
        protocol.decodeBase64(allocator, encoded_content) catch {
            return protocol.formatError(
                allocator,
                req.id,
                ErrorCode.INVALID_REQUEST,
                "Invalid base64 content",
            );
        }
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(content);

    if (content.len > files.MAX_FILE_SIZE) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.FILE_TOO_LARGE,
            "Content exceeds maximum file size",
        );
    }

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
    const entries = try files.listDir(allocator, io, req.params.path);
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

/// Executes a git operation with tier-based permission checks.
fn executeGitOp(
    allocator: Allocator,
    io: Io,
    req: protocol.Request,
    tok: *const token_mod.Token,
) ![]const u8 {
    const args = req.params.args orelse {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_REQUEST,
            "Missing git args",
        );
    };

    if (args.len == 0) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.INVALID_REQUEST,
            "Empty git args",
        );
    }

    // Classify subcommand to determine required tier
    const tier = git_mod.classifySubcommand(args);
    if (tier == .blocked) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.GIT_BLOCKED,
            "Git command not allowed",
        );
    }

    // Check token has the required permission tier
    const required_op = git_mod.requiredOp(tier);
    if (!tok.allows("files", required_op, req.params.path)) {
        return protocol.formatError(
            allocator,
            req.id,
            ErrorCode.SCOPE_VIOLATION,
            "Insufficient git permissions",
        );
    }

    // Validate args against blocked flags
    git_mod.validateArgs(args) catch |err| {
        return switch (err) {
            git_mod.GitError.BlockedArg => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.GIT_BLOCKED,
                "Blocked git argument",
            ),
            git_mod.GitError.EmptyArgs => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.INVALID_REQUEST,
                "Empty git args",
            ),
            else => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.GIT_ERROR,
                "Git validation error",
            ),
        };
    };

    // Execute git command
    var result = git_mod.executeGit(
        allocator,
        io,
        req.params.path,
        args,
    ) catch |err| {
        return switch (err) {
            git_mod.GitError.SpawnFailed => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.GIT_ERROR,
                "Failed to execute git",
            ),
            git_mod.GitError.OutputTooLong => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.GIT_ERROR,
                "Git output too large",
            ),
            git_mod.GitError.OutOfMemory => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.INTERNAL_ERROR,
                "Out of memory",
            ),
            else => protocol.formatError(
                allocator,
                req.id,
                ErrorCode.GIT_ERROR,
                "Git execution error",
            ),
        };
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    return protocol.formatSuccess(allocator, req.id, .{
        .git = result,
    });
}

/// Forbidden directory components. If any path component exactly matches
/// one of these, access is denied for that component and all children.
const FORBIDDEN_DIRS = [_][]const u8{
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".password-store",
};

/// Forbidden multi-component directory sequences.
/// Matched as consecutive path component runs.
const ForbiddenSeq = struct { components: []const []const u8 };
const FORBIDDEN_SEQS = [_]ForbiddenSeq{
    .{ .components = &.{ ".clawgate", "keys" } },
    .{ .components = &.{ ".config", "gcloud" } },
    .{ .components = &.{ ".config", "google-chrome" } },
    .{ .components = &.{ ".config", "chromium" } },
    .{ .components = &.{ ".config", "Code" } },
    .{ .components = &.{ ".config", "op" } },
    .{ .components = &.{ ".docker", "config.json" } },
    .{ .components = &.{ ".local", "share", "keyrings" } },
    .{ .components = &.{ ".mozilla", "firefox" } },
};

/// Forbidden exact filenames (matched as final path component).
const FORBIDDEN_FILENAMES = [_][]const u8{
    ".netrc",
    ".npmrc",
    ".git-credentials",
    "private.pem",
    "private.key",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "service-account.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
};

/// Forbidden filename suffixes (matched at end of final component).
const FORBIDDEN_SUFFIXES = [_][]const u8{
    ".env",
    ".env.local",
    ".env.production",
    ".p12",
    ".pfx",
};

/// Checks if a path matches any forbidden pattern.
/// Uses component-aware matching to avoid substring false positives.
fn isForbiddenPath(path: []const u8) bool {
    // Collect components into stack buffer
    var components: [128][]const u8 = undefined;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |c| {
        if (c.len == 0) continue;
        if (count >= components.len) return true;
        components[count] = c;
        count += 1;
    }
    if (count == 0) return false;

    const parts = components[0..count];
    const filename = parts[count - 1];

    // Check single forbidden directory components
    for (parts) |comp| {
        for (FORBIDDEN_DIRS) |dir| {
            if (std.mem.eql(u8, comp, dir)) return true;
        }
    }

    // Check multi-component forbidden sequences
    for (FORBIDDEN_SEQS) |seq| {
        if (seq.components.len > count) continue;
        const end = count - seq.components.len + 1;
        for (0..end) |start| {
            var matched = true;
            for (seq.components, 0..) |sc, j| {
                if (!std.mem.eql(u8, parts[start + j], sc)) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
    }

    // Check forbidden exact filenames
    for (FORBIDDEN_FILENAMES) |name| {
        if (std.mem.eql(u8, filename, name)) return true;
    }

    // Check forbidden filename suffixes
    for (FORBIDDEN_SUFFIXES) |suffix| {
        if (std.mem.endsWith(u8, filename, suffix)) return true;
    }

    // Check .env variant files as path components (e.g.,
    // .env.local, .env.staging — plain ".env" is already
    // caught by FORBIDDEN_SUFFIXES).
    for (parts) |comp| {
        if (std.mem.startsWith(u8, comp, ".env.")) return true;
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
        git_mod.GitError.SpawnFailed => .{
            ErrorCode.GIT_ERROR,
            "Failed to execute git",
        },
        git_mod.GitError.BlockedCommand,
        git_mod.GitError.BlockedArg,
        => .{
            ErrorCode.GIT_BLOCKED,
            "Blocked git command or argument",
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

    const response = try handleRequest(allocator, io, req_json, kp.public_key, .{});
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":true");
    try std.testing.expect(has_ok != null);

    // Content is now base64 encoded: "test content" -> "dGVzdCBjb250ZW50"
    const has_content = std.mem.indexOf(u8, response, "dGVzdCBjb250ZW50");
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

    const response = try handleRequest(allocator, io, req_json, kp2.public_key, .{});
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

    const response = try handleRequest(allocator, io, req_json, kp.public_key, .{});
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

    const response = try handleRequest(allocator, io, req_json, kp.public_key, .{});
    defer allocator.free(response);

    const has_ok = std.mem.indexOf(u8, response, "\"ok\":false");
    const has_err = std.mem.indexOf(u8, response, "FILE_NOT_FOUND");
    try std.testing.expect(has_ok != null);
    try std.testing.expect(has_err != null);
}

test "handle issuer/subject validation" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    const kp = crypto.generateKeypair(io);

    const tok = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "my-issuer",
        "my-subject",
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
        "{{\"id\":\"req1\",\"token\":\"{s}\"," ++
            "\"op\":\"read\"," ++
            "\"params\":{{\"path\":\"/tmp/test.txt\"}}}}",
        .{tok},
    ) catch unreachable;

    // Matching issuer/subject: should pass validation
    {
        const response = try handleRequest(
            allocator,
            io,
            req_json,
            kp.public_key,
            .{
                .expected_issuer = "my-issuer",
                .expected_subject = "my-subject",
            },
        );
        defer allocator.free(response);
        // Should not be INVALID_TOKEN
        const has_invalid = std.mem.indexOf(
            u8,
            response,
            "issuer mismatch",
        );
        try std.testing.expect(has_invalid == null);
    }

    // Wrong issuer: should be rejected
    {
        const response = try handleRequest(
            allocator,
            io,
            req_json,
            kp.public_key,
            .{ .expected_issuer = "other-issuer" },
        );
        defer allocator.free(response);
        const has_err = std.mem.indexOf(
            u8,
            response,
            "issuer mismatch",
        );
        try std.testing.expect(has_err != null);
    }

    // Wrong subject: should be rejected
    {
        const response = try handleRequest(
            allocator,
            io,
            req_json,
            kp.public_key,
            .{ .expected_subject = "other-subject" },
        );
        defer allocator.free(response);
        const has_err = std.mem.indexOf(
            u8,
            response,
            "subject mismatch",
        );
        try std.testing.expect(has_err != null);
    }

    // Both wrong: rejected on first check (issuer)
    {
        const response = try handleRequest(
            allocator,
            io,
            req_json,
            kp.public_key,
            .{
                .expected_issuer = "wrong-iss",
                .expected_subject = "wrong-sub",
            },
        );
        defer allocator.free(response);
        const has_err = std.mem.indexOf(
            u8,
            response,
            "issuer mismatch",
        );
        try std.testing.expect(has_err != null);
    }

    // No identity checks (null): should pass validation
    {
        const response = try handleRequest(
            allocator,
            io,
            req_json,
            kp.public_key,
            .{},
        );
        defer allocator.free(response);
        const has_invalid = std.mem.indexOf(
            u8,
            response,
            "mismatch",
        );
        try std.testing.expect(has_invalid == null);
    }
}

test "isForbiddenPath blocks sensitive directories" {
    // SSH keys
    try std.testing.expect(isForbiddenPath("/home/user/.ssh/id_rsa"));
    try std.testing.expect(isForbiddenPath("/home/user/.ssh/authorized_keys"));

    // GPG keys
    try std.testing.expect(isForbiddenPath("/home/user/.gnupg/private-keys"));

    // Cloud credentials
    try std.testing.expect(isForbiddenPath("/home/user/.aws/credentials"));
    const gcloud_path = "/home/user/.config/gcloud/creds.json";
    try std.testing.expect(isForbiddenPath(gcloud_path));
    try std.testing.expect(isForbiddenPath("/home/user/.azure/config"));
    try std.testing.expect(isForbiddenPath("/home/user/.kube/config"));

    // ClawGate keys
    const claw_key = "/home/user/.clawgate/keys/secret.key";
    try std.testing.expect(isForbiddenPath(claw_key));

    // Network credentials
    try std.testing.expect(isForbiddenPath("/home/user/.netrc"));
    try std.testing.expect(isForbiddenPath("/home/user/.npmrc"));
    try std.testing.expect(isForbiddenPath("/home/user/.git-credentials"));

    // Docker
    try std.testing.expect(isForbiddenPath("/home/user/.docker/config.json"));
}

test "isForbiddenPath blocks sensitive file types" {
    // Environment files
    try std.testing.expect(isForbiddenPath("/app/.env"));
    try std.testing.expect(isForbiddenPath("/app/.env.local"));
    try std.testing.expect(isForbiddenPath("/app/.env.production"));
    try std.testing.expect(isForbiddenPath("/project/config/.env"));

    // Private keys (specific patterns)
    try std.testing.expect(isForbiddenPath("/certs/private.pem"));
    try std.testing.expect(isForbiddenPath("/certs/private.key"));
    try std.testing.expect(isForbiddenPath("/keys/cert.p12"));
    try std.testing.expect(isForbiddenPath("/home/user/.ssh/id_rsa"));
    try std.testing.expect(isForbiddenPath("/home/user/.ssh/id_ed25519"));

    // Credential JSON files
    try std.testing.expect(isForbiddenPath("/app/credentials.json"));
    try std.testing.expect(isForbiddenPath("/config/service-account.json"));
    try std.testing.expect(isForbiddenPath("/app/secrets.json"));
    try std.testing.expect(isForbiddenPath("/k8s/secrets.yaml"));
}

test "isForbiddenPath allows safe paths" {
    // Normal project files
    try std.testing.expect(!isForbiddenPath("/home/user/project/src/main.zig"));
    try std.testing.expect(!isForbiddenPath("/tmp/test.txt"));
    try std.testing.expect(!isForbiddenPath("/var/log/app.log"));

    // Config files that aren't secrets
    try std.testing.expect(!isForbiddenPath("/app/config.json"));
    try std.testing.expect(!isForbiddenPath("/app/settings.yaml"));

    // Public keys are OK
    try std.testing.expect(!isForbiddenPath("/home/user/.clawgate/public.key"));
}

test "isForbiddenPath - no false positives on similar names" {
    // Paths containing forbidden substrings but NOT in forbidden locations
    // These should NOT be blocked (false positive prevention)

    // .ssh in filename/dirname but not /.ssh/ directory
    try std.testing.expect(!isForbiddenPath("/home/user/.ssh-backup/key"));
    try std.testing.expect(!isForbiddenPath("/home/user/my.ssh.dir/file"));
    try std.testing.expect(!isForbiddenPath("/data/sshconfig/file"));
    try std.testing.expect(!isForbiddenPath("/home/user/openssh-docs/readme"));

    // .env in path but not as suffix or /.env pattern
    try std.testing.expect(!isForbiddenPath("/home/user/project.env.example"));
    try std.testing.expect(!isForbiddenPath("/home/user/env-setup/config"));
    try std.testing.expect(!isForbiddenPath("/data/environment/vars"));

    // Similar to aws/gcloud but not the actual credential dirs
    try std.testing.expect(!isForbiddenPath("/home/user/aws-docs/guide.md"));
    try std.testing.expect(!isForbiddenPath("/data/gcloud-tutorial/steps"));

    // Keys in path but not private key patterns
    try std.testing.expect(!isForbiddenPath("/home/user/api-keys-docs/readme"));
    try std.testing.expect(!isForbiddenPath("/data/keyboard/layout.json"));
}

test "isForbiddenPath - component-aware matching" {
    // Exact component match required, not substring
    // ".ssh-backup" is not ".ssh"
    try std.testing.expect(
        !isForbiddenPath("/home/user/.ssh-backup/key"),
    );
    // ".sshx" is not ".ssh"
    try std.testing.expect(
        !isForbiddenPath("/home/user/.sshx/key"),
    );
    // But exact ".ssh" component is blocked
    try std.testing.expect(
        isForbiddenPath("/home/user/.ssh/config"),
    );
    // ".ssh" as the last component is also blocked
    try std.testing.expect(
        isForbiddenPath("/home/user/.ssh"),
    );

    // Multi-component sequences
    try std.testing.expect(
        isForbiddenPath("/home/u/.config/gcloud/creds"),
    );
    try std.testing.expect(
        !isForbiddenPath("/home/u/.config/gcloudx/creds"),
    );
    try std.testing.expect(
        isForbiddenPath("/h/.local/share/keyrings/k"),
    );

    // .env component matching
    try std.testing.expect(isForbiddenPath("/app/.env"));
    try std.testing.expect(
        isForbiddenPath("/app/.env.staging"),
    );
    try std.testing.expect(
        !isForbiddenPath("/app/not.env/file"),
    );
}

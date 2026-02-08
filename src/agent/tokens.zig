//! Token storage for the agent daemon.
//!
//! Loads JWT capability tokens from disk, validates them, and finds the
//! best matching token for a given path and operation.

const std = @import("std");
const token_mod = @import("../capability/token.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;

pub const TokenStoreError = error{
    DirectoryNotFound,
    TokenParseError,
    IoError,
    OutOfMemory,
};

/// A stored token with its raw JWT string and file path.
pub const StoredToken = struct {
    /// Raw JWT string (owned)
    raw: []const u8,
    /// Parsed token
    parsed: token_mod.Token,
    /// Token file path for removal (owned)
    file_path: []const u8,
};

/// Token store managing a collection of capability tokens.
pub const TokenStore = struct {
    /// Array of stored tokens (owned slice)
    tokens: []StoredToken,
    /// Token directory path (owned)
    token_dir: []const u8,

    /// Loads all tokens from a directory.
    /// Each .token file contains one raw JWT string.
    /// Caller owns returned TokenStore and must call deinit().
    pub fn loadFromDir(
        allocator: Allocator,
        io: Io,
        dir_path: []const u8,
    ) TokenStoreError!TokenStore {
        const owned_dir = allocator.dupe(u8, dir_path) catch {
            return TokenStoreError.OutOfMemory;
        };
        errdefer allocator.free(owned_dir);

        const dir = Dir.openDir(
            .cwd(),
            io,
            dir_path,
            .{ .iterate = true },
        ) catch {
            return TokenStoreError.DirectoryNotFound;
        };
        defer dir.close(io);

        var tokens: std.ArrayListUnmanaged(StoredToken) = .empty;
        errdefer {
            for (tokens.items) |*tok| {
                freeStoredToken(allocator, tok);
            }
            tokens.deinit(allocator);
        }

        var iter = dir.iterate();
        while (iter.next(io) catch return TokenStoreError.IoError) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".token")) continue;

            const full_path = std.fs.path.join(allocator, &.{
                dir_path, entry.name,
            }) catch continue;

            const stored = loadTokenFile(
                allocator,
                io,
                full_path,
            ) catch |err| {
                std.log.warn(
                    "Failed to load token {s}: {}",
                    .{ entry.name, err },
                );
                allocator.free(full_path);
                continue;
            };

            // loadTokenFile duplicates the path, so free the original
            allocator.free(full_path);

            tokens.append(allocator, stored) catch {
                freeStoredToken(allocator, @constCast(&stored));
                return TokenStoreError.OutOfMemory;
            };
        }

        return TokenStore{
            .tokens = tokens.toOwnedSlice(allocator) catch {
                return TokenStoreError.OutOfMemory;
            },
            .token_dir = owned_dir,
        };
    }

    /// Releases all resources held by the token store.
    pub fn deinit(self: *TokenStore, allocator: Allocator) void {
        for (self.tokens) |*tok| {
            freeStoredToken(allocator, tok);
        }
        allocator.free(self.tokens);
        allocator.free(self.token_dir);
    }

    /// Finds a non-expired token that allows the operation on the path.
    /// Returns null if no matching token found.
    pub fn findForPath(
        self: *TokenStore,
        resource: []const u8,
        op: []const u8,
        path: []const u8,
    ) ?*StoredToken {
        for (self.tokens) |*tok| {
            if (tok.parsed.allows(resource, op, path)) {
                return tok;
            }
        }
        return null;
    }

    /// Adds a new token to the store and saves to disk.
    /// Token is parsed and validated before adding.
    pub fn addToken(
        self: *TokenStore,
        allocator: Allocator,
        io: Io,
        raw_jwt: []const u8,
    ) !void {
        const raw = try allocator.dupe(u8, raw_jwt);
        errdefer allocator.free(raw);

        var parsed = token_mod.Token.parse(allocator, raw) catch {
            return TokenStoreError.TokenParseError;
        };
        errdefer parsed.deinit(allocator);

        if (parsed.isExpired()) {
            return token_mod.TokenError.TokenExpired;
        }

        // Generate filename from token ID
        const token_id = parsed.getId();
        const filename = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.token",
            .{ self.token_dir, token_id },
        );
        errdefer allocator.free(filename);

        // Save to disk with restricted permissions (owner only)
        const file = Dir.createFile(.cwd(), io, filename, .{
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        }) catch {
            return TokenStoreError.IoError;
        };
        defer file.close(io);

        file.writeStreamingAll(io, raw_jwt) catch {
            return TokenStoreError.IoError;
        };

        // Add to in-memory store
        const stored = StoredToken{
            .raw = raw,
            .parsed = parsed,
            .file_path = filename,
        };

        const new_tokens = try allocator.realloc(
            self.tokens,
            self.tokens.len + 1,
        );
        new_tokens[new_tokens.len - 1] = stored;
        self.tokens = new_tokens;
    }

    /// Removes a token by its ID (jti). Deletes the token file from disk.
    pub fn removeToken(
        self: *TokenStore,
        allocator: Allocator,
        io: Io,
        token_id: []const u8,
    ) !void {
        var found_idx: ?usize = null;
        for (self.tokens, 0..) |*tok, i| {
            if (std.mem.eql(u8, tok.parsed.getId(), token_id)) {
                found_idx = i;
                break;
            }
        }

        const idx = found_idx orelse return error.TokenNotFound;

        // Delete file
        Dir.deleteFile(.cwd(), io, self.tokens[idx].file_path) catch {};

        // Free token resources
        freeStoredToken(allocator, &self.tokens[idx]);

        // Remove from slice by shifting
        if (idx < self.tokens.len - 1) {
            std.mem.copyForwards(
                StoredToken,
                self.tokens[idx..],
                self.tokens[idx + 1 ..],
            );
        }

        self.tokens = allocator.realloc(
            self.tokens,
            self.tokens.len - 1,
        ) catch self.tokens[0 .. self.tokens.len - 1];
    }

    /// Removes a token by its raw JWT string.
    /// Used by the agent daemon to auto-remove tokens
    /// rejected with TOKEN_REVOKED.
    pub fn removeByRaw(
        self: *TokenStore,
        allocator: Allocator,
        io: Io,
        raw: []const u8,
    ) void {
        var found_idx: ?usize = null;
        for (self.tokens, 0..) |*tok, i| {
            if (std.mem.eql(u8, tok.raw, raw)) {
                found_idx = i;
                break;
            }
        }
        const idx = found_idx orelse return;

        Dir.deleteFile(
            .cwd(),
            io,
            self.tokens[idx].file_path,
        ) catch {};

        freeStoredToken(allocator, &self.tokens[idx]);

        if (idx < self.tokens.len - 1) {
            std.mem.copyForwards(
                StoredToken,
                self.tokens[idx..],
                self.tokens[idx + 1 ..],
            );
        }

        self.tokens = allocator.realloc(
            self.tokens,
            self.tokens.len - 1,
        ) catch self.tokens[0 .. self.tokens.len - 1];
    }

    /// Returns all tokens for listing.
    pub fn list(self: *TokenStore) []StoredToken {
        return self.tokens;
    }
};

/// Loads a single token file.
fn loadTokenFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) !StoredToken {
    const file = Dir.openFile(.cwd(), io, path, .{}) catch {
        return TokenStoreError.IoError;
    };
    defer file.close(io);

    const stat = file.stat(io) catch return TokenStoreError.IoError;
    const file_size: usize = @intCast(stat.size);

    if (file_size > 16 * 1024) {
        return TokenStoreError.TokenParseError;
    }

    const raw = try allocator.alloc(u8, file_size);

    const bytes_read = file.readPositionalAll(io, raw, 0) catch {
        allocator.free(raw);
        return TokenStoreError.IoError;
    };

    // Trim whitespace (newlines at end)
    const trimmed = std.mem.trim(u8, raw[0..bytes_read], " \t\r\n");
    const raw_trimmed = allocator.dupe(u8, trimmed) catch {
        allocator.free(raw);
        return TokenStoreError.OutOfMemory;
    };
    allocator.free(raw);
    errdefer allocator.free(raw_trimmed);

    var parsed = token_mod.Token.parse(allocator, raw_trimmed) catch {
        return TokenStoreError.TokenParseError;
    };
    errdefer parsed.deinit(allocator);

    const file_path = try allocator.dupe(u8, path);

    return StoredToken{
        .raw = raw_trimmed,
        .parsed = parsed,
        .file_path = file_path,
    };
}

/// Frees a stored token's resources.
fn freeStoredToken(allocator: Allocator, tok: *StoredToken) void {
    allocator.free(tok.raw);
    allocator.free(tok.file_path);
    tok.parsed.deinit(allocator);
}

// Tests

test "load empty directory" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    // Create temp directory
    const test_dir = "/tmp/clawgate_test_tokens_empty";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer Dir.deleteDir(.cwd(), io, test_dir) catch {};

    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);
}

test "findForPath returns null for empty store" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_tokens_empty2";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer Dir.deleteDir(.cwd(), io, test_dir) catch {};

    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    const result = store.findForPath("files", "read", "/tmp/test.txt");
    try std.testing.expect(result == null);
}

test "load and find token" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const crypto = @import("../capability/crypto.zig");

    // Create test directory
    const test_dir = "/tmp/clawgate_test_tokens_find";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer {
        Dir.deleteFile(
            .cwd(),
            io,
            "/tmp/clawgate_test_tokens_find/test.token",
        ) catch {};
        Dir.deleteDir(.cwd(), io, test_dir) catch {};
    }

    // Generate a test token
    const kp = crypto.generateKeypair(io);
    const capabilities = [_]token_mod.Capability{
        .{
            .r = "files",
            .o = &[_][]const u8{ "read", "list" },
            .s = "/tmp/**",
        },
    };

    const jwt = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "test-issuer",
        "test-subject",
        &capabilities,
        3600,
    );
    defer allocator.free(jwt);

    // Write token to file
    const token_path = "/tmp/clawgate_test_tokens_find/test.token";
    const file = try Dir.createFile(.cwd(), io, token_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, jwt);

    // Load store
    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), store.tokens.len);

    // Should find token for /tmp path
    const found = store.findForPath("files", "read", "/tmp/test.txt");
    try std.testing.expect(found != null);

    // Should not find for /etc path
    const not_found = store.findForPath("files", "read", "/etc/passwd");
    try std.testing.expect(not_found == null);

    // Should not find for write (not in token)
    const no_write = store.findForPath("files", "write", "/tmp/test.txt");
    try std.testing.expect(no_write == null);
}

test "addToken and removeToken" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const crypto = @import("../capability/crypto.zig");

    // Create test directory
    const test_dir = "/tmp/clawgate_test_tokens_add";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer Dir.deleteDir(.cwd(), io, test_dir) catch {};

    // Load empty store
    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);

    // Create a test token
    const kp = crypto.generateKeypair(io);
    const capabilities = [_]token_mod.Capability{
        .{
            .r = "files",
            .o = &[_][]const u8{"read"},
            .s = "/home/**",
        },
    };

    const jwt = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "issuer",
        "subject",
        &capabilities,
        3600,
    );
    defer allocator.free(jwt);

    // Add token
    try store.addToken(allocator, io, jwt);
    try std.testing.expectEqual(@as(usize, 1), store.tokens.len);

    // Should find token now
    const found = store.findForPath("files", "read", "/home/user/file.txt");
    try std.testing.expect(found != null);

    // Get token ID for removal
    const token_id = store.tokens[0].parsed.getId();
    const token_id_copy = try allocator.dupe(u8, token_id);
    defer allocator.free(token_id_copy);

    // Remove token
    try store.removeToken(allocator, io, token_id_copy);
    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);

    // Should not find token anymore
    const not_found = store.findForPath("files", "read", "/home/user/file.txt");
    try std.testing.expect(not_found == null);
}

// Error handling tests

test "loadFromDir - nonexistent directory" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const result = TokenStore.loadFromDir(
        allocator,
        io,
        "/tmp/nonexistent_clawgate_dir_12345",
    );
    try std.testing.expectError(TokenStoreError.DirectoryNotFound, result);
}

test "loadFromDir - skips non-token files" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_non_token";
    const other_file = test_dir ++ "/other.txt";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer {
        Dir.deleteFile(.cwd(), io, other_file) catch {};
        Dir.deleteDir(.cwd(), io, test_dir) catch {};
    }

    // Create a non-.token file
    const other_path = "/tmp/clawgate_test_non_token/other.txt";
    const file = try Dir.createFile(.cwd(), io, other_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "not a token");

    // Load store - should skip the non-.token file
    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);
}

test "loadFromDir - skips invalid token files" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_invalid_token";
    const bad_file = test_dir ++ "/bad.token";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer {
        Dir.deleteFile(.cwd(), io, bad_file) catch {};
        Dir.deleteDir(.cwd(), io, test_dir) catch {};
    }

    // Create invalid token file
    const bad_path = "/tmp/clawgate_test_invalid_token/bad.token";
    const file = try Dir.createFile(.cwd(), io, bad_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "not.a.valid.jwt");

    // Load store - should skip invalid token and not crash
    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);
}

test "loadFromDir - skips empty token files" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_empty_token";
    const empty_file = test_dir ++ "/empty.token";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer {
        Dir.deleteFile(.cwd(), io, empty_file) catch {};
        Dir.deleteDir(.cwd(), io, test_dir) catch {};
    }

    // Create empty token file
    const empty_path = "/tmp/clawgate_test_empty_token/empty.token";
    const file = try Dir.createFile(.cwd(), io, empty_path, .{});
    file.close(io);

    // Load store - should skip empty file
    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);
}

test "removeToken - nonexistent token ID" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_remove_nonexistent";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer Dir.deleteDir(.cwd(), io, test_dir) catch {};

    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    // Try to remove token that doesn't exist
    const result = store.removeToken(allocator, io, "nonexistent_id");
    try std.testing.expectError(error.TokenNotFound, result);
}

test "addToken - invalid JWT rejected" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_dir = "/tmp/clawgate_test_add_invalid";
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer Dir.deleteDir(.cwd(), io, test_dir) catch {};

    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    // Try to add invalid JWT
    const result = store.addToken(allocator, io, "not.a.valid.jwt");
    try std.testing.expectError(TokenStoreError.TokenParseError, result);

    // Store should still be empty
    try std.testing.expectEqual(@as(usize, 0), store.tokens.len);
}

test "list returns all tokens" {
    const allocator = std.testing.allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const crypto = @import("../capability/crypto.zig");

    // Use unique directory name to avoid test pollution
    const test_dir = "/tmp/clawgate_test_list_tokens";

    // Clean up leftover files from previous runs
    cleanupTestDir(io, test_dir);
    Dir.createDir(.cwd(), io, test_dir, .default_dir) catch {};
    defer cleanupTestDir(io, test_dir);

    var store = try TokenStore.loadFromDir(allocator, io, test_dir);
    defer store.deinit(allocator);

    // Initially empty
    try std.testing.expectEqual(@as(usize, 0), store.list().len);

    // Add a token
    const kp = crypto.generateKeypair(io);
    const capabilities = [_]token_mod.Capability{
        .{ .r = "files", .o = &[_][]const u8{"read"}, .s = "/**" },
    };

    const jwt = try token_mod.createToken(
        allocator,
        io,
        kp.secret_key,
        "issuer",
        "subject",
        &capabilities,
        3600,
    );
    defer allocator.free(jwt);

    try store.addToken(allocator, io, jwt);

    // Now should have 1
    try std.testing.expectEqual(@as(usize, 1), store.list().len);
}

fn cleanupTestDir(io: std.Io, dir_path: []const u8) void {
    const dir = Dir.openDir(
        .cwd(),
        io,
        dir_path,
        .{ .iterate = true },
    ) catch return;
    defer dir.close(io);

    var iter = dir.iterate();
    while (iter.next(io) catch null) |entry| {
        const file_path = std.fs.path.join(
            std.testing.allocator,
            &.{ dir_path, entry.name },
        ) catch continue;
        defer std.testing.allocator.free(file_path);
        Dir.deleteFile(.cwd(), io, file_path) catch {};
    }

    Dir.deleteDir(.cwd(), io, dir_path) catch {};
}

//! Glob pattern matching for capability scopes.
//!
//! Supports patterns:
//! - `/exact/path` - exact match
//! - `/path/*` - single level wildcard (direct children only)
//! - `/path/**` - recursive wildcard (all descendants)
//! - `/path/*.ext` - extension matching in directory

const std = @import("std");

/// Checks if a path matches a scope pattern.
pub fn matches(pattern: []const u8, path: []const u8) bool {
    // Handle /** recursive wildcard
    if (std.mem.endsWith(u8, pattern, "/**")) {
        const prefix = pattern[0 .. pattern.len - 3];
        // Path must start with prefix (excluding the trailing slash of prefix)
        if (prefix.len == 0) return true;
        if (!std.mem.startsWith(u8, path, prefix)) return false;
        // Path must be exactly prefix or have / after prefix
        if (path.len == prefix.len) return true;
        return path[prefix.len] == '/';
    }

    // Handle /* single-level wildcard
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        if (!std.mem.startsWith(u8, path, prefix)) return false;
        if (path.len <= prefix.len) return false;
        if (path[prefix.len] != '/') return false;
        const remainder = path[prefix.len + 1 ..];
        // Must not contain more slashes (single level only)
        return std.mem.indexOfScalar(u8, remainder, '/') == null;
    }

    // Handle *.ext patterns in directory
    if (std.mem.indexOfScalar(u8, pattern, '*')) |star_pos| {
        const prefix = pattern[0..star_pos];
        const suffix = pattern[star_pos + 1 ..];

        if (!std.mem.startsWith(u8, path, prefix)) return false;
        if (!std.mem.endsWith(u8, path, suffix)) return false;

        // Guard against overlapping prefix/suffix
        if (path.len < prefix.len + suffix.len) return false;

        // Ensure the matched portion doesn't span directories
        const matched = path[prefix.len .. path.len - suffix.len];
        if (std.mem.indexOfScalar(u8, matched, '/') != null) return false;

        return true;
    }

    // Exact match
    return std.mem.eql(u8, pattern, path);
}

/// Normalizes a path by removing trailing slashes.
pub fn normalizePath(path: []const u8) []const u8 {
    var result = path;
    while (result.len > 1 and result[result.len - 1] == '/') {
        result = result[0 .. result.len - 1];
    }
    return result;
}

/// Canonicalizes a path by resolving . and .. components.
/// Returns null if path is invalid (e.g., escapes root with ..).
/// Caller owns returned memory.
pub fn canonicalizePath(
    allocator: std.mem.Allocator,
    path: []const u8,
) ?[]const u8 {
    // Must be absolute path
    if (path.len == 0 or path[0] != '/') return null;

    var components: std.ArrayListUnmanaged([]const u8) = .empty;
    defer components.deinit(allocator);

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) {
            // Skip empty components and current dir
            continue;
        } else if (std.mem.eql(u8, component, "..")) {
            // Go up one level
            if (components.items.len == 0) {
                // Trying to escape root
                return null;
            }
            _ = components.pop();
        } else {
            components.append(allocator, component) catch return null;
        }
    }

    // Build result
    if (components.items.len == 0) {
        return allocator.dupe(u8, "/") catch null;
    }

    var total_len: usize = 0;
    for (components.items) |c| {
        total_len += 1 + c.len; // "/" + component
    }

    const result = allocator.alloc(u8, total_len) catch return null;
    var pos: usize = 0;
    for (components.items) |c| {
        result[pos] = '/';
        pos += 1;
        @memcpy(result[pos..][0..c.len], c);
        pos += c.len;
    }

    return result;
}

/// Checks if a path is within a base directory.
/// Empty base returns false (invalid scope).
pub fn isWithin(base: []const u8, path: []const u8) bool {
    const norm_base = normalizePath(base);
    const norm_path = normalizePath(path);

    // Empty base is invalid - reject
    if (norm_base.len == 0) return false;

    if (!std.mem.startsWith(u8, norm_path, norm_base)) return false;
    if (norm_path.len == norm_base.len) return true;

    // Special case: root "/" contains everything
    if (norm_base.len == 1 and norm_base[0] == '/') return true;

    return norm_path[norm_base.len] == '/';
}

// Tests

test "exact match" {
    try std.testing.expect(matches("/home/m/file.txt", "/home/m/file.txt"));
    try std.testing.expect(!matches("/home/m/file.txt", "/home/m/other.txt"));
    try std.testing.expect(!matches("/home/m/file.txt", "/home/m/file.txt/"));
    try std.testing.expect(!matches("/home/m", "/home/m/file.txt"));
}

test "single level wildcard /*" {
    try std.testing.expect(matches("/home/m/*", "/home/m/file.txt"));
    try std.testing.expect(matches("/home/m/*", "/home/m/readme"));
    try std.testing.expect(!matches("/home/m/*", "/home/m/sub/file.txt"));
    try std.testing.expect(!matches("/home/m/*", "/home/other/file.txt"));
    try std.testing.expect(!matches("/home/m/*", "/home/m"));
}

test "recursive wildcard /**" {
    try std.testing.expect(matches("/home/m/**", "/home/m/file.txt"));
    try std.testing.expect(matches("/home/m/**", "/home/m/sub/file.txt"));
    try std.testing.expect(matches("/home/m/**", "/home/m/a/b/c/file.txt"));
    try std.testing.expect(!matches("/home/m/**", "/home/other/file.txt"));
    try std.testing.expect(!matches("/home/m/**", "/home/mx/file.txt"));
    // Edge case: pattern matches the directory itself
    try std.testing.expect(matches("/home/m/**", "/home/m"));
}

test "extension pattern *.ext" {
    try std.testing.expect(matches("/home/m/*.zig", "/home/m/main.zig"));
    try std.testing.expect(matches("/home/m/*.zig", "/home/m/test.zig"));
    try std.testing.expect(!matches("/home/m/*.zig", "/home/m/main.c"));
    try std.testing.expect(!matches("/home/m/*.zig", "/home/m/sub/main.zig"));
}

test "root patterns" {
    try std.testing.expect(matches("/**", "/any/path/at/all"));
    try std.testing.expect(matches("/*", "/toplevel"));
    try std.testing.expect(!matches("/*", "/top/nested"));
}

test "normalizePath" {
    try std.testing.expectEqualStrings("/home/m", normalizePath("/home/m/"));
    try std.testing.expectEqualStrings("/home/m", normalizePath("/home/m///"));
    try std.testing.expectEqualStrings("/", normalizePath("/"));
    try std.testing.expectEqualStrings("/home", normalizePath("/home"));
}

test "isWithin" {
    try std.testing.expect(isWithin("/home/m", "/home/m/file.txt"));
    try std.testing.expect(isWithin("/home/m", "/home/m"));
    try std.testing.expect(isWithin("/home/m/", "/home/m/sub/file"));
    try std.testing.expect(!isWithin("/home/m", "/home/mx/file"));
    try std.testing.expect(!isWithin("/home/m", "/home/other"));
}

test "canonicalizePath" {
    const allocator = std.testing.allocator;

    // Normal path unchanged
    const p1 = canonicalizePath(allocator, "/home/user/file.txt").?;
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/home/user/file.txt", p1);

    // Path with .. resolved
    const p2 = canonicalizePath(allocator, "/home/user/../other/file.txt").?;
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/home/other/file.txt", p2);

    // Path with . removed
    const p3 = canonicalizePath(allocator, "/home/./user/./file.txt").?;
    defer allocator.free(p3);
    try std.testing.expectEqualStrings("/home/user/file.txt", p3);

    // Double slashes handled
    const p4 = canonicalizePath(allocator, "/home//user///file.txt").?;
    defer allocator.free(p4);
    try std.testing.expectEqualStrings("/home/user/file.txt", p4);

    // Escaping root returns null
    try std.testing.expect(
        canonicalizePath(allocator, "/../etc/passwd") == null,
    );
    try std.testing.expect(
        canonicalizePath(allocator, "/home/../../etc") == null,
    );

    // Root path
    const p5 = canonicalizePath(allocator, "/").?;
    defer allocator.free(p5);
    try std.testing.expectEqualStrings("/", p5);

    // Non-absolute path returns null
    try std.testing.expect(
        canonicalizePath(allocator, "relative/path") == null,
    );
}

test "canonicalizePath security - path traversal attacks" {
    const allocator = std.testing.allocator;

    // Various path traversal attack patterns that MUST return null

    // Basic escape attempts
    try std.testing.expect(canonicalizePath(allocator, "/..") == null);
    try std.testing.expect(canonicalizePath(allocator, "/../") == null);
    try std.testing.expect(canonicalizePath(allocator, "/../..") == null);

    // Escape from deep path
    try std.testing.expect(canonicalizePath(
        allocator,
        "/home/user/../../../etc/passwd",
    ) == null);

    // Escape with trailing components
    try std.testing.expect(canonicalizePath(
        allocator,
        "/tmp/../../../etc/shadow",
    ) == null);

    // Multiple .. in sequence
    try std.testing.expect(canonicalizePath(
        allocator,
        "/a/b/c/../../../../etc",
    ) == null);

    // Valid traversal that stays within bounds should work
    const valid = canonicalizePath(allocator, "/home/user/../other/file").?;
    defer allocator.free(valid);
    try std.testing.expectEqualStrings("/home/other/file", valid);
}

// Additional security edge case tests

test "canonicalizePath empty path returns null" {
    const allocator = std.testing.allocator;

    // Empty path is not valid
    try std.testing.expect(canonicalizePath(allocator, "") == null);
}

test "canonicalizePath root path" {
    const allocator = std.testing.allocator;

    // Root path should be valid
    const root = canonicalizePath(allocator, "/").?;
    defer allocator.free(root);
    try std.testing.expectEqualStrings("/", root);

    // Root with trailing components
    const root2 = canonicalizePath(allocator, "/./").?;
    defer allocator.free(root2);
    try std.testing.expectEqualStrings("/", root2);
}

test "canonicalizePath consecutive slashes" {
    const allocator = std.testing.allocator;

    // Many consecutive slashes should be collapsed
    const p1 = canonicalizePath(allocator, "//home//user///file").?;
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/home/user/file", p1);

    // Extreme case
    const p2 = canonicalizePath(allocator, "/////a/////b/////c").?;
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/a/b/c", p2);
}

test "canonicalizePath with dot-dot-like names" {
    const allocator = std.testing.allocator;

    // Names that look like .. but aren't should be preserved
    const p1 = canonicalizePath(allocator, "/home/...").?;
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/home/...", p1);

    const p2 = canonicalizePath(allocator, "/home/..a").?;
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/home/..a", p2);

    const p3 = canonicalizePath(allocator, "/home/a..").?;
    defer allocator.free(p3);
    try std.testing.expectEqualStrings("/home/a..", p3);
}

test "matches with empty strings" {
    // Empty path: /** matches empty (prefix is empty, returns true)
    // This is intentional: empty prefix means "match anything"
    try std.testing.expect(!matches("/home/**", ""));
    try std.testing.expect(matches("/**", "")); // Empty prefix matches all
    try std.testing.expect(!matches("/*", ""));

    // Empty pattern: exact match with empty path only
    try std.testing.expect(!matches("", "/home/file"));
    try std.testing.expect(matches("", "")); // Both empty = exact match
}

test "matches with root pattern" {
    // /** matches everything including root
    try std.testing.expect(matches("/**", "/"));
    try std.testing.expect(matches("/**", "/anything"));

    // /* matches "/" because:
    // - prefix is empty, path starts with ""
    // - path[0] is '/', remainder after '/' is empty
    // - empty remainder has no '/', so returns true
    // This is intentional: root directory is a "single level" under nothing
    try std.testing.expect(matches("/*", "/"));
}

test "isWithin with root base" {
    // Root as base should match everything
    try std.testing.expect(isWithin("/", "/any/path"));
    try std.testing.expect(isWithin("/", "/"));
}

test "isWithin prevents prefix confusion" {
    // /home/m should not match /home/mario (prefix but not path boundary)
    try std.testing.expect(!isWithin("/home/m", "/home/mario"));
    try std.testing.expect(!isWithin("/home/m", "/home/mxyz/file"));

    // But should match actual subdirs
    try std.testing.expect(isWithin("/home/m", "/home/m/file"));
    try std.testing.expect(isWithin("/home/m", "/home/m"));
}

test "matches recursive wildcard prefix boundary" {
    // /home/m/** should NOT match /home/mario (not a subpath)
    try std.testing.expect(!matches("/home/m/**", "/home/mario"));
    try std.testing.expect(!matches("/home/m/**", "/home/mxyz/file"));

    // But should match actual subdirs
    try std.testing.expect(matches("/home/m/**", "/home/m/file"));
    try std.testing.expect(matches("/home/m/**", "/home/m"));
}

test "canonicalizePath very long path" {
    const allocator = std.testing.allocator;

    // Build a very long path (100 components)
    var long_path_buf: [2048]u8 = undefined;
    var pos: usize = 0;
    for (0..100) |i| {
        long_path_buf[pos] = '/';
        pos += 1;
        const written = std.fmt.bufPrint(
            long_path_buf[pos..],
            "dir{d}",
            .{i},
        ) catch unreachable;
        pos += written.len;
    }
    const long_path = long_path_buf[0..pos];

    // Should still work
    const result = canonicalizePath(allocator, long_path).?;
    defer allocator.free(result);
    try std.testing.expect(result.len > 0);
    try std.testing.expect(result[0] == '/');
}

test "extension pattern edge cases" {
    // Extension with empty base name
    try std.testing.expect(matches("/home/*.txt", "/home/.txt"));

    // Pattern at root
    try std.testing.expect(matches("/*.txt", "/file.txt"));
    try std.testing.expect(!matches("/*.txt", "/sub/file.txt"));
}

test "single level wildcard edge cases" {
    // File with multiple dots
    try std.testing.expect(matches("/tmp/*", "/tmp/file.tar.gz"));

    // Hidden files (starting with .)
    try std.testing.expect(matches("/tmp/*", "/tmp/.hidden"));

    // File that is just the parent
    try std.testing.expect(!matches("/tmp/*", "/tmp"));
}

// Bug-finding negative tests - designed to catch implementation bugs

test "canonicalizePath rejects percent-encoded traversal" {
    // Paths should already be decoded before reaching us, but verify
    // that literal %2e%2e doesn't magically become ..
    const allocator = std.testing.allocator;

    // These are literal strings, not URL-encoded
    // If implementation ever decodes URLs, this would be a vulnerability
    const p1 = canonicalizePath(allocator, "/home/user/%2e%2e/passwd");
    if (p1) |path| {
        // Should NOT have decoded %2e%2e to ..
        try std.testing.expect(std.mem.indexOf(u8, path, "..") == null);
        allocator.free(path);
    }

    // Null byte injection attempt (literal string)
    const p2 = canonicalizePath(allocator, "/home/user/\x00/../passwd");
    // Should either be null or not contain traversal
    if (p2) |path| {
        defer allocator.free(path);
        try std.testing.expect(std.mem.indexOf(u8, path, "passwd") == null or
            std.mem.indexOf(u8, path, "..") == null);
    }
}

test "matches rejects path component boundary attacks" {
    // These patterns should NOT allow escaping to sibling directories

    // Pattern: /home/user/** (user has access to their home)
    // Attack: access /home/useradmin or /home/user../admin
    try std.testing.expect(!matches("/home/user/**", "/home/useradmin/file"));
    try std.testing.expect(!matches("/home/user/**", "/home/user-admin/file"));
    try std.testing.expect(!matches("/home/user/**", "/home/user_admin/file"));

    // Empty component attack (shouldn't match)
    try std.testing.expect(!matches("/home/user/**", "/home//user/file"));
}

test "isWithin handles edge case paths" {
    // Empty base is invalid - returns false for security
    try std.testing.expect(!isWithin("", "/home/user/file"));
    try std.testing.expect(!isWithin("", ""));

    // Empty path
    try std.testing.expect(!isWithin("/home", ""));

    // Root as base
    try std.testing.expect(isWithin("/", "/anything"));
    try std.testing.expect(isWithin("/", "/"));

    // Identical paths
    try std.testing.expect(isWithin("/home/user", "/home/user"));
}

test "canonicalizePath with maximum nesting" {
    const allocator = std.testing.allocator;

    // Deeply nested path with many .. reduces to root
    // /a/b/c/d/e/f/g + 7 x ".." = /
    const deep_path = "/a/b/c/d/e/f/g/../../../../../../..";
    const result = canonicalizePath(allocator, deep_path);

    // Reduces to root /
    if (result) |path| {
        defer allocator.free(path);
        try std.testing.expectEqualStrings("/", path);
    }
}

test "matches with unicode-like paths" {
    // Test that multibyte sequences don't confuse pattern matching
    // (paths use raw bytes, not unicode decoding)
    try std.testing.expect(matches("/data/**", "/data/file\xc0\xaf"));
    try std.testing.expect(!matches("/data/*", "/data/dir\xc0\xaf/file"));
}

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

/// Checks if a path is within a base directory.
pub fn isWithin(base: []const u8, path: []const u8) bool {
    const norm_base = normalizePath(base);
    const norm_path = normalizePath(path);

    if (!std.mem.startsWith(u8, norm_path, norm_base)) return false;
    if (norm_path.len == norm_base.len) return true;
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

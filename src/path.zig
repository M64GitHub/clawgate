//! Path manipulation utilities.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Expands ~ to home directory in path.
/// The home parameter should come from Threaded.environString("HOME").
pub fn expand(
    allocator: Allocator,
    path: []const u8,
    home: []const u8,
) ![]const u8 {
    if (path.len == 0) {
        return allocator.dupe(u8, path);
    }

    if (path[0] != '~') {
        return allocator.dupe(u8, path);
    }

    if (path.len == 1) {
        return allocator.dupe(u8, home);
    }

    // Replace ~ with home directory
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path[1..] });
}

// Tests

test "expand expands tilde" {
    const allocator = std.testing.allocator;

    const expanded = try expand(
        allocator,
        "~/.clawgate/tokens",
        "/home/user",
    );
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/home/user/.clawgate/tokens", expanded);
}

test "expand handles absolute paths" {
    const allocator = std.testing.allocator;

    const expanded = try expand(allocator, "/tmp/tokens", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/tmp/tokens", expanded);
}

test "expand handles tilde only" {
    const allocator = std.testing.allocator;

    const expanded = try expand(allocator, "~", "/home/testuser");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/home/testuser", expanded);
}

test "expand handles empty path" {
    const allocator = std.testing.allocator;

    const expanded = try expand(allocator, "", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("", expanded);
}

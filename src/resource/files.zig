//! File operations for the resource daemon.
//!
//! Implements read, write, list, and stat operations with safety limits
//! to prevent abuse and resource exhaustion.

const std = @import("std");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;
const File = std.Io.File;

pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;
pub const TRUNCATE_AT: usize = 512 * 1024;

/// Security option: whether to follow symlinks.
/// Default is false for security (prevents symlink-based scope escapes).
pub const FOLLOW_SYMLINKS: bool = false;

pub const FileError = error{
    FileNotFound,
    AccessDenied,
    FileTooLarge,
    NotAFile,
    NotADirectory,
    InvalidPath,
    IsSymlink,
    IoError,
    OutOfMemory,
};

pub const WriteMode = enum {
    create,
    overwrite,
    append,

    pub fn fromString(s: ?[]const u8) WriteMode {
        const mode = s orelse return .create;
        if (std.mem.eql(u8, mode, "overwrite")) return .overwrite;
        if (std.mem.eql(u8, mode, "append")) return .append;
        return .create;
    }
};

/// Reads file content with optional offset and length limits.
/// Truncates to TRUNCATE_AT bytes if file is larger than requested limit.
/// Caller owns returned content memory.
pub fn readFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    offset: usize,
    max_len: ?usize,
) FileError!protocol.ReadResult {
    const file = Dir.openFile(.cwd(), io, path, .{
        .follow_symlinks = FOLLOW_SYMLINKS,
    }) catch |err| {
        return switch (err) {
            error.FileNotFound => FileError.FileNotFound,
            error.AccessDenied => FileError.AccessDenied,
            error.IsDir => FileError.NotAFile,
            error.SymLinkLoop => FileError.IsSymlink,
            else => FileError.IoError,
        };
    };
    defer file.close(io);

    const stat = file.stat(io) catch return FileError.IoError;

    if (stat.kind != .file) {
        return FileError.NotAFile;
    }

    const file_size: usize = @intCast(stat.size);
    if (file_size > MAX_FILE_SIZE) {
        return FileError.FileTooLarge;
    }

    if (offset >= file_size) {
        const empty = allocator.alloc(u8, 0) catch {
            return FileError.OutOfMemory;
        };
        return protocol.ReadResult{
            .content = empty,
            .size = file_size,
            .truncated = false,
        };
    }

    const limit = max_len orelse TRUNCATE_AT;
    const available = file_size - offset;
    const read_len = @min(limit, @min(available, TRUNCATE_AT));
    const truncated = available > read_len;

    const buf = allocator.alloc(u8, read_len) catch {
        return FileError.OutOfMemory;
    };
    errdefer allocator.free(buf);

    const total_read = file.readPositionalAll(io, buf, offset) catch {
        return FileError.IoError;
    };

    if (total_read < read_len) {
        const trimmed = allocator.realloc(buf, total_read) catch buf;
        return protocol.ReadResult{
            .content = trimmed,
            .size = file_size,
            .truncated = truncated,
        };
    }

    return protocol.ReadResult{
        .content = buf,
        .size = file_size,
        .truncated = truncated,
    };
}

/// Writes content to a file with the specified mode.
/// Returns the number of bytes written.
pub fn writeFile(
    io: Io,
    path: []const u8,
    content: []const u8,
    mode: WriteMode,
) FileError!usize {
    switch (mode) {
        .create, .overwrite => {
            // Note: createFile doesn't have follow_symlinks option
            // If path is a symlink, it will be followed
            // For security, check if target exists and is a symlink first
            if (!FOLLOW_SYMLINKS) {
                // Check if path exists and is a symlink
                const stat = Dir.statFile(.cwd(), io, path, .{
                    .follow_symlinks = false,
                }) catch |err| switch (err) {
                    error.FileNotFound => null, // OK, file doesn't exist
                    else => return FileError.IoError,
                };
                if (stat) |s| {
                    if (s.kind == .sym_link) {
                        return FileError.IsSymlink;
                    }
                }
            }

            const file = Dir.createFile(.cwd(), io, path, .{
                .truncate = true,
            }) catch |err| {
                return switch (err) {
                    error.AccessDenied => FileError.AccessDenied,
                    error.IsDir => FileError.NotAFile,
                    else => FileError.IoError,
                };
            };
            defer file.close(io);

            file.writeStreamingAll(io, content) catch {
                return FileError.IoError;
            };
            return content.len;
        },
        .append => {
            const file = Dir.openFile(.cwd(), io, path, .{
                .mode = .read_write,
                .follow_symlinks = FOLLOW_SYMLINKS,
            }) catch |err| {
                return switch (err) {
                    error.FileNotFound => FileError.FileNotFound,
                    error.AccessDenied => FileError.AccessDenied,
                    error.IsDir => FileError.NotAFile,
                    error.SymLinkLoop => FileError.IsSymlink,
                    else => FileError.IoError,
                };
            };
            defer file.close(io);

            const stat = file.stat(io) catch return FileError.IoError;
            const end_offset: u64 = stat.size;

            file.writePositionalAll(io, content, end_offset) catch {
                return FileError.IoError;
            };
            return content.len;
        },
    }
}

/// Lists directory contents.
/// Caller owns returned entries array and all strings within.
pub fn listDir(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    depth: u8,
) FileError![]protocol.Entry {
    _ = depth;

    const dir = Dir.openDir(
        .cwd(),
        io,
        path,
        .{ .iterate = true, .follow_symlinks = FOLLOW_SYMLINKS },
    ) catch |err| {
        return switch (err) {
            error.FileNotFound => FileError.FileNotFound,
            error.AccessDenied => FileError.AccessDenied,
            error.NotDir => FileError.NotADirectory,
            error.SymLinkLoop => FileError.IsSymlink,
            else => FileError.IoError,
        };
    };
    defer dir.close(io);

    var entries: std.ArrayListUnmanaged(protocol.Entry) = .empty;
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
        }
        entries.deinit(allocator);
    }

    var iter = dir.iterate();
    while (iter.next(io) catch return FileError.IoError) |entry| {
        const name = allocator.dupe(u8, entry.name) catch {
            return FileError.OutOfMemory;
        };
        errdefer allocator.free(name);

        const entry_type: []const u8 = switch (entry.kind) {
            .directory => "dir",
            else => "file",
        };

        const size: ?usize = if (entry.kind == .file) blk: {
            const full_path = std.fs.path.join(allocator, &.{
                path, entry.name,
            }) catch break :blk null;
            defer allocator.free(full_path);

            const f = Dir.openFile(.cwd(), io, full_path, .{}) catch {
                break :blk null;
            };
            defer f.close(io);

            const stat = f.stat(io) catch break :blk null;
            break :blk @intCast(stat.size);
        } else null;

        entries.append(allocator, .{
            .name = name,
            .type = entry_type,
            .size = size,
        }) catch return FileError.OutOfMemory;
    }

    return entries.toOwnedSlice(allocator) catch return FileError.OutOfMemory;
}

/// Returns file or directory metadata.
/// Caller owns the modified timestamp string.
pub fn statFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) FileError!protocol.StatResult {
    const file = Dir.openFile(.cwd(), io, path, .{
        .follow_symlinks = FOLLOW_SYMLINKS,
    }) catch |err| {
        return switch (err) {
            error.FileNotFound => {
                const modified = allocator.dupe(u8, "") catch {
                    return FileError.OutOfMemory;
                };
                return protocol.StatResult{
                    .exists = false,
                    .type = "unknown",
                    .size = 0,
                    .modified = modified,
                };
            },
            error.AccessDenied => FileError.AccessDenied,
            error.IsDir => {
                return statDir(allocator, io, path);
            },
            error.SymLinkLoop => FileError.IsSymlink,
            else => FileError.IoError,
        };
    };
    defer file.close(io);

    const stat = file.stat(io) catch return FileError.IoError;

    const file_type: []const u8 = switch (stat.kind) {
        .directory => "dir",
        .file => "file",
        else => "other",
    };

    const modified = formatTimestamp(allocator, stat.mtime) catch {
        return FileError.OutOfMemory;
    };

    return protocol.StatResult{
        .exists = true,
        .type = file_type,
        .size = @intCast(stat.size),
        .modified = modified,
    };
}

/// Returns metadata for a directory path.
fn statDir(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) FileError!protocol.StatResult {
    const dir = Dir.openDir(.cwd(), io, path, .{
        .follow_symlinks = FOLLOW_SYMLINKS,
    }) catch |err| {
        return switch (err) {
            error.FileNotFound => FileError.FileNotFound,
            error.AccessDenied => FileError.AccessDenied,
            error.SymLinkLoop => FileError.IsSymlink,
            else => FileError.IoError,
        };
    };
    defer dir.close(io);

    const stat = dir.stat(io) catch return FileError.IoError;

    const modified = formatTimestamp(allocator, stat.mtime) catch {
        return FileError.OutOfMemory;
    };

    return protocol.StatResult{
        .exists = true,
        .type = "dir",
        .size = 0,
        .modified = modified,
    };
}

/// Formats a timestamp as ISO 8601 string.
fn formatTimestamp(allocator: Allocator, mtime: Io.Timestamp) ![]const u8 {
    const ns = mtime.nanoseconds;
    const secs: i64 = @intCast(@divTrunc(ns, std.time.ns_per_s));
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(secs) };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();

    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        },
    );
}

/// Frees a ReadResult's content.
pub fn freeReadResult(allocator: Allocator, result: *protocol.ReadResult) void {
    allocator.free(result.content);
}

/// Frees a ListResult's entries and names.
pub fn freeListResult(
    allocator: Allocator,
    entries: []protocol.Entry,
) void {
    for (entries) |entry| {
        allocator.free(entry.name);
    }
    allocator.free(entries);
}

/// Frees a StatResult's modified timestamp.
pub fn freeStatResult(allocator: Allocator, result: *protocol.StatResult) void {
    allocator.free(result.modified);
}

// Tests

test "read file - normal" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_read.txt";
    const test_content = "Hello, ClawGate!";

    {
        const file = try Dir.createFile(.cwd(), io, test_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, test_content);
    }
    defer Dir.deleteFile(.cwd(), io, test_path) catch {};

    var result = try readFile(allocator, io, test_path, 0, null);
    defer freeReadResult(allocator, &result);

    try std.testing.expectEqualStrings(test_content, result.content);
    try std.testing.expectEqual(@as(usize, 16), result.size);
    try std.testing.expect(!result.truncated);
}

test "read file - with offset" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_offset.txt";
    const test_content = "Hello, ClawGate!";

    {
        const file = try Dir.createFile(.cwd(), io, test_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, test_content);
    }
    defer Dir.deleteFile(.cwd(), io, test_path) catch {};

    var result = try readFile(allocator, io, test_path, 7, null);
    defer freeReadResult(allocator, &result);

    try std.testing.expectEqualStrings("ClawGate!", result.content);
    try std.testing.expectEqual(@as(usize, 16), result.size);
}

test "read file - not found" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const result = readFile(
        allocator,
        io,
        "/tmp/nonexistent_file_12345.txt",
        0,
        null,
    );
    try std.testing.expectError(FileError.FileNotFound, result);
}

test "write file - create" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_write.txt";
    defer Dir.deleteFile(.cwd(), io, test_path) catch {};

    const written = try writeFile(io, test_path, "Test content", .create);
    try std.testing.expectEqual(@as(usize, 12), written);

    var result = try readFile(allocator, io, test_path, 0, null);
    defer freeReadResult(allocator, &result);

    try std.testing.expectEqualStrings("Test content", result.content);
}

test "write file - append" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_append.txt";

    {
        const file = try Dir.createFile(.cwd(), io, test_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "First");
    }
    defer Dir.deleteFile(.cwd(), io, test_path) catch {};

    _ = try writeFile(io, test_path, " Second", .append);

    var result = try readFile(allocator, io, test_path, 0, null);
    defer freeReadResult(allocator, &result);

    try std.testing.expectEqualStrings("First Second", result.content);
}

test "list directory" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const entries = try listDir(allocator, io, "/tmp", 1);
    defer freeListResult(allocator, entries);

    try std.testing.expect(entries.len > 0);
}

test "stat file" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_stat.txt";

    {
        const file = try Dir.createFile(.cwd(), io, test_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "stat test");
    }
    defer Dir.deleteFile(.cwd(), io, test_path) catch {};

    var result = try statFile(allocator, io, test_path);
    defer freeStatResult(allocator, &result);

    try std.testing.expect(result.exists);
    try std.testing.expectEqualStrings("file", result.type);
    try std.testing.expectEqual(@as(usize, 9), result.size);
    try std.testing.expect(result.modified.len > 0);
}

test "stat nonexistent file" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var result = try statFile(allocator, io, "/tmp/nonexistent_stat_12345.txt");
    defer freeStatResult(allocator, &result);

    try std.testing.expect(!result.exists);
}

test "format timestamp" {
    const allocator = std.testing.allocator;

    const mtime = Io.Timestamp{
        .nanoseconds = 1706706000 * std.time.ns_per_s,
    };

    const ts = formatTimestamp(allocator, mtime) catch unreachable;
    defer allocator.free(ts);

    try std.testing.expect(ts.len == 20);
    try std.testing.expect(std.mem.startsWith(u8, ts, "2024-"));
}

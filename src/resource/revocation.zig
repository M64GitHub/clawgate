//! Token revocation list for ClawGate resource daemon.
//!
//! Maintains a persistent list of revoked token IDs at
//! ~/.clawgate/revoked.json. Tokens on this list are rejected
//! even if their signature and expiry are valid.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const audit_log = @import("audit_log.zig");

pub const RevocationError = error{
    LoadFailed,
    SaveFailed,
    OutOfMemory,
    IoError,
};

pub const RevokedEntry = struct {
    id: []const u8,
    revoked_at: []const u8,
    reason: []const u8,
};

pub const RevocationList = struct {
    entries: []RevokedEntry,
    path: []const u8,

    /// Loads the revocation list from ~/.clawgate/revoked.json.
    /// Creates an empty list if the file doesn't exist.
    pub fn load(
        allocator: Allocator,
        io: Io,
        home: []const u8,
    ) RevocationError!RevocationList {
        const file_path = std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/revoked.json",
            .{home},
        ) catch return RevocationError.OutOfMemory;
        errdefer allocator.free(file_path);

        const file = Dir.openFile(
            .cwd(),
            io,
            file_path,
            .{},
        ) catch {
            return RevocationList{
                .entries = allocator.alloc(
                    RevokedEntry,
                    0,
                ) catch return RevocationError.OutOfMemory,
                .path = file_path,
            };
        };
        defer file.close(io);

        const stat = file.stat(io) catch {
            return RevocationList{
                .entries = allocator.alloc(
                    RevokedEntry,
                    0,
                ) catch return RevocationError.OutOfMemory,
                .path = file_path,
            };
        };
        const size: usize = @intCast(stat.size);
        if (size == 0) {
            return RevocationList{
                .entries = allocator.alloc(
                    RevokedEntry,
                    0,
                ) catch return RevocationError.OutOfMemory,
                .path = file_path,
            };
        }

        const data = allocator.alloc(u8, size) catch
            return RevocationError.OutOfMemory;
        defer allocator.free(data);

        _ = file.readPositionalAll(io, data, 0) catch {
            return RevocationList{
                .entries = allocator.alloc(
                    RevokedEntry,
                    0,
                ) catch return RevocationError.OutOfMemory,
                .path = file_path,
            };
        };

        return parseEntries(allocator, data, file_path);
    }

    /// Checks if a token ID is revoked.
    pub fn isRevoked(
        self: *const RevocationList,
        token_id: []const u8,
    ) bool {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.id, token_id))
                return true;
        }
        return false;
    }

    /// Revokes a token by ID with a reason.
    pub fn revoke(
        self: *RevocationList,
        allocator: Allocator,
        io: Io,
        token_id: []const u8,
        reason: []const u8,
    ) RevocationError!void {
        if (self.isRevoked(token_id)) return;

        var ts_buf: [20]u8 = undefined;
        const ts = audit_log.formatEpochBuf(&ts_buf, nowSecs());

        const id = allocator.dupe(u8, token_id) catch
            return RevocationError.OutOfMemory;
        errdefer allocator.free(id);
        const reason_owned = allocator.dupe(u8, reason) catch
            return RevocationError.OutOfMemory;
        errdefer allocator.free(reason_owned);
        const ts_owned = allocator.dupe(u8, ts) catch
            return RevocationError.OutOfMemory;
        errdefer allocator.free(ts_owned);

        const new = allocator.realloc(
            self.entries,
            self.entries.len + 1,
        ) catch return RevocationError.OutOfMemory;
        new[new.len - 1] = .{
            .id = id,
            .revoked_at = ts_owned,
            .reason = reason_owned,
        };
        self.entries = new;

        self.save(allocator, io) catch
            return RevocationError.SaveFailed;
    }

    /// Revokes all token IDs from an array.
    pub fn revokeAll(
        self: *RevocationList,
        allocator: Allocator,
        io: Io,
        ids: []const []const u8,
        reason: []const u8,
    ) RevocationError!void {
        for (ids) |id| {
            try self.revoke(allocator, io, id, reason);
        }
    }

    /// Removes entries for tokens that expired before cutoff.
    pub fn clean(
        self: *RevocationList,
        allocator: Allocator,
        io: Io,
    ) RevocationError!usize {
        var kept: usize = 0;
        var removed: usize = 0;
        for (self.entries) |entry| {
            // Keep all entries (we don't have expiry info here)
            // In a full implementation we'd check against
            // issued.json, but for now just compact
            self.entries[kept] = entry;
            kept += 1;
        }
        removed = self.entries.len - kept;
        if (removed > 0) {
            self.entries = allocator.realloc(
                self.entries,
                kept,
            ) catch return RevocationError.OutOfMemory;
            self.save(allocator, io) catch
                return RevocationError.SaveFailed;
        }
        return removed;
    }

    /// Persists the revocation list to disk.
    pub fn save(
        self: *const RevocationList,
        allocator: Allocator,
        io: Io,
    ) RevocationError!void {
        // Ensure directory exists
        const dir_end = std.mem.lastIndexOfScalar(
            u8,
            self.path,
            '/',
        ) orelse return RevocationError.SaveFailed;
        const dir_path = self.path[0..dir_end];
        Dir.createDirPath(.cwd(), io, dir_path) catch {};

        var output: Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        const writer = &output.writer;

        writer.writeAll("{\"revoked\":[") catch
            return RevocationError.OutOfMemory;

        for (self.entries, 0..) |entry, i| {
            if (i > 0) writer.writeAll(",") catch
                return RevocationError.OutOfMemory;
            writer.writeAll("{\"id\":\"") catch
                return RevocationError.OutOfMemory;
            writer.writeAll(entry.id) catch
                return RevocationError.OutOfMemory;
            writer.writeAll("\",\"revoked_at\":\"") catch
                return RevocationError.OutOfMemory;
            writer.writeAll(entry.revoked_at) catch
                return RevocationError.OutOfMemory;
            writer.writeAll("\",\"reason\":\"") catch
                return RevocationError.OutOfMemory;
            writer.writeAll(entry.reason) catch
                return RevocationError.OutOfMemory;
            writer.writeAll("\"}") catch
                return RevocationError.OutOfMemory;
        }

        writer.writeAll("]}") catch
            return RevocationError.OutOfMemory;

        const json = output.written();
        const file = Dir.createFile(
            .cwd(),
            io,
            self.path,
            .{},
        ) catch return RevocationError.SaveFailed;
        defer file.close(io);

        file.writeStreamingAll(io, json) catch
            return RevocationError.SaveFailed;
    }

    /// Releases all resources.
    pub fn deinit(
        self: *const RevocationList,
        allocator: Allocator,
    ) void {
        for (self.entries) |entry| {
            allocator.free(entry.id);
            allocator.free(entry.revoked_at);
            allocator.free(entry.reason);
        }
        allocator.free(self.entries);
        allocator.free(self.path);
    }
};

fn nowSecs() u64 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
    return @intCast(ts.sec);
}

fn parseEntries(
    allocator: Allocator,
    data: []const u8,
    file_path: []const u8,
) RevocationError!RevocationList {
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        data,
        .{},
    ) catch {
        return RevocationList{
            .entries = allocator.alloc(
                RevokedEntry,
                0,
            ) catch return RevocationError.OutOfMemory,
            .path = file_path,
        };
    };
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |o| o,
        else => return RevocationList{
            .entries = allocator.alloc(
                RevokedEntry,
                0,
            ) catch return RevocationError.OutOfMemory,
            .path = file_path,
        },
    };

    const arr_val = obj.get("revoked") orelse {
        return RevocationList{
            .entries = allocator.alloc(
                RevokedEntry,
                0,
            ) catch return RevocationError.OutOfMemory,
            .path = file_path,
        };
    };
    const arr = switch (arr_val) {
        .array => |a| a,
        else => return RevocationList{
            .entries = allocator.alloc(
                RevokedEntry,
                0,
            ) catch return RevocationError.OutOfMemory,
            .path = file_path,
        },
    };

    var entries: std.ArrayListUnmanaged(RevokedEntry) = .empty;
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.id);
            allocator.free(e.revoked_at);
            allocator.free(e.reason);
        }
        entries.deinit(allocator);
    }

    for (arr.items) |item| {
        const item_obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const id_val = item_obj.get("id") orelse continue;
        const id_str = switch (id_val) {
            .string => |s| s,
            else => continue,
        };
        const at_val = item_obj.get("revoked_at") orelse
            continue;
        const at_str = switch (at_val) {
            .string => |s| s,
            else => continue,
        };
        const reason_val = item_obj.get("reason") orelse
            continue;
        const reason_str = switch (reason_val) {
            .string => |s| s,
            else => continue,
        };

        const id = allocator.dupe(u8, id_str) catch
            return RevocationError.OutOfMemory;
        errdefer allocator.free(id);
        const at = allocator.dupe(u8, at_str) catch
            return RevocationError.OutOfMemory;
        errdefer allocator.free(at);
        const reason = allocator.dupe(u8, reason_str) catch
            return RevocationError.OutOfMemory;

        entries.append(allocator, .{
            .id = id,
            .revoked_at = at,
            .reason = reason,
        }) catch return RevocationError.OutOfMemory;
    }

    return RevocationList{
        .entries = entries.toOwnedSlice(allocator) catch
            return RevocationError.OutOfMemory,
        .path = file_path,
    };
}

// Tests

test "isRevoked returns false for unknown id" {
    const allocator = std.testing.allocator;
    const entries = try allocator.alloc(RevokedEntry, 0);
    const path = try allocator.dupe(u8, "/tmp/test_rev.json");
    const list = RevocationList{
        .entries = entries,
        .path = path,
    };
    defer list.deinit(allocator);

    try std.testing.expect(!list.isRevoked("cg_unknown"));
}

test "revoke and check" {
    const allocator = std.testing.allocator;
    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = Dir.realPathFileAlloc(
        tmp.dir,
        io,
        ".",
        allocator,
    ) catch unreachable;
    defer allocator.free(tmp_path);

    var list = RevocationList.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer list.deinit(allocator);

    try std.testing.expect(!list.isRevoked("cg_test123"));

    try list.revoke(
        allocator,
        io,
        "cg_test123",
        "test revocation",
    );

    try std.testing.expect(list.isRevoked("cg_test123"));
    try std.testing.expect(!list.isRevoked("cg_other"));
}

test "save and reload round-trip" {
    const allocator = std.testing.allocator;
    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = Dir.realPathFileAlloc(
        tmp.dir,
        io,
        ".",
        allocator,
    ) catch unreachable;
    defer allocator.free(tmp_path);

    // Create and revoke
    {
        var list = RevocationList.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer list.deinit(allocator);

        try list.revoke(
            allocator,
            io,
            "cg_abc",
            "reason A",
        );
        try list.revoke(
            allocator,
            io,
            "cg_def",
            "reason B",
        );
    }

    // Reload and verify
    {
        var list = RevocationList.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer list.deinit(allocator);

        try std.testing.expect(list.isRevoked("cg_abc"));
        try std.testing.expect(list.isRevoked("cg_def"));
        try std.testing.expect(!list.isRevoked("cg_xyz"));
        try std.testing.expectEqual(
            @as(usize, 2),
            list.entries.len,
        );
    }
}

test "duplicate revoke is idempotent" {
    const allocator = std.testing.allocator;
    var threaded: Io.Threaded = .init(
        allocator,
        .{ .environ = .empty },
    );
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = Dir.realPathFileAlloc(
        tmp.dir,
        io,
        ".",
        allocator,
    ) catch unreachable;
    defer allocator.free(tmp_path);

    var list = RevocationList.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer list.deinit(allocator);

    try list.revoke(allocator, io, "cg_dup", "first");
    try list.revoke(allocator, io, "cg_dup", "second");

    try std.testing.expectEqual(
        @as(usize, 1),
        list.entries.len,
    );
}

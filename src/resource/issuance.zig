//! Token issuance tracking for ClawGate.
//!
//! Records metadata about issued tokens at ~/.clawgate/issued.json
//! for revocation and auditing purposes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const audit_log = @import("audit_log.zig");

pub const IssuanceError = error{
    LoadFailed,
    SaveFailed,
    OutOfMemory,
    IoError,
};

pub const IssuedEntry = struct {
    id: []const u8,
    scope: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
};

pub const IssuanceLog = struct {
    entries: []IssuedEntry,
    path: []const u8,

    /// Loads the issuance log from ~/.clawgate/issued.json.
    pub fn load(
        allocator: Allocator,
        io: Io,
        home: []const u8,
    ) IssuanceError!IssuanceLog {
        const file_path = std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/issued.json",
            .{home},
        ) catch return IssuanceError.OutOfMemory;
        errdefer allocator.free(file_path);

        const file = Dir.openFile(
            .cwd(),
            io,
            file_path,
            .{},
        ) catch {
            return IssuanceLog{
                .entries = allocator.alloc(
                    IssuedEntry,
                    0,
                ) catch return IssuanceError.OutOfMemory,
                .path = file_path,
            };
        };
        defer file.close(io);

        const stat = file.stat(io) catch {
            return IssuanceLog{
                .entries = allocator.alloc(
                    IssuedEntry,
                    0,
                ) catch return IssuanceError.OutOfMemory,
                .path = file_path,
            };
        };
        const size: usize = @intCast(stat.size);
        if (size == 0) {
            return IssuanceLog{
                .entries = allocator.alloc(
                    IssuedEntry,
                    0,
                ) catch return IssuanceError.OutOfMemory,
                .path = file_path,
            };
        }

        const data = allocator.alloc(u8, size) catch
            return IssuanceError.OutOfMemory;
        defer allocator.free(data);

        _ = file.readPositionalAll(io, data, 0) catch {
            return IssuanceLog{
                .entries = allocator.alloc(
                    IssuedEntry,
                    0,
                ) catch return IssuanceError.OutOfMemory,
                .path = file_path,
            };
        };

        return parseEntries(allocator, data, file_path);
    }

    /// Records a new issued token entry.
    pub fn record(
        self: *IssuanceLog,
        allocator: Allocator,
        io: Io,
        entry: IssuedEntry,
    ) IssuanceError!void {
        const id = allocator.dupe(u8, entry.id) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(id);
        const sc = allocator.dupe(u8, entry.scope) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(sc);
        const iat = allocator.dupe(u8, entry.issued_at) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(iat);
        const exp = allocator.dupe(u8, entry.expires_at) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(exp);

        const new = allocator.realloc(
            self.entries,
            self.entries.len + 1,
        ) catch return IssuanceError.OutOfMemory;
        new[new.len - 1] = .{
            .id = id,
            .scope = sc,
            .issued_at = iat,
            .expires_at = exp,
        };
        self.entries = new;

        self.save(allocator, io) catch
            return IssuanceError.SaveFailed;
    }

    /// Removes an entry by token ID and saves to disk.
    pub fn removeById(
        self: *IssuanceLog,
        allocator: Allocator,
        io: Io,
        token_id: []const u8,
    ) IssuanceError!void {
        var found_idx: ?usize = null;
        for (self.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.id, token_id)) {
                found_idx = i;
                break;
            }
        }
        const idx = found_idx orelse return;

        allocator.free(self.entries[idx].id);
        allocator.free(self.entries[idx].scope);
        allocator.free(self.entries[idx].issued_at);
        allocator.free(self.entries[idx].expires_at);

        if (idx < self.entries.len - 1) {
            std.mem.copyForwards(
                IssuedEntry,
                self.entries[idx..],
                self.entries[idx + 1 ..],
            );
        }

        self.entries = allocator.realloc(
            self.entries,
            self.entries.len - 1,
        ) catch self.entries[0 .. self.entries.len - 1];

        self.save(allocator, io) catch
            return IssuanceError.SaveFailed;
    }

    /// Returns all token IDs.
    pub fn allIds(
        self: *const IssuanceLog,
        allocator: Allocator,
    ) IssuanceError![][]const u8 {
        const ids = allocator.alloc(
            []const u8,
            self.entries.len,
        ) catch return IssuanceError.OutOfMemory;
        for (self.entries, 0..) |entry, i| {
            ids[i] = entry.id;
        }
        return ids;
    }

    /// Persists the issuance log to disk.
    pub fn save(
        self: *const IssuanceLog,
        allocator: Allocator,
        io: Io,
    ) IssuanceError!void {
        const dir_end = std.mem.lastIndexOfScalar(
            u8,
            self.path,
            '/',
        ) orelse return IssuanceError.SaveFailed;
        const dir_path = self.path[0..dir_end];
        Dir.createDirPath(.cwd(), io, dir_path) catch {};

        var output: Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        const writer = &output.writer;

        writer.writeAll("{\"tokens\":[") catch
            return IssuanceError.OutOfMemory;

        for (self.entries, 0..) |entry, i| {
            if (i > 0) writer.writeAll(",") catch
                return IssuanceError.OutOfMemory;
            writer.writeAll("{\"id\":\"") catch
                return IssuanceError.OutOfMemory;
            writer.writeAll(entry.id) catch
                return IssuanceError.OutOfMemory;
            writer.writeAll("\",\"scope\":\"") catch
                return IssuanceError.OutOfMemory;
            writer.writeAll(entry.scope) catch
                return IssuanceError.OutOfMemory;
            writer.writeAll("\",\"issued_at\":\"") catch
                return IssuanceError.OutOfMemory;
            writer.writeAll(entry.issued_at) catch
                return IssuanceError.OutOfMemory;
            writer.writeAll("\",\"expires_at\":\"") catch
                return IssuanceError.OutOfMemory;
            writer.writeAll(entry.expires_at) catch
                return IssuanceError.OutOfMemory;
            writer.writeAll("\"}") catch
                return IssuanceError.OutOfMemory;
        }

        writer.writeAll("]}") catch
            return IssuanceError.OutOfMemory;

        const json = output.written();
        const file = Dir.createFile(
            .cwd(),
            io,
            self.path,
            .{},
        ) catch return IssuanceError.SaveFailed;
        defer file.close(io);

        file.writeStreamingAll(io, json) catch
            return IssuanceError.SaveFailed;
    }

    /// Releases all resources.
    pub fn deinit(
        self: *const IssuanceLog,
        allocator: Allocator,
    ) void {
        for (self.entries) |entry| {
            allocator.free(entry.id);
            allocator.free(entry.scope);
            allocator.free(entry.issued_at);
            allocator.free(entry.expires_at);
        }
        allocator.free(self.entries);
        allocator.free(self.path);
    }
};

fn parseEntries(
    allocator: Allocator,
    data: []const u8,
    file_path: []const u8,
) IssuanceError!IssuanceLog {
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        data,
        .{},
    ) catch {
        return IssuanceLog{
            .entries = allocator.alloc(
                IssuedEntry,
                0,
            ) catch return IssuanceError.OutOfMemory,
            .path = file_path,
        };
    };
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |o| o,
        else => return IssuanceLog{
            .entries = allocator.alloc(
                IssuedEntry,
                0,
            ) catch return IssuanceError.OutOfMemory,
            .path = file_path,
        },
    };

    const arr_val = obj.get("tokens") orelse {
        return IssuanceLog{
            .entries = allocator.alloc(
                IssuedEntry,
                0,
            ) catch return IssuanceError.OutOfMemory,
            .path = file_path,
        };
    };
    const arr = switch (arr_val) {
        .array => |a| a,
        else => return IssuanceLog{
            .entries = allocator.alloc(
                IssuedEntry,
                0,
            ) catch return IssuanceError.OutOfMemory,
            .path = file_path,
        },
    };

    var entries: std.ArrayListUnmanaged(IssuedEntry) = .empty;
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.id);
            allocator.free(e.scope);
            allocator.free(e.issued_at);
            allocator.free(e.expires_at);
        }
        entries.deinit(allocator);
    }

    for (arr.items) |item| {
        const item_obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const id_str = switch (item_obj.get("id") orelse
            continue) {
            .string => |s| s,
            else => continue,
        };
        const scope_str = switch (item_obj.get("scope") orelse
            continue) {
            .string => |s| s,
            else => continue,
        };
        const iat_str = switch (item_obj.get("issued_at") orelse
            continue) {
            .string => |s| s,
            else => continue,
        };
        const exp_str = switch (item_obj.get("expires_at") orelse
            continue) {
            .string => |s| s,
            else => continue,
        };

        const id = allocator.dupe(u8, id_str) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(id);
        const sc = allocator.dupe(u8, scope_str) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(sc);
        const iat = allocator.dupe(u8, iat_str) catch
            return IssuanceError.OutOfMemory;
        errdefer allocator.free(iat);
        const exp = allocator.dupe(u8, exp_str) catch
            return IssuanceError.OutOfMemory;

        entries.append(allocator, .{
            .id = id,
            .scope = sc,
            .issued_at = iat,
            .expires_at = exp,
        }) catch return IssuanceError.OutOfMemory;
    }

    return IssuanceLog{
        .entries = entries.toOwnedSlice(allocator) catch
            return IssuanceError.OutOfMemory,
        .path = file_path,
    };
}

// Tests

test "record and reload round-trip" {
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

    {
        var log = IssuanceLog.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer log.deinit(allocator);

        try log.record(allocator, io, .{
            .id = "cg_test1",
            .scope = "/tmp/**",
            .issued_at = "2026-01-01T00:00:00Z",
            .expires_at = "2026-01-02T00:00:00Z",
        });
    }

    {
        var log = IssuanceLog.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer log.deinit(allocator);

        try std.testing.expectEqual(
            @as(usize, 1),
            log.entries.len,
        );
        try std.testing.expectEqualStrings(
            "cg_test1",
            log.entries[0].id,
        );
        try std.testing.expectEqualStrings(
            "/tmp/**",
            log.entries[0].scope,
        );
    }
}

test "empty log creation" {
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

    var log = IssuanceLog.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer log.deinit(allocator);

    try std.testing.expectEqual(
        @as(usize, 0),
        log.entries.len,
    );
}

test "allIds returns all token ids" {
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

    var log = IssuanceLog.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer log.deinit(allocator);

    try log.record(allocator, io, .{
        .id = "cg_a",
        .scope = "/a/**",
        .issued_at = "2026-01-01T00:00:00Z",
        .expires_at = "2026-01-02T00:00:00Z",
    });
    try log.record(allocator, io, .{
        .id = "cg_b",
        .scope = "/b/**",
        .issued_at = "2026-01-01T00:00:00Z",
        .expires_at = "2026-01-02T00:00:00Z",
    });

    const ids = try log.allIds(allocator);
    defer allocator.free(ids);

    try std.testing.expectEqual(@as(usize, 2), ids.len);
    try std.testing.expectEqualStrings("cg_a", ids[0]);
    try std.testing.expectEqualStrings("cg_b", ids[1]);
}

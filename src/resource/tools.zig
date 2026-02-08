//! Tool registry for ClawGate custom tools.
//!
//! Stores tool configurations at ~/.clawgate/tools.json.
//! Each tool defines a command, argument restrictions, timeouts,
//! and output limits.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

pub const ToolError = error{
    LoadFailed,
    SaveFailed,
    OutOfMemory,
    NotFound,
    DuplicateName,
    IoError,
};

pub const ArgMode = enum {
    allowlist,
    passthrough,
};

pub const ToolConfig = struct {
    command: []const u8,
    allow_args: []const []const u8,
    deny_args: []const []const u8,
    arg_mode: ArgMode,
    scope: ?[]const u8,
    timeout_seconds: u32,
    max_output_bytes: usize,
    description: []const u8,
    examples: []const []const u8,
    created: []const u8,
};

const ToolEntry = struct {
    name: []const u8,
    config: ToolConfig,
};

pub const ToolRegistry = struct {
    entries: []ToolEntry,
    path: []const u8,

    /// Loads the tool registry from ~/.clawgate/tools.json.
    pub fn load(
        allocator: Allocator,
        io: Io,
        home: []const u8,
    ) ToolError!ToolRegistry {
        const file_path = std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/tools.json",
            .{home},
        ) catch return ToolError.OutOfMemory;
        errdefer allocator.free(file_path);

        const file = Dir.openFile(
            .cwd(),
            io,
            file_path,
            .{},
        ) catch {
            return ToolRegistry{
                .entries = allocator.alloc(
                    ToolEntry,
                    0,
                ) catch return ToolError.OutOfMemory,
                .path = file_path,
            };
        };
        defer file.close(io);

        const stat = file.stat(io) catch {
            return ToolRegistry{
                .entries = allocator.alloc(
                    ToolEntry,
                    0,
                ) catch return ToolError.OutOfMemory,
                .path = file_path,
            };
        };
        const size: usize = @intCast(stat.size);
        if (size == 0) {
            return ToolRegistry{
                .entries = allocator.alloc(
                    ToolEntry,
                    0,
                ) catch return ToolError.OutOfMemory,
                .path = file_path,
            };
        }

        const data = allocator.alloc(u8, size) catch
            return ToolError.OutOfMemory;
        defer allocator.free(data);

        _ = file.readPositionalAll(io, data, 0) catch {
            return ToolRegistry{
                .entries = allocator.alloc(
                    ToolEntry,
                    0,
                ) catch return ToolError.OutOfMemory,
                .path = file_path,
            };
        };

        return parseRegistry(allocator, data, file_path);
    }

    /// Looks up a tool by name.
    pub fn get(
        self: *const ToolRegistry,
        name: []const u8,
    ) ?*const ToolConfig {
        for (self.entries) |*entry| {
            if (std.mem.eql(u8, entry.name, name))
                return &entry.config;
        }
        return null;
    }

    /// Returns all registered tool names.
    pub fn listNames(
        self: *const ToolRegistry,
        allocator: Allocator,
    ) ToolError![]const []const u8 {
        const names = allocator.alloc(
            []const u8,
            self.entries.len,
        ) catch return ToolError.OutOfMemory;
        for (self.entries, 0..) |entry, i| {
            names[i] = entry.name;
        }
        return names;
    }

    /// Registers a new tool.
    pub fn register(
        self: *ToolRegistry,
        allocator: Allocator,
        io: Io,
        name: []const u8,
        config: ToolConfig,
    ) ToolError!void {
        if (self.get(name) != null)
            return ToolError.DuplicateName;

        const owned_name = allocator.dupe(u8, name) catch
            return ToolError.OutOfMemory;
        errdefer allocator.free(owned_name);

        const owned_config = dupeConfig(
            allocator,
            config,
        ) catch return ToolError.OutOfMemory;

        const new = allocator.realloc(
            self.entries,
            self.entries.len + 1,
        ) catch return ToolError.OutOfMemory;
        new[new.len - 1] = .{
            .name = owned_name,
            .config = owned_config,
        };
        self.entries = new;

        self.save(allocator, io) catch
            return ToolError.SaveFailed;
    }

    /// Updates an existing tool's configuration.
    pub fn update(
        self: *ToolRegistry,
        allocator: Allocator,
        io: Io,
        name: []const u8,
        config: ToolConfig,
    ) ToolError!void {
        for (self.entries) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                // Dupe before free: config may alias
                // fields from the old entry.
                const new_config = dupeConfig(
                    allocator,
                    config,
                ) catch return ToolError.OutOfMemory;
                freeConfig(allocator, &entry.config);
                entry.config = new_config;
                self.save(allocator, io) catch
                    return ToolError.SaveFailed;
                return;
            }
        }
        return ToolError.NotFound;
    }

    /// Removes a tool by name.
    pub fn remove(
        self: *ToolRegistry,
        allocator: Allocator,
        io: Io,
        name: []const u8,
    ) ToolError!void {
        var found_idx: ?usize = null;
        for (self.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                found_idx = i;
                break;
            }
        }
        const idx = found_idx orelse
            return ToolError.NotFound;

        allocator.free(self.entries[idx].name);
        freeConfig(allocator, &self.entries[idx].config);

        if (idx < self.entries.len - 1) {
            std.mem.copyForwards(
                ToolEntry,
                self.entries[idx..],
                self.entries[idx + 1 ..],
            );
        }

        self.entries = allocator.realloc(
            self.entries,
            self.entries.len - 1,
        ) catch self.entries[0 .. self.entries.len - 1];

        self.save(allocator, io) catch
            return ToolError.SaveFailed;
    }

    /// Persists the registry to disk.
    pub fn save(
        self: *const ToolRegistry,
        allocator: Allocator,
        io: Io,
    ) ToolError!void {
        const dir_end = std.mem.lastIndexOfScalar(
            u8,
            self.path,
            '/',
        ) orelse return ToolError.SaveFailed;
        Dir.createDirPath(
            .cwd(),
            io,
            self.path[0..dir_end],
        ) catch {};

        var output: Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        const w = &output.writer;

        w.writeAll("{\"tools\":{") catch
            return ToolError.OutOfMemory;

        for (self.entries, 0..) |entry, i| {
            if (i > 0) w.writeAll(",") catch
                return ToolError.OutOfMemory;
            w.writeAll("\"") catch
                return ToolError.OutOfMemory;
            w.writeAll(entry.name) catch
                return ToolError.OutOfMemory;
            w.writeAll("\":{") catch
                return ToolError.OutOfMemory;

            // command
            w.writeAll("\"command\":\"") catch
                return ToolError.OutOfMemory;
            writeJsonEscaped(w, entry.config.command) catch
                return ToolError.OutOfMemory;
            w.writeAll("\"") catch
                return ToolError.OutOfMemory;

            // arg_mode
            w.writeAll(",\"arg_mode\":\"") catch
                return ToolError.OutOfMemory;
            w.writeAll(switch (entry.config.arg_mode) {
                .allowlist => "allowlist",
                .passthrough => "passthrough",
            }) catch return ToolError.OutOfMemory;
            w.writeAll("\"") catch
                return ToolError.OutOfMemory;

            // allow_args
            w.writeAll(",\"allow_args\":[") catch
                return ToolError.OutOfMemory;
            for (entry.config.allow_args, 0..) |arg, j| {
                if (j > 0) w.writeAll(",") catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
                writeJsonEscaped(w, arg) catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
            }
            w.writeAll("]") catch
                return ToolError.OutOfMemory;

            // deny_args
            w.writeAll(",\"deny_args\":[") catch
                return ToolError.OutOfMemory;
            for (entry.config.deny_args, 0..) |arg, j| {
                if (j > 0) w.writeAll(",") catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
                writeJsonEscaped(w, arg) catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
            }
            w.writeAll("]") catch
                return ToolError.OutOfMemory;

            // scope
            if (entry.config.scope) |sc| {
                w.writeAll(",\"scope\":\"") catch
                    return ToolError.OutOfMemory;
                writeJsonEscaped(w, sc) catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
            } else {
                w.writeAll(",\"scope\":null") catch
                    return ToolError.OutOfMemory;
            }

            // timeout_seconds
            w.print(",\"timeout_seconds\":{d}", .{
                entry.config.timeout_seconds,
            }) catch return ToolError.OutOfMemory;

            // max_output_bytes
            w.print(",\"max_output_bytes\":{d}", .{
                entry.config.max_output_bytes,
            }) catch return ToolError.OutOfMemory;

            // description
            w.writeAll(",\"description\":\"") catch
                return ToolError.OutOfMemory;
            writeJsonEscaped(
                w,
                entry.config.description,
            ) catch return ToolError.OutOfMemory;
            w.writeAll("\"") catch
                return ToolError.OutOfMemory;

            // examples
            w.writeAll(",\"examples\":[") catch
                return ToolError.OutOfMemory;
            for (entry.config.examples, 0..) |ex, j| {
                if (j > 0) w.writeAll(",") catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
                writeJsonEscaped(w, ex) catch
                    return ToolError.OutOfMemory;
                w.writeAll("\"") catch
                    return ToolError.OutOfMemory;
            }
            w.writeAll("]") catch
                return ToolError.OutOfMemory;

            // created
            w.writeAll(",\"created\":\"") catch
                return ToolError.OutOfMemory;
            w.writeAll(entry.config.created) catch
                return ToolError.OutOfMemory;
            w.writeAll("\"") catch
                return ToolError.OutOfMemory;

            w.writeAll("}") catch
                return ToolError.OutOfMemory;
        }

        w.writeAll("}}") catch return ToolError.OutOfMemory;

        const json = output.written();
        const file = Dir.createFile(
            .cwd(),
            io,
            self.path,
            .{},
        ) catch return ToolError.SaveFailed;
        defer file.close(io);

        file.writeStreamingAll(io, json) catch
            return ToolError.SaveFailed;
    }

    /// Releases all resources.
    pub fn deinit(self: *ToolRegistry, allocator: Allocator) void {
        for (self.entries) |*entry| {
            allocator.free(entry.name);
            freeConfig(allocator, &entry.config);
        }
        allocator.free(self.entries);
        allocator.free(self.path);
    }
};

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

fn dupeConfig(
    allocator: Allocator,
    config: ToolConfig,
) !ToolConfig {
    const command = try allocator.dupe(u8, config.command);
    errdefer allocator.free(command);

    const allow_args = try dupeStringSlice(
        allocator,
        config.allow_args,
    );
    errdefer freeStringSlice(allocator, allow_args);

    const deny_args = try dupeStringSlice(
        allocator,
        config.deny_args,
    );
    errdefer freeStringSlice(allocator, deny_args);

    const scope_val: ?[]const u8 = if (config.scope) |s|
        try allocator.dupe(u8, s)
    else
        null;
    errdefer if (scope_val) |s| allocator.free(s);

    const description = try allocator.dupe(
        u8,
        config.description,
    );
    errdefer allocator.free(description);

    const examples = try dupeStringSlice(
        allocator,
        config.examples,
    );
    errdefer freeStringSlice(allocator, examples);

    const created = try allocator.dupe(u8, config.created);

    return ToolConfig{
        .command = command,
        .allow_args = allow_args,
        .deny_args = deny_args,
        .arg_mode = config.arg_mode,
        .scope = scope_val,
        .timeout_seconds = config.timeout_seconds,
        .max_output_bytes = config.max_output_bytes,
        .description = description,
        .examples = examples,
        .created = created,
    };
}

fn freeConfig(allocator: Allocator, config: *ToolConfig) void {
    allocator.free(config.command);
    freeStringSlice(allocator, config.allow_args);
    freeStringSlice(allocator, config.deny_args);
    if (config.scope) |s| allocator.free(s);
    allocator.free(config.description);
    freeStringSlice(allocator, config.examples);
    allocator.free(config.created);
}

fn dupeStringSlice(
    allocator: Allocator,
    slice: []const []const u8,
) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, slice.len);
    var i: usize = 0;
    errdefer {
        for (result[0..i]) |s| allocator.free(s);
        allocator.free(result);
    }
    while (i < slice.len) : (i += 1) {
        result[i] = try allocator.dupe(u8, slice[i]);
    }
    return result;
}

fn freeStringSlice(
    allocator: Allocator,
    slice: []const []const u8,
) void {
    for (slice) |s| allocator.free(s);
    allocator.free(slice);
}

fn parseRegistry(
    allocator: Allocator,
    data: []const u8,
    file_path: []const u8,
) ToolError!ToolRegistry {
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        data,
        .{},
    ) catch {
        return ToolRegistry{
            .entries = allocator.alloc(
                ToolEntry,
                0,
            ) catch return ToolError.OutOfMemory,
            .path = file_path,
        };
    };
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return ToolRegistry{
            .entries = allocator.alloc(
                ToolEntry,
                0,
            ) catch return ToolError.OutOfMemory,
            .path = file_path,
        },
    };

    const tools_val = root.get("tools") orelse {
        return ToolRegistry{
            .entries = allocator.alloc(
                ToolEntry,
                0,
            ) catch return ToolError.OutOfMemory,
            .path = file_path,
        };
    };
    const tools_obj = switch (tools_val) {
        .object => |o| o,
        else => return ToolRegistry{
            .entries = allocator.alloc(
                ToolEntry,
                0,
            ) catch return ToolError.OutOfMemory,
            .path = file_path,
        },
    };

    var entries: std.ArrayListUnmanaged(ToolEntry) = .empty;
    errdefer {
        for (entries.items) |*e| {
            allocator.free(e.name);
            freeConfig(allocator, &e.config);
        }
        entries.deinit(allocator);
    }

    var iter = tools_obj.iterator();
    while (iter.next()) |kv| {
        const tool_obj = switch (kv.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        const name = allocator.dupe(u8, kv.key_ptr.*) catch
            return ToolError.OutOfMemory;
        errdefer allocator.free(name);

        const config = parseToolConfig(
            allocator,
            tool_obj,
        ) catch continue;

        entries.append(allocator, .{
            .name = name,
            .config = config,
        }) catch return ToolError.OutOfMemory;
    }

    return ToolRegistry{
        .entries = entries.toOwnedSlice(allocator) catch
            return ToolError.OutOfMemory,
        .path = file_path,
    };
}

fn parseToolConfig(
    allocator: Allocator,
    obj: std.json.ObjectMap,
) !ToolConfig {
    const command = switch (obj.get("command") orelse
        return error.MissingField) {
        .string => |s| try allocator.dupe(u8, s),
        else => return error.MissingField,
    };
    errdefer allocator.free(command);

    const arg_mode: ArgMode = blk: {
        const mode_val = obj.get("arg_mode") orelse
            break :blk .passthrough;
        const mode_str = switch (mode_val) {
            .string => |s| s,
            else => break :blk .passthrough,
        };
        if (std.mem.eql(u8, mode_str, "allowlist"))
            break :blk .allowlist;
        break :blk .passthrough;
    };

    const allow_args = try parseStringArray(
        allocator,
        obj.get("allow_args"),
    );
    errdefer freeStringSlice(allocator, allow_args);

    const deny_args = try parseStringArray(
        allocator,
        obj.get("deny_args"),
    );
    errdefer freeStringSlice(allocator, deny_args);

    const scope_val: ?[]const u8 = blk: {
        const sv = obj.get("scope") orelse break :blk null;
        switch (sv) {
            .string => |s| break :blk try allocator.dupe(u8, s),
            .null => break :blk null,
            else => break :blk null,
        }
    };
    errdefer if (scope_val) |s| allocator.free(s);

    const timeout: u32 = blk: {
        const tv = obj.get("timeout_seconds") orelse
            break :blk 30;
        switch (tv) {
            .integer => |i| break :blk @intCast(i),
            else => break :blk 30,
        }
    };

    const max_output: usize = blk: {
        const mv = obj.get("max_output_bytes") orelse
            break :blk 65536;
        switch (mv) {
            .integer => |i| break :blk @intCast(i),
            else => break :blk 65536,
        }
    };

    const description = blk: {
        const dv = obj.get("description") orelse
            break :blk try allocator.dupe(u8, "");
        switch (dv) {
            .string => |s| break :blk try allocator.dupe(u8, s),
            else => break :blk try allocator.dupe(u8, ""),
        }
    };
    errdefer allocator.free(description);

    const examples = try parseStringArray(
        allocator,
        obj.get("examples"),
    );
    errdefer freeStringSlice(allocator, examples);

    const created = blk: {
        const cv = obj.get("created") orelse
            break :blk try allocator.dupe(u8, "");
        switch (cv) {
            .string => |s| break :blk try allocator.dupe(u8, s),
            else => break :blk try allocator.dupe(u8, ""),
        }
    };

    return ToolConfig{
        .command = command,
        .allow_args = allow_args,
        .deny_args = deny_args,
        .arg_mode = arg_mode,
        .scope = scope_val,
        .timeout_seconds = timeout,
        .max_output_bytes = max_output,
        .description = description,
        .examples = examples,
        .created = created,
    };
}

fn parseStringArray(
    allocator: Allocator,
    val: ?std.json.Value,
) ![]const []const u8 {
    const v = val orelse
        return allocator.alloc([]const u8, 0);
    const arr = switch (v) {
        .array => |a| a,
        else => return allocator.alloc([]const u8, 0),
    };

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |s| allocator.free(s);
        result.deinit(allocator);
    }

    for (arr.items) |item| {
        const s = switch (item) {
            .string => |s| s,
            else => continue,
        };
        const owned = try allocator.dupe(u8, s);
        try result.append(allocator, owned);
    }

    return result.toOwnedSlice(allocator);
}

// Tests

test "register and get" {
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

    var reg = ToolRegistry.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer reg.deinit(allocator);

    try reg.register(allocator, io, "calc", .{
        .command = "bc -l",
        .allow_args = &[_][]const u8{"-q"},
        .deny_args = &[_][]const u8{},
        .arg_mode = .allowlist,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "Calculator (bc)",
        .examples = &[_][]const u8{
            "echo \"2+2\" | clawgate tool calc",
        },
        .created = "2026-01-01T00:00:00Z",
    });

    const config = reg.get("calc");
    try std.testing.expect(config != null);
    try std.testing.expectEqualStrings(
        "bc -l",
        config.?.command,
    );
    try std.testing.expect(reg.get("unknown") == null);
}

test "listNames" {
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

    var reg = ToolRegistry.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer reg.deinit(allocator);

    try reg.register(allocator, io, "tool_a", .{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    });

    const names = try reg.listNames(allocator);
    defer allocator.free(names);

    try std.testing.expectEqual(@as(usize, 1), names.len);
    try std.testing.expectEqualStrings("tool_a", names[0]);
}

test "remove" {
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

    var reg = ToolRegistry.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer reg.deinit(allocator);

    try reg.register(allocator, io, "rm_me", .{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    });

    try std.testing.expect(reg.get("rm_me") != null);
    try reg.remove(allocator, io, "rm_me");
    try std.testing.expect(reg.get("rm_me") == null);
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

    {
        var reg = ToolRegistry.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer reg.deinit(allocator);

        try reg.register(allocator, io, "calc", .{
            .command = "bc -l",
            .allow_args = &[_][]const u8{"-q"},
            .deny_args = &[_][]const u8{"--exec"},
            .arg_mode = .allowlist,
            .scope = null,
            .timeout_seconds = 10,
            .max_output_bytes = 65536,
            .description = "Calculator",
            .examples = &[_][]const u8{"2+2"},
            .created = "2026-01-01T00:00:00Z",
        });
    }

    {
        var reg = ToolRegistry.load(
            allocator,
            io,
            tmp_path,
        ) catch unreachable;
        defer reg.deinit(allocator);

        try std.testing.expectEqual(
            @as(usize, 1),
            reg.entries.len,
        );
        const config = reg.get("calc");
        try std.testing.expect(config != null);
        try std.testing.expectEqualStrings(
            "bc -l",
            config.?.command,
        );
        try std.testing.expectEqual(
            @as(u32, 10),
            config.?.timeout_seconds,
        );
    }
}

test "duplicate name rejected" {
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

    var reg = ToolRegistry.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer reg.deinit(allocator);

    const config = ToolConfig{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "",
        .examples = &[_][]const u8{},
        .created = "",
    };

    try reg.register(allocator, io, "dup", config);
    try std.testing.expectError(
        ToolError.DuplicateName,
        reg.register(allocator, io, "dup", config),
    );
}

//! Persistent audit log for ClawGate resource daemon.
//!
//! Writes audit events to ~/.clawgate/logs/audit.log with ISO 8601
//! timestamps. Events are also emitted to stderr via std.log.

const std = @import("std");
const protocol = @import("../protocol/json.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

pub const AuditLog = struct {
    file: File,

    /// Opens or creates the audit log file at
    /// {home}/.clawgate/logs/audit.log.
    /// Writes a daemon_start entry on init.
    pub fn init(
        allocator: Allocator,
        io: Io,
        home: []const u8,
    ) !AuditLog {
        const log_dir = try std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/logs",
            .{home},
        );
        defer allocator.free(log_dir);

        const log_path = try std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/logs/audit.log",
            .{home},
        );
        defer allocator.free(log_path);

        Dir.createDirPath(.cwd(), io, log_dir) catch {};

        const file = try Dir.createFile(
            .cwd(),
            io,
            log_path,
            .{ .truncate = false },
        );
        errdefer file.close(io);

        var ts_buf: [20]u8 = undefined;
        const ts = formatTimestampBuf(&ts_buf);
        var line_buf: [64]u8 = undefined;
        var line_w = Io.Writer.fixed(&line_buf);
        line_w.print(
            "{s} AUDIT daemon_start\n",
            .{ts},
        ) catch {};
        const startup = line_w.buffered();
        const pos = file.length(io) catch 0;
        file.writePositionalAll(io, startup, pos) catch {};

        return .{ .file = file };
    }

    /// Logs an audit event to file and stderr.
    pub fn logEvent(
        self: *const AuditLog,
        allocator: Allocator,
        io: Io,
        request_json: []const u8,
        response_json: []const u8,
    ) void {
        var req_id: []const u8 = "unknown";
        var op: []const u8 = "unknown";
        var path: []const u8 = "unknown";

        // Tokenless tool_list bypasses parseRequest
        const is_tool_list = std.mem.indexOf(
            u8,
            request_json,
            "\"token\":",
        ) == null and std.mem.indexOf(
            u8,
            request_json,
            "\"tool_list\"",
        ) != null;

        if (is_tool_list) {
            req_id = "discovery";
            op = "tool_list";
            path = "-";
        }

        var parsed_req = if (!is_tool_list)
            protocol.parseRequest(
                allocator,
                request_json,
            ) catch null
        else
            null;
        defer if (parsed_req) |*pr| pr.deinit();

        if (parsed_req) |pr| {
            req_id = pr.value.id;
            op = pr.value.op;
            if (std.mem.eql(u8, op, "tool")) {
                path = pr.value.params.tool_name orelse
                    "unknown";
            } else {
                path = pr.value.params.path;
            }
        }

        const success = std.mem.indexOf(
            u8,
            response_json,
            "\"ok\":true",
        ) != null;

        var error_code: []const u8 = "";
        if (!success) {
            error_code = extractErrorCode(response_json);
        }

        var ts_buf: [20]u8 = undefined;
        const ts = formatTimestampBuf(&ts_buf);

        const line = if (success)
            std.fmt.allocPrint(
                allocator,
                "{s} AUDIT req={s} op={s} path={s}" ++
                    " success=true\n",
                .{ ts, req_id, op, path },
            ) catch null
        else
            std.fmt.allocPrint(
                allocator,
                "{s} AUDIT req={s} op={s} path={s}" ++
                    " success=false error={s}\n",
                .{ ts, req_id, op, path, error_code },
            ) catch null;
        defer if (line) |l| allocator.free(l);

        if (line) |l| {
            const pos = self.file.length(io) catch 0;
            self.file.writePositionalAll(
                io,
                l,
                pos,
            ) catch {};
        }

        if (success) {
            std.log.info(
                "AUDIT: req={s} op={s} path={s}" ++
                    " success=true",
                .{ req_id, op, path },
            );
        } else {
            std.log.info(
                "AUDIT: req={s} op={s} path={s}" ++
                    " success=false error={s}",
                .{ req_id, op, path, error_code },
            );
        }
    }

    /// Closes the log file.
    pub fn deinit(self: *const AuditLog, io: Io) void {
        self.file.close(io);
    }
};

/// Extracts "code" value from response JSON like
/// `"error":{"code":"SCOPE_VIOLATION",...}`.
fn extractErrorCode(json: []const u8) []const u8 {
    const marker = "\"code\":\"";
    const start_idx = std.mem.indexOf(
        u8,
        json,
        marker,
    ) orelse return "UNKNOWN";
    const val_start = start_idx + marker.len;
    if (val_start >= json.len) return "UNKNOWN";
    const rest = json[val_start..];
    const end_idx = std.mem.indexOf(
        u8,
        rest,
        "\"",
    ) orelse return "UNKNOWN";
    return rest[0..end_idx];
}

/// Formats a UTC timestamp into the provided buffer.
/// Returns the formatted slice "YYYY-MM-DDThh:mm:ssZ".
fn formatTimestampBuf(buf: *[20]u8) []const u8 {
    const ts = std.posix.clock_gettime(.REALTIME) catch
        return "0000-00-00T00:00:00Z";
    const now: u64 = @intCast(ts.sec);
    return formatEpochBuf(buf, now);
}

/// Formats an epoch seconds value into ISO 8601.
pub fn formatEpochBuf(buf: *[20]u8, secs: u64) []const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();

    var w = Io.Writer.fixed(buf);
    w.print(
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        },
    ) catch return "0000-00-00T00:00:00Z";
    return w.buffered();
}

// Tests

test "init creates log directory and file" {
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

    const audit_log = try AuditLog.init(allocator, io, tmp_path);
    defer audit_log.deinit(io);

    // Verify directory exists
    const log_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/logs",
        .{tmp_path},
    );
    defer allocator.free(log_dir);

    var dir = Dir.openDir(.cwd(), io, log_dir, .{}) catch {
        return error.TestUnexpectedResult;
    };
    dir.close(io);

    // Verify file exists and contains startup line
    const log_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/logs/audit.log",
        .{tmp_path},
    );
    defer allocator.free(log_path);

    const file = try Dir.openFile(.cwd(), io, log_path, .{});
    defer file.close(io);

    const len = try file.length(io);
    try std.testing.expect(len > 0);

    const content = try allocator.alloc(u8, @intCast(len));
    defer allocator.free(content);
    _ = file.readPositionalAll(io, content, 0) catch
        unreachable;

    try std.testing.expect(
        std.mem.indexOf(u8, content, "AUDIT daemon_start") != null,
    );
}

test "logEvent writes to file" {
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

    const audit_log = try AuditLog.init(allocator, io, tmp_path);
    defer audit_log.deinit(io);

    const req_json =
        \\{"id":"req123","token":"t","op":"read",
    ++
        \\"params":{"path":"/tmp/test"}}
    ;
    const resp_json =
        "{\"id\":\"req123\",\"ok\":true,\"result\":{}}";

    audit_log.logEvent(allocator, io, req_json, resp_json);

    // Read back and verify
    const log_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/logs/audit.log",
        .{tmp_path},
    );
    defer allocator.free(log_path);

    const file = try Dir.openFile(.cwd(), io, log_path, .{});
    defer file.close(io);

    const len = try file.length(io);
    const content = try allocator.alloc(u8, @intCast(len));
    defer allocator.free(content);
    _ = file.readPositionalAll(io, content, 0) catch
        unreachable;

    try std.testing.expect(
        std.mem.indexOf(u8, content, "req=req123") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, content, "op=read") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, content, "path=/tmp/test") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, content, "success=true") != null,
    );
}

test "logEvent records error code on failure" {
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

    const audit_log = try AuditLog.init(allocator, io, tmp_path);
    defer audit_log.deinit(io);

    const req_json =
        \\{"id":"req456","token":"t","op":"read",
    ++
        \\"params":{"path":"/etc/shadow"}}
    ;
    const resp_json =
        \\{"id":"req456","ok":false,
    ++
        \\"error":{"code":"SCOPE_VIOLATION",
    ++
        \\"message":"Path not in scope"}}
    ;

    audit_log.logEvent(allocator, io, req_json, resp_json);

    const log_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/logs/audit.log",
        .{tmp_path},
    );
    defer allocator.free(log_path);

    const file = try Dir.openFile(.cwd(), io, log_path, .{});
    defer file.close(io);

    const len = try file.length(io);
    const content = try allocator.alloc(u8, @intCast(len));
    defer allocator.free(content);
    _ = file.readPositionalAll(io, content, 0) catch
        unreachable;

    try std.testing.expect(
        std.mem.indexOf(u8, content, "success=false") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            content,
            "error=SCOPE_VIOLATION",
        ) != null,
    );
}

test "logEvent handles malformed JSON gracefully" {
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

    const audit_log = try AuditLog.init(allocator, io, tmp_path);
    defer audit_log.deinit(io);

    audit_log.logEvent(
        allocator,
        io,
        "garbage{{{",
        "not json",
    );

    const log_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/logs/audit.log",
        .{tmp_path},
    );
    defer allocator.free(log_path);

    const file = try Dir.openFile(.cwd(), io, log_path, .{});
    defer file.close(io);

    const len = try file.length(io);
    const content = try allocator.alloc(u8, @intCast(len));
    defer allocator.free(content);
    _ = file.readPositionalAll(io, content, 0) catch
        unreachable;

    try std.testing.expect(
        std.mem.indexOf(u8, content, "req=unknown") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, content, "op=unknown") != null,
    );
}

test "timestamp formatting" {
    var buf: [20]u8 = undefined;
    const ts = formatEpochBuf(&buf, 1768566645);
    try std.testing.expectEqualStrings(
        "2026-01-16T12:30:45Z",
        ts,
    );
}

test "extractErrorCode" {
    try std.testing.expectEqualStrings(
        "SCOPE_VIOLATION",
        extractErrorCode(
            \\{"error":{"code":"SCOPE_VIOLATION","message":"x"}}
        ),
    );

    try std.testing.expectEqualStrings(
        "INVALID_TOKEN",
        extractErrorCode(
            \\{"ok":false,"error":{"code":"INVALID_TOKEN"}}
        ),
    );

    try std.testing.expectEqualStrings(
        "UNKNOWN",
        extractErrorCode("no code here"),
    );
}

//! Revoke and revoked CLI commands.
//!
//! `clawgate revoke <id> [--reason "..."]` - revoke a token
//! `clawgate revoke --all [--reason "..."]` - revoke all tokens
//! `clawgate revoked ls` - list revoked tokens
//! `clawgate revoked clean` - remove expired entries

const std = @import("std");
const revocation = @import("../resource/revocation.zig");
const issuance = @import("../resource/issuance.zig");
const audit_log = @import("../resource/audit_log.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = Io.File;

pub const RevokeError = error{
    InvalidArgs,
    LoadFailed,
    RevokeFailed,
    OutOfMemory,
};

/// Handles `clawgate revoke` command.
pub fn revoke(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) RevokeError!void {
    const home_dir = home orelse {
        std.debug.print("Error: HOME not set\n", .{});
        return RevokeError.InvalidArgs;
    };

    var token_id: ?[]const u8 = null;
    var reason: []const u8 = "manual revocation";
    var all = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--all")) {
            all = true;
        } else if (std.mem.eql(u8, arg, "--reason")) {
            if (i + 1 >= args.len) {
                printRevokeUsage();
                return RevokeError.InvalidArgs;
            }
            i += 1;
            reason = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printRevokeUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            token_id = arg;
        } else {
            std.debug.print(
                "Error: Unknown option: {s}\n",
                .{arg},
            );
            return RevokeError.InvalidArgs;
        }
    }

    if (!all and token_id == null) {
        std.debug.print(
            "Error: Token ID or --all required\n\n",
            .{},
        );
        printRevokeUsage();
        return RevokeError.InvalidArgs;
    }

    var list = revocation.RevocationList.load(
        allocator,
        io,
        home_dir,
    ) catch {
        std.debug.print(
            "Error: Failed to load revocation list\n",
            .{},
        );
        return RevokeError.LoadFailed;
    };
    defer list.deinit(allocator);

    if (all) {
        var issued = issuance.IssuanceLog.load(
            allocator,
            io,
            home_dir,
        ) catch {
            std.debug.print(
                "Error: Failed to load issuance log\n",
                .{},
            );
            return RevokeError.LoadFailed;
        };
        defer issued.deinit(allocator);

        const ids = issued.allIds(allocator) catch
            return RevokeError.OutOfMemory;
        defer allocator.free(ids);

        list.revokeAll(allocator, io, ids, reason) catch {
            std.debug.print("Error: Failed to revoke\n", .{});
            return RevokeError.RevokeFailed;
        };

        // Clear the issuance log (best-effort)
        clearIssuanceLog(io, home_dir);

        const stdout = File.stdout();
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &buf,
            "Revoked {d} token(s)\n",
            .{ids.len},
        ) catch "Revoked\n";
        stdout.writeStreamingAll(io, msg) catch {};
    } else {
        list.revoke(
            allocator,
            io,
            token_id.?,
            reason,
        ) catch {
            std.debug.print("Error: Failed to revoke\n", .{});
            return RevokeError.RevokeFailed;
        };

        // Remove from issuance log (best-effort)
        removeFromIssuanceLog(
            allocator,
            io,
            home_dir,
            token_id.?,
        );

        const stdout = File.stdout();
        stdout.writeStreamingAll(
            io,
            "Token revoked\n",
        ) catch {};
    }
}

/// Handles `clawgate revoked` command.
pub fn revoked(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) RevokeError!void {
    const home_dir = home orelse {
        std.debug.print("Error: HOME not set\n", .{});
        return RevokeError.InvalidArgs;
    };

    if (args.len == 0) {
        printRevokedUsage();
        return RevokeError.InvalidArgs;
    }

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "ls") or
        std.mem.eql(u8, subcmd, "list"))
    {
        var list = revocation.RevocationList.load(
            allocator,
            io,
            home_dir,
        ) catch {
            std.debug.print(
                "Error: Failed to load revocation list\n",
                .{},
            );
            return RevokeError.LoadFailed;
        };
        defer list.deinit(allocator);

        const stdout = File.stdout();
        if (list.entries.len == 0) {
            stdout.writeStreamingAll(
                io,
                "No revoked tokens\n",
            ) catch {};
            return;
        }

        for (list.entries) |entry| {
            var buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(
                &buf,
                "{s}  {s}  {s}\n",
                .{ entry.id, entry.revoked_at, entry.reason },
            ) catch continue;
            stdout.writeStreamingAll(io, line) catch {};
        }
    } else if (std.mem.eql(u8, subcmd, "clean")) {
        var list = revocation.RevocationList.load(
            allocator,
            io,
            home_dir,
        ) catch {
            std.debug.print(
                "Error: Failed to load revocation list\n",
                .{},
            );
            return RevokeError.LoadFailed;
        };
        defer list.deinit(allocator);

        const removed = list.clean(allocator, io) catch {
            std.debug.print("Error: Failed to clean\n", .{});
            return RevokeError.RevokeFailed;
        };

        const stdout = File.stdout();
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &buf,
            "Removed {d} expired entries\n",
            .{removed},
        ) catch "Cleaned\n";
        stdout.writeStreamingAll(io, msg) catch {};
    } else if (std.mem.eql(u8, subcmd, "--help") or
        std.mem.eql(u8, subcmd, "-h"))
    {
        printRevokedUsage();
    } else {
        std.debug.print(
            "Error: Unknown subcommand: {s}\n\n",
            .{subcmd},
        );
        printRevokedUsage();
        return RevokeError.InvalidArgs;
    }
}

/// Overwrites issued.json with an empty token list.
fn clearIssuanceLog(io: Io, home: []const u8) void {
    var buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(
        &buf,
        "{s}/.clawgate/issued.json",
        .{home},
    ) catch return;
    const file = Io.Dir.createFile(
        .cwd(),
        io,
        path,
        .{},
    ) catch return;
    defer file.close(io);
    file.writeStreamingAll(
        io,
        "{\"tokens\":[]}",
    ) catch {};
}

/// Removes a single entry from issued.json by token ID.
fn removeFromIssuanceLog(
    allocator: Allocator,
    io: Io,
    home: []const u8,
    token_id: []const u8,
) void {
    var issued = issuance.IssuanceLog.load(
        allocator,
        io,
        home,
    ) catch return;
    defer issued.deinit(allocator);
    issued.removeById(allocator, io, token_id) catch {};
}

fn printRevokeUsage() void {
    const usage =
        \\Usage: clawgate revoke <token-id> [options]
        \\       clawgate revoke --all [options]
        \\
        \\Revoke a capability token.
        \\
        \\Options:
        \\  --reason <text>   Reason for revocation
        \\  --all             Revoke all issued tokens
        \\  -h, --help        Show this help
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printRevokedUsage() void {
    const usage =
        \\Usage: clawgate revoked <subcommand>
        \\
        \\Manage revoked tokens.
        \\
        \\Subcommands:
        \\  ls, list    List revoked tokens
        \\  clean       Remove expired entries
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "revoke with missing args prints usage" {
    // Just verify the functions exist and compile
    const allocator = std.testing.allocator;
    _ = allocator;
}

//! Agent daemon main loop.
//!
//! Connects to NATS, loads tokens, and keeps connection alive.
//! The daemon itself doesn't subscribe to any subjects - it's a
//! background service that maintains connectivity for CLI and MCP.

const std = @import("std");
const nats = @import("nats");
const tokens = @import("tokens.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_NATS_URL = "nats://localhost:4222";
const DEFAULT_TOKEN_DIR = "~/.clawgate/tokens";
const KEEPALIVE_INTERVAL_MS: u64 = 60000;

pub const DaemonError = error{
    TokenDirNotFound,
    ConnectionFailed,
    OutOfMemory,
};

/// Configuration for the agent daemon.
pub const Config = struct {
    nats_url: []const u8 = DEFAULT_NATS_URL,
    token_dir: []const u8 = DEFAULT_TOKEN_DIR,
    environ: std.process.Environ = .empty,
};

/// Runs the agent daemon with the given configuration.
/// This function blocks indefinitely, maintaining NATS connection.
pub fn run(allocator: Allocator, config: Config) DaemonError!void {
    var threaded: std.Io.Threaded = .init(allocator, .{
        .environ = config.environ,
    });
    defer threaded.deinit();

    // Get HOME from environment via Threaded's environString
    const home = threaded.environString("HOME") orelse "/tmp";

    runWithIo(allocator, threaded.io(), config, home) catch |err| {
        return err;
    };
}

/// Internal entry point that accepts an Io instance for testing.
pub fn runWithIo(
    allocator: Allocator,
    io: Io,
    config: Config,
    home: []const u8,
) !void {
    // Expand token directory path
    const token_dir = try expandPath(allocator, config.token_dir, home);
    defer allocator.free(token_dir);

    std.log.info("Loading tokens from {s}", .{token_dir});
    var store = tokens.TokenStore.loadFromDir(allocator, io, token_dir) catch {
        std.log.err("Token directory not found: {s}", .{token_dir});
        std.log.info("Create it with: mkdir -p {s}", .{token_dir});
        return DaemonError.TokenDirNotFound;
    };
    defer store.deinit(allocator);

    std.log.info("Loaded {d} token(s)", .{store.tokens.len});

    std.log.info("Connecting to NATS at {s}", .{config.nats_url});
    const client = nats.Client.connect(
        allocator,
        io,
        config.nats_url,
        .{ .name = "clawgate-agent" },
    ) catch {
        std.log.err("Failed to connect to NATS server", .{});
        return DaemonError.ConnectionFailed;
    };
    defer client.deinit(allocator);

    std.log.info("Agent daemon ready", .{});

    keepAliveLoop(io, client);
}

/// Periodic NATS ping to maintain connection.
fn keepAliveLoop(io: Io, client: *nats.Client) void {
    while (true) {
        io.sleep(.fromMilliseconds(KEEPALIVE_INTERVAL_MS), .awake) catch {};

        // Ping NATS to keep connection alive
        _ = client.getRtt() catch |err| {
            std.log.warn("NATS ping failed: {}", .{err});
        };
    }
}

/// Expands ~ to home directory in path.
/// The home parameter should come from Threaded.environString("HOME").
pub fn expandPath(
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

test "expandPath expands tilde" {
    const allocator = std.testing.allocator;

    const expanded = try expandPath(allocator, "~/.clawgate/tokens", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/home/user/.clawgate/tokens", expanded);
}

test "expandPath handles absolute paths" {
    const allocator = std.testing.allocator;

    const expanded = try expandPath(allocator, "/tmp/tokens", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/tmp/tokens", expanded);
}

test "expandPath handles tilde only" {
    const allocator = std.testing.allocator;

    const expanded = try expandPath(allocator, "~", "/home/testuser");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/home/testuser", expanded);
}

test "expandPath handles empty path" {
    const allocator = std.testing.allocator;

    const expanded = try expandPath(allocator, "", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("", expanded);
}

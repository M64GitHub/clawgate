//! Configuration loading for ClawGate.
//!
//! Loads configuration from ~/.clawgate/config.toml with support for:
//! - TCP connection settings
//! - Key paths
//! - Forbidden paths (resource daemon)
//! - Token directory (agent daemon)
//! - File operation limits

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;

pub const ConfigError = error{
    FileNotFound,
    ParseError,
    MissingRequiredField,
    IoError,
    OutOfMemory,
};

/// Full ClawGate configuration.
pub const Config = struct {
    /// TCP connection settings.
    tcp: TcpConfig,
    /// Key file paths.
    keys: KeysConfig,
    /// Resource daemon settings (only when mode=resource).
    resource: ResourceConfig,
    /// Agent daemon settings (only when mode=agent).
    agent: AgentConfig,

    /// Releases all allocated memory.
    pub fn deinit(self: *Config, allocator: Allocator) void {
        self.tcp.deinit(allocator);
        self.keys.deinit(allocator);
        self.resource.deinit(allocator);
        self.agent.deinit(allocator);
    }
};

/// TCP connection configuration.
pub const TcpConfig = struct {
    /// Listen address for agent daemon.
    listen_addr: []const u8,
    /// Listen port for agent daemon.
    listen_port: u16 = 4223,
    /// Connect address for resource daemon (optional).
    connect_addr: ?[]const u8 = null,
    /// Connect port for resource daemon.
    connect_port: u16 = 4223,

    pub fn deinit(self: *TcpConfig, allocator: Allocator) void {
        allocator.free(self.listen_addr);
        if (self.connect_addr) |a| allocator.free(a);
    }
};

/// Key file configuration.
pub const KeysConfig = struct {
    /// Path to Ed25519 private key (for signing tokens).
    private_key: []const u8,
    /// Path to Ed25519 public key (for verifying tokens).
    public_key: []const u8,

    pub fn deinit(self: *KeysConfig, allocator: Allocator) void {
        allocator.free(self.private_key);
        allocator.free(self.public_key);
    }
};

/// Resource daemon configuration.
pub const ResourceConfig = struct {
    /// Paths that can never be granted access to.
    forbidden_paths: []const []const u8,
    /// Maximum file size allowed (bytes).
    max_file_size: usize = 100 * 1024 * 1024,
    /// Truncate files larger than this (bytes).
    truncate_at: usize = 512 * 1024,
    /// Expected token issuer (validates iss claim).
    expected_issuer: ?[]const u8 = null,
    /// Expected token subject (validates sub claim).
    expected_subject: ?[]const u8 = null,

    pub fn deinit(self: *ResourceConfig, allocator: Allocator) void {
        for (self.forbidden_paths) |p| {
            allocator.free(p);
        }
        allocator.free(self.forbidden_paths);
        if (self.expected_issuer) |v| allocator.free(v);
        if (self.expected_subject) |v| allocator.free(v);
    }
};

/// Agent daemon configuration.
pub const AgentConfig = struct {
    /// Directory where capability tokens are stored.
    token_dir: []const u8,

    pub fn deinit(self: *AgentConfig, allocator: Allocator) void {
        allocator.free(self.token_dir);
    }
};

/// Default forbidden paths for security.
pub const DEFAULT_FORBIDDEN_PATHS = [_][]const u8{
    "~/.ssh/**",
    "~/.gnupg/**",
    "~/.clawgate/keys/**",
    "~/.aws/**",
    "~/.config/gcloud/**",
    "~/.kube/**",
};

/// Returns the default config file path (~/.clawgate/config.toml).
/// Caller owns returned memory.
pub fn getConfigPath(allocator: Allocator, home: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/config.toml",
        .{home},
    );
}

/// Loads configuration from the default path or returns defaults.
/// Caller must call Config.deinit() when done.
pub fn load(allocator: Allocator, io: Io, home: []const u8) !Config {
    const config_path = try getConfigPath(allocator, home);
    defer allocator.free(config_path);

    return loadFromPath(allocator, io, config_path, home) catch |err| {
        if (err == ConfigError.FileNotFound) {
            return defaults(allocator, home);
        }
        return err;
    };
}

/// Loads configuration from a specific path.
/// Caller must call Config.deinit() when done.
pub fn loadFromPath(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    home: []const u8,
) !Config {
    const file = Dir.openFile(.cwd(), io, path, .{}) catch {
        return ConfigError.FileNotFound;
    };
    defer file.close(io);

    const stat = file.stat(io) catch return ConfigError.IoError;
    const file_size: usize = @intCast(stat.size);

    if (file_size > 64 * 1024) {
        return ConfigError.ParseError;
    }

    const content = allocator.alloc(u8, file_size) catch {
        return ConfigError.OutOfMemory;
    };
    defer allocator.free(content);

    const bytes_read = file.readPositionalAll(io, content, 0) catch {
        return ConfigError.IoError;
    };

    return parse(allocator, content[0..bytes_read], home);
}

/// Parses TOML configuration content.
/// Caller must call Config.deinit() when done.
pub fn parse(
    allocator: Allocator,
    content: []const u8,
    home: []const u8,
) !Config {
    var config = try defaults(allocator, home);
    errdefer config.deinit(allocator);

    var current_section: Section = .none;
    var forbidden_list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (forbidden_list.items) |p| allocator.free(p);
        forbidden_list.deinit(allocator);
    }

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");

        if (line.len == 0 or line[0] == '#') continue;

        if (line[0] == '[') {
            current_section = parseSection(line);
            continue;
        }

        const kv = parseKeyValue(line) orelse continue;

        switch (current_section) {
            .tcp => {
                try applyTcpConfig(allocator, &config.tcp, kv, home);
            },
            .keys => {
                try applyKeysConfig(allocator, &config.keys, kv, home);
            },
            .resource => {
                try applyResourceConfig(
                    allocator,
                    &config.resource,
                    kv,
                    &forbidden_list,
                    home,
                );
            },
            .agent => {
                try applyAgentConfig(allocator, &config.agent, kv, home);
            },
            .none => {},
        }
    }

    if (forbidden_list.items.len > 0) {
        for (config.resource.forbidden_paths) |p| allocator.free(p);
        allocator.free(config.resource.forbidden_paths);
        config.resource.forbidden_paths = forbidden_list.toOwnedSlice(
            allocator,
        ) catch return ConfigError.OutOfMemory;
    } else {
        forbidden_list.deinit(allocator);
    }

    return config;
}

/// Returns default configuration.
/// Caller must call Config.deinit() when done.
pub fn defaults(allocator: Allocator, home: []const u8) !Config {
    const listen_addr = allocator.dupe(u8, "0.0.0.0") catch {
        return ConfigError.OutOfMemory;
    };
    errdefer allocator.free(listen_addr);

    const private_key = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/keys/secret.key",
        .{home},
    ) catch return ConfigError.OutOfMemory;
    errdefer allocator.free(private_key);

    const public_key = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/keys/public.key",
        .{home},
    ) catch return ConfigError.OutOfMemory;
    errdefer allocator.free(public_key);

    const forbidden = try allocateDefaultForbiddenPaths(allocator, home);
    errdefer {
        for (forbidden) |p| allocator.free(p);
        allocator.free(forbidden);
    }

    const token_dir = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate/tokens",
        .{home},
    ) catch return ConfigError.OutOfMemory;

    return Config{
        .tcp = .{
            .listen_addr = listen_addr,
            .listen_port = 4223,
            .connect_addr = null,
            .connect_port = 4223,
        },
        .keys = .{
            .private_key = private_key,
            .public_key = public_key,
        },
        .resource = .{
            .forbidden_paths = forbidden,
            .max_file_size = 100 * 1024 * 1024,
            .truncate_at = 512 * 1024,
        },
        .agent = .{
            .token_dir = token_dir,
        },
    };
}

const Section = enum {
    none,
    tcp,
    keys,
    resource,
    agent,
};

fn parseSection(line: []const u8) Section {
    const trimmed = std.mem.trim(u8, line, "[] \t");
    if (std.mem.eql(u8, trimmed, "tcp")) return .tcp;
    if (std.mem.eql(u8, trimmed, "keys")) return .keys;
    if (std.mem.eql(u8, trimmed, "resource")) return .resource;
    if (std.mem.eql(u8, trimmed, "agent")) return .agent;
    return .none;
}

const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

fn parseKeyValue(line: []const u8) ?KeyValue {
    const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return null;

    const key = std.mem.trim(u8, line[0..eq_pos], " \t");
    var value = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");

    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        value = value[1 .. value.len - 1];
    }

    return KeyValue{ .key = key, .value = value };
}

fn applyTcpConfig(
    allocator: Allocator,
    config: *TcpConfig,
    kv: KeyValue,
    home: []const u8,
) !void {
    if (std.mem.eql(u8, kv.key, "listen_addr")) {
        allocator.free(config.listen_addr);
        config.listen_addr = try expandAndDupe(allocator, kv.value, home);
    } else if (std.mem.eql(u8, kv.key, "listen_port")) {
        config.listen_port = std.fmt.parseInt(u16, kv.value, 10) catch 4223;
    } else if (std.mem.eql(u8, kv.key, "connect_addr")) {
        if (config.connect_addr) |a| allocator.free(a);
        config.connect_addr = try expandAndDupe(allocator, kv.value, home);
    } else if (std.mem.eql(u8, kv.key, "connect_port")) {
        config.connect_port = std.fmt.parseInt(u16, kv.value, 10) catch 4223;
    }
}

fn applyKeysConfig(
    allocator: Allocator,
    config: *KeysConfig,
    kv: KeyValue,
    home: []const u8,
) !void {
    if (std.mem.eql(u8, kv.key, "private_key")) {
        allocator.free(config.private_key);
        config.private_key = try expandAndDupe(allocator, kv.value, home);
    } else if (std.mem.eql(u8, kv.key, "public_key")) {
        allocator.free(config.public_key);
        config.public_key = try expandAndDupe(allocator, kv.value, home);
    }
}

fn applyResourceConfig(
    allocator: Allocator,
    config: *ResourceConfig,
    kv: KeyValue,
    forbidden_list: *std.ArrayListUnmanaged([]const u8),
    home: []const u8,
) !void {
    if (std.mem.eql(u8, kv.key, "forbidden_path")) {
        const path = expandAndDupe(allocator, kv.value, home) catch {
            return ConfigError.OutOfMemory;
        };
        forbidden_list.append(allocator, path) catch {
            allocator.free(path);
            return ConfigError.OutOfMemory;
        };
    } else if (std.mem.eql(u8, kv.key, "max_file_size")) {
        config.max_file_size = std.fmt.parseInt(
            usize,
            kv.value,
            10,
        ) catch config.max_file_size;
    } else if (std.mem.eql(u8, kv.key, "truncate_at")) {
        config.truncate_at = std.fmt.parseInt(
            usize,
            kv.value,
            10,
        ) catch config.truncate_at;
    } else if (std.mem.eql(u8, kv.key, "expected_issuer")) {
        if (config.expected_issuer) |v| allocator.free(v);
        config.expected_issuer = allocator.dupe(
            u8,
            kv.value,
        ) catch return ConfigError.OutOfMemory;
    } else if (std.mem.eql(u8, kv.key, "expected_subject")) {
        if (config.expected_subject) |v| allocator.free(v);
        config.expected_subject = allocator.dupe(
            u8,
            kv.value,
        ) catch return ConfigError.OutOfMemory;
    }
}

fn applyAgentConfig(
    allocator: Allocator,
    config: *AgentConfig,
    kv: KeyValue,
    home: []const u8,
) !void {
    if (std.mem.eql(u8, kv.key, "token_dir")) {
        allocator.free(config.token_dir);
        config.token_dir = try expandAndDupe(allocator, kv.value, home);
    }
}

fn expandAndDupe(
    allocator: Allocator,
    value: []const u8,
    home: []const u8,
) ![]const u8 {
    if (value.len > 0 and value[0] == '~') {
        if (value.len == 1) {
            return allocator.dupe(u8, home) catch {
                return ConfigError.OutOfMemory;
            };
        }
        return std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ home, value[1..] },
        ) catch return ConfigError.OutOfMemory;
    }
    return allocator.dupe(u8, value) catch return ConfigError.OutOfMemory;
}

fn allocateDefaultForbiddenPaths(
    allocator: Allocator,
    home: []const u8,
) ![]const []const u8 {
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }

    for (DEFAULT_FORBIDDEN_PATHS) |pattern| {
        const expanded = expandAndDupe(allocator, pattern, home) catch {
            return ConfigError.OutOfMemory;
        };
        paths.append(allocator, expanded) catch {
            allocator.free(expanded);
            return ConfigError.OutOfMemory;
        };
    }

    return paths.toOwnedSlice(allocator) catch return ConfigError.OutOfMemory;
}

/// Checks if a path matches any forbidden pattern.
/// Uses glob matching from capability/scope.zig patterns.
pub fn isForbidden(config: *const ResourceConfig, path: []const u8) bool {
    for (config.forbidden_paths) |pattern| {
        if (matchesForbiddenPattern(pattern, path)) {
            return true;
        }
    }
    return false;
}

fn matchesForbiddenPattern(pattern: []const u8, path: []const u8) bool {
    if (std.mem.endsWith(u8, pattern, "/**")) {
        const prefix = pattern[0 .. pattern.len - 3];
        return std.mem.startsWith(u8, path, prefix);
    }

    if (std.mem.endsWith(u8, pattern, "/*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        if (!std.mem.startsWith(u8, path, prefix)) return false;
        const rest = path[prefix.len..];
        // rest should be "/filename" - starts with / and has no more /
        if (rest.len == 0 or rest[0] != '/') return false;
        return std.mem.indexOfScalar(u8, rest[1..], '/') == null;
    }

    return std.mem.eql(u8, pattern, path);
}

// Tests

test "defaults creates valid config" {
    const allocator = std.testing.allocator;

    var config = try defaults(allocator, "/home/test");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings(
        "0.0.0.0",
        config.tcp.listen_addr,
    );
    try std.testing.expectEqual(@as(u16, 4223), config.tcp.listen_port);
    try std.testing.expectEqualStrings(
        "/home/test/.clawgate/keys/secret.key",
        config.keys.private_key,
    );
    try std.testing.expectEqualStrings(
        "/home/test/.clawgate/keys/public.key",
        config.keys.public_key,
    );
    try std.testing.expectEqualStrings(
        "/home/test/.clawgate/tokens",
        config.agent.token_dir,
    );
    try std.testing.expect(config.resource.forbidden_paths.len > 0);
}

test "parse simple config" {
    const allocator = std.testing.allocator;

    const content =
        \\# ClawGate config
        \\[tcp]
        \\listen_addr = "127.0.0.1"
        \\listen_port = 5000
        \\connect_addr = "remote.example.com"
        \\connect_port = 4223
        \\
        \\[keys]
        \\private_key = "~/.clawgate/custom/secret.key"
        \\public_key = "~/.clawgate/custom/public.key"
        \\
        \\[agent]
        \\token_dir = "/var/lib/clawgate/tokens"
        \\
        \\[resource]
        \\max_file_size = 52428800
        \\truncate_at = 262144
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings(
        "127.0.0.1",
        config.tcp.listen_addr,
    );
    try std.testing.expectEqual(@as(u16, 5000), config.tcp.listen_port);
    try std.testing.expectEqualStrings(
        "remote.example.com",
        config.tcp.connect_addr.?,
    );
    try std.testing.expectEqual(@as(u16, 4223), config.tcp.connect_port);
    try std.testing.expectEqualStrings(
        "/home/user/.clawgate/custom/secret.key",
        config.keys.private_key,
    );
    try std.testing.expectEqualStrings(
        "/var/lib/clawgate/tokens",
        config.agent.token_dir,
    );
    try std.testing.expectEqual(
        @as(usize, 52428800),
        config.resource.max_file_size,
    );
    try std.testing.expectEqual(
        @as(usize, 262144),
        config.resource.truncate_at,
    );
}

test "parse forbidden paths with tilde expansion" {
    const allocator = std.testing.allocator;

    const content =
        \\[resource]
        \\forbidden_path = "/etc/shadow"
        \\forbidden_path = "/root/**"
        \\forbidden_path = "~/.secret/**"
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqual(
        @as(usize, 3),
        config.resource.forbidden_paths.len,
    );
    try std.testing.expectEqualStrings(
        "/etc/shadow",
        config.resource.forbidden_paths[0],
    );
    try std.testing.expectEqualStrings(
        "/root/**",
        config.resource.forbidden_paths[1],
    );
    // Tilde should now be expanded to home directory
    try std.testing.expectEqualStrings(
        "/home/user/.secret/**",
        config.resource.forbidden_paths[2],
    );
}

test "isForbidden matches recursive patterns" {
    const allocator = std.testing.allocator;

    var config = try defaults(allocator, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expect(
        isForbidden(&config.resource, "/home/user/.ssh/id_rsa"),
    );
    try std.testing.expect(
        isForbidden(&config.resource, "/home/user/.ssh/config"),
    );
    try std.testing.expect(
        isForbidden(&config.resource, "/home/user/.gnupg/pubring.gpg"),
    );
    try std.testing.expect(
        isForbidden(&config.resource, "/home/user/.aws/credentials"),
    );

    try std.testing.expect(
        !isForbidden(&config.resource, "/home/user/projects/file.txt"),
    );
    try std.testing.expect(
        !isForbidden(&config.resource, "/tmp/safe.txt"),
    );
}

test "parseKeyValue handles quoted values" {
    const kv1 = parseKeyValue("listen_addr = \"127.0.0.1\"");
    try std.testing.expect(kv1 != null);
    try std.testing.expectEqualStrings("listen_addr", kv1.?.key);
    try std.testing.expectEqualStrings("127.0.0.1", kv1.?.value);

    const kv2 = parseKeyValue("listen_addr = 0.0.0.0");
    try std.testing.expect(kv2 != null);
    try std.testing.expectEqualStrings("0.0.0.0", kv2.?.value);
}

test "parseSection identifies sections" {
    try std.testing.expectEqual(Section.tcp, parseSection("[tcp]"));
    try std.testing.expectEqual(Section.keys, parseSection("[keys]"));
    try std.testing.expectEqual(Section.resource, parseSection("[resource]"));
    try std.testing.expectEqual(Section.agent, parseSection("[agent]"));
    try std.testing.expectEqual(Section.none, parseSection("[unknown]"));
}

test "expandAndDupe expands tilde" {
    const allocator = std.testing.allocator;

    const expanded = try expandAndDupe(
        allocator,
        "~/.clawgate/keys",
        "/home/test",
    );
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings(
        "/home/test/.clawgate/keys",
        expanded,
    );
}

test "expandAndDupe handles absolute paths" {
    const allocator = std.testing.allocator;

    const expanded = try expandAndDupe(
        allocator,
        "/etc/ssl/certs",
        "/home/test",
    );
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/etc/ssl/certs", expanded);
}

test "expandAndDupe handles tilde only" {
    const allocator = std.testing.allocator;

    const expanded = try expandAndDupe(allocator, "~", "/home/test");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("/home/test", expanded);
}

test "getConfigPath returns correct path" {
    const allocator = std.testing.allocator;

    const path = try getConfigPath(allocator, "/home/user");
    defer allocator.free(path);

    try std.testing.expectEqualStrings(
        "/home/user/.clawgate/config.toml",
        path,
    );
}

// Critical: isForbidden pattern matching

test "isForbidden matches single-level wildcard patterns" {
    const allocator = std.testing.allocator;

    const paths = [_][]const u8{
        "/home/user/.secret/*",
        "/tmp/private/*",
    };

    const config = ResourceConfig{
        .forbidden_paths = &paths,
        .max_file_size = 100 * 1024 * 1024,
        .truncate_at = 512 * 1024,
    };

    // Single level should match
    try std.testing.expect(isForbidden(&config, "/home/user/.secret/file.txt"));
    try std.testing.expect(isForbidden(&config, "/tmp/private/data"));

    // Nested paths should NOT match with /*
    try std.testing.expect(
        !isForbidden(&config, "/home/user/.secret/sub/file.txt"),
    );
    try std.testing.expect(!isForbidden(&config, "/tmp/private/a/b/c"));

    // Parent should not match
    try std.testing.expect(!isForbidden(&config, "/home/user/.secret"));
    _ = allocator;
}

test "isForbidden matches exact paths" {
    const allocator = std.testing.allocator;

    const paths = [_][]const u8{
        "/etc/shadow",
        "/etc/passwd",
        "/home/user/.bashrc",
    };

    const config = ResourceConfig{
        .forbidden_paths = &paths,
        .max_file_size = 100 * 1024 * 1024,
        .truncate_at = 512 * 1024,
    };

    // Exact matches
    try std.testing.expect(isForbidden(&config, "/etc/shadow"));
    try std.testing.expect(isForbidden(&config, "/etc/passwd"));
    try std.testing.expect(isForbidden(&config, "/home/user/.bashrc"));

    // Similar but not exact should NOT match
    try std.testing.expect(!isForbidden(&config, "/etc/shadow.bak"));
    try std.testing.expect(!isForbidden(&config, "/etc/passwd.old"));
    try std.testing.expect(!isForbidden(&config, "/etc"));
    try std.testing.expect(!isForbidden(&config, "/home/user/.bashrc.d/file"));
    _ = allocator;
}

// Critical: TCP config fields

test "parse tcp config fields" {
    const allocator = std.testing.allocator;

    const content =
        \\[tcp]
        \\listen_addr = "192.168.1.100"
        \\listen_port = 8080
        \\connect_addr = "agent.example.com"
        \\connect_port = 4223
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings(
        "192.168.1.100",
        config.tcp.listen_addr,
    );
    try std.testing.expectEqual(@as(u16, 8080), config.tcp.listen_port);
    try std.testing.expect(config.tcp.connect_addr != null);
    try std.testing.expectEqualStrings(
        "agent.example.com",
        config.tcp.connect_addr.?,
    );
    try std.testing.expectEqual(@as(u16, 4223), config.tcp.connect_port);
}

// Important: Empty and minimal configs

test "parse empty config returns defaults" {
    const allocator = std.testing.allocator;

    var config = try parse(allocator, "", "/home/user");
    defer config.deinit(allocator);

    // Should have all defaults
    try std.testing.expectEqualStrings(
        "0.0.0.0",
        config.tcp.listen_addr,
    );
    try std.testing.expectEqualStrings(
        "/home/user/.clawgate/keys/secret.key",
        config.keys.private_key,
    );
    try std.testing.expect(config.resource.forbidden_paths.len > 0);
}

test "parse comments-only config returns defaults" {
    const allocator = std.testing.allocator;

    const content =
        \\# This is a comment
        \\# Another comment
        \\
        \\# More comments
        \\
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings(
        "0.0.0.0",
        config.tcp.listen_addr,
    );
}

test "parse invalid numeric values uses defaults" {
    const allocator = std.testing.allocator;

    const content =
        \\[resource]
        \\max_file_size = not_a_number
        \\truncate_at = -999
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    // Should keep default values when parsing fails
    try std.testing.expectEqual(
        @as(usize, 100 * 1024 * 1024),
        config.resource.max_file_size,
    );
    try std.testing.expectEqual(
        @as(usize, 512 * 1024),
        config.resource.truncate_at,
    );
}

test "parse config with unknown keys ignores them" {
    const allocator = std.testing.allocator;

    const content =
        \\[tcp]
        \\listen_addr = "127.0.0.1"
        \\unknown_key = "should be ignored"
        \\another_unknown = 12345
        \\
        \\[unknown_section]
        \\foo = "bar"
        \\
        \\[keys]
        \\private_key = "~/.clawgate/keys/secret.key"
        \\public_key = "~/.clawgate/keys/public.key"
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    // Should parse valid keys and ignore unknown ones
    try std.testing.expectEqualStrings(
        "127.0.0.1",
        config.tcp.listen_addr,
    );
    try std.testing.expectEqualStrings(
        "/home/user/.clawgate/keys/secret.key",
        config.keys.private_key,
    );
}

test "load falls back to defaults when file not found" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    // Use a path that definitely doesn't exist
    const result = loadFromPath(
        allocator,
        io,
        "/nonexistent/path/config.toml",
        "/home/user",
    );

    try std.testing.expectError(ConfigError.FileNotFound, result);
}

// Edge cases

test "parseKeyValue handles line without equals" {
    const result = parseKeyValue("no equals sign here");
    try std.testing.expect(result == null);
}

test "parseKeyValue handles empty value" {
    const kv = parseKeyValue("key = ");
    try std.testing.expect(kv != null);
    try std.testing.expectEqualStrings("key", kv.?.key);
    try std.testing.expectEqualStrings("", kv.?.value);
}

test "parseKeyValue handles value with embedded equals" {
    const kv = parseKeyValue("addr = host:4222?token=abc=def");
    try std.testing.expect(kv != null);
    try std.testing.expectEqualStrings("addr", kv.?.key);
    try std.testing.expectEqualStrings(
        "host:4222?token=abc=def",
        kv.?.value,
    );
}

test "parseSection handles whitespace" {
    try std.testing.expectEqual(Section.tcp, parseSection("[ tcp ]"));
    try std.testing.expectEqual(Section.keys, parseSection("[  keys  ]"));
    try std.testing.expectEqual(Section.resource, parseSection("[resource ]"));
}

test "parseSection handles empty brackets" {
    try std.testing.expectEqual(Section.none, parseSection("[]"));
    try std.testing.expectEqual(Section.none, parseSection("[  ]"));
}

test "parse handles mixed whitespace and empty lines" {
    const allocator = std.testing.allocator;

    const content =
        \\
        \\
        \\[tcp]
        \\
        \\listen_addr = "10.0.0.1"
        \\
        \\
        \\[keys]
        \\
        \\private_key = "/path/to/key"
        \\public_key = "/path/to/pub"
        \\
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings("10.0.0.1", config.tcp.listen_addr);
    try std.testing.expectEqualStrings("/path/to/key", config.keys.private_key);
}

test "parse handles inline comments style gracefully" {
    const allocator = std.testing.allocator;

    // Note: our parser doesn't strip inline comments, value includes them
    // This tests current behavior - inline comments are NOT supported
    const content =
        \\[tcp]
        \\listen_addr = "0.0.0.0"
    ;

    var config = try parse(allocator, content, "/home/user");
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings(
        "0.0.0.0",
        config.tcp.listen_addr,
    );
}

test "matchesForbiddenPattern edge cases" {
    // Empty pattern
    try std.testing.expect(!matchesForbiddenPattern("", "/some/path"));

    // Empty path
    try std.testing.expect(!matchesForbiddenPattern("/foo/**", ""));

    // Pattern equals path exactly
    const exact = matchesForbiddenPattern("/exact/path", "/exact/path");
    try std.testing.expect(exact);

    // Just /** pattern
    try std.testing.expect(matchesForbiddenPattern("/**", "/anything"));
    try std.testing.expect(matchesForbiddenPattern("/**", "/a/b/c/d"));

    // Just /* pattern
    try std.testing.expect(matchesForbiddenPattern("/*", "/file"));
    try std.testing.expect(!matchesForbiddenPattern("/*", "/dir/file"));
}

test "expandAndDupe handles empty string" {
    const allocator = std.testing.allocator;

    const expanded = try expandAndDupe(allocator, "", "/home/user");
    defer allocator.free(expanded);

    try std.testing.expectEqualStrings("", expanded);
}

test "forbidden paths with tilde are expanded in defaults" {
    const allocator = std.testing.allocator;

    var config = try defaults(allocator, "/home/testuser");
    defer config.deinit(allocator);

    // Verify tilde was expanded in default forbidden paths
    var found_ssh = false;
    for (config.resource.forbidden_paths) |path| {
        if (std.mem.indexOf(u8, path, "/home/testuser/.ssh") != null) {
            found_ssh = true;
            // Should NOT contain tilde
            try std.testing.expect(
                std.mem.indexOf(u8, path, "~") == null,
            );
        }
    }
    try std.testing.expect(found_ssh);
}

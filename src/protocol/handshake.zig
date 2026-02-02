//! Handshake protocol for E2E session establishment.
//!
//! Defines JSON messages exchanged during the initial TCP handshake
//! and provides EncryptedConnection for encrypted communication.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const tcp = @import("../transport/tcp.zig");
const e2e = @import("../capability/e2e.zig");

pub const HandshakeError = error{
    InvalidJson,
    MissingField,
    UnsupportedVersion,
    HandshakeFailed,
    InvalidPublicKey,
    ConnectionFailed,
    OutOfMemory,
};

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Session ID prefix.
const SESSION_PREFIX = "sess_";

/// Handshake request from resource to agent.
pub const HandshakeRequest = struct {
    version: u8 = PROTOCOL_VERSION,
    resource_pubkey: []const u8,
    resource_id: []const u8,

    /// Serializes to JSON. Caller owns returned memory.
    pub fn serialize(self: HandshakeRequest, allocator: Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();

        const writer = &output.writer;

        try writer.print(
            "{{\"version\":{d},\"resource_pubkey\":\"",
            .{self.version},
        );
        try writer.writeAll(self.resource_pubkey);
        try writer.writeAll("\",\"resource_id\":\"");
        try writeJsonEscaped(writer, self.resource_id);
        try writer.writeAll("\"}");

        const result = output.written();
        const owned = try allocator.dupe(u8, result);
        output.deinit();
        return owned;
    }

    /// Parses from JSON. Caller must call deinit().
    pub fn parse(
        allocator: Allocator,
        json: []const u8,
    ) HandshakeError!ParsedRequest {
        const parsed = std.json.parseFromSlice(
            HandshakeRequest,
            allocator,
            json,
            .{ .ignore_unknown_fields = true },
        ) catch {
            return HandshakeError.InvalidJson;
        };

        if (parsed.value.version != PROTOCOL_VERSION) {
            parsed.deinit();
            return HandshakeError.UnsupportedVersion;
        }

        return ParsedRequest{
            .value = parsed.value,
            .parsed = parsed,
        };
    }
};

/// Parsed request with cleanup handle.
pub const ParsedRequest = struct {
    value: HandshakeRequest,
    parsed: std.json.Parsed(HandshakeRequest),

    pub fn deinit(self: *ParsedRequest) void {
        self.parsed.deinit();
    }
};

/// Handshake response from agent to resource.
pub const HandshakeResponse = struct {
    ok: bool,
    agent_pubkey: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    @"error": ?[]const u8 = null,

    /// Serializes to JSON. Caller owns returned memory.
    pub fn serialize(self: HandshakeResponse, allocator: Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();

        const writer = &output.writer;

        try writer.print("{{\"ok\":{s}", .{if (self.ok) "true" else "false"});

        if (self.agent_pubkey) |pubkey| {
            try writer.writeAll(",\"agent_pubkey\":\"");
            try writer.writeAll(pubkey);
            try writer.writeAll("\"");
        }

        if (self.session_id) |sid| {
            try writer.writeAll(",\"session_id\":\"");
            try writer.writeAll(sid);
            try writer.writeAll("\"");
        }

        if (self.@"error") |err| {
            try writer.writeAll(",\"error\":\"");
            try writeJsonEscaped(writer, err);
            try writer.writeAll("\"");
        }

        try writer.writeAll("}");

        const result = output.written();
        const owned = try allocator.dupe(u8, result);
        output.deinit();
        return owned;
    }

    /// Parses from JSON. Caller must call deinit().
    pub fn parse(
        allocator: Allocator,
        json: []const u8,
    ) HandshakeError!ParsedResponse {
        const parsed = std.json.parseFromSlice(
            HandshakeResponse,
            allocator,
            json,
            .{ .ignore_unknown_fields = true },
        ) catch {
            return HandshakeError.InvalidJson;
        };

        return ParsedResponse{
            .value = parsed.value,
            .parsed = parsed,
        };
    }
};

/// Parsed response with cleanup handle.
pub const ParsedResponse = struct {
    value: HandshakeResponse,
    parsed: std.json.Parsed(HandshakeResponse),

    pub fn deinit(self: *ParsedResponse) void {
        self.parsed.deinit();
    }
};

/// Connection with E2E encryption established.
pub const EncryptedConnection = struct {
    conn: *tcp.Connection,
    session: e2e.Session,

    /// Sends an encrypted message.
    pub fn sendEncrypted(
        self: *EncryptedConnection,
        allocator: Allocator,
        plaintext: []const u8,
    ) !void {
        const encrypted = try self.session.encrypt(allocator, plaintext);
        defer allocator.free(encrypted);

        self.conn.send(encrypted) catch {
            return HandshakeError.ConnectionFailed;
        };
    }

    /// Receives and decrypts a message. Caller owns returned memory.
    pub fn recvEncrypted(
        self: *EncryptedConnection,
        allocator: Allocator,
    ) ![]u8 {
        const encrypted = self.conn.recv(allocator) catch {
            return HandshakeError.ConnectionFailed;
        };
        defer allocator.free(encrypted);

        return self.session.decrypt(allocator, encrypted) catch {
            return HandshakeError.HandshakeFailed;
        };
    }

    /// Cleans up session secrets. Does NOT close underlying connection.
    pub fn deinit(self: *EncryptedConnection, allocator: Allocator) void {
        self.session.deinit(allocator);
    }
};

/// Generates a random session ID (e.g., "sess_abc123def456...").
/// Uses 128 bits (16 bytes) of entropy for security.
pub fn generateSessionId(io: Io) [37]u8 {
    var result: [37]u8 = undefined;

    // Copy prefix "sess_" (5 chars)
    @memcpy(result[0..SESSION_PREFIX.len], SESSION_PREFIX);

    // Generate 16 random bytes (128 bits) and hex-encode to 32 chars
    var random_bytes: [16]u8 = undefined;
    io.random(&random_bytes);

    const hex_chars = "0123456789abcdef";
    for (random_bytes, 0..) |byte, i| {
        result[SESSION_PREFIX.len + i * 2] = hex_chars[byte >> 4];
        result[SESSION_PREFIX.len + i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    return result;
}

/// Writes a string with JSON escaping.
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

test "HandshakeRequest JSON roundtrip" {
    const allocator = std.testing.allocator;

    const req = HandshakeRequest{
        .version = 1,
        .resource_pubkey = "dGVzdHB1YmtleQ==",
        .resource_id = "test-resource",
    };

    const json = try req.serialize(allocator);
    defer allocator.free(json);

    var parsed = try HandshakeRequest.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 1), parsed.value.version);
    try std.testing.expectEqualStrings("dGVzdHB1YmtleQ==", parsed.value.resource_pubkey);
    try std.testing.expectEqualStrings("test-resource", parsed.value.resource_id);
}

test "HandshakeResponse JSON roundtrip (success)" {
    const allocator = std.testing.allocator;

    const resp = HandshakeResponse{
        .ok = true,
        .agent_pubkey = "YWdlbnRwdWJrZXk=",
        .session_id = "sess_abc123",
    };

    const json = try resp.serialize(allocator);
    defer allocator.free(json);

    var parsed = try HandshakeResponse.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqualStrings("YWdlbnRwdWJrZXk=", parsed.value.agent_pubkey.?);
    try std.testing.expectEqualStrings("sess_abc123", parsed.value.session_id.?);
    try std.testing.expect(parsed.value.@"error" == null);
}

test "HandshakeResponse JSON roundtrip (error)" {
    const allocator = std.testing.allocator;

    const resp = HandshakeResponse{
        .ok = false,
        .@"error" = "unsupported version",
    };

    const json = try resp.serialize(allocator);
    defer allocator.free(json);

    var parsed = try HandshakeResponse.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(!parsed.value.ok);
    try std.testing.expectEqualStrings("unsupported version", parsed.value.@"error".?);
    try std.testing.expect(parsed.value.agent_pubkey == null);
    try std.testing.expect(parsed.value.session_id == null);
}

test "session ID format validation" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const session_id = generateSessionId(io);

    // Verify prefix
    try std.testing.expectEqualStrings(SESSION_PREFIX, session_id[0..SESSION_PREFIX.len]);

    // Verify length (5 prefix + 32 hex chars = 37)
    try std.testing.expectEqual(@as(usize, 37), session_id.len);

    // Verify hex chars
    for (session_id[SESSION_PREFIX.len..]) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}

test "session ID is random" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const id1 = generateSessionId(io);
    const id2 = generateSessionId(io);

    // Very unlikely to be equal
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "version validation rejects unsupported" {
    const allocator = std.testing.allocator;

    const json = "{\"version\":99,\"resource_pubkey\":\"a\",\"resource_id\":\"b\"}";

    const result = HandshakeRequest.parse(allocator, json);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

test "invalid JSON rejected" {
    const allocator = std.testing.allocator;

    const result = HandshakeRequest.parse(allocator, "not valid json");
    try std.testing.expectError(HandshakeError.InvalidJson, result);
}

test "EncryptedConnection send/recv roundtrip" {
    const allocator = std.testing.allocator;

    var threaded: Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    // Set up TCP connection
    var listener = try tcp.Listener.bind(io, "127.0.0.1", 0);
    defer listener.close();

    const port = listener.server.socket.address.getPort();

    var client_conn = try tcp.connectTo(io, "127.0.0.1", port);
    defer client_conn.close();

    var server_conn = try listener.accept();
    defer server_conn.close();

    // Generate keypairs
    var client_kp = e2e.KeyPair.generate(io);
    defer client_kp.deinit();

    var server_kp = e2e.KeyPair.generate(io);
    defer server_kp.deinit();

    const session_id = "sess_test123456ab";

    // Establish sessions on both sides
    const client_session = try e2e.Session.establish(
        allocator,
        client_kp.secret_key,
        server_kp.public_key,
        session_id,
    );

    const server_session = try e2e.Session.establish(
        allocator,
        server_kp.secret_key,
        client_kp.public_key,
        session_id,
    );

    // Create encrypted connections
    var client_enc = EncryptedConnection{
        .conn = &client_conn,
        .session = client_session,
    };
    defer client_enc.deinit(allocator);

    var server_enc = EncryptedConnection{
        .conn = &server_conn,
        .session = server_session,
    };
    defer server_enc.deinit(allocator);

    // Client sends, server receives
    const message = "Hello, encrypted world!";
    try client_enc.sendEncrypted(allocator, message);

    const received = try server_enc.recvEncrypted(allocator);
    defer allocator.free(received);

    try std.testing.expectEqualStrings(message, received);

    // Server sends, client receives
    const reply = "Got your message!";
    try server_enc.sendEncrypted(allocator, reply);

    const reply_received = try client_enc.recvEncrypted(allocator);
    defer allocator.free(reply_received);

    try std.testing.expectEqualStrings(reply, reply_received);
}

test "resource_id with special characters" {
    const allocator = std.testing.allocator;

    const req = HandshakeRequest{
        .version = 1,
        .resource_pubkey = "abc",
        .resource_id = "name with \"quotes\" and \\backslash",
    };

    const json = try req.serialize(allocator);
    defer allocator.free(json);

    // Should be valid JSON - parse back
    var parsed = try HandshakeRequest.parse(allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "name with \"quotes\" and \\backslash",
        parsed.value.resource_id,
    );
}

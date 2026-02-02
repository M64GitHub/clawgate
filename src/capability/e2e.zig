//! End-to-end encryption for ClawGate TCP connections.
//!
//! Provides X25519 key exchange and XChaCha20-Poly1305 authenticated
//! encryption. Keys are ephemeral per session for forward secrecy.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const X25519 = std.crypto.dh.X25519;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const base64 = std.base64;

pub const E2eError = error{
    InvalidPublicKey,
    DecryptionFailed,
    MessageTooShort,
    OutOfMemory,
};

pub const KEY_LENGTH = 32;
pub const NONCE_LENGTH = 24;
pub const TAG_LENGTH = 16;
pub const OVERHEAD = NONCE_LENGTH + TAG_LENGTH;

const HKDF_SALT = "clawgate-e2e-v1";

/// X25519 keypair for key exchange.
pub const KeyPair = struct {
    public_key: [KEY_LENGTH]u8,
    secret_key: [KEY_LENGTH]u8,

    /// Generates a new random keypair.
    pub fn generate(io: Io) KeyPair {
        const kp = X25519.KeyPair.generate(io);
        return .{
            .public_key = kp.public_key,
            .secret_key = kp.secret_key,
        };
    }

    /// Returns base64-encoded public key. Caller owns returned memory.
    pub fn publicKeyBase64(self: KeyPair, allocator: Allocator) ![]u8 {
        const encoded = try allocator.alloc(u8, 44);
        _ = base64.standard.Encoder.encode(encoded, &self.public_key);
        return encoded;
    }

    /// Zeros out the secret key.
    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

/// Established E2E session with shared secret.
pub const Session = struct {
    shared_secret: [KEY_LENGTH]u8,
    session_id: []const u8,
    nonce_counter: u64,

    /// Establishes session by deriving shared secret via X25519 + HKDF.
    pub fn establish(
        allocator: Allocator,
        my_secret: [KEY_LENGTH]u8,
        their_public: [KEY_LENGTH]u8,
        session_id: []const u8,
    ) !Session {
        var x25519_shared = X25519.scalarmult(my_secret, their_public) catch {
            return E2eError.InvalidPublicKey;
        };
        defer std.crypto.secureZero(u8, &x25519_shared);

        const prk = HkdfSha256.extract(HKDF_SALT, &x25519_shared);

        var shared_secret: [KEY_LENGTH]u8 = undefined;
        HkdfSha256.expand(&shared_secret, session_id, prk);

        const owned_session_id = try allocator.dupe(u8, session_id);

        return .{
            .shared_secret = shared_secret,
            .session_id = owned_session_id,
            .nonce_counter = 0,
        };
    }

    /// Encrypts plaintext. Returns nonce || ciphertext || tag.
    /// Caller owns returned memory.
    pub fn encrypt(
        self: *Session,
        allocator: Allocator,
        plaintext: []const u8,
    ) ![]u8 {
        const output_len = OVERHEAD + plaintext.len;
        const output = try allocator.alloc(u8, output_len);
        errdefer allocator.free(output);

        const nonce = self.generateNonce();
        self.nonce_counter += 1;

        @memcpy(output[0..NONCE_LENGTH], &nonce);

        const ciphertext = output[NONCE_LENGTH .. output_len - TAG_LENGTH];
        const tag_ptr: *[TAG_LENGTH]u8 = @ptrCast(
            output[output_len - TAG_LENGTH ..][0..TAG_LENGTH],
        );

        XChaCha20Poly1305.encrypt(
            ciphertext,
            tag_ptr,
            plaintext,
            "",
            nonce,
            self.shared_secret,
        );

        return output;
    }

    /// Decrypts ciphertext (nonce || ciphertext || tag).
    /// Returns plaintext. Caller owns returned memory.
    pub fn decrypt(
        self: *Session,
        allocator: Allocator,
        encrypted: []const u8,
    ) ![]u8 {
        if (encrypted.len < OVERHEAD) {
            return E2eError.MessageTooShort;
        }

        const nonce: [NONCE_LENGTH]u8 = encrypted[0..NONCE_LENGTH].*;
        const ct_end = encrypted.len - TAG_LENGTH;
        const ciphertext = encrypted[NONCE_LENGTH..ct_end];
        const tag_start = encrypted[encrypted.len - TAG_LENGTH ..];
        const tag: [TAG_LENGTH]u8 = tag_start[0..TAG_LENGTH].*;

        const plaintext = try allocator.alloc(u8, ciphertext.len);

        XChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag,
            "",
            nonce,
            self.shared_secret,
        ) catch {
            allocator.free(plaintext);
            return E2eError.DecryptionFailed;
        };

        return plaintext;
    }

    /// Generates nonce from counter.
    fn generateNonce(self: *Session) [NONCE_LENGTH]u8 {
        var nonce: [NONCE_LENGTH]u8 = undefined;
        @memset(&nonce, 0);
        std.mem.writeInt(u64, nonce[0..8], self.nonce_counter, .little);
        return nonce;
    }

    /// Zeros out secrets and frees session_id.
    pub fn deinit(self: *Session, allocator: Allocator) void {
        std.crypto.secureZero(u8, &self.shared_secret);
        allocator.free(self.session_id);
    }
};

/// Decodes base64 public key to 32 bytes.
pub fn decodePublicKey(encoded: []const u8) E2eError![KEY_LENGTH]u8 {
    if (encoded.len != 44) {
        return E2eError.InvalidPublicKey;
    }

    var decoded: [KEY_LENGTH]u8 = undefined;
    base64.standard.Decoder.decode(&decoded, encoded) catch {
        return E2eError.InvalidPublicKey;
    };

    return decoded;
}

/// Encodes 32-byte public key to base64 (44 chars with padding).
pub fn encodePublicKey(key: [KEY_LENGTH]u8) [44]u8 {
    var encoded: [44]u8 = undefined;
    _ = base64.standard.Encoder.encode(&encoded, &key);
    return encoded;
}

// Tests

test "KeyPair generation produces valid keys" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = KeyPair.generate(io);
    try std.testing.expectEqual(@as(usize, 32), kp.public_key.len);
    try std.testing.expectEqual(@as(usize, 32), kp.secret_key.len);

    var all_zero = true;
    for (kp.public_key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "two parties derive identical shared secret" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    const session_id = "sess_test123456789";

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        session_id,
    );
    defer alice_session.deinit(allocator);

    var bob_session = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        session_id,
    );
    defer bob_session.deinit(allocator);

    try std.testing.expectEqualSlices(
        u8,
        &alice_session.shared_secret,
        &bob_session.shared_secret,
    );
}

test "encrypt/decrypt roundtrip" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_roundtrip_test",
    );
    defer alice_session.deinit(allocator);

    var bob_session = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        "sess_roundtrip_test",
    );
    defer bob_session.deinit(allocator);

    const plaintext = "Hello, ClawGate E2E!";
    const encrypted = try alice_session.encrypt(allocator, plaintext);
    defer allocator.free(encrypted);

    try std.testing.expectEqual(
        plaintext.len + OVERHEAD,
        encrypted.len,
    );

    const decrypted = try bob_session.decrypt(allocator, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "tampered ciphertext fails authentication" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_tamper_test",
    );
    defer alice_session.deinit(allocator);

    var bob_session = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        "sess_tamper_test",
    );
    defer bob_session.deinit(allocator);

    const encrypted = try alice_session.encrypt(allocator, "secret message");
    defer allocator.free(encrypted);

    encrypted[NONCE_LENGTH + 5] ^= 0xFF;

    const result = bob_session.decrypt(allocator, encrypted);
    try std.testing.expectError(E2eError.DecryptionFailed, result);
}

test "wrong key decryption fails" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);
    const eve = KeyPair.generate(io);

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_wrong_key",
    );
    defer alice_session.deinit(allocator);

    var eve_session = try Session.establish(
        allocator,
        eve.secret_key,
        alice.public_key,
        "sess_wrong_key",
    );
    defer eve_session.deinit(allocator);

    const encrypted = try alice_session.encrypt(allocator, "for bob only");
    defer allocator.free(encrypted);

    const result = eve_session.decrypt(allocator, encrypted);
    try std.testing.expectError(E2eError.DecryptionFailed, result);
}

test "nonce counter increments" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_nonce_test",
    );
    defer session.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), session.nonce_counter);

    const e1 = try session.encrypt(allocator, "msg1");
    defer allocator.free(e1);
    try std.testing.expectEqual(@as(u64, 1), session.nonce_counter);

    const e2 = try session.encrypt(allocator, "msg2");
    defer allocator.free(e2);
    try std.testing.expectEqual(@as(u64, 2), session.nonce_counter);

    const e3 = try session.encrypt(allocator, "msg3");
    defer allocator.free(e3);
    try std.testing.expectEqual(@as(u64, 3), session.nonce_counter);

    const nonce1 = e1[0..NONCE_LENGTH].*;
    const nonce2 = e2[0..NONCE_LENGTH].*;
    const nonce3 = e3[0..NONCE_LENGTH].*;

    try std.testing.expect(!std.mem.eql(u8, &nonce1, &nonce2));
    try std.testing.expect(!std.mem.eql(u8, &nonce2, &nonce3));
    try std.testing.expect(!std.mem.eql(u8, &nonce1, &nonce3));
}

test "base64 encode/decode roundtrip" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const kp = KeyPair.generate(io);

    const encoded = encodePublicKey(kp.public_key);
    try std.testing.expectEqual(@as(usize, 44), encoded.len);

    const decoded = try decodePublicKey(&encoded);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &decoded);

    const encoded_alloc = try kp.publicKeyBase64(allocator);
    defer allocator.free(encoded_alloc);
    try std.testing.expectEqualSlices(u8, &encoded, encoded_alloc);
}

test "session deinit zeros secrets" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_zero_test",
    );

    const secret_copy = session.shared_secret;
    var all_zero = true;
    for (secret_copy) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);

    session.deinit(allocator);

    all_zero = true;
    for (session.shared_secret) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(all_zero);
}

test "keypair deinit zeros secret key" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    var kp = KeyPair.generate(io);

    var all_zero = true;
    for (kp.secret_key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);

    kp.deinit();

    all_zero = true;
    for (kp.secret_key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(all_zero);
}

test "decrypt message too short" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_short_test",
    );
    defer session.deinit(allocator);

    const short_msg = "too short";
    const result = session.decrypt(allocator, short_msg);
    try std.testing.expectError(E2eError.MessageTooShort, result);
}

test "invalid base64 public key" {
    const result = decodePublicKey("not valid base64!!!!!!!!!!!!!!!!!!!!!!!!");
    try std.testing.expectError(E2eError.InvalidPublicKey, result);
}

test "wrong length base64 public key" {
    const result = decodePublicKey("dG9vIHNob3J0");
    try std.testing.expectError(E2eError.InvalidPublicKey, result);
}

test "encrypt empty message" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_empty_test",
    );
    defer alice_session.deinit(allocator);

    var bob_session = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        "sess_empty_test",
    );
    defer bob_session.deinit(allocator);

    const encrypted = try alice_session.encrypt(allocator, "");
    defer allocator.free(encrypted);

    try std.testing.expectEqual(OVERHEAD, encrypted.len);

    const decrypted = try bob_session.decrypt(allocator, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "encrypt large message" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    var alice_session = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_large_test",
    );
    defer alice_session.deinit(allocator);

    var bob_session = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        "sess_large_test",
    );
    defer bob_session.deinit(allocator);

    const large_msg = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(large_msg);
    @memset(large_msg, 'A');

    const encrypted = try alice_session.encrypt(allocator, large_msg);
    defer allocator.free(encrypted);

    const decrypted = try bob_session.decrypt(allocator, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, large_msg, decrypted);
}

test "different session IDs derive different keys" {
    // Security: Messages encrypted with one session ID can't be
    // decrypted by a session with a different ID, even with same keypairs
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice = KeyPair.generate(io);
    const bob = KeyPair.generate(io);

    // Alice session with session_id "A"
    var alice_session_a = try Session.establish(
        allocator,
        alice.secret_key,
        bob.public_key,
        "sess_id_A",
    );
    defer alice_session_a.deinit(allocator);

    // Bob session with DIFFERENT session_id "B"
    var bob_session_b = try Session.establish(
        allocator,
        bob.secret_key,
        alice.public_key,
        "sess_id_B",
    );
    defer bob_session_b.deinit(allocator);

    // Encrypt with session A
    const encrypted = try alice_session_a.encrypt(allocator, "secret msg");
    defer allocator.free(encrypted);

    // Decryption with session B should fail (different derived keys)
    const decrypt_result = bob_session_b.decrypt(allocator, encrypted);
    try std.testing.expectError(E2eError.DecryptionFailed, decrypt_result);
}

test "replay attack across sessions fails" {
    // Security: Even with same session_id, each session has fresh keypairs
    // so replaying old messages to new sessions fails
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.testing.allocator;

    const alice1 = KeyPair.generate(io);
    const bob1 = KeyPair.generate(io);

    // First session
    var alice_session1 = try Session.establish(
        allocator,
        alice1.secret_key,
        bob1.public_key,
        "same_session_id",
    );
    defer alice_session1.deinit(allocator);

    const encrypted = try alice_session1.encrypt(allocator, "secret");
    defer allocator.free(encrypted);

    // New keypairs for "new connection"
    const alice2 = KeyPair.generate(io);
    const bob2 = KeyPair.generate(io);

    // New session with same session_id but different keys
    var bob_session2 = try Session.establish(
        allocator,
        bob2.secret_key,
        alice2.public_key,
        "same_session_id",
    );
    defer bob_session2.deinit(allocator);

    // Replay attack: trying to decrypt old message with new session
    const replay_result = bob_session2.decrypt(allocator, encrypted);
    try std.testing.expectError(E2eError.DecryptionFailed, replay_result);
}

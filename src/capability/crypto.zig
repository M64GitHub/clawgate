//! Ed25519 cryptographic operations for capability tokens.
//!
//! Handles key generation, loading, signing, and verification.
//! Keys are stored as raw bytes: 64 bytes for secret key, 32 bytes for public.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;
const File = std.Io.File;

pub const SecretKey = [Ed25519.SecretKey.encoded_length]u8;
pub const PublicKey = [Ed25519.PublicKey.encoded_length]u8;
pub const Signature = [Ed25519.Signature.encoded_length]u8;

pub const KeyPair = struct {
    secret_key: SecretKey,
    public_key: PublicKey,
};

pub const CryptoError = error{
    InvalidKeyLength,
    InvalidKey,
    InvalidSignature,
    FileNotFound,
    ReadError,
    WriteError,
};

/// Generates a new Ed25519 keypair.
pub fn generateKeypair(io: Io) KeyPair {
    const kp = Ed25519.KeyPair.generate(io);
    return .{
        .secret_key = kp.secret_key.toBytes(),
        .public_key = kp.public_key.toBytes(),
    };
}

/// Generates keypair and saves to files.
pub fn generateAndSaveKeypair(
    io: Io,
    secret_path: []const u8,
    public_path: []const u8,
) !void {
    const kp = generateKeypair(io);
    try saveSecretKey(io, secret_path, kp.secret_key);
    try savePublicKey(io, public_path, kp.public_key);
}

/// Saves a secret key to a file.
pub fn saveSecretKey(
    io: Io,
    path: []const u8,
    key: SecretKey,
) !void {
    const file = Dir.createFile(.cwd(), io, path, .{
        .permissions = File.Permissions.fromMode(0o600),
    }) catch {
        return CryptoError.WriteError;
    };
    defer file.close(io);
    file.writeStreamingAll(io, &key) catch return CryptoError.WriteError;
}

/// Saves a public key to a file.
pub fn savePublicKey(
    io: Io,
    path: []const u8,
    key: PublicKey,
) !void {
    const file = Dir.createFile(.cwd(), io, path, .{}) catch {
        return CryptoError.WriteError;
    };
    defer file.close(io);
    file.writeStreamingAll(io, &key) catch return CryptoError.WriteError;
}

/// Loads a secret key from a file.
/// SECURITY: Caller should zero the key when done using:
/// `std.crypto.secureZero(SecretKey, &key);`
pub fn loadSecretKey(io: Io, path: []const u8) !SecretKey {
    const file = Dir.openFile(.cwd(), io, path, .{}) catch {
        return CryptoError.FileNotFound;
    };
    defer file.close(io);

    var key: SecretKey = undefined;
    const bytes_read = file.readPositionalAll(io, &key, 0) catch {
        return CryptoError.ReadError;
    };
    if (bytes_read != Ed25519.SecretKey.encoded_length) {
        return CryptoError.InvalidKeyLength;
    }
    return key;
}

/// Loads a public key from a file.
pub fn loadPublicKey(io: Io, path: []const u8) !PublicKey {
    const file = Dir.openFile(.cwd(), io, path, .{}) catch {
        return CryptoError.FileNotFound;
    };
    defer file.close(io);

    var key: PublicKey = undefined;
    const bytes_read = file.readPositionalAll(io, &key, 0) catch {
        return CryptoError.ReadError;
    };
    if (bytes_read != Ed25519.PublicKey.encoded_length) {
        return CryptoError.InvalidKeyLength;
    }
    return key;
}

/// Signs data with a secret key.
pub fn sign(data: []const u8, secret_key: SecretKey) CryptoError!Signature {
    const sk = Ed25519.SecretKey.fromBytes(secret_key) catch {
        return CryptoError.InvalidKey;
    };
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch {
        return CryptoError.InvalidKey;
    };
    const sig = kp.sign(data, null) catch {
        return CryptoError.InvalidKey;
    };
    return sig.toBytes();
}

/// Verifies a signature against data and public key.
pub fn verify(
    data: []const u8,
    signature: Signature,
    public_key: PublicKey,
) bool {
    const sig = Ed25519.Signature.fromBytes(signature);
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    sig.verify(data, pk) catch return false;
    return true;
}

/// Encodes bytes as lowercase hex string.
pub fn hexEncode(
    allocator: Allocator,
    bytes: []const u8,
) ![]u8 {
    const charset = "0123456789abcdef";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        result[i * 2 + 0] = charset[b >> 4];
        result[i * 2 + 1] = charset[b & 15];
    }
    return result;
}

/// Decodes a hex string to bytes.
pub fn hexDecode(
    allocator: Allocator,
    hex: []const u8,
) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const result = try allocator.alloc(u8, hex.len / 2);
    for (result, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
            allocator.free(result);
            return error.InvalidHexChar;
        };
    }
    return result;
}

// Tests

test "generate keypair" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = generateKeypair(io);
    try std.testing.expect(kp.secret_key.len == 64);
    try std.testing.expect(kp.public_key.len == 32);
}

test "sign and verify" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = generateKeypair(io);
    const data = "Hello, ClawGate!";

    const signature = try sign(data, kp.secret_key);
    try std.testing.expect(verify(data, signature, kp.public_key));

    // Wrong data should fail
    try std.testing.expect(!verify("Wrong data", signature, kp.public_key));

    // Wrong key should fail
    const other_kp = generateKeypair(io);
    try std.testing.expect(!verify(data, signature, other_kp.public_key));
}

test "hex encode/decode roundtrip" {
    const allocator = std.testing.allocator;

    const original = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const hex = try hexEncode(allocator, &original);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("deadbeef", hex);

    const decoded = try hexDecode(allocator, hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}

// Additional crypto edge case tests

test "sign empty data" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = generateKeypair(io);

    // Signing empty data should work
    const signature = try sign("", kp.secret_key);
    try std.testing.expect(verify("", signature, kp.public_key));

    // Should not verify with non-empty data
    try std.testing.expect(!verify("x", signature, kp.public_key));
}

test "verify with modified signature fails" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = generateKeypair(io);
    const data = "test data";

    var signature = try sign(data, kp.secret_key);

    // Flip a bit in the signature
    signature[0] ^= 0x01;

    // Verification should fail
    try std.testing.expect(!verify(data, signature, kp.public_key));
}

test "verify with modified public key fails" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const kp = generateKeypair(io);
    const data = "test data";

    const signature = try sign(data, kp.secret_key);

    // Modify the public key
    var bad_pk = kp.public_key;
    bad_pk[0] ^= 0x01;

    // Verification should fail
    try std.testing.expect(!verify(data, signature, bad_pk));
}

test "save and load keypair roundtrip" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const secret_path = "/tmp/clawgate_test_secret.key";
    const public_path = "/tmp/clawgate_test_public.key";

    defer {
        Dir.deleteFile(.cwd(), io, secret_path) catch {};
        Dir.deleteFile(.cwd(), io, public_path) catch {};
    }

    // Generate and save
    try generateAndSaveKeypair(io, secret_path, public_path);

    // Load and verify
    const loaded_sk = try loadSecretKey(io, secret_path);
    const loaded_pk = try loadPublicKey(io, public_path);

    // Sign with loaded key
    const data = "test data for roundtrip";
    const sig = try sign(data, loaded_sk);

    // Verify with loaded public key
    try std.testing.expect(verify(data, sig, loaded_pk));
}

test "loadSecretKey - file not found" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const result = loadSecretKey(io, "/tmp/nonexistent_key_12345.key");
    try std.testing.expectError(CryptoError.FileNotFound, result);
}

test "loadPublicKey - file not found" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const result = loadPublicKey(io, "/tmp/nonexistent_key_12345.key");
    try std.testing.expectError(CryptoError.FileNotFound, result);
}

test "loadSecretKey - file too short" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_short_key.key";

    // Create file with only 10 bytes (should be 64)
    const file = try Dir.createFile(.cwd(), io, test_path, .{});
    defer {
        file.close(io);
        Dir.deleteFile(.cwd(), io, test_path) catch {};
    }
    try file.writeStreamingAll(io, "short_key!");

    const result = loadSecretKey(io, test_path);
    try std.testing.expectError(CryptoError.InvalidKeyLength, result);
}

test "loadPublicKey - file too short" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const test_path = "/tmp/clawgate_test_short_pub.key";

    // Create file with only 10 bytes (should be 32)
    const file = try Dir.createFile(.cwd(), io, test_path, .{});
    defer {
        file.close(io);
        Dir.deleteFile(.cwd(), io, test_path) catch {};
    }
    try file.writeStreamingAll(io, "short_key!");

    const result = loadPublicKey(io, test_path);
    try std.testing.expectError(CryptoError.InvalidKeyLength, result);
}

test "hex decode - uppercase" {
    const allocator = std.testing.allocator;

    // Uppercase hex should work
    const decoded = try hexDecode(allocator, "DEADBEEF");
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, decoded);
}

test "hex decode - mixed case" {
    const allocator = std.testing.allocator;

    // Mixed case hex should work
    const decoded = try hexDecode(allocator, "DeAdBeEf");
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, decoded);
}

test "hex decode - invalid length" {
    const allocator = std.testing.allocator;

    // Odd length should fail
    const result = hexDecode(allocator, "abc");
    try std.testing.expectError(error.InvalidHexLength, result);
}

test "hex decode - invalid chars" {
    const allocator = std.testing.allocator;

    // Invalid hex chars should fail
    const result = hexDecode(allocator, "ghij");
    try std.testing.expectError(error.InvalidHexChar, result);
}

test "hex encode empty" {
    const allocator = std.testing.allocator;

    const hex = try hexEncode(allocator, "");
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("", hex);
}

test "hex decode empty" {
    const allocator = std.testing.allocator;

    const decoded = try hexDecode(allocator, "");
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "hex encode all byte values" {
    const allocator = std.testing.allocator;

    // Test encoding all 256 byte values
    var all_bytes: [256]u8 = undefined;
    for (&all_bytes, 0..) |*b, i| {
        b.* = @intCast(i);
    }

    const hex = try hexEncode(allocator, &all_bytes);
    defer allocator.free(hex);

    // Verify length
    try std.testing.expectEqual(@as(usize, 512), hex.len);

    // Decode back
    const decoded = try hexDecode(allocator, hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &all_bytes, decoded);
}

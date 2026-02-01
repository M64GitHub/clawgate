//! Setup commands for ClawGate.
//!
//! Provides key generation for Ed25519 keypairs used to sign
//! capability tokens.

const std = @import("std");
const crypto = @import("../capability/crypto.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;

pub const SetupError = error{
    InvalidArgs,
    KeygenFailed,
    DirectoryCreateFailed,
    OutOfMemory,
};

/// Configuration for keygen command.
pub const KeygenConfig = struct {
    /// Output directory for keys (default: ~/.clawgate/keys)
    output_dir: ?[]const u8 = null,
    /// Force overwrite existing keys
    force: bool = false,
};

/// Generates Ed25519 keypair and saves to disk.
/// Keys are saved to ~/.clawgate/keys/ by default.
pub fn keygen(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) SetupError!void {
    var config = KeygenConfig{};

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--output") or
            std.mem.eql(u8, arg, "-o"))
        {
            if (i + 1 >= args.len) {
                printKeygenUsage();
                return SetupError.InvalidArgs;
            }
            i += 1;
            config.output_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--force") or
            std.mem.eql(u8, arg, "-f"))
        {
            config.force = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            printKeygenUsage();
            return;
        }
    }

    // Get key directory
    const key_dir = config.output_dir orelse blk: {
        const home_dir = home orelse {
            std.debug.print("Error: HOME not set\n", .{});
            return SetupError.KeygenFailed;
        };
        break :blk std.fmt.allocPrint(
            allocator,
            "{s}/.clawgate/keys",
            .{home_dir},
        ) catch return SetupError.OutOfMemory;
    };
    defer if (config.output_dir == null) allocator.free(key_dir);

    // Create directory structure
    const clawgate_dir = std.fmt.allocPrint(
        allocator,
        "{s}/.clawgate",
        .{home orelse "."},
    ) catch return SetupError.OutOfMemory;
    defer allocator.free(clawgate_dir);

    Dir.createDir(.cwd(), io, clawgate_dir, .default_dir) catch {};
    Dir.createDir(.cwd(), io, key_dir, .default_dir) catch {};

    // Build key paths
    const secret_path = std.fmt.allocPrint(
        allocator,
        "{s}/secret.key",
        .{key_dir},
    ) catch return SetupError.OutOfMemory;
    defer allocator.free(secret_path);

    const public_path = std.fmt.allocPrint(
        allocator,
        "{s}/public.key",
        .{key_dir},
    ) catch return SetupError.OutOfMemory;
    defer allocator.free(public_path);

    // Check if keys exist
    if (!config.force) {
        const secret_exists = Dir.openFile(
            .cwd(),
            io,
            secret_path,
            .{},
        ) catch null;
        if (secret_exists) |f| {
            f.close(io);
            std.debug.print(
                "Error: Keys already exist at {s}\n",
                .{key_dir},
            );
            std.debug.print("Use --force to overwrite\n", .{});
            return SetupError.KeygenFailed;
        }
    }

    // Generate and save keypair
    std.debug.print("Generating Ed25519 keypair...\n", .{});

    crypto.generateAndSaveKeypair(io, secret_path, public_path) catch {
        std.debug.print("Error: Failed to generate keypair\n", .{});
        return SetupError.KeygenFailed;
    };

    // Load public key to show fingerprint
    const public_key = crypto.loadPublicKey(io, public_path) catch {
        std.debug.print("Warning: Could not read public key\n", .{});
        return;
    };

    // Display fingerprint (first 8 bytes as hex)
    const fingerprint = std.fmt.bytesToHex(public_key[0..8], .lower);

    std.debug.print("\nKeypair generated successfully!\n\n", .{});
    std.debug.print("  Secret key: {s}\n", .{secret_path});
    std.debug.print("  Public key: {s}\n", .{public_path});
    std.debug.print("  Fingerprint: {s}\n\n", .{fingerprint});
    std.debug.print(
        "IMPORTANT: Keep your secret key secure! " ++
            "Never share it.\n",
        .{},
    );
    std.debug.print(
        "Copy the public key to machines that will verify tokens.\n",
        .{},
    );
}

/// Prints keygen command usage.
fn printKeygenUsage() void {
    const usage =
        \\Usage: clawgate keygen [options]
        \\
        \\Generate Ed25519 keypair for signing capability tokens.
        \\
        \\Options:
        \\  -o, --output <dir>    Output directory (default: ~/.clawgate/keys)
        \\  -f, --force           Overwrite existing keys
        \\  -h, --help            Show this help
        \\
        \\The keypair consists of:
        \\  - secret.key: Used to sign tokens (keep secure!)
        \\  - public.key: Used to verify tokens (share with resource daemon)
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "keygen config defaults" {
    const config = KeygenConfig{};
    try std.testing.expect(config.output_dir == null);
    try std.testing.expect(!config.force);
}

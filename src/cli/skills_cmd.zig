//! Skills generation CLI commands.
//!
//! `clawgate skills generate` - regenerate all skill files
//! `clawgate skills export <dir>` - export to specified directory

const std = @import("std");
const tools_mod = @import("../resource/tools.zig");
const skills = @import("../resource/skills.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = Io.File;

pub const SkillsCmdError = error{
    InvalidArgs,
    LoadFailed,
    GenerateFailed,
    OutOfMemory,
};

/// Main entry point for `clawgate skills` commands.
pub fn run(
    allocator: Allocator,
    io: Io,
    args: []const [:0]const u8,
    home: ?[]const u8,
) SkillsCmdError!void {
    const home_dir = home orelse {
        std.debug.print("Error: HOME not set\n", .{});
        return SkillsCmdError.InvalidArgs;
    };

    if (args.len == 0) {
        printUsage();
        return SkillsCmdError.InvalidArgs;
    }

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "generate")) {
        return handleGenerate(
            allocator,
            io,
            "skills/clawgate",
            home_dir,
        );
    } else if (std.mem.eql(u8, subcmd, "export")) {
        if (args.len < 2) {
            std.debug.print(
                "Error: Output directory required\n",
                .{},
            );
            return SkillsCmdError.InvalidArgs;
        }
        return handleGenerate(
            allocator,
            io,
            args[1],
            home_dir,
        );
    } else if (std.mem.eql(u8, subcmd, "--help") or
        std.mem.eql(u8, subcmd, "-h"))
    {
        printUsage();
    } else {
        std.debug.print(
            "Error: Unknown subcommand: {s}\n\n",
            .{subcmd},
        );
        printUsage();
        return SkillsCmdError.InvalidArgs;
    }
}

fn handleGenerate(
    allocator: Allocator,
    io: Io,
    output_dir: []const u8,
    home: []const u8,
) SkillsCmdError!void {
    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        home,
    ) catch {
        std.debug.print(
            "Error: Failed to load tool registry\n",
            .{},
        );
        return SkillsCmdError.LoadFailed;
    };
    defer reg.deinit(allocator);

    skills.generateAll(
        allocator,
        io,
        &reg,
        output_dir,
    ) catch {
        std.debug.print(
            "Error: Failed to generate skills\n",
            .{},
        );
        return SkillsCmdError.GenerateFailed;
    };

    const stdout = File.stdout();
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &buf,
        "Skills generated in {s}/\n",
        .{output_dir},
    ) catch "Skills generated\n";
    stdout.writeStreamingAll(io, msg) catch {};
}

fn printUsage() void {
    const usage =
        \\Usage: clawgate skills <subcommand>
        \\
        \\Generate skill files from registered tools.
        \\
        \\Subcommands:
        \\  generate          Generate skill files (skills/clawgate/)
        \\  export <dir>      Export to specified directory
        \\
    ;
    std.debug.print("{s}", .{usage});
}

// Tests

test "skills_cmd compiles" {
    // Verify module compiles correctly
    try std.testing.expect(true);
}

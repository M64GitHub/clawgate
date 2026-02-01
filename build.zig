//! ClawGate build configuration
//!
//! Build commands:
//!   zig build              - Build clawgate binary
//!   zig build run -- <args> - Run clawgate with arguments
//!   zig build test         - Run unit tests
//!   zig build fmt          - Format source code

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options for nats.zig
    const enable_debug = b.option(
        bool,
        "EnableDebug",
        "Enable debug prints for NATS (default: false)",
    ) orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_debug", enable_debug);

    // nats.zig module
    const nats = b.addModule("nats", .{
        .root_source_file = b.path("src/nats/nats.zig"),
        .target = target,
        .imports = &.{
            .{
                .name = "build_options",
                .module = build_options.createModule(),
            },
        },
    });

    // ClawGate executable
    const exe = b.addExecutable(.{
        .name = "clawgate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nats", .module = nats },
            },
        }),
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run clawgate").dependOn(&run_cmd.step);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nats", .module = nats },
            },
        }),
    });
    const run_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

    // Format step
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "build.zig" },
        .check = false,
    });
    b.step("fmt", "Format source code").dependOn(&fmt.step);

    // Format check step
    const fmt_check = b.addFmt(.{
        .paths = &.{ "src", "build.zig" },
        .check = true,
    });
    b.step("fmt-check", "Check formatting").dependOn(&fmt_check.step);
}

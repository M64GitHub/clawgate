//! Skill file generation for ClawGate custom tools.
//!
//! Generates markdown skill files from the tool registry for AI
//! agent consumption.

const std = @import("std");
const tools_mod = @import("tools.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

pub const SkillError = error{
    OutOfMemory,
    WriteFailed,
};

/// Generates a markdown skill file for a single tool.
pub fn generateToolSkill(
    allocator: Allocator,
    name: []const u8,
    config: tools_mod.ToolConfig,
) SkillError![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const w = &output.writer;

    w.print("# Tool: {s}\n\n", .{name}) catch
        return SkillError.OutOfMemory;

    if (config.description.len > 0) {
        w.print("{s}\n\n", .{config.description}) catch
            return SkillError.OutOfMemory;
    }

    w.print("**Command:** `{s}`\n", .{config.command}) catch
        return SkillError.OutOfMemory;
    w.print("**Timeout:** {d}s\n", .{
        config.timeout_seconds,
    }) catch return SkillError.OutOfMemory;
    w.print("**Max output:** {d} bytes\n", .{
        config.max_output_bytes,
    }) catch return SkillError.OutOfMemory;

    w.writeAll("\n## Usage\n\n") catch
        return SkillError.OutOfMemory;
    w.print(
        "```bash\nclawgate tool {s} [args...]\n```\n",
        .{name},
    ) catch return SkillError.OutOfMemory;

    if (config.examples.len > 0) {
        w.writeAll("\n## Examples\n\n") catch
            return SkillError.OutOfMemory;
        for (config.examples) |ex| {
            w.print("```bash\n{s}\n```\n\n", .{ex}) catch
                return SkillError.OutOfMemory;
        }
    }

    if (config.allow_args.len > 0) {
        w.writeAll("\n## Allowed Arguments\n\n") catch
            return SkillError.OutOfMemory;
        for (config.allow_args) |arg| {
            w.print("- `{s}`\n", .{arg}) catch
                return SkillError.OutOfMemory;
        }
    }

    if (config.deny_args.len > 0) {
        w.writeAll("\n## Blocked Arguments\n\n") catch
            return SkillError.OutOfMemory;
        for (config.deny_args) |arg| {
            w.print("- `{s}`\n", .{arg}) catch
                return SkillError.OutOfMemory;
        }
    }

    const result = output.written();
    const owned = allocator.dupe(u8, result) catch
        return SkillError.OutOfMemory;
    output.deinit();
    return owned;
}

/// Generates a router SKILL.md referencing all tools.
pub fn generateRouter(
    allocator: Allocator,
    tool_names: []const []const u8,
) SkillError![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const w = &output.writer;

    w.writeAll("# ClawGate Skills\n\n") catch
        return SkillError.OutOfMemory;
    w.writeAll("## Core Operations\n\n") catch
        return SkillError.OutOfMemory;
    w.writeAll("- [File Operations](core/files.md)\n") catch
        return SkillError.OutOfMemory;
    w.writeAll("- [Git Operations](core/git.md)\n") catch
        return SkillError.OutOfMemory;

    if (tool_names.len > 0) {
        w.writeAll("\n## Custom Tools\n\n") catch
            return SkillError.OutOfMemory;
        for (tool_names) |name| {
            w.print(
                "- [{s}](tools/{s}.md)\n",
                .{ name, name },
            ) catch return SkillError.OutOfMemory;
        }
    }

    const result = output.written();
    const owned = allocator.dupe(u8, result) catch
        return SkillError.OutOfMemory;
    output.deinit();
    return owned;
}

/// Generates all skill files into output_dir.
pub fn generateAll(
    allocator: Allocator,
    io: Io,
    registry: *const tools_mod.ToolRegistry,
    output_dir: []const u8,
) SkillError!void {
    // Create directory structure
    const tools_dir = std.fmt.allocPrint(
        allocator,
        "{s}/tools",
        .{output_dir},
    ) catch return SkillError.OutOfMemory;
    defer allocator.free(tools_dir);

    Dir.createDirPath(.cwd(), io, tools_dir) catch {};

    // Generate per-tool skill files
    const names = registry.listNames(allocator) catch
        return SkillError.OutOfMemory;
    defer allocator.free(names);

    for (registry.entries) |entry| {
        const content = try generateToolSkill(
            allocator,
            entry.name,
            entry.config,
        );
        defer allocator.free(content);

        const file_path = std.fmt.allocPrint(
            allocator,
            "{s}/tools/{s}.md",
            .{ output_dir, entry.name },
        ) catch return SkillError.OutOfMemory;
        defer allocator.free(file_path);

        const file = Dir.createFile(
            .cwd(),
            io,
            file_path,
            .{},
        ) catch return SkillError.WriteFailed;
        defer file.close(io);
        file.writeStreamingAll(io, content) catch
            return SkillError.WriteFailed;
    }

    // Generate router
    const router = try generateRouter(allocator, names);
    defer allocator.free(router);

    const router_path = std.fmt.allocPrint(
        allocator,
        "{s}/SKILL.md",
        .{output_dir},
    ) catch return SkillError.OutOfMemory;
    defer allocator.free(router_path);

    const router_file = Dir.createFile(
        .cwd(),
        io,
        router_path,
        .{},
    ) catch return SkillError.WriteFailed;
    defer router_file.close(io);
    router_file.writeStreamingAll(io, router) catch
        return SkillError.WriteFailed;
}

// Tests

test "generateToolSkill produces markdown" {
    const allocator = std.testing.allocator;

    const config = tools_mod.ToolConfig{
        .command = "bc -l",
        .allow_args = &[_][]const u8{"-q"},
        .deny_args = &[_][]const u8{},
        .arg_mode = .allowlist,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "Calculator (bc)",
        .examples = &[_][]const u8{
            "echo \"2+2\" | clawgate tool calc",
        },
        .created = "2026-01-01T00:00:00Z",
    };

    const md = try generateToolSkill(allocator, "calc", config);
    defer allocator.free(md);

    try std.testing.expect(
        std.mem.indexOf(u8, md, "# Tool: calc") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, md, "Calculator (bc)") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, md, "`bc -l`") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, md, "## Examples") != null,
    );
}

test "generateRouter produces markdown with tools" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{ "calc", "grep" };
    const md = try generateRouter(allocator, &names);
    defer allocator.free(md);

    try std.testing.expect(
        std.mem.indexOf(u8, md, "# ClawGate Skills") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, md, "tools/calc.md") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, md, "tools/grep.md") != null,
    );
}

test "generateAll writes files" {
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

    var reg = tools_mod.ToolRegistry.load(
        allocator,
        io,
        tmp_path,
    ) catch unreachable;
    defer reg.deinit(allocator);

    try reg.register(allocator, io, "test_tool", .{
        .command = "echo",
        .allow_args = &[_][]const u8{},
        .deny_args = &[_][]const u8{},
        .arg_mode = .passthrough,
        .scope = null,
        .timeout_seconds = 10,
        .max_output_bytes = 65536,
        .description = "Test tool",
        .examples = &[_][]const u8{},
        .created = "",
    });

    const out_dir = std.fmt.allocPrint(
        allocator,
        "{s}/skills",
        .{tmp_path},
    ) catch unreachable;
    defer allocator.free(out_dir);

    try generateAll(allocator, io, &reg, out_dir);

    // Verify SKILL.md exists
    const router_path = std.fmt.allocPrint(
        allocator,
        "{s}/skills/SKILL.md",
        .{tmp_path},
    ) catch unreachable;
    defer allocator.free(router_path);

    const router_file = Dir.openFile(
        .cwd(),
        io,
        router_path,
        .{},
    ) catch {
        return error.TestUnexpectedResult;
    };
    router_file.close(io);
}

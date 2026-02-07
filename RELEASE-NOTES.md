# ClawGate v0.2.1 Release Notes

This release hardens security across the board: component-aware
forbidden path matching (no more substring false positives),
git config key whitelisting, identity validation for tokens,
improved symlink protection with TOCTOU-safe two-phase writes,
and robust output truncation for large git diffs.

## Git Operations

ClawGate now supports running git commands on repositories hosted on your
primary machine. Like file access, git operations are scoped by capability
tokens, time-bounded, and fully audited.

### Three Permission Tiers

| Tier | Grant Flag | What It Allows |
|------|-----------|----------------|
| **Read-only** | `--git` | status, diff, log, show, blame, branch list, ... |
| **Write** | `--git-write` | add, commit, checkout, merge, rebase, reset, ... |
| **Full** | `--git-full` | push, pull, fetch, remote add/remove, submodule |

Each tier includes all permissions from the previous tier.

### Usage

**Grant git access** (on your laptop):
```bash
# Read-only git (+ file read/list/stat)
clawgate grant --git ~/projects/** --ttl 24h

# Git read + write (+ file read/write)
clawgate grant --git-write ~/projects/** --ttl 8h

# Full git access including push/pull/fetch
clawgate grant --git-full ~/projects/** --ttl 4h
```

**Run git commands** (on agent machine):
```bash
clawgate git ~/projects/myapp status
clawgate git ~/projects/myapp diff HEAD~3
clawgate git ~/projects/myapp log --oneline -20
clawgate git ~/projects/myapp blame src/main.zig
clawgate git ~/projects/myapp commit -m "fix: resolve edge case"
clawgate git ~/projects/myapp push origin main
```

**MCP tool** (for Claude Code, Codex, etc.):
```json
{
  "name": "clawgate_git",
  "arguments": {
    "path": "/home/mario/projects/myapp",
    "args": ["status", "--short"]
  }
}
```

### Security

Git operations inherit all existing ClawGate security properties (E2E
encryption, token scoping, forbidden paths, audit logging) and add
git-specific protections:

- **Command allowlists** - Only approved git subcommands are permitted
  per tier. Dangerous commands like `filter-branch` are always blocked.
- **Blocked flags** - Top-level git flags that could escape scope or
  execute arbitrary code are rejected:
  `-c`, `--exec-path`, `--git-dir`, `--work-tree`, `-C`
- **Per-subcommand blocks** - Flags like `rebase --exec`,
  `diff --ext-diff`, and `config --global` are blocked.
- **Output truncation** - Git output is capped at 512 KB to prevent
  memory exhaustion.
- **Repository validation** - Target path must contain a `.git/`
  directory.

### New Error Codes

| Code | Description |
|------|-------------|
| `GIT_ERROR` | Git command execution failed |
| `GIT_BLOCKED` | Command or flag blocked by allowlist |
| `GIT_NOT_REPO` | Target path is not a git repository |
| `GIT_TIMEOUT` | Git command timed out |

### Files Added/Changed

**New files:**
- `src/resource/git.zig` - Git execution engine, allowlists, argument validation
- `src/cli/git_cmd.zig` - `clawgate git` CLI command

**Modified files:**
- `src/protocol/json.zig` - Added `args` field, `GitResult` type, `"git"` operation
- `src/resource/handlers.zig` - Git dispatch and tier-based permission checks
- `src/cli/grant.zig` - `--git`, `--git-write`, `--git-full` flags
- `src/agent/mcp.zig` - `clawgate_git` MCP tool
- `src/main.zig` - `git` command routing

### Test Coverage

250 tests passing, including new tests for:
- Git subcommand classification (all three tiers + blocked)
- Argument validation (blocked top-level flags, per-subcommand flags)
- Special subcommand handling (stash, remote, config, branch, tag)
- Git request JSON building
- MCP tool count verification

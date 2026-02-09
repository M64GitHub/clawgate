# ClawGate Release History

---

## v0.3.2

This release fixes two bugs affecting tool invocation from non-TTY
environments (AI agents, scripts, CI) and adds **hot-reload** for the
tool registry so newly registered tools work without restarting the
resource daemon.

### Tool Registry Hot-Reload

Previously, the resource daemon loaded the tool registry once at
startup and cached it for the lifetime of the process. Registering a
new tool via `clawgate tool register` while the daemon was running
would result in `TOOL_DENIED` until a full daemon restart.

The resource daemon now reloads the tool registry on every request,
matching the existing behavior of the revocation list. Tools
registered or removed while the daemon is running take effect
immediately.

```bash
# With daemons already running:
clawgate tool register jq --command jq --description "JSON processor"
clawgate grant --tool jq --read /path/**

# Works immediately - no restart needed
clawgate tool jq '.name' /path/config.json
```

### Non-TTY Stdin Hang Fix

Tool invocations from non-TTY environments (AI agents like OpenClaw,
cron jobs, CI pipelines, scripts) would hang indefinitely. The CLI
unconditionally tried to read stdin before sending the tool request,
blocking forever when stdin had no writer and no EOF.

**Before:** `clawgate tool rg pattern /path` hangs when run from a
script or agent.

**After:** The CLI uses `poll(0)` to check for pending stdin data
before attempting to read. If no data is immediately available, stdin
reading is skipped entirely.

### Integration Tests

Added 2 new integration tests verifying hot-reload behavior:

- **"tool registered after daemon start works"** - registers a tool
  while daemons are running, invokes without restart
- **"tool removed after daemon start is denied"** - removes a tool
  while daemons are running, verifies denial

### Modified Files

| File | Changes |
|------|---------|
| `src/resource/daemon.zig` | Tool registry reloaded per-request in `mainLoop()` (same pattern as revocation list); removed stale `tool_reg` parameter from `runWithIo`, `connectAndServe`, `mainLoop` |
| `src/cli/tool_cmd.zig` | Added `posix.poll(0)` guard before stdin read in `handleTest` and `handleInvocation` to prevent blocking on empty non-TTY stdin |
| `testing/test_tools.sh` | New hot-reload integration tests (register/remove while daemons running) |

---

## v0.3.1

This release adds **tokenless tool discovery** via `tool remote-list`,
letting agents discover all registered tools without requiring any
capability token or grant. It also improves audit logging for
discovery requests and adds security hardening tests for the
tokenless IPC path.

### Tokenless Tool Discovery

`clawgate tool remote-list` can be used by the agent to discover tools
registered on the primary system, granted or not.
The command is purely metadata - it returns tool names and
descriptions, never executes anything. The resource daemon returns
all registered tools unconditionally.

```bash
# No grant needed - just run it
clawgate tool remote-list
```

### MCP Integration

The `clawgate_tool_list` MCP tool also works without tokens - it
uses the same tokenless discovery path.

### Security Hardening

Added 8 integration tests verifying that the tokenless IPC path
cannot be exploited.

---

## v0.3.0

This release extends ClawGate beyond file and git access. You can now
register **custom CLI tools** on your primary machine and invoke them
from isolated agents through the same zero-trust pipeline: capability
tokens, argument validation, output truncation, audit logging, and
E2E encryption.

Also new: **token revocation**, **issuance tracking**, and **skill
file generation**.

### Custom Tools

Register any CLI tool on the resource machine and grant agents access
to invoke it remotely:

```bash
# Register a tool (primary machine)
clawgate tool register calc \
  --command "bc -l" \
  --allow-args "-q" \
  --timeout 10 \
  --description "Calculator (bc)"

# Grant access
clawgate grant --tool calc --ttl 4h

# Invoke from agent
echo "2+2" | clawgate tool calc
```

### Token Revocation

```bash
clawgate revoke cg_abc123... --reason "compromised"
clawgate revoke --all --reason "key rotation"
clawgate revoked ls
clawgate revoked clean
```

### Grant Enhancements

- `--tool <name>` flag (repeatable) grants access to specific tools
- `--tools-all` grants access to all registered tools
- Path argument is now optional for tool-only tokens
- Combined tokens: `clawgate grant --read --tool calc /path/**`

### New Files

| File | Purpose |
|------|---------|
| `src/resource/revocation.zig` | Revocation list management |
| `src/resource/issuance.zig` | Issuance tracking |
| `src/resource/tools.zig` | Tool registry (CRUD + persistence) |
| `src/resource/tool_exec.zig` | Tool execution engine |
| `src/resource/skills.zig` | Skill file generation |
| `src/cli/revoke.zig` | `revoke` / `revoked` CLI |
| `src/cli/tool_cmd.zig` | `tool` management + invocation CLI |
| `src/cli/skills_cmd.zig` | `skills` generate/export CLI |

---

## v0.2.3

This release adds human-readable expiration dates to token management
commands, making it easy to see when tokens expire at a glance.

### Token Expiration Display

`clawgate token list` and `clawgate token show` now display expiration
(and issuance) timestamps as ISO 8601 dates instead of raw Unix
timestamps.

### Files Changed

- `src/resource/audit_log.zig` - Made `formatEpochBuf` public for reuse
- `src/cli/token.zig` - Added formatted expiration dates to list and
  show commands

---

## v0.2.2

This release adds persistent audit logging on the resource daemon,
fixes a critical agent daemon reconnection bug, and migrates the IPC
transport to cross-platform POSIX for macOS support.

### Audit Log

The resource daemon now writes a persistent audit log to
`~/.clawgate/logs/audit.log`. Every request is recorded with
timestamp, request ID, operation, path, and success/error status.

**Format:**
```
<timestamp> AUDIT req=<id> op=<op> path=<path> success=<bool> [error=<code>]
```

**CLI command:**
```bash
clawgate audit          # View audit log summary and recent entries
```

#### Files Added/Changed

**New files:**
- `src/resource/audit_log.zig` - Audit log writer with atomic append
- `src/cli/audit.zig` - `clawgate audit` CLI command

**Modified files:**
- `src/resource/daemon.zig` - Audit log initialization and per-request logging
- `src/main.zig` - `audit` command routing

### Agent Daemon Reconnection Fix

Fixed a critical bug where the agent daemon would hang permanently after
the resource daemon disconnected. The agent could not accept new
connections and had to be restarted manually.

**Root cause:** The IPC service loop had no way to detect TCP
disconnection. It blocked on IPC accept calls and never checked the
health of the TCP connection to the resource daemon.

**Fix:** Rewrote the IPC service loop using Zig 0.16's `io.async()` +
`io.select()` pattern to race IPC accept against TCP disconnect
detection. The agent now detects resource daemon disconnection
immediately and returns to accepting new connections.

Additionally, `sendRequest()` now clears the connection state on
failure, ensuring the IPC loop exits even if a CLI command discovers
the dead connection first.

### POSIX Portability

Migrated `src/transport/unix.zig` from Linux-only `std.os.linux`
syscalls to cross-platform POSIX. ClawGate now compiles and runs on
both Linux and macOS.

**Changes:**
- All socket operations use `std.posix` / `std.posix.system` with
  comptime type dispatch for Linux raw syscalls vs libc
- Non-blocking server socket via `fcntl(F.SETFL, O.NONBLOCK)` instead
  of `SOCK_NONBLOCK` (which macOS does not support)
- Platform-derived `MAX_PATH_LEN` from `sockaddr.un` struct (108 on
  Linux, 104 on macOS)
- macOS `sockaddr.un.len` field handled via `@hasField` comptime check

---

## v0.2.1

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

# ClawGate v0.2.2 Release Notes

This release adds persistent audit logging on the resource daemon,
fixes a critical agent daemon reconnection bug, and migrates the IPC
transport to cross-platform POSIX for macOS support.

## Audit Log

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

### Files Added/Changed

**New files:**
- `src/resource/audit_log.zig` - Audit log writer with atomic append
- `src/cli/audit.zig` - `clawgate audit` CLI command

**Modified files:**
- `src/resource/daemon.zig` - Audit log initialization and per-request logging
- `src/main.zig` - `audit` command routing

## Agent Daemon Reconnection Fix

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

## POSIX Portability

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

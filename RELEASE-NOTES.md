# ClawGate v0.3.2 Release Notes

This release fixes two bugs affecting tool invocation from non-TTY
environments (AI agents, scripts, CI) and adds **hot-reload** for the
tool registry so newly registered tools work without restarting the
resource daemon.

## Tool Registry Hot-Reload

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

## Non-TTY Stdin Hang Fix

Tool invocations from non-TTY environments (AI agents like OpenClaw,
cron jobs, CI pipelines, scripts) would hang indefinitely. The CLI
unconditionally tried to read stdin before sending the tool request,
blocking forever when stdin had no writer and no EOF.

**Before:** `clawgate tool rg pattern /path` hangs when run from a
script or agent.

**After:** The CLI uses `poll(0)` to check for pending stdin data
before attempting to read. If no data is immediately available, stdin
reading is skipped entirely.

## Integration Tests

Added 2 new integration tests verifying hot-reload behavior:

- **"tool registered after daemon start works"** - registers a tool
  while daemons are running, invokes without restart
- **"tool removed after daemon start is denied"** - removes a tool
  while daemons are running, verifies denial

## Modified Files

| File | Changes |
|------|---------|
| `src/resource/daemon.zig` | Tool registry reloaded per-request in `mainLoop()` (same pattern as revocation list); removed stale `tool_reg` parameter from `runWithIo`, `connectAndServe`, `mainLoop` |
| `src/cli/tool_cmd.zig` | Added `posix.poll(0)` guard before stdin read in `handleTest` and `handleInvocation` to prevent blocking on empty non-TTY stdin |
| `testing/test_tools.sh` | New hot-reload integration tests (register/remove while daemons running) |

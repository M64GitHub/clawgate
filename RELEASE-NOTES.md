# ClawGate v0.3.1 Release Notes

This release adds **tokenless tool discovery** via `tool remote-list`,
letting agents discover all registered tools without requiring any
capability token or grant. It also improves audit logging for
discovery requests and adds security hardening tests for the
tokenless IPC path.

## Tokenless Tool Discovery

`clawgate tool remote-list` no longer requires a capability token.
The command is purely metadata — it returns tool names and
descriptions, never executes anything. The resource daemon returns
all registered tools unconditionally.

```bash
# No grant needed — just run it
clawgate tool remote-list
```

```
calc    Calculator (bc)
catnum  Cat with line numbers
```

**Why:** Tool discovery is a read-only metadata operation. Requiring
a token with `--tool` scope created friction and broke the common
case where agents have `--read` or `--git` tokens but want to see
what tools are available.

### How It Works

1. CLI sends a tokenless `{"op":"tool_list","params":{}}` via IPC
2. Agent daemon detects the tokenless request and forwards it to
   the resource daemon over the E2E encrypted TCP connection
3. Resource daemon intercepts the tokenless `tool_list` request
   before token validation and returns all registered tools
4. Actual tool **invocation** still requires a properly scoped token

### MCP Integration

The `clawgate_tool_list` MCP tool also works without tokens — it
uses the same tokenless discovery path.

## Audit Log Improvements

Discovery requests now produce clean audit entries:

```
2026-02-08T12:00:00Z AUDIT req=discovery op=tool_list path=- success=true
```

Previously, tokenless requests produced `req=unknown op=unknown
path=unknown` because the audit logger tried to parse the tokenless
JSON as a standard request.

## Security Hardening

Added 8 integration tests verifying that the tokenless IPC path
cannot be exploited:

- Tokenless `read`, `write`, `git`, `tool`, `list`, `stat` requests
  are all rejected with "Token required"
- Empty tokenless requests are rejected
- `tool_list` responses cannot leak file contents

## Modified Files

| File | Changes |
|------|---------|
| `src/resource/handlers.zig` | Tokenless `tool_list` interception before `parseRequest` |
| `src/resource/audit_log.zig` | Proper audit entries for tokenless discovery |
| `src/agent/daemon.zig` | Tokenless IPC detection, simplified `handleToolListDiscovery` |
| `src/agent/mcp.zig` | Tokenless `clawgate_tool_list` MCP tool |
| `src/cli/tool_cmd.zig` | Tokenless `handleRemoteList` |
| `docs/TOOL-GUIDE.md` | Updated discovery docs (no token required) |
| `testing/test_tools.sh` | New tokenless security tests |

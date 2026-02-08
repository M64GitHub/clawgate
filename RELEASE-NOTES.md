# ClawGate v0.3.0 Release Notes

This release extends ClawGate beyond file and git access. You can now
register **custom CLI tools** on your primary machine and invoke them
from isolated agents through the same zero-trust pipeline: capability
tokens, argument validation, output truncation, audit logging, and
E2E encryption.

Also new: **token revocation**, **issuance tracking**, and **skill
file generation**.

## Custom Tools

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

### Security

- **Argument validation**: allowlist mode (only listed flags pass) or
  passthrough mode (all flags except denied ones pass)
- **No shell execution**: commands run via direct argv, never through
  a shell
- **Output truncation**: configurable per-tool output limit
- **Per-tool capability**: tokens grant access to specific tools only

### Management

```bash
clawgate tool ls                     # List tools
clawgate tool info calc              # Show details
clawgate tool update calc --timeout 30
clawgate tool remove calc
clawgate tool test calc -q           # Test locally (no daemon)
```

## Token Revocation

Revoke tokens before they expire. The revocation list is checked on
every request by the resource daemon.

```bash
clawgate revoke cg_abc123... --reason "compromised"
clawgate revoke --all --reason "key rotation"
clawgate revoked ls
clawgate revoked clean               # Remove expired entries
```

A revoked token returns `TOKEN_REVOKED`. The agent daemon automatically
removes rejected tokens from its local store.

## Issuance Tracking

Every token created by `clawgate grant` is recorded in
`~/.clawgate/issued.json`. This enables bulk revocation (`--all`) and
provides an audit trail of granted access.

## Skill File Generation

Generate markdown skill files from the tool registry, making tools
discoverable by AI agents:

```bash
clawgate skills generate             # Generate to skills/clawgate/
clawgate skills export /path/to/dir
```

## Grant Enhancements

- `--tool <name>` flag (repeatable) grants access to specific tools
- `--tools-all` grants access to all registered tools
- Path argument is now optional for tool-only tokens
- Combined tokens: `clawgate grant --read --tool calc /path/**`

## MCP Integration

New `clawgate_tool` MCP tool (6th tool) for invoking registered tools
via JSON-RPC.

## New Files

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

## Modified Files

| File | Changes |
|------|---------|
| `src/protocol/json.zig` | `"tool"` op, `ToolResult`, new params |
| `src/resource/handlers.zig` | Revocation check, tool routing |
| `src/resource/daemon.zig` | Loads registry + revocation list |
| `src/resource/audit_log.zig` | Logs tool name for tool operations |
| `src/cli/grant.zig` | `--tool`, `--tools-all`, issuance log |
| `src/agent/mcp.zig` | `clawgate_tool` MCP tool |
| `src/main.zig` | v0.3.0, new command routing |

## Documentation

- New: `docs/TOOL-GUIDE.md` - Practical guide for custom tools
- New: `docs/README.md` - Documentation index
- Updated: `docs/OPENCLAW-QUICK-SETUP.md` - Added git access, skill
  file setup, chat-based token workflow
- Updated: `README.md` - Guides/Reference doc sections

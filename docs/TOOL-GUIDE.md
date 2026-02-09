# Custom Tools - Practical Guide

ClawGate lets you register **custom tools** on your primary machine and
invoke them from the agent machine. Tools go through the same zero-trust
pipeline as file and git operations: capability tokens, argument
validation, output truncation, audit logging, and end-to-end encryption.

This guide walks you through integrating your first tool from scratch.

## Table of Contents

- [Your First Tool: Calculator](#your-first-tool-calculator)
- [Tool Scope and Path Security](#tool-scope-and-path-security)
- [Troubleshooting](#troubleshooting)
- [Going Further](#going-further)
- [Remote Tool Discovery](#remote-tool-discovery)
- [Command Reference](#command-reference)
- [Token Revocation](#token-revocation)

---

## Your First Tool: Calculator

This walkthrough registers `bc` (a standard Unix calculator) as a
ClawGate tool and invokes it from the agent machine. Every step shows
where to run the command: **primary** (your laptop) or **agent** (the
isolated machine).

### Step 1: Generate Keys

> Skip this if you already have keys from a previous setup.

**[primary]**
```bash
clawgate keygen
```

This creates an Ed25519 keypair at `~/.clawgate/keys/`. The private key
signs tokens, the public key verifies them.

### Step 2: Register the Tool

**[primary]**
```bash
clawgate tool register calc \
  --command "bc -l" \
  --allow-args "-q" \
  --timeout 10 \
  --max-output 65536 \
  --description "Calculator (bc)" \
  --example 'echo "2+2" | clawgate tool calc'
```

Expected output:

```
Tool registered
```

What happened: ClawGate saved the tool definition to
`~/.clawgate/tools.json`. The `--allow-args "-q"` means only the `-q`
flag is allowed - any other flag will be rejected. This is the
**allowlist** argument mode (the default).

### Step 3: Test Locally

Before involving daemons and tokens, verify the tool works directly
on the primary machine.

**[primary]**
```bash
echo "2+2" | clawgate tool test calc
```

Expected output:

```
4
```

Try a blocked flag to confirm argument validation works:

**[primary]**
```bash
echo "1+1" | clawgate tool test calc --exec
```

Expected output:

```
Error: Blocked argument
```

Good - `--exec` is not in the allowlist, so it was rejected.

### Step 4: Start the Agent Daemon

**[agent]**
```bash
clawgate --mode agent
```

Expected output:

```
Loading tokens from ~/.clawgate/tokens
Loaded 0 token(s)
Binding TCP listener on 0.0.0.0:53280
Agent daemon ready, waiting for connections
```

The agent daemon listens on port 53280 and waits for the resource daemon
to connect. Leave this running.

### Step 5: Start the Resource Daemon

**[primary]**
```bash
clawgate --mode resource --connect <agent-ip>:53280
```

Replace `<agent-ip>` with the agent machine's IP address (or
`localhost` if testing on the same machine).

Expected output:

```
Connecting to agent at <agent-ip>:53280
Connected, performing handshake
E2E session established
```

Both daemons are now connected with end-to-end encryption. Leave this
running too.

### Step 6: Grant a Tool Token

**[primary]**
```bash
clawgate grant --tool calc --ttl 1h
```

Expected output: a JWT token (a long base64 string):

```
eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOi...
```

This token grants permission to invoke `calc` and nothing else. It
expires in 1 hour. Copy the full token string.

### Step 7: Add the Token on the Agent

**[agent]** (open a second terminal on the agent machine)
```bash
clawgate token add <paste-token-here>
```

Expected output:

```
Token added: cg_a1b2c3d4...
```

The token is now stored at `~/.clawgate/tokens/` on the agent machine
and will be used automatically for tool invocations.

> **OpenClaw users:** You don't need to SSH into the agent machine.
> Just paste the token into your chat and the agent adds it for you.
> See the [OpenClaw Quick Setup](OPENCLAW-QUICK-SETUP.md) for details.

### Step 8: Invoke the Tool

**[agent]**
```bash
echo "2+2" | clawgate tool calc
```

Expected output:

```
4
```

What happened behind the scenes:

1. The agent CLI found a token granting `invoke` access to `calc`
2. It sent the request (with the token) to the local agent daemon
3. The agent daemon forwarded it over the encrypted TCP connection
4. The resource daemon validated the token signature, expiry, and
   capabilities
5. It checked that `calc` is a registered tool
6. It executed `bc -l` with the piped input
7. The output traveled back through the encrypted channel

Try floating point:

```bash
echo "scale=2; 22/7" | clawgate tool calc
```

Expected output:

```
3.14
```

### Step 9: Check the Audit Log

Every tool invocation is logged on the primary machine.

**[primary]**
```bash
clawgate audit
```

The audit log is at `~/.clawgate/logs/audit.log`. Each entry records
the operation, tool name, token ID, and result.

### Step 10: Cleanup

**[primary]**

Remove the tool from the registry:

```bash
clawgate tool remove calc
```

Expected output:

```
Tool removed
```

Stop both daemons with `Ctrl+C` in their respective terminals.

> **Why no `--scope`?** The calculator tool (`bc`) reads from stdin and
> writes to stdout. It never accesses the filesystem, so no scope is
> needed. Tools without a scope are blocked from receiving any
> path-like arguments (`/...`, `~/...`, `./...`, `../...`).

---

## Tool Scope and Path Security

Tools that access the filesystem **must** have a `--scope` restricting
which directories they can reach. Without a scope, ClawGate blocks
any argument that looks like a file path.

### Registering a Scoped Tool

Scope values are semicolon-separated directories relative to `$HOME`:

**[primary]**
```bash
clawgate tool register mygrep \
  --command "grep" \
  --arg-mode passthrough \
  --deny-args "--exec" \
  --scope "projects/webapp" \
  --description "Grep within webapp"
```

Now `mygrep` can only access files under `~/projects/webapp/`:

```bash
# Works - path within scope:
clawgate tool test mygrep -rn "TODO" ~/projects/webapp/src/

# Blocked - path outside scope:
clawgate tool test mygrep -rn "TODO" /etc/hosts
# Error: Path blocked

# Blocked - traversal attempt:
clawgate tool test mygrep -rn "TODO" ~/projects/webapp/../../etc/passwd
# Error: Path blocked
```

### Multiple Scope Entries

Grant access to several directories:

```bash
clawgate tool register mygrep \
  --command "grep" \
  --arg-mode passthrough \
  --deny-args "--exec" \
  --scope "projects/webapp;Documents/reports" \
  --description "Grep in webapp and reports"
```

A path argument passes if it falls within **any** of the scope entries.

### Scope Rules

| Rule | Example | Result |
|------|---------|--------|
| Paths relative to `$HOME` | `--scope "projects"` | Access `~/projects/**` |
| Multiple entries | `--scope "a;b"` | Access `~/a/**` or `~/b/**` |
| `.` rejected | `--scope "."` | Error (too permissive) |
| `..` rejected | `--scope ".."` | Error (escapes `$HOME`) |
| Absolute paths rejected | `--scope "/etc"` | Error (must be relative) |
| Empty segments rejected | `--scope "a;;b"` | Error (malformed) |

### How Path Scanning Works

ClawGate applies three layers of argument security:

1. **Flag validation** - Allow/deny lists for flags (`-x`, `--flag`)
2. **Path scanning** - Non-flag arguments that look like file paths
   are canonicalized and checked against the tool's scope
3. **CWD confinement** - The tool subprocess runs with its working
   directory set to `$HOME`, so relative paths resolve predictably

Only syntactically unambiguous path forms are detected: `/...`,
`~/...`, `./...`, `../...`, `.`, and `..`. Bare words like `pattern`
or `TODO` pass through unscanned (they could be tool subcommands or
search patterns).

### Forbidden Paths

Even within scope, certain sensitive directories are always blocked:

- `~/.ssh/`
- `~/.gnupg/`
- `~/.clawgate/keys/`
- `~/.aws/`

### No Scope = No Filesystem Access

Tools registered without `--scope` cannot receive path-like arguments
at all. This is the correct setting for pure stdin/stdout tools like
calculators, formatters, or linters that read from stdin:

```bash
# No scope needed - reads from stdin only:
clawgate tool register calc --command "bc -l"

# Path argument blocked (no scope):
clawgate tool test calc /etc/passwd
# Error: Path blocked
```

---

## Troubleshooting

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `Error: --command required` | Missing `--command` flag during register | Add `--command "your-command"` |
| `Error: Tool 'X' already exists` | Tool name taken | Use a different name, or remove first |
| `Error: Tool 'X' not found` | Tool not registered | Register it with `clawgate tool register` |
| `Error: Blocked argument` | Flag not in allowlist (or in denylist) | Add the flag to `--allow-args` or remove from `--deny-args` |
| `Error: Path blocked` | Path argument outside tool scope | Add `--scope` to cover the path, or widen existing scope |
| `Error: Path blocked` (no scope) | Tool has no scope but received a path | Add `--scope` if the tool needs filesystem access |
| `Error: Invalid scope value` | Scope contains `.`, `..`, absolute path, or empty segment | Use relative paths only: `--scope "projects/myapp"` |
| `Error: No tokens found` | No tokens in agent's token store | Run `clawgate token add` on the agent |
| `Error: No token grants invoke access to tool 'X'` | Token doesn't cover this tool | Grant a new token with `--tool X` |
| `Error: Failed to connect to daemon` | Agent daemon not running | Start it with `clawgate --mode agent` |
| `Error: Failed to load tool registry` | No tools registered yet | Register your first tool |
| `Error: HOME not set` | `$HOME` not in environment | `export HOME=/home/youruser` |
| `TOKEN_REVOKED` | Token was revoked | Grant and add a new token |
| `TOKEN_EXPIRED` | Token TTL elapsed | Grant and add a new token |
| `TOOL_DENIED` | No tool registry or no tools matched | Grant a token with `--tool` or `--tools-all` |
| `ARG_BLOCKED` | Tool argument blocked by allow/deny list | Adjust `--allow-args` or `--deny-args` |
| `PATH_BLOCKED` | Path argument outside tool scope | Widen `--scope` or remove the path argument |

**Daemon startup order**: Start the agent daemon first, then the
resource daemon. The resource daemon connects to the agent, not the
other way around.

**Testing on one machine**: Use `--connect localhost:53280` on the
resource daemon if both daemons run on the same machine.

---

## Going Further

### Updating a Tool

Change a tool's configuration without re-registering:

**[primary]**
```bash
clawgate tool update calc --timeout 20
```

```
Tool updated
```

You can update `--command`, `--timeout`, `--max-output`, `--scope`,
and `--description`. Existing tokens remain valid - the tool registry
is checked at execution time, not at token creation.

### Listing and Inspecting Tools

**[primary]**
```bash
clawgate tool ls
```

```
calc     bc -l   Calculator (bc)
mygrep   grep    Safe grep          [projects/webapp]
```

```bash
clawgate tool info calc
```

```
Name:        calc
Command:     bc -l
Arg mode:    allowlist
Scope:       (none)
Timeout:     10s
Max output:  65536 bytes
Description: Calculator (bc)
```

### Argument Security: Allowlist vs Passthrough

**Allowlist mode** (default): only explicitly listed flags are allowed.
Everything else is blocked. Best for tools where you want tight control.

```bash
clawgate tool register calc \
  --command "bc -l" \
  --allow-args "-q"
# Only -q passes through. --exec, -c, etc. are all blocked.
```

**Passthrough mode**: all arguments pass through except those in the
deny list. Best for tools that are generally safe but have a few
dangerous flags.

```bash
clawgate tool register mygrep \
  --command "grep" \
  --deny-args "--exec" \
  --deny-args "-c" \
  --arg-mode passthrough \
  --scope "projects/webapp" \
  --description "Safe grep"
```

The `--scope` is required because `grep` accesses the filesystem.
Without it, any path-like argument would be blocked.

```bash
# Works (passthrough allows everything not denied):
clawgate tool test mygrep -rn "TODO" ~/projects/webapp/

# Blocked flag:
clawgate tool test mygrep --exec "evil" ~/projects/webapp/
# Error: Blocked argument

# Blocked path (outside scope):
clawgate tool test mygrep -rn "TODO" /etc/hosts
# Error: Path blocked

# Also blocked (--flag=value form):
clawgate tool test mygrep --exec=evil ~/projects/webapp/
# Error: Blocked argument
```

Both modes always allow positional (non-flag) arguments, but
path-like arguments are still validated against the tool's scope.

### Multiple Tools in One Token

Grant access to several tools with a single token:

**[primary]**
```bash
clawgate grant --tool calc --tool wc --ttl 4h
```

The resulting token allows invoking both `calc` and `wc`, but nothing
else.

### Combined File + Tool Tokens

A single token can grant file access and tool access together:

**[primary]**
```bash
clawgate grant --read --tool calc --ttl 1h /tmp/**
```

This token lets the agent read files under `/tmp/` **and** invoke `calc`.

### All-Tools Access

Grant access to every registered tool at once:

**[primary]**
```bash
clawgate grant --tools-all --ttl 4h
```

Or combine with file and git access for full access:

```bash
clawgate grant --read --write --git --tools-all --ttl 24h ~/projects/**
```

### Output Limits

Tools have a configurable output size limit (default: 65536 bytes).
If a tool produces more output than the limit, it is truncated and
the response includes a `truncated` flag.

```bash
# Register a tool with a small output limit:
clawgate tool register small \
  --command "cat" \
  --scope "projects/webapp" \
  --max-output 16

echo "this is more than sixteen bytes" | clawgate tool test small
# Output truncated to 16 bytes
```

Update the limit if needed:

```bash
clawgate tool update small --max-output 1048576
```

### Skill File Generation

ClawGate can generate markdown "skill files" from the tool registry.
These describe your tools in a format that AI agents can read.

**[primary]**
```bash
clawgate skills generate
```

```
Skills generated in skills/clawgate/
```

This creates:

```
skills/clawgate/
  SKILL.md              <- Index with links to all tools
  tools/
    calc.md             <- Per-tool documentation
    mygrep.md
```

Export to a custom directory:

```bash
clawgate skills export /path/to/output
```

---

## Remote Tool Discovery

Agents can discover what tools are available without knowing names in
advance:

**[agent]**
```bash
clawgate tool remote-list
```

Expected output:

```
calc     Calculator (bc)
mygrep   Safe grep          [projects/webapp]
```

This is a discovery command - it shows all registered tools regardless
of token scope. No token or grant is required. The agent daemon
forwards the request to the resource daemon, which returns every
tool in the registry unconditionally. Actual tool invocation still
requires a properly scoped token.

---

## Command Reference

### Tool Management (primary machine)

| Command | Purpose |
|---------|---------|
| `clawgate tool register <name> --command "..." [--scope "..."] [options]` | Register a new tool |
| `clawgate tool ls` | List all registered tools |
| `clawgate tool info <name>` | Show tool details |
| `clawgate tool update <name> [options]` | Update tool configuration |
| `clawgate tool remove <name>` | Remove a tool |
| `clawgate tool test <name> [args]` | Test a tool locally (no daemons) |

### Token Granting (primary machine)

| Command | Purpose |
|---------|---------|
| `clawgate grant --tool <name> --ttl <duration>` | Grant access to one tool |
| `clawgate grant --tool X --tool Y --ttl <duration>` | Grant access to multiple tools |
| `clawgate grant --tools-all --ttl <duration>` | Grant access to all tools |
| `clawgate grant --read --tool <name> --ttl <duration> <path>` | Combined file + tool access |
| `clawgate keygen` | Generate Ed25519 keypair |

### Token Management (agent machine)

| Command | Purpose |
|---------|---------|
| `clawgate token add <jwt>` | Store a token |
| `clawgate token list` | List stored tokens |
| `clawgate token remove <id>` | Remove a token |

### Tool Invocation (agent machine)

| Command | Purpose |
|---------|---------|
| `clawgate tool remote-list` | List tools available via daemon |
| `clawgate tool <name> [args]` | Invoke tool via daemon |
| `echo "data" \| clawgate tool <name>` | Invoke tool with stdin |

### Skills (primary machine)

| Command | Purpose |
|---------|---------|
| `clawgate skills generate` | Generate skill files from registry |
| `clawgate skills export <dir>` | Export skill files to a directory |

### Revocation (primary machine)

| Command | Purpose |
|---------|---------|
| `clawgate revoke <id> --reason "..."` | Revoke a single token |
| `clawgate revoke --all --reason "..."` | Revoke all issued tokens |
| `clawgate revoked ls` | List revoked tokens |
| `clawgate revoked clean` | Remove expired entries |

---

## Token Revocation

### What Is Revocation?

Tokens are time-bounded, but sometimes you need to cut access
immediately - before the token expires. Revocation lets you invalidate
a token so it is rejected on every future request, even if it hasn't
expired yet.

### When to Revoke

- The agent machine may be compromised
- A session is over and you want to clean up access
- You're rotating keys
- You granted too broad access by mistake

### Revoking a Single Token

Find the token ID from the issuance log or token list:

**[agent]**
```bash
clawgate token list
```

```
cg_a1b2c3d4e5f6...  expires 2026-02-08T15:30:00Z
```

Then revoke it on the primary machine:

**[primary]**
```bash
clawgate revoke cg_a1b2c3d4e5f6... --reason "session over"
```

```
Token revoked
```

### Revoking All Tokens

Revoke every token that was ever issued:

**[primary]**
```bash
clawgate revoke --all --reason "key rotation"
```

```
Revoked 3 token(s)
```

### Checking Revocation Status

**[primary]**
```bash
clawgate revoked ls
```

```
cg_a1b2c3d4...  2026-02-08T14:30:45Z  session over
cg_x9y8z7w6...  2026-02-08T14:31:00Z  key rotation
```

### What Happens on the Agent Side

When a revoked token is used, the resource daemon rejects the request
with `TOKEN_REVOKED`. The agent daemon then **automatically removes
the rejected token** from its local store. The agent does not need to
do anything manually - revoked tokens are cleaned up on first use.

### Cleaning Up Expired Entries

Over time, the revocation list accumulates entries for tokens that
have already expired. Clean them up:

**[primary]**
```bash
clawgate revoked clean
```

```
Removed 2 expired entries
```

This is optional housekeeping. Expired tokens are rejected by the
expiry check before the revocation check, so stale entries don't
cause problems - they just take up space.

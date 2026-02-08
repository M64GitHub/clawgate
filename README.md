[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16+-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/M64GitHub/clawgate/releases)
[![GitHub Release](https://img.shields.io/github/v/release/M64GitHub/clawgate)](https://github.com/M64GitHub/clawgate/releases/latest)

# ClawGate

**ClawGate** is a secure capability proxy for isolated AI agents. It lets agents access files, run git commands, and invoke registered tools on your primary machine - all through cryptographically signed capability tokens with fine-grained, time-bounded, audited access control.

Think of it as **SSH keys meet JWT tokens meet capability-based security** - designed specifically for the AI agent era. Isolation without compromise.

## The Problem

You're running [OpenClaw](https://github.com/openclaw/openclaw) (or Claude Code, or any AI agent) on an isolated machine - maybe a Mac Mini, a VPS, or a sandboxed container. **Smart move for security.**

But now your agent needs to read files, run builds, or use tools on your machine. Your options?

| Approach | Problem |
|----------|---------|
| NFS/SMB mount | Full filesystem access. Agent gets pwned -> you get pwned |
| SSH + rsync | Credentials on the agent machine. Same problem |
| Manual copy | Tedious. Breaks flow. Doesn't scale |
| Cloud sync | Your code on someone else's servers |

**None of these assume the agent might be compromised.** But it might be - prompt injection is real.

## The Solution

ClawGate provides **secure, scoped, audited access to files, git, and custom tools** over direct TCP with end-to-end encryption:

**Key principles:**
- **Zero trust** - Assumes the agent machine is compromised
- **Least privilege** - Grant only specific paths and tools, not everything
- **Time-bounded** - Tokens expire (1 hour, 24 hours, 7 days)
- **Revocable** - Revoke tokens instantly, before they expire
- **Complete audit** - Every operation logged with cryptographic proof

## Quick Start

### Requirements

- **Platforms:** Linux or macOS (uses Unix sockets for local IPC)
- **Build:** Zig 0.16+ (if building from source)

> **Note:** Windows is not currently supported. WSL2 works but is untested.


**1. Install** (on both machines):
```bash
curl -sSL https://clawgate.io/install.sh | sh
```
Or build from source (requires Zig 0.16+):
```bash
git clone https://github.com/M64GitHub/clawgate && cd clawgate
zig build -Doptimize=ReleaseSafe
sudo cp zig-out/bin/clawgate /usr/local/bin/
```

**2. Generate keys** (on your laptop):
```bash
clawgate keygen
# Creates ~/.clawgate/keys/secret.key and public.key
```

**3. Copy public key to agent machine**:
```bash
# On agent machine - create the directory:
mkdir -p ~/.clawgate/keys

# From your laptop - copy the public key:
scp ~/.clawgate/keys/public.key agent-machine:~/.clawgate/keys/
```
The agent needs your public key to verify token signatures.

**4. Grant access** (on your laptop):
```bash
clawgate grant --read ~/projects --ttl 24h
# Or with git access:
clawgate grant --git ~/projects --ttl 24h
# Or grant a registered tool:
clawgate grant --tool calc --ttl 4h
# Outputs a token - copy it to the agent machine
```

**5. Add token** (on agent machine):
```bash
clawgate token add "<paste-token-here>"
```

**6. Start daemons**:
```bash
# On agent machine (start first):
clawgate --mode agent

# On your laptop:
clawgate --mode resource --connect <agent-ip>:4223
```

**Done.** Your agent can now securely read files, run git commands, and invoke tools - depending on what you granted.

## OpenClaw Integration

ClawGate was built for [OpenClaw](https://github.com/openclaw/openclaw).  

Add the skill file: copy `skills/clawgate/SKILL.md` to your workspace.  
Or let the agent do it. Paste it in Telegram / Whatsapp.  
**Done**.  

```bash
# Your agent can now use these commands:
clawgate cat ~/projects/app/src/main.zig
clawgate ls ~/projects/app/src/
clawgate write ~/projects/app/notes.md --content "TODO: refactor"
clawgate git ~/projects/app status
clawgate git ~/projects/app diff HEAD~3
clawgate tool calc                          # Invoke registered tools
echo "2+2" | clawgate tool calc             # With stdin
```

### Example Interaction

<img  width="400px" alt="image" src="https://github.com/user-attachments/assets/953da1d4-7e3c-4946-b5ee-1e21c9c18a49" />

Resource daemon logs audit events (on private laptop)
<img width="1906" height="274" alt="image" src="https://github.com/user-attachments/assets/9e63403f-ba10-44f5-aa55-21339f2a8f9f" />

Token list (on isolated agent)
<img width="1871" height="328" alt="image" src="https://github.com/user-attachments/assets/b0ce0add-34b8-496e-8822-a950f1e2adcc" />

### Works With Any Agent

ClawGate isn't locked to OpenClaw. It works with **any AI agent** that can:  

- Call CLI commands (Claude Code, Cursor, etc.)
- Use **MCP**  servers (Claude Code, Codex, etc.)

## How It Works

### Capability Tokens

When you run `clawgate grant`, you create a **capability token** - a JWT signed with Ed25519:

```json
{
  "iss": "clawgate:resource:mario-laptop",
  "sub": "clawgate:agent:mario-minipc",
  "exp": 1706832000,
  "cg": {
    "cap": [
      {
        "r": "files",
        "o": ["read", "list", "stat", "git"],
        "s": "/home/mario/projects/**"
      },
      {
        "r": "tools",
        "o": ["invoke"],
        "s": "calc"
      }
    ]
  }
}
```

This token says: *"The agent on mario-minipc can read, list, and stat files, run read-only git commands under `/home/mario/projects/`, and invoke the `calc` tool - until the expiry time."*

The token is **self-contained** - the resource daemon validates the signature and checks permissions without any database lookup.

### Scope Patterns

```bash
clawgate grant --read /home/mario/file.txt      # Exact file
clawgate grant --read /home/mario/projects/*    # Direct children only
clawgate grant --read /home/mario/projects/**   # Recursive (all descendants)
clawgate grant --read /home/mario/projects/*.zig # Glob pattern
clawgate grant --git /home/mario/projects/**    # Git read-only + file read
clawgate grant --git-write /home/mario/projects/** # Git read+write
clawgate grant --git-full /home/mario/projects/**  # Git full (+ push/pull)
clawgate grant --tool calc                         # Single tool
clawgate grant --tools-all --ttl 4h                # All registered tools
clawgate grant --read --tool calc /home/mario/**   # Files + tool combined
```

### Audit Trail

Every operation is logged persistently to `~/.clawgate/logs/audit.log` on the resource machine:

```
2026-02-07T14:30:45Z AUDIT req=req_1384782a op=git path=/home/m64/space/ai/clawgate success=true
2026-02-07T14:30:46Z AUDIT req=req_79565e1c op=read path=/etc/shadow success=false error=SCOPE_VIOLATION
```

Events are also printed to stderr by the resource daemon. Denied operations that never reach the resource daemon fail immediately on the agent side:

```
> clawgate ls /etc/hosts
Error: No token grants list access to /etc/hosts
```

### Git Operations

ClawGate supports running git commands on repositories hosted on your primary machine with three permission tiers:

| Tier | Grant Flag | Allows |
|------|-----------|--------|
| **Read-only** | `--git` | status, diff, log, show, blame, branch (list), ... |
| **Write** | `--git-write` | add, commit, checkout, merge, rebase, reset, ... |
| **Full** | `--git-full` | push, pull, fetch, remote add/remove, submodule |

```bash
# Grant git read-only access
clawgate grant --git ~/projects/** --ttl 24h

# Run git commands from the agent
clawgate git ~/projects/myapp status
clawgate git ~/projects/myapp log --oneline -20
clawgate git ~/projects/myapp diff HEAD~3
```

> **Scope tip:** For git-only workflows, granting the exact repo path is
> sufficient: `clawgate grant --git ~/projects/myapp`. Git commands only
> check the repository root path. However, `--git` also enables file
> read/list/stat, and those check individual file paths - so use
> `~/projects/myapp/**` if you also want to read files inside the repo
> with `clawgate cat` or `clawgate ls`.

**Security:** Git commands run through allowlists with blocked flags (`-c`, `--exec-path`, `--git-dir`, `--work-tree`) to prevent scope escapes and arbitrary code execution. See the [Design Document](docs/DESIGN.md) for the full allowlist specification.

### Custom Tools

ClawGate can proxy **any command-line tool** through its secure pipeline. Tools are registered on the resource machine by the owner - the agent can only invoke what has been explicitly registered and granted.

```bash
# Register a tool (on your laptop)
clawgate tool register calc \
  --command "bc -l" \
  --allow-args "-q" \
  --timeout 10 \
  --max-output 65536 \
  --description "Calculator (bc)" \
  --example 'echo "2+2" | clawgate tool calc'

# Grant access and invoke from the agent
clawgate grant --tool calc --ttl 4h
echo "2+2" | clawgate tool calc
```

Each tool has an **argument validation mode**:

| Mode | Behavior |
|------|----------|
| **Allowlist** (default) | Only explicitly listed flags are permitted |
| **Passthrough** | All flags allowed except those in the deny list |

**Security:** Commands are executed via direct argv - never through a shell. No shell expansion, no pipes, no semicolons. Output is truncated at the configured limit.

```bash
# Manage tools
clawgate tool ls                     # List registered tools
clawgate tool info calc              # Show tool details
clawgate tool update calc --timeout 30
clawgate tool remove calc
clawgate tool test calc -q           # Test locally (no daemon needed)
```

### Token Revocation

Tokens can be revoked before they expire. The revocation list is stored on the resource machine and checked on every incoming request - a revoked token is a dead credential, even if the agent still holds it.

```bash
clawgate revoke cg_a1b2c3... --reason "compromised"
clawgate revoke --all --reason "key rotation"
clawgate revoked ls                  # List revoked tokens
clawgate revoked clean               # Remove expired entries
```

### Skill Generation

ClawGate auto-generates markdown skill files from the tool registry, making registered tools discoverable by AI agents.

```bash
clawgate skills generate             # Generate to skills/clawgate/
clawgate skills export /path/to/dir  # Export to custom directory
```

Tool management commands (`register`, `update`, `remove`) automatically regenerate skill files after modifying the registry.

## Features

| Feature | Description |
|---------|-------------|
| **Capability-based security** | Cryptographic Ed25519 tokens, not passwords |
| **End-to-end encryption** | X25519 + XChaCha20-Poly1305 with forward secrecy |
| **Fine-grained access** | Grant specific paths and tools, not "everything" |
| **Custom tool proxy** | Register any CLI tool, invoke remotely with argument validation |
| **Token revocation** | Revoke tokens before expiry, resource-side enforcement |
| **Time-bounded tokens** | 1h, 24h, 7d - you choose |
| **Persistent audit trail** | Every operation logged to `~/.clawgate/logs/audit.log` |
| **Issuance tracking** | Every granted token recorded for audit and bulk revocation |
| **Forbidden paths** | `~/.ssh`, `~/.aws`, `~/.gnupg` can NEVER be granted |
| **Git operations** | Three-tier git access: read-only, write, full (push/pull) |
| **Git command allowlists** | Defense-in-depth with blocked flags and subcommands |
| **Argument safety** | Per-tool allowlist/denylist, no shell execution |
| **Skill generation** | Auto-generated agent-readable docs from tool registry |
| **Large file handling** | Files >512KB automatically truncated with metadata |
| 🦞 **OpenClaw native** | Skill file included |
| **Symlink protection** | Symlinks rejected to prevent scope escape attacks |
| **Fast** | Pure Zig, zero dependencies, minimal latency |
| **Zero trust design** | Assumes agent machine is compromised |

## Security

ClawGate is a **security tool**. We take this seriously.

### Threat Model

**Assumed threat:** The agent machine is compromised (e.g., via prompt injection). The attacker has full control of the agent process and any tokens stored there.

**Defense layers:**

| Layer | Protection |
|-------|------------|
| **Transport** | X25519 key exchange + XChaCha20-Poly1305 encryption |
| **Forward secrecy** | Fresh ephemeral keys per session |
| **Authentication** | Ed25519 signed tokens |
| **Authorization** | Per-request scope validation |
| **Revocation** | Resource-side revocation list, checked every request |
| **Path safety** | Canonicalization, traversal protection |
| **Git allowlists** | Tiered command allowlists, blocked flags (`-c`, `--exec`) |
| **Argument validation** | Per-tool allowlist/denylist for command flags |
| **No shell execution** | Tools run via direct argv, no shell interpolation |
| **Output limits** | Per-tool configurable output truncation |
| **Symlink rejection** | All symlinks unconditionally rejected |
| **Forbidden paths** | ~/.ssh, ~/.aws, ~/.gnupg - hardcoded, ungrantable |
| **Time limits** | Tokens expire, limiting blast radius |
| **Audit** | Every operation logged locally |

### Security Practices

- **Security audit every development phase** - We don't ship without review
- **No dynamic memory in hot path** - Bounded allocations only
- **Fuzz tested** - Token parsing, path matching, JSON handling
- **Zero dependencies** - Zig stdlib only, no supply chain risk

### Reporting Vulnerabilities

Found a security issue? Email security@clawgate.io (or open a private advisory on GitHub).

See [SECURITY.md](SECURITY.md) for our full security policy.


## CLI Reference

```
ClawGate - Secure capability proxy for isolated AI agents

Usage:
  clawgate --mode agent             Run agent daemon (listens for connections)
  clawgate --mode resource          Run resource daemon (connects to agent)
  clawgate mcp-server               Run MCP server (stdio)

Capability Management (primary machine):
  clawgate grant [opts] [path]      Grant access (path optional for tool-only)
    --read                          Allow read operations
    --write                         Allow write operations
    --git                           Git read-only (+ read, list, stat)
    --git-write                     Git read+write (+ file write)
    --git-full                      Git full access (+ push/pull/fetch)
    --tool <name>                   Grant access to a registered tool
    --tools-all                     Grant access to all registered tools
    --ttl <duration>                Token lifetime (2h, 24h, 7d)
  clawgate keygen                   Generate Ed25519 keypair

Token Revocation (primary machine):
  clawgate revoke <id>              Revoke a token by ID
  clawgate revoke --all             Revoke all issued tokens
    --reason <text>                 Revocation reason
  clawgate revoked ls               List revoked tokens
  clawgate revoked clean            Remove expired entries

Tool Registry (primary machine):
  clawgate tool register <name>     Register a new tool
  clawgate tool ls                  List registered tools
  clawgate tool info <name>         Show tool details
  clawgate tool update <name>       Update tool configuration
  clawgate tool remove <name>       Remove a tool
  clawgate tool test <name> [args]  Test tool locally (no daemon)

Skill Generation (primary machine):
  clawgate skills generate          Generate skill files from registry
  clawgate skills export <dir>      Export to custom directory

Token Management (agent machine):
  clawgate token add <token>        Add a capability token
  clawgate token list               List stored tokens
  clawgate token show <id>          Show token details
  clawgate token remove <id>        Remove a token

File Operations (agent machine):
  clawgate cat <path>               Read file
  clawgate ls <path>                List directory
  clawgate write <path>             Write file (stdin or --content)
  clawgate stat <path>              Get file info
  clawgate git <repo> <args...>     Run git command
  clawgate tool <name> [args...]    Invoke a registered tool

Monitoring:
  clawgate audit                    Show audit log file info
  clawgate audit --json             Output as JSON (reserved)

Daemon Options:
  --listen <addr:port>              Listen address (agent mode, default 0.0.0.0:4223)
  --connect <host:port>             Connect address (resource mode)
  --public-key <path>               Public key path (resource mode)
  --token-dir <path>                Token directory (agent mode)

General Options:
  --help, -h                        Show this help
  --version, -v                     Show version

https://clawgate.io
```

> **Tip:** Running a subcommand without required arguments shows detailed help.
> For example, `clawgate grant` shows all grant options including `--list`,
> `--stat`, `-k/--key`, `--issuer`, and `--subject`.

### Example: Token Listing

```
$ clawgate token list
Stored tokens (6):

  ID:      cg_9ae7ce62f4a5b869a8c120fa
  Issuer:  clawgate:resource
  Subject: clawgate:agent
  Scope:   ~/space/ai/remembra/** [read, list, stat, git]
  Expires: 2026-02-08T05:51:26Z
  Status:  Valid
  ...

$ clawgate token show cg_7ab54be138936dfb8d29b81d
Token: cg_7ab54be138936dfb8d29b81d

  Issuer:  clawgate:resource
  Subject: clawgate:agent
  Issued:  2026-02-07T06:02:28Z
  Expires: 2026-02-08T06:02:28Z

  Capabilities:
    - files: ~/space/ai/tiger-style [read, list, stat, git]

  Status: Valid
```

## Architecture

ClawGate is split into two cooperating sides: the **resource side** (your laptop) and the **agent side** (the isolated machine).

### Resource Side (your laptop)

**Resource Daemon**
- Runs on your primary machine where your files live
- Responsibilities:
  - Verifies capability token signatures
  - Checks token revocation list
  - Enforces scope and permissions
  - Executes file operations (read, list, stat, write)
  - Executes git commands (with tiered allowlists)
  - Executes registered tools (with argument validation)
  - Writes audit events

**Tool Registry** (`~/.clawgate/tools.json`)
- Stores tool configurations, argument validation rules, and execution limits
- Tools registered and managed by the machine owner

**Protected Resources**
- Your local files (e.g. `~/projects`)
- Never mounted or shared directly
- Only accessed via validated requests handled by the Resource Daemon

### Agent Side (isolated machine, e.g. Mac Mini or VPS)

**Agent Daemon**
- Runs next to the AI agent
- Responsibilities:
  - Stores issued capability tokens
  - Proxies file, git, and tool requests to the Resource Daemon
  - Exposes a local IPC interface (Unix socket)

**AI Agent**
- Any AI system (OpenClaw, Claude Code, Cursor, etc.)
- Talks only to the local Agent Daemon
- Never has direct filesystem access

**MCP Server (optional)**
- Runs over stdio
- Connects to the Agent Daemon via Unix socket
- Provides tool-style access for compatible agents
- Exposes `clawgate_read_file`, `clawgate_git`, `clawgate_tool`, and more

### Communication

- The Resource Daemon connects to the Agent Daemon over TCP (`:4223`)
- All file, git, and tool requests pass through this channel
- The Resource Daemon is the only component that touches the filesystem and executes tools

(Security properties of this channel are defined in the **Security** section.)

## Documentation

| Document | Description |
|----------|-------------|
| [**OpenClaw Quick Setup**](docs/OPENCLAW-QUICK-SETUP.md) | 5-minute setup guide for OpenClaw integration |
| [**Design Document**](docs/DESIGN.md) | Technical reference: architecture, security model, protocol specification |
| [**Tool Feature Overview**](docs/TOOL-FEATURE-OVERVIEW.md) | Custom tools, token revocation, skill generation |
| [**Glob Patterns**](docs/GLOBBING.md) | Complete reference for scope pattern matching with all edge cases |

## Roadmap

- [x] Core protocol and daemons
- [x] Capability token system
- [x] CLI commands
- [x] MCP server for Claude Code, etc.
- [x] Git operations (three-tier: read-only, write, full)
- [x] Custom tool proxy (register, invoke, argument validation)
- [x] Token revocation list
- [x] Skill file generation from tool registry
- [ ] Setup wizard (`clawgate setup`)
- [ ] Web dashboard for audit viewing
- [ ] Multi-resource federation

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- **Bug reports** - Open an issue with reproduction steps
- **Feature requests** - Open an issue describing the use case
- **Pull requests** - Fork, branch, PR (with tests please)

## License

MIT - see [LICENSE](LICENSE)

<p align="center">
  <b>ClawGate</b> - Secure capability proxy for the AI agent era<br>
  Built with &lt;3 and Zig by <a href="https://github.com/M64GitHub">M64</a><br>Designed in cooperation with <a href="https://github.com/EchoMaster128">Echo128 🦞</a><br>
  <a href="https://clawgate.io">clawgate.io</a>
</p>


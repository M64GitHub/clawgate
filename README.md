[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16+-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/M64GitHub/clawgate/releases)
[![GitHub Release](https://img.shields.io/github/v/release/M64GitHub/clawgate?include_prereleases)
![logo](https://github.com/user-attachments/assets/6ccb9158-7dd1-49dd-95a7-48f1156a1d92)

<p align="center">                                                 
    🦞⛓️ Secure file access for isolated AI agents ⛓️🦞
</p>

**ClawGate** lets AI agents running on isolated machines securely access files on your primary machine. Instead of mounting filesystems or sharing credentials, ClawGate uses cryptographically signed capability tokens with fine-grained, time-bounded, audited access control.

Think of it as **SSH keys meet JWT tokens meet capability-based security** - designed specifically for the AI agent era.

## The Problem

You're running [OpenClaw](https://github.com/openclaw/openclaw) (or Claude Code, or any AI agent) on an isolated machine - maybe a Mac Mini, a VPS, or a sandboxed container. **Smart move for security.**

But now your agent needs to read your project files. Your options?

| Approach | Problem |
|----------|---------|
| NFS/SMB mount | Full filesystem access. Agent gets pwned -> you get pwned |
| SSH + rsync | Credentials on the agent machine. Same problem |
| Manual copy | Tedious. Breaks flow. Doesn't scale |
| Cloud sync | Your code on someone else's servers |

**None of these assume the agent might be compromised.** But it might be - prompt injection is real.

## The Solution

ClawGate provides **secure, scoped, audited file access** over direct TCP with end-to-end encryption:

**Key principles:**
- **Zero trust** - Assumes the agent machine is compromised
- **Least privilege** - Grant only specific paths, not filesystems
- **Time-bounded** - Tokens expire (1 hour, 24 hours, 7 days)
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

**Done.** Your agent can now securely read files in `~/projects`.

## OpenClaw Integration

ClawGate was built for [OpenClaw](https://github.com/openclaw/openclaw).  

Add the skill file: copy `skills/clawgate/SKILL.md` to your workspace.  
**Done**.  

```bash
# Your agent can now use these commands:
clawgate cat ~/projects/app/src/main.zig
clawgate ls ~/projects/app/src/
clawgate write ~/projects/app/notes.md --content "TODO: refactor"
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
    "cap": [{
      "r": "files",
      "o": ["read", "list", "stat"],
      "s": "/home/mario/projects/**"
    }]
  }
}
```

This token says: *"The agent on mario-minipc can read, list, and stat files under `/home/mario/projects/` until the expiry time."*

The token is **self-contained** - the resource daemon validates the signature and checks permissions without any database lookup.

### Scope Patterns

```bash
clawgate grant --read /home/mario/file.txt      # Exact file
clawgate grant --read /home/mario/projects/*    # Direct children only
clawgate grant --read /home/mario/projects/**   # Recursive (all descendants)
clawgate grant --read /home/mario/projects/*.zig # Glob pattern
```

### Audit Trail

Every successful operation is logged locally on the resource daemon:

```bash
clawgate audit
# [2026-02-01T10:23:45Z] READ /home/mario/projects/app/main.zig success=true
# [2026-02-01T10:23:47Z] LIST /home/mario/projects/app/ success=true
```

Denied operations fail immediately on the agent daemon:

```
> clawgate ls /etc/hosts
Error: No token grants list access to /etc/hosts
```

## Features

| Feature | Description |
|---------|-------------|
| **Capability-based security** | Cryptographic Ed25519 tokens, not passwords |
| **End-to-end encryption** | X25519 + XChaCha20-Poly1305 with forward secrecy |
| **Fine-grained access** | Grant `/projects/app/**` not "everything" |
| **Time-bounded tokens** | 1h, 24h, 7d - you choose |
| **Complete audit trail** | Every operation logged with token ID |
| **Forbidden paths** | `~/.ssh`, `~/.aws`, `~/.gnupg` can NEVER be granted |
| **Large file handling** | Files >512KB automatically truncated with metadata |
| 🦞 **OpenClaw native** | Skill file included |
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
| **Path safety** | Canonicalization, traversal protection |
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
ClawGate - Secure file access for isolated AI agents

USAGE:
  clawgate <command> [options]

DAEMON COMMANDS:
  --mode resource       Run resource daemon (on your laptop)
  --mode agent          Run agent daemon (on isolated machine)
  mcp-server            Run MCP server (stdio, for OpenClaw)

SETUP COMMANDS:
  keygen                Generate Ed25519 keypair
  grant [options] PATH  Create capability token
    --read              Allow read, list, stat
    --write             Allow write (implies read)
    --ttl DURATION      Token lifetime (1h, 24h, 7d, etc.)

FILE COMMANDS (agent side):
  cat PATH              Read file contents
  ls PATH               List directory
  write PATH            Write file (--content or stdin)
  stat PATH             Get file metadata

ADMIN COMMANDS:
  audit                 Watch audit event stream
  token add TOKEN       Add token to agent store
  token list            List stored tokens
  token remove ID       Remove token

OPTIONS:
  --config PATH         Config file (default: ~/.clawgate/config.toml)
  --verbose             Verbose logging
  --version             Show version
  --help                Show this help

EXAMPLES:
  # Grant read access to projects for 24 hours
  clawgate grant --read --ttl 24h ~/projects

  # Read a file through ClawGate
  clawgate cat ~/projects/app/main.zig

  # Watch all file access in real-time
  clawgate audit --json | jq .
```


## Configuration

ClawGate uses `~/.clawgate/config.toml`:

```toml
[tcp]
# Agent daemon settings
listen_addr = "0.0.0.0"
listen_port = 4223

# Resource daemon settings
connect_addr = "agent.example.com"
connect_port = 4223

[keys]
private_key = "~/.clawgate/keys/secret.key"
public_key = "~/.clawgate/keys/public.key"

[resource]
# Additional forbidden paths (beyond hardcoded ones)
forbidden_paths = [
  "~/.config/secrets/**",
  "~/private/**"
]

# File size limits
max_file_size = 104857600  # 100MB
truncate_at = 524288       # 512KB

[agent]
token_dir = "~/.clawgate/tokens"
```

## Architecture

ClawGate is split into two cooperating sides: the **resource side** (your laptop) and the **agent side** (the isolated machine).

### Resource Side (your laptop)

**Resource Daemon**
- Runs on your primary machine where your files live
- Responsibilities:
  - Verifies capability token signatures
  - Enforces scope and permissions
  - Executes file operations (read, list, stat, write)
  - Writes audit events

**Protected Resources**
- Your local files (e.g. `~/projects`)
- Never mounted or shared directly
- Only accessed via validated requests handled by the Resource Daemon

### Agent Side (isolated machine, e.g. Mac Mini or VPS)

**Agent Daemon**
- Runs next to the AI agent
- Responsibilities:
  - Stores issued capability tokens
  - Proxies file access requests to the Resource Daemon
  - Exposes a local IPC interface (Unix socket)

**AI Agent**
- Any AI system (OpenClaw, Claude Code, Cursor, etc.)
- Talks only to the local Agent Daemon
- Never has direct filesystem access

**MCP Server (optional)**
- Runs over stdio
- Connects to the Agent Daemon via Unix socket
- Provides tool-style access for compatible agents

### Communication

- The Resource Daemon connects to the Agent Daemon over TCP (`:4223`)
- All file access requests pass through this channel
- The Resource Daemon is the only component that touches the filesystem

(Security properties of this channel are defined in the **Security** section.)

## Documentation

| Document | Description |
|----------|-------------|
| [**OpenClaw Quick Setup**](docs/OPENCLAW-QUICK-SETUP.md) | 5-minute setup guide for OpenClaw integration |
| [**Design Document**](docs/DESIGN.md) | Technical reference: architecture, security model, protocol specification |
| [**Glob Patterns**](docs/GLOBBING.md) | Complete reference for scope pattern matching with all edge cases |

## Roadmap

- [x] Core protocol and daemons
- [x] Capability token system
- [x] CLI commands
- [x] MCP server for Claude Code, etc.
- [ ] Setup wizard (`clawgate setup`)
- [ ] Web dashboard for audit viewing
- [ ] Token revocation list
- [ ] Multi-resource federation

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- **Bug reports** - Open an issue with reproduction steps
- **Feature requests** - Open an issue describing the use case
- **Pull requests** - Fork, branch, PR (with tests please)

## License

MIT - see [LICENSE](LICENSE)

<p align="center">
  <b>ClawGate</b> - Secure file access for the AI agent era<br>
  Built with &lt;3 and Zig by <a href="https://github.com/M64GitHub">M64</a>  and <a href="https://github.com/EchoMaster128">Echo128 🦞</a><br>
  <a href="https://clawgate.io">clawgate.io</a>
</p>


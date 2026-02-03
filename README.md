[![Release](https://img.shields.io/github/v/release/M64GitHub/clawgate?include_prereleases)](https://github.com/M64GitHub/clawgate/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16+-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)

![gemini-2 5-flash-image_make_this_logo_more_suitable_as_a_brand_logo_for_an_ai_software_security_product-0(1)](https://github.com/user-attachments/assets/6ccb9158-7dd1-49dd-95a7-48f1156a1d92)

<p align="center">                                                 
    🦞⛓️ Secure file access for isolated AI agents ⛓️🦞
</p>

**ClawGate** lets AI agents running on isolated machines securely access files on your primary machine. Instead of mounting filesystems or sharing credentials, ClawGate uses cryptographically signed capability tokens with fine-grained, time-bounded, audited access control.

Think of it as **SSH keys meet JWT tokens meet capability-based security** - designed specifically for the AI agent era.

<img width="1043" height="1269" alt="image" src="https://github.com/user-attachments/assets/3c6b06c8-1be7-4ea3-9cea-d09222f28419" />



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

```
┌─────────────────────┐                    ┌─────────────────────────┐
│   YOUR LAPTOP       │                    │   ISOLATED MACHINE      │
│                     │                    │                         │
│   ~/projects/       │                    │   OpenClaw / Claude     │
│   ~/documents/      │◄──── TCP:4223 ────►│   ClawGate Agent        │
│                     │   (E2E encrypted)  │                         │
│   ClawGate Resource │                    │   "Read ~/projects/     │
│   Daemon            │                    │    app/src/main.zig"    │
└─────────────────────┘                    └─────────────────────────┘
         │                                            │
         │  ✓ Validates token signature               │
         │  ✓ Checks path is in scope                 │
         │  ✓ Logs to audit trail                     │
         │  ✓ Returns file content                    │
         └────────────────────────────────────────────┘
```

**Key principles:**
- **Zero trust** - Assumes the agent machine is compromised
- **Least privilege** - Grant only specific paths, not filesystems
- **Time-bounded** - Tokens expire (1 hour, 24 hours, 7 days)
- **Complete audit** - Every operation logged with cryptographic proof

## Quick Start

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
# Creates ~/.clawgate/keys/private.key and public.key
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
Add the skill file: copy `skills/clawgate/SKILL.md` to your workspace

```bash
# Your agent can now use these commands:
clawgate cat ~/projects/app/src/main.zig
clawgate ls ~/projects/app/src/
clawgate write ~/projects/app/notes.md --content "TODO: refactor"
```
<img width="1044" height="954" alt="image" src="https://github.com/user-attachments/assets/311d7518-8232-40c7-aa27-98126217e87f" />


### Works With Any Agent

ClawGate isn't locked to OpenClaw. It works with **any AI agent** that can:
- Call CLI commands (Claude Code, Cursor, Aider, etc.)
- Use MCP servers

**Examples:**

| Agent | Integration |
|-------|-------------|
| **OpenClaw** | MCP server or skill file |
| **Claude Code** | Skill file with CLI commands |
| **Cursor** | Custom tool calling clawgate CLI |
| **Aider** | Shell commands in chat |

The MCP server and CLI are convenience layers over the core E2E encrypted TCP protocol.

---

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

### Request Flow

```
Agent                   E2E Tunnel            Resource Daemon
  │                        │                         │
  │ ── read request ────►  │  ────────────────────►  │
  │    + token             │   (XChaCha20-Poly1305)  │
  │                        │                         ├─ Verify signature
  │                        │                         ├─ Check not expired
  │                        │                         ├─ Check path in scope
  │                        │                         ├─ Read file
  │                        │                         ├─ Log to audit
  │  ◄─────────────────────│  ◄── file content ────  │
  │                        │                         │
```

### Audit Trail

Every operation is logged locally on the resource daemon:

```bash
clawgate audit
# [2026-02-01T10:23:45Z] READ /home/mario/projects/app/main.zig OK (1.2KB, 3ms)
# [2026-02-01T10:23:47Z] LIST /home/mario/projects/app/ OK (12 entries, 1ms)
# [2026-02-01T10:24:01Z] READ /home/mario/.ssh/id_rsa DENIED (forbidden path)
```

---

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
| 🦞 **OpenClaw native** | MCP server + skill file included |
| **Fast** | Pure Zig, zero dependencies, minimal latency |
| **Zero trust design** | Assumes agent machine is compromised |

---

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

---

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

---

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
private_key = "~/.clawgate/keys/private.key"
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

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         YOUR LAPTOP                                │
│                                                                    │
│  ┌─────────────┐    ┌──────────────────┐                           │
│  │   Files     │◄───│ Resource Daemon  │                           │
│  │ ~/projects/ │    │                  │                           │
│  └─────────────┘    │ • Token verify   │                           │
│                     │ • Scope check    │                           │
│                     │ • File ops       │                           │
│                     │ • Audit logging  │                           │
│                     └────────┬─────────┘                           │
│                              │                                     │
└──────────────────────────────┼─────────────────────────────────────┘
                               │
                    TCP :4223  │  E2E Encrypted
                   (outbound)  │  X25519 + XChaCha20
                               │
┌──────────────────────────────┼─────────────────────────────────────┐
│     ISOLATED MACHINE         │        (i.e. mac mini)              │
│                              │                                     │
│  ┌─────────────────┐    ┌────┴─────────────┐                       │
│  │    OpenClaw     │───►│  Agent Daemon    │◄── listens :4223      │
│  │    or any AI    │    │                  │                       │
│  │    agent        │    │ • Token store    │                       │
│  └────────┬────────┘    │ • Request proxy  │                       │
│           │             │ • IPC server     │                       │
│           │             └──────────────────┘                       │
│           │                      ▲                                 │
│           ▼                      │ Unix socket                     │
│  ┌─────────────────┐             │                                 │
│  │   MCP Server    │─────────────┘                                 │
│  │   (stdio)       │                                               │
│  └─────────────────┘                                               │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [**OpenClaw Quick Setup**](docs/OPENCLAW-QUICK-SETUP.md) | 5-minute setup guide for OpenClaw integration |
| [**Glob Patterns**](docs/GLOBBING.md) | Complete reference for scope pattern matching with all edge cases |

---

## Roadmap

- [x] Core protocol and daemons
- [x] Capability token system
- [x] CLI commands
- [x] MCP server for OpenClaw
- [ ] Setup wizard (`clawgate setup`)
- [ ] Web dashboard for audit viewing
- [ ] Token revocation list
- [ ] Multi-resource federation
- [ ] **ClawGate Key** - ESP32 hardware module for air-gapped token signing

---

## Built With

| Technology | Purpose |
|------------|---------|
| [**Zig**](https://ziglang.org) | Memory-safe systems programming |
| [**Ed25519**](https://ed25519.cr.yp.to/) | Digital signatures for capability tokens |
| [**X25519**](https://cr.yp.to/ecdh.html) | Elliptic curve Diffie-Hellman key exchange |
| [**XChaCha20-Poly1305**](https://datatracker.ietf.org/doc/html/rfc8439) | Authenticated encryption |

**Zero external dependencies** - Everything is built on Zig's standard library.

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- **Bug reports** - Open an issue with reproduction steps
- **Feature requests** - Open an issue describing the use case
- **Pull requests** - Fork, branch, PR (with tests please)

## License

MIT - see [LICENSE](LICENSE)

---

<p align="center">
  <b>ClawGate</b> - Secure file access for the AI agent era<br>
  Built with &lt;3 and Zig by <a href="https://github.com/M64GitHub">M64</a> 🦞<br>
  <a href="https://clawgate.io">clawgate.io</a>
</p>


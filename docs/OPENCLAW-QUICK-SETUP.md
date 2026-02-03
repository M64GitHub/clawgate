# ClawGate + OpenClaw Quick Setup

**Give your AI agent secure file access in 5 minutes.**

ClawGate lets your OpenClaw agent read and write files on your primary machine through an encrypted tunnel with capability-based access control.

- End-to-end encrypted (X25519 + XChaCha20-Poly1305)
- Time-limited, scoped tokens (grant only what's needed)
- Hot-reload tokens while running (no restarts!)
- Auto-reconnect on connection drops

## Prerequisites

- Two machines on the same network (or connected via SSH tunnel)
- Zig 0.16+ if building from source

## Setup (One-Time)

### 1. Install on Both Machines

```bash
curl -sSL https://clawgate.io/install.sh | sh
```

Or build from source (requires Zig 0.16+):
```bash
cd clawgate
zig build -Doptimize=ReleaseSafe -Dcpu=baseline
sudo cp zig-out/bin/clawgate /usr/local/bin/
```

### 2. Generate Keys (Primary Machine)

```bash
clawgate keygen
# Creates ~/.clawgate/keys/secret.key and public.key
```

### 3. Copy Public Key to Agent Machine

```bash
# On agent machine - create the directory first:
mkdir -p ~/.clawgate/keys

# From primary machine - copy your public key:
scp ~/.clawgate/keys/public.key agent-host:~/.clawgate/keys/
```

The agent needs your public key to verify token signatures.

## Connect

### Agent Machine (start first)

```bash
clawgate --mode agent
# Listening on 0.0.0.0:4223
```

### Primary Machine

```bash
clawgate --mode resource --connect <agent-ip>:4223
# E2E encrypted tunnel established!
```

The resource daemon auto-reconnects if the connection drops.

## Grant Access

On your **primary machine**, create a token:

```bash
clawgate grant --read "/home/you/projects/**" --ttl 24h
```

Copy the output token. On the **agent machine**:

```bash
clawgate token add "<paste-token>"
```

Done! Your agent can now read files.

---

## The Magic: Live Token Updates

> **No restarts needed!** Add tokens anytime while both daemons run.

```bash
# Primary: grant access to another path
clawgate grant --read --write "/tmp/agent-output/*" --ttl 8h

# Agent: add the new token
clawgate token add "<new-token>"

# Immediately works!
clawgate ls /tmp/agent-output/
```

Expand access on the fly. Revoke by letting tokens expire.


## Quick Reference

| Command | Where | What |
|---------|-------|------|
| `clawgate --mode agent` | Agent | Start agent daemon |
| `clawgate --mode resource --connect host:4223` | Primary | Connect to agent |
| `clawgate grant --read "path/**" --ttl 24h` | Primary | Create read token |
| `clawgate grant --write "path/*" --ttl 8h` | Primary | Create write-only token |
| `clawgate token add "<token>"` | Agent | Store a token |
| `clawgate token list` | Agent | Show all tokens |
| `clawgate cat /path/file` | Agent | Read a file |
| `clawgate ls /path/` | Agent | List directory |
| `clawgate write /path/file -c "content"` | Agent | Write a file |

### Grant Patterns

| Grant | Agent Can Do | Use Case |
|-------|--------------|----------|
| `--read` | read, list, stat | Code browsing |
| `--write` | write only | Blind drop box |
| `--read --write` | everything | Full collaboration |


## Troubleshooting

| Problem | Fix |
|---------|-----|
| "No token grants access" | Check path scope with `clawgate token list` |
| "Handshake failed" | Copy public.key to agent machine |
| "Connection refused" | Start agent daemon first |


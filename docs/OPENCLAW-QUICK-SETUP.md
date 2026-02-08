# ClawGate + OpenClaw Quick Setup

**Give your AI agent secure file and git access in 5 minutes.**

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
# Listening on 0.0.0.0:53280
```

### Primary Machine

```bash
clawgate --mode resource --connect <agent-ip>:53280
# E2E encrypted tunnel established!
```

The resource daemon auto-reconnects if the connection drops.

## Install the Skill File (One-Time)

Copy the ClawGate skill file to your agent's workspace so the agent
knows all ClawGate commands:

```bash
# From your primary machine:
scp -r skills/clawgate/ agent-host:~/.openclaw/workspace/skills/clawgate/
```

Or paste the contents of `skills/clawgate/SKILL.md` directly into a
chat message - your agent will learn the commands from it.

Once the skill file is in place, **the agent can manage tokens
itself**. You never need to SSH into the agent machine again for
token operations.

## Grant Access

On your **primary machine**, create a token:

```bash
clawgate grant --read "/home/you/projects/**" --ttl 24h
```

Now just paste the token into your chat with the agent:

> Here's a new ClawGate token, please add it:
> eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOi...

The agent runs `clawgate token add` for you. Done!

This can also be done manually - it corresponds to this command
on the **agent machine**:

```bash
clawgate token add "<paste-token>"
```

You can also ask the agent to manage its tokens:

> "Show me your current tokens" → agent runs `clawgate token list`
>
> "Remove the expired token cg_abc123" → agent runs
> `clawgate token remove cg_abc123`

Again, these correspond to the manual commands on the agent machine:

```bash
clawgate token list
clawgate token remove cg_abc123
```

---

## Live Token Updates

> **No restarts needed!** Add tokens anytime while both daemons run.

Grant more access on your laptop and paste the token into chat:

```bash
# Primary: grant access to another path
clawgate grant --read --write "/tmp/agent-output/*" --ttl 8h
# → paste the output token into chat with the agent
```

The agent adds the token and can use it immediately. This corresponds
to running manually on the agent machine:

```bash
clawgate token add "<new-token>"

# Immediately works!
clawgate ls /tmp/agent-output/
```

Expand access on the fly. Revoke by letting tokens expire.

---

## Git Access

ClawGate can proxy git commands to repositories on your primary
machine. Grant access on your **primary machine**:

```bash
clawgate grant --git "/home/you/projects/myapp/**" --ttl 24h
```

Paste the token into chat (or run `clawgate token add` manually on
the agent). Your agent can now run git commands:

```bash
clawgate git /home/you/projects/myapp status
clawgate git /home/you/projects/myapp log --oneline -10
clawgate git /home/you/projects/myapp diff HEAD~3
```

### Permission Tiers

Git access comes in three tiers. Each tier includes the previous:

| Grant | Allows | Examples |
|-------|--------|----------|
| `--git` | Read-only | status, diff, log, show, blame, branch |
| `--git-write` | + Local writes | add, commit, checkout, merge, rebase |
| `--git-full` | + Remote ops | push, pull, fetch |

```bash
# Let the agent commit code:
clawgate grant --git-write "/home/you/projects/myapp/**" --ttl 8h

# Full access including push/pull:
clawgate grant --git-full "/home/you/projects/myapp/**" --ttl 4h
```

### Scope Tip

`--git` also enables file read/list/stat. To let the agent browse
files inside the repo with `clawgate cat` and `clawgate ls`, use the
`/**` glob:

```bash
# Git + file browsing inside repo:
clawgate grant --git "/home/you/projects/myapp/**" --ttl 24h

# Git only (no file browsing):
clawgate grant --git /home/you/projects/myapp --ttl 24h
```

---

## Quick Reference

| Command | Where | What |
|---------|-------|------|
| `clawgate --mode agent` | Agent | Start agent daemon |
| `clawgate --mode resource --connect host:53280` | Primary | Connect to agent |
| `clawgate grant --read "path/**" --ttl 24h` | Primary | Create read token |
| `clawgate grant --write "path/*" --ttl 8h` | Primary | Create write-only token |
| `clawgate grant --git "repo/**" --ttl 24h` | Primary | Create git read-only token |
| `clawgate grant --git-write "repo/**" --ttl 8h` | Primary | Create git read+write token |
| `clawgate token add "<token>"` | Agent | Store a token |
| `clawgate token list` | Agent | Show all tokens |
| `clawgate cat /path/file` | Agent | Read a file |
| `clawgate ls /path/` | Agent | List directory |
| `clawgate write /path/file -c "content"` | Agent | Write a file |
| `clawgate git /path/repo status` | Agent | Run git command |

### Grant Patterns

| Grant | Agent Can Do | Use Case |
|-------|--------------|----------|
| `--read` | read, list, stat | Code browsing |
| `--write` | write only | Blind drop box |
| `--read --write` | read + write | Full collaboration |
| `--git` | git read + file read | Review code and history |
| `--git-write` | git read+write | Commit changes |
| `--git-full` | git full + push/pull | Full git workflow |


## Troubleshooting

| Problem | Fix |
|---------|-----|
| "No token grants access" | Check path scope with `clawgate token list` |
| "Handshake failed" | Copy public.key to agent machine |
| "Connection refused" | Start agent daemon first |
| "GIT_BLOCKED" | Command or flag not in allowlist for the tier |

---

## What's Next?

- [**Custom Tools Guide**](TOOL-GUIDE.md) - Register your own CLI
  tools and invoke them through ClawGate's secure pipeline
- Token revocation and advanced topics are covered in the Tool Guide


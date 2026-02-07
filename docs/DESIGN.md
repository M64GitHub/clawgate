# ClawGate Design Document

**Version:** 0.2.1
**Status:** Implementation Complete

## Executive Summary

ClawGate is a secure bridge enabling isolated AI agents to access files and
run git commands on a user's primary machine through capability-based,
auditable access control. The system uses Ed25519-signed JWT tokens for
fine-grained permissions and X25519/XChaCha20-Poly1305 end-to-end encryption
over direct TCP connections.

**Key properties:**
- Capability-based access control with scoped, time-limited tokens
- End-to-end encryption with forward secrecy
- Outbound-only connections from the trusted machine
- Hardcoded forbidden paths for sensitive credentials
- Three-tier git permissions with command allowlists
- Audit trail of successful file and git operations on the resource daemon

## Document Scope

This document is intended for developers, security auditors, and operators.
It covers the internal architecture, security model, protocol specification,
and deployment scenarios. For quick-start usage, see the README.

## Architecture Overview

### System Components

ClawGate consists of four main components:

1. **Resource Daemon** - Runs on the primary machine (your laptop/workstation).
   Connects outbound to the agent, validates tokens, executes file and git
   operations, and maintains the audit log.

2. **Agent Daemon** - Runs on the isolated machine (AI agent environment).
   Listens for connections, stores capability tokens, and proxies requests
   from local tools to the resource daemon.

3. **MCP Server** - Model Context Protocol server running on the isolated
   machine. Provides JSON-RPC 2.0 interface over stdio for AI tool integration.

4. **CLI Tools** - Commands for token management, file operations, key
   generation, and daemon control.

### Component Diagrams

#### OpenClaw via Skill

```
+-------------------------+                    +-------------------------+
|    PRIMARY MACHINE      |                    |    ISOLATED MACHINE     |
|    (Your Laptop)        |                    |    (AI Agent Host)      |
|-------------------------|                    |-------------------------|
|                         |                    |                         |
|  +------------------+   |    E2E Encrypted   |   +------------------+  |
|  | Resource Daemon  |<--|-------- TCP -------|-->| Agent Daemon     |  |
|  |------------------|   |     Port 4223      |   |------------------|  |
|  | - Token verify   |   |                    |   | - Token store    |  |
|  | - File ops       |   |                    |   | - IPC server     |  |
|  | - Audit logging  |   |                    |   +--------^---------+  |
|  +------------------+   |                    |            |            |
|          |              |                    |      Unix Socket        |
|          v              |                    |            |            |
|  +------------------+   |                    |   +--------+---------+  |
|  |   File System    |   |                    |   | CLI              |  |
|  +------------------+   |                    |   | (clawgate cat,   |  |
|                         |                    |   |  ls, write, ...) |  |
|  +------------------+   |                    |   +--------^---------+  |
|  | Ed25519 Keys     |   |                    |            |            |
|  | ~/.clawgate/keys |   |                    |        subprocess       |
|  +------------------+   |                    |            |            |
|                         |                    |   +--------+---------+  |
+-------------------------+                    |   | AI Tool          |  |
                                               |   | (OpenClaw)       |  |
                                               |   +------------------+  |
                                               +-------------------------+
```

#### Data Flow

**Request Path:**
```
AI Tool (OpenClaw)
   |
   | subprocess call
   v
CLI (clawgate cat, ls, ...)
   |
   | JSON (Unix socket IPC)
   v
Agent Daemon
   |
   | Encrypted JSON (TCP)
   v
Resource Daemon
   |
   | Token validation, scope check
   v
File System
```

**Response Path:** Reverse of request path, with file content returned to stdout.

#### Claude via MCP Server

```
+-------------------------+                    +-------------------------+
|    PRIMARY MACHINE      |                    |    ISOLATED MACHINE     |
|    (Your Laptop)        |                    |    (AI Agent Host)      |
|-------------------------|                    |-------------------------|
|                         |                    |                         |
|  +------------------+   |    E2E Encrypted   |   +------------------+  |
|  | Resource Daemon  |<--|-------- TCP -------|-->| Agent Daemon     |  |
|  |------------------|   |     Port 4223      |   |------------------|  |
|  | - Token verify   |   |                    |   | - Token store    |  |
|  | - File ops       |   |                    |   | - IPC server     |  |
|  | - Audit logging  |   |                    |   +--------^---------+  |
|  +------------------+   |                    |            |            |
|          |              |                    |      Unix Socket        |
|          v              |                    |            |            |
|  +------------------+   |                    |   +--------+---------+  |
|  |   File System    |   |                    |   | MCP Server       |  |
|  +------------------+   |                    |   |------------------|  |
|                         |                    |   | - JSON-RPC 2.0   |  |
|  +------------------+   |                    |   | - stdio          |  |
|  | Ed25519 Keys     |   |                    |   +--------^---------+  |
|  | ~/.clawgate/keys |   |                    |            |            |
|  +------------------+   |                    |          stdio          |
|                         |                    |            |            |
+-------------------------+                    |   +--------+---------+  |
                                               |   | AI Tool          |  |
                                               |   | (Claude, etc.)   |  |
                                               |   +------------------+  |
                                               +-------------------------+
```

#### Data Flow

**Request Path:**
```
AI Tool (Claude)
   |
   | JSON-RPC (stdio)
   v
MCP Server
   |
   | JSON (Unix socket IPC)
   v
Agent Daemon
   |
   | Encrypted JSON (TCP)
   v
Resource Daemon
   |
   | Token validation, scope check
   v
File System
```

**Response Path:** Reverse of request path, with file content base64-encoded.

### Connection Model

The connection model is designed for security:

1. **Resource daemon initiates** - The trusted machine always connects
   outbound. No inbound connections to your laptop are required.

2. **Agent daemon listens** - The isolated machine accepts connections on
   port 4223 (configurable).

3. **Single active connection** - One resource daemon connects to one agent
   daemon at a time.

4. **Persistent connection** - The connection remains open for the session
   duration, with automatic reconnection on disconnect.

## Security Model

### Threat Model

ClawGate assumes the following threat model:

**Trusted:**
- The primary machine running the resource daemon
- The user's Ed25519 signing keys
- The local file system on the primary machine

**Untrusted:**
- The isolated machine running the AI agent
- The network between machines
- The AI agent itself
- Any process on the isolated machine

**Threats Addressed:**
- Network eavesdropping (E2E encryption)
- Token forgery (Ed25519 signatures)
- Token replay (nonce-based encryption, expiration)
- Path traversal attacks (canonicalization)
- Unauthorized file access (capability scopes)
- Credential theft (hardcoded forbidden paths)
- Session hijacking (forward secrecy)

### Defense Layers

#### Layer 1: Network Encryption (E2E)

All communication is encrypted end-to-end using:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Exchange | X25519 ECDH | Establish shared secret |
| Encryption | XChaCha20-Poly1305 | Authenticated encryption |
| Key Derivation | HKDF-SHA256 | Derive session key |

**Forward Secrecy:** Fresh X25519 keypairs are generated per session. Past
sessions cannot be decrypted even if long-term keys are compromised.

**Replay Prevention:** Counter-based nonces ensure each message is unique
within a session. Cross-session replay fails due to different session keys.

#### Layer 2: Capability Tokens (JWT)

Access is controlled by signed capability tokens:

| Property | Value |
|----------|-------|
| Signature | Ed25519 (EdDSA) |
| Key Size | 32-byte public, 64-byte secret |
| Signature Size | 64 bytes |

Tokens are:
- **Scoped** - Limited to specific paths via glob patterns
- **Time-limited** - Expire after configurable TTL
- **Operation-limited** - Specify allowed operations (read/write/list/stat)
- **Signed** - Cannot be forged without the secret key

#### Layer 3: Path Security

Multiple layers protect against path-based attacks:

1. **Canonicalization** - Paths are normalized to remove `..`, `.`, and `//`
   before any checks. Attempts to escape via traversal are rejected.

2. **Symlink Rejection** - All file operations reject symbolic links,
   preventing symlink-based scope escapes.

3. **Forbidden Paths** - Hardcoded patterns block access to sensitive
   locations regardless of token scope.

#### Layer 4: Audit Logging

**Important:** Denied operations fail immediately on the agent side (with error
messages like "No token grants access") and never reach the resource daemon.
This is a security feature - unauthorized requests are rejected before crossing
the network.

Successful operations that reach the resource daemon are logged with:
- Request ID for tracing
- Operation type (read/write/list/stat)
- Target path
- Timestamp

Logs are written to stderr with `AUDIT:` prefix.

### Cryptographic Primitives

| Primitive | Algorithm | Key/Output Size | Standard |
|-----------|-----------|-----------------|----------|
| Token Signing | Ed25519 | 32B pub / 64B sec / 64B sig | RFC 8032 |
| Key Exchange | X25519 | 32B keys / 32B shared | RFC 7748 |
| Encryption | XChaCha20-Poly1305 | 32B key / 24B nonce / 16B tag | RFC 8439 ext. |
| Key Derivation | HKDF-SHA256 | Variable | RFC 5869 |

### Key Management

**Key Generation:**
```bash
clawgate keygen -o ~/.clawgate/keys
```

Creates:
- `secret.key` - 64-byte Ed25519 secret key (permissions: 0600)
- `public.key` - 32-byte Ed25519 public key (permissions: 0644)

**Secret Zeroing:** All cryptographic secrets are explicitly zeroed using
`std.crypto.secureZero()` when no longer needed, preventing recovery from
freed memory.

### Forbidden Paths

The following paths are **always blocked**, regardless of token scope:

**Directory Patterns (substring match):**
```
/.ssh/              SSH keys and configuration
/.gnupg/            GPG keys and keyrings
/.clawgate/keys/    ClawGate's own signing keys
/.aws/              AWS credentials
/.config/gcloud/    Google Cloud SDK credentials
/.azure/            Azure credentials
/.kube/             Kubernetes configuration
/.docker/config.json Docker credentials
/.netrc             Network credentials
/.npmrc             NPM authentication tokens
/.git-credentials   Git credential storage
/.password-store/   Password manager data
/.local/share/keyrings/ System keyrings
/.mozilla/firefox/  Firefox profiles (passwords, cookies)
/.config/google-chrome/ Chrome profiles
/.config/chromium/  Chromium profiles
/.config/Code/      VS Code secrets
/.config/op/        1Password CLI
```

**File Suffixes (exact match):**
```
.env                Environment secrets
.env.local          Local environment overrides
.env.production     Production secrets
/private.pem        Private keys
/private.key        Private keys
/id_rsa             SSH private key
/id_ed25519         SSH private key
/id_ecdsa           SSH private key
.p12                Certificate bundles
.pfx                Certificate bundles
credentials.json    Service credentials
service-account.json GCP service accounts
secrets.json        Application secrets
secrets.yaml        Application secrets
secrets.yml         Application secrets
```

**Special Pattern:**
- Any path containing `/.env` (hidden .env files anywhere)

These patterns cannot be overridden by configuration or tokens.

## Capability Token Format

### JWT Structure

Tokens use the standard JWT format:
```
BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
```

### Header

```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

Only EdDSA (Ed25519) algorithm is accepted. Any other algorithm is rejected.

### Payload Claims

```json
{
  "iss": "clawgate:resource:laptop",
  "sub": "clawgate:agent:minipc",
  "iat": 1706745600,
  "exp": 1706832000,
  "jti": "cg_a1b2c3d4e5f6g7h8i9j0k1l2",
  "cg": {
    "v": 1,
    "cap": [
      {
        "r": "files",
        "o": ["read", "list", "stat"],
        "s": "/home/mario/projects/**"
      }
    ]
  }
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | Issuer identity (resource daemon) |
| `sub` | string | Subject identity (agent daemon) |
| `iat` | i64 | Issued-at Unix timestamp |
| `exp` | i64 | Expiration Unix timestamp |
| `jti` | string | Unique token ID (`cg_` + 24 hex chars) |
| `cg.v` | u8 | ClawGate claims version (currently 1) |
| `cg.cap` | array | Array of capability grants |
| `cg.cap[].r` | string | Resource type (always `"files"`) |
| `cg.cap[].o` | array | Operations: `read`, `write`, `list`, `stat`, `git`, `git_write`, `git_remote` |
| `cg.cap[].s` | string | Scope pattern (glob) |

### Scope Patterns

| Pattern | Example | Matches |
|---------|---------|---------|
| Exact | `/home/mario/file.txt` | Only that exact file |
| Single-level | `/tmp/*` | Direct children of /tmp |
| Recursive | `/home/mario/**` | All descendants |
| Extension | `/src/*.zig` | .zig files in /src (not recursive) |

**Pattern Details:**
- Paths must be absolute (start with `/`)
- `*` matches any characters except `/`
- `**` matches any characters including `/`
- Patterns are matched after path canonicalization

### Token Lifecycle

```
1. CREATION (Primary Machine)
   clawgate grant --read --ttl 24h ~/projects > token.txt
                    |
                    v
2. TRANSFER (Manual)
   Copy token.txt to isolated machine
   Copy public.key to isolated machine
                    |
                    v
3. STORAGE (Isolated Machine)
   clawgate token add "$(cat token.txt)"
   Token stored in ~/.clawgate/tokens/
                    |
                    v
4. VALIDATION (On Each Request)
   - Parse JWT structure
   - Verify Ed25519 signature
   - Check expiration
   - Match scope pattern
   - Check forbidden paths
                    |
                    v
5. EXPIRATION (Automatic)
   Token becomes unusable after exp timestamp
```

### Token Validation Flow

```
Receive Request with Token
         |
         v
    Parse JWT
    (3 parts separated by '.')
         |
    [Parse Error?] --Yes--> Reject: INVALID_TOKEN
         |
         No
         v
    Verify Signature
    (Ed25519 against public key)
         |
    [Invalid?] --Yes--> Reject: INVALID_TOKEN
         |
         No
         v
    Check Expiration
    (now <= exp)
         |
    [Expired?] --Yes--> Reject: TOKEN_EXPIRED
         |
         No
         v
    Canonicalize Request Path
    (resolve ., .., //)
         |
    [Escape Detected?] --Yes--> Reject: INVALID_PATH
         |
         No
         v
    Check Forbidden Paths
    (hardcoded patterns)
         |
    [Forbidden?] --Yes--> Reject: ACCESS_DENIED
         |
         No
         v
    Match Token Scope
    (glob pattern against path)
         |
    [No Match?] --Yes--> Reject: SCOPE_VIOLATION
         |
         No
         v
    Execute Operation
```

## Protocol Specification

### Transport Layer

**TCP with Length Prefix:**
```
+----------------+------------------+
| Length (4B)    | Payload          |
| Big-endian     | (variable)       |
+----------------+------------------+
```

| Parameter | Value |
|-----------|-------|
| Default Port | 4223 |
| Length Prefix | 4 bytes, big-endian |
| Max Message Size | 100 MB |

### Handshake Protocol

**Phase 1: Key Exchange**

Resource daemon connects and sends:
```json
{
  "version": 1,
  "resource_pubkey": "<base64 X25519 ephemeral public key>",
  "resource_id": "clawgate-resource"
}
```

Agent daemon responds:
```json
{
  "ok": true,
  "agent_pubkey": "<base64 X25519 ephemeral public key>",
  "session_id": "sess_a1b2c3d4e5f6g7h8"
}
```

Or on error:
```json
{
  "ok": false,
  "error": "Version 2 not supported"
}
```

**Phase 2: Session Establishment**

Both parties:
1. Compute X25519 shared secret: `shared = X25519(my_secret, their_public)`
2. Derive session key: `key = HKDF-SHA256(salt="clawgate-e2e-v1", ikm=shared, info=session_id)`
3. Initialize nonce counter to 0

All subsequent messages are encrypted.

### Encrypted Message Format

```
+-------------+-------------------+-----------+
| Nonce (24B) | Ciphertext        | Tag (16B) |
+-------------+-------------------+-----------+
```

| Field | Size | Description |
|-------|------|-------------|
| Nonce | 24 bytes | Counter-based (8B counter + 16B zeros) |
| Ciphertext | Variable | XChaCha20-encrypted payload |
| Tag | 16 bytes | Poly1305 authentication tag |

**Overhead:** 40 bytes per message (24 nonce + 16 tag)

### Request Format

```json
{
  "id": "req_12345",
  "token": "<JWT capability token>",
  "op": "read",
  "params": {
    "path": "/home/mario/file.txt",
    "offset": 0,
    "length": 4096
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique request ID for correlation |
| `token` | string | JWT capability token |
| `op` | string | Operation: `read`, `write`, `list`, `stat`, `git` |
| `params` | object | Operation-specific parameters |

**Operation Parameters:**

| Operation | Parameter | Type | Description |
|-----------|-----------|------|-------------|
| read | path | string | Absolute file path |
| read | offset | u64? | Starting byte offset |
| read | length | u64? | Max bytes to read |
| write | path | string | Absolute file path |
| write | content | string | Base64-encoded content |
| write | mode | string | `create`, `overwrite`, or `append` |
| list | path | string | Absolute directory path |
| list | depth | u32? | Listing depth (default: 1) |
| stat | path | string | Absolute path |
| git | path | string | Absolute repository path |
| git | args | string[] | Git arguments (e.g. `["status", "--short"]`) |

### Response Format

**Success:**
```json
{
  "id": "req_12345",
  "ok": true,
  "result": { ... }
}
```

**Error:**
```json
{
  "id": "req_12345",
  "ok": false,
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "Path not in granted scope"
  }
}
```

**Result Types:**

Read:
```json
{
  "content": "<base64-encoded bytes>",
  "size": 1024,
  "truncated": false
}
```

Write:
```json
{
  "bytes_written": 256
}
```

List:
```json
{
  "entries": [
    {"name": "file.txt", "type": "file", "size": 1024},
    {"name": "subdir", "type": "dir", "size": null}
  ]
}
```

Stat:
```json
{
  "exists": true,
  "type": "file",
  "size": 4096,
  "modified": "2026-01-31T10:00:00Z"
}
```

Git:
```json
{
  "stdout": "M  src/main.zig\n?? new_file.txt\n",
  "stderr": "",
  "exit_code": 0,
  "truncated": false
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `INVALID_TOKEN` | Token parse or signature failed |
| `TOKEN_EXPIRED` | Token has expired |
| `SCOPE_VIOLATION` | Path not within token's scope |
| `INVALID_OP` | Unknown operation |
| `INVALID_PATH` | Path canonicalization failed |
| `INVALID_REQUEST` | Malformed request JSON |
| `FILE_NOT_FOUND` | File or directory not found |
| `ACCESS_DENIED` | Permission denied or forbidden path |
| `FILE_TOO_LARGE` | File exceeds 100 MB limit |
| `NOT_A_FILE` | Expected file, got directory |
| `NOT_A_DIRECTORY` | Expected directory, got file |
| `IS_SYMLINK` | Symlinks not allowed |
| `GIT_ERROR` | Git command execution failed |
| `GIT_BLOCKED` | Git command or flag blocked by allowlist |
| `GIT_NOT_REPO` | Target path is not a git repository |
| `GIT_TIMEOUT` | Git command timed out |
| `INTERNAL_ERROR` | Unexpected server error |

---

## Git Operations

### Overview

ClawGate supports executing git commands on repositories hosted on the
primary machine. Git operations use a three-tier permission model with
command allowlists for defense in depth.

### Permission Tiers

| Tier | Token Operation | Grants | Example Commands |
|------|----------------|--------|-----------------|
| **Read-only** | `git` | Read-only git ops | status, diff, log, show, branch (list), blame |
| **Write** | `git_write` | Mutating git ops | add, commit, checkout, merge, rebase, reset |
| **Remote** | `git_remote` | Remote git ops | push, pull, fetch, remote add/remove |

Each tier implies the previous: `git_remote` > `git_write` > `git`.

### Grant CLI Flags

```bash
clawgate grant --git ~/projects/myapp        # git only (exact repo path)
clawgate grant --git ~/projects/**           # git + file read/list/stat (recursive)
clawgate grant --git-write ~/projects/**     # + git_write + file write
clawgate grant --git-full ~/projects/**      # + git_remote
```

**Scope behavior:** Git operations validate the repository root path against
the token scope. An exact path grant (no glob) is sufficient for git commands
alone. However, `--git` also enables file read/list/stat operations, which
validate individual file paths - these require a `/**` glob to access files
within the repository.

### Request Format

```json
{
  "id": "req_abc123",
  "token": "<jwt>",
  "op": "git",
  "params": {
    "path": "/home/mario/projects/myapp",
    "args": ["diff", "--stat", "HEAD~3"]
  }
}
```

### Response Format

```json
{
  "id": "req_abc123",
  "ok": true,
  "result": {
    "stdout": " src/main.zig | 5 ++---\n 1 file changed\n",
    "stderr": "",
    "exit_code": 0,
    "truncated": false
  }
}
```

Output is truncated at 512 KB (same as file reads). The `truncated` flag
indicates when output was cut short.

### Command Allowlists

#### Tier 1: `git` (read-only)

```
status, diff, log, show, branch (list only), tag (list only),
rev-parse, ls-files, ls-tree, blame, shortlog, describe,
name-rev, rev-list, cat-file, diff-tree, diff-files, diff-index,
for-each-ref, symbolic-ref, stash list, remote (-v, show),
config --get/--get-all/--list (read-only config)
```

#### Tier 2: `git_write` (mutating)

All of tier 1 plus:
```
add, commit, checkout, switch, merge, rebase, reset, stash
(save/pop/apply/drop), cherry-pick, revert, clean, rm, mv,
restore, branch (create/delete), tag (create/delete), am, apply,
format-patch, notes, config (set)
```

#### Tier 3: `git_remote` (remote)

All of tier 1 + tier 2 plus:
```
push, pull, fetch, remote (add/remove/set-url), submodule, clone
```

### Blocked Flags

These top-level git flags are **always rejected** (all tiers):

| Flag | Reason |
|------|--------|
| `-c` | Arbitrary config override (e.g. `core.fsmonitor`) |
| `--exec-path` | Arbitrary executable path |
| `--git-dir` | Escape scope to different repository |
| `--work-tree` | Escape scope to different directory |
| `-C` | We set cwd ourselves; prevent confusion |

Per-subcommand blocks:

| Subcommand + Flag | Reason |
|-------------------|--------|
| `rebase --exec` | Runs arbitrary shell commands |
| `am --exec` | Runs arbitrary shell commands |
| `diff --ext-diff` | Runs external diff program |
| `config --global` | Modify system-wide config |
| `config --system` | Modify system-wide config |
| `filter-branch` | Always blocked (runs shell commands) |

### Validation Flow

```
Receive Git Request
       |
       v
  Extract subcommand from args
       |
       v
  Classify subcommand tier
  (read / write / remote / blocked)
       |
  [Blocked?] --Yes--> Reject: GIT_BLOCKED
       |
       No
       v
  Check token has required tier
  (git / git_write / git_remote)
       |
  [Insufficient?] --Yes--> Reject: ACCESS_DENIED
       |
       No
       v
  Validate args against blocked flags
       |
  [Blocked flag?] --Yes--> Reject: GIT_BLOCKED
       |
       No
       v
  Verify .git/ exists in repo path
       |
  [Not a repo?] --Yes--> Reject: GIT_NOT_REPO
       |
       No
       v
  Execute: git -C <repo_path> <args...>
       |
       v
  Return GitResult (stdout, stderr, exit_code)
```

### Security Considerations

1. **Git runs on the resource daemon** (trusted machine) using the user's
   own git config and credentials
2. **Command allowlists** prevent arbitrary code execution via git hooks
   and exec flags
3. **Forbidden paths** still apply - git can't access `~/.ssh/` etc.
4. **Scope validation** - git only runs in token-scoped directories
5. **Output truncation at 512 KB** prevents memory exhaustion
6. **`--git-dir`/`--work-tree` blocked** prevents pointing git at repos
   outside scope

---

## MCP Integration

### Overview

The MCP (Model Context Protocol) server enables AI tools to access ClawGate
capabilities via JSON-RPC 2.0 over stdio.

### Methods

| Method | Description |
|--------|-------------|
| `initialize` | Returns server capabilities |
| `tools/list` | Returns available tools |
| `tools/call` | Executes a tool |

### Tools

| Tool | Description |
|------|-------------|
| `clawgate_read_file` | Read file contents |
| `clawgate_write_file` | Write file contents |
| `clawgate_list_directory` | List directory entries |
| `clawgate_stat` | Get file/directory metadata |
| `clawgate_git` | Run git commands on the primary machine |

### Example Session

```json
// Request
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

// Response
{"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {...}}}

// Request
{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

// Response
{"jsonrpc": "2.0", "id": 2, "result": {"tools": [...]}}

// Request
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
  "name": "clawgate_read_file",
  "arguments": {"path": "/home/mario/readme.txt"}
}}

// Response
{"jsonrpc": "2.0", "id": 3, "result": {"content": "..."}}

// Request (git)
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
  "name": "clawgate_git",
  "arguments": {"path": "/home/mario/projects/myapp",
                "args": ["status", "--short"]}
}}

// Response
{"jsonrpc": "2.0", "id": 4, "result": {"content": "M src/main.zig\n"}}
```

## Deployment Scenarios

### Scenario 1: Private LAN (Mac Mini + MacBook)

A common setup where a Mac Mini runs AI workloads and accesses files on your
MacBook over the local network.

**Network Topology:**
```
+------------------+         +------------------+
|  MacBook (LAN)   |         |  Mac Mini (LAN)  |
|  192.168.1.10    |         |  192.168.1.100   |
|------------------|         |------------------|
|  Resource Daemon |-------->|  Agent Daemon    |
|  (connects out)  |  :4223  |  (listens)       |
|                  |         |  MCP Server      |
+------------------+         +--------+---------+
                                      |
                                      v
                             +------------------+
                             |  Claude Code     |
                             +------------------+
```

**Setup Steps:**

1. **Generate keys** (MacBook):
   ```bash
   clawgate keygen
   ```

2. **Grant access** (MacBook):
   ```bash
   clawgate grant --read --ttl 24h ~/projects > token.txt
   ```

3. **Prepare agent machine** (Mac Mini):
   ```bash
   mkdir -p ~/.clawgate/keys
   ```

4. **Copy files to Mac Mini** (from MacBook):
   ```bash
   scp token.txt mini:~/
   scp ~/.clawgate/keys/public.key mini:~/.clawgate/keys/
   ```
   The agent needs your public key to verify token signatures.

5. **Store token** (Mac Mini):
   ```bash
   clawgate token add "$(cat ~/token.txt)"
   ```

6. **Start agent daemon** (Mac Mini):
   ```bash
   clawgate --mode agent --listen 0.0.0.0:4223
   ```

7. **Start resource daemon** (MacBook):
   ```bash
   clawgate --mode resource --connect 192.168.1.100:4223
   ```

8. **Test access** (Mac Mini):
   ```bash
   clawgate cat ~/projects/myapp/README.md
   ```

**Security Notes:**
- Both machines should be on a trusted network segment
- Consider firewall rules to restrict port 4223 access
- Use short TTL tokens (1-24 hours) for regular work

### Scenario 2: VPS with SSH Tunnel

Running Claude Code on a VPS while accessing local files through an SSH tunnel.

**Network Topology:**
```
+------------------+                      +------------------+
|  Local Laptop    |                      |  VPS             |
|  (behind NAT)    |                      |  (public IP)     |
|------------------|     SSH Tunnel       |------------------|
|  Resource Daemon |=====================>|  Agent Daemon    |
|  connects to     |  localhost:4223      |  listens :4223   |
|  localhost:4223  |                      |  MCP Server      |
+------------------+                      +--------+---------+
                                                   |
                                                   v
                                          +------------------+
                                          |  Claude Code     |
                                          +------------------+
```

**Setup Steps:**

1. **Establish SSH tunnel** (local laptop):
   ```bash
   ssh -R 4223:localhost:4223 user@vps.example.com
   ```
   This forwards VPS port 4223 to your local machine.

2. **Generate keys and grant access** (local laptop):
   ```bash
   clawgate keygen
   clawgate grant --read --write --ttl 8h ~/code > token.txt
   ```

3. **Prepare agent machine** (VPS):
   ```bash
   mkdir -p ~/.clawgate/keys
   ```

4. **Copy files to VPS** (from local laptop):
   ```bash
   scp token.txt user@vps.example.com:~/
   scp ~/.clawgate/keys/public.key user@vps.example.com:~/.clawgate/keys/
   ```
   The agent needs your public key to verify token signatures.

5. **Store token** (VPS):
   ```bash
   clawgate token add "$(cat ~/token.txt)"
   ```

6. **Start agent daemon** (VPS):
   ```bash
   clawgate --mode agent --listen 127.0.0.1:4223
   ```
   Note: Listen only on localhost for security.

7. **Start resource daemon** (local laptop):
   ```bash
   clawgate --mode resource --connect localhost:4223
   ```
   Connection goes through the SSH tunnel.

**Security Considerations:**
- The SSH tunnel provides an additional encryption layer
- Agent daemon should only listen on 127.0.0.1 (not 0.0.0.0)
- Use SSH key authentication, not passwords
- Consider shorter TTL tokens when VPS security is uncertain
- VPS firewall should block external access to port 4223

### Scenario 3: Docker Container

Running the agent daemon in a Docker container.

**Dockerfile:**
```dockerfile
FROM debian:bookworm-slim

COPY clawgate /usr/local/bin/
COPY public.key /etc/clawgate/

RUN mkdir -p /var/lib/clawgate/tokens

EXPOSE 4223

CMD ["clawgate", "--mode", "agent", \
     "--listen", "0.0.0.0:4223", \
     "--token-dir", "/var/lib/clawgate/tokens"]
```

**Docker Compose:**
```yaml
version: '3.8'
services:
  clawgate-agent:
    build: .
    ports:
      - "4223:4223"
    volumes:
      - ./tokens:/var/lib/clawgate/tokens
    restart: unless-stopped
```

**Notes:**
- Mount token directory as volume for persistence
- Copy resource's public key into container at build time (agent needs it to verify token signatures)
- Network mode may need adjustment for your setup

## CLI Reference

### Daemon Commands

```bash
# Run agent daemon
clawgate --mode agent [options]
  --listen <addr:port>     Listen address (default: 0.0.0.0:4223)
  --token-dir <path>       Token directory (default: ~/.clawgate/tokens)

# Run resource daemon
clawgate --mode resource [options]
  --connect <host:port>    Connect to agent (required)
  --public-key <path>      Public key (default: ~/.clawgate/keys/public.key)
  --resource-id <id>       Resource identifier (default: clawgate-resource)

# Run MCP server
clawgate mcp-server [options]
  --token-dir <path>       Token directory (default: ~/.clawgate/tokens)
```

### Capability Commands

```bash
# Generate Ed25519 keypair
clawgate keygen [options]
  -o, --output <dir>       Output directory (default: ~/.clawgate/keys)
  -f, --force              Overwrite existing keys

# Grant capability token
clawgate grant [options] <path>
  -r, --read               Allow read (includes list, stat)
  -w, --write              Allow write
  --list                   Allow list only
  --stat                   Allow stat only
  --git                    Git read-only (+ read, list, stat)
  --git-write              Git read+write (+ file write)
  --git-full               Git full access (+ push/pull/fetch)
  -t, --ttl <duration>     Token lifetime (default: 24h)
  -k, --key <path>         Secret key path
  --issuer <id>            Issuer identity
  --subject <id>           Subject identity
```

**TTL formats:** `1h`, `24h`, `7d`, `3600s`, `1800m`, or plain seconds.

### Token Management

```bash
# Add token to store
clawgate token add [token]
  -d, --token-dir <dir>    Token directory
  # Token can be argument or stdin

# List stored tokens
clawgate token list
  -d, --token-dir <dir>    Token directory
  --json                   Output as JSON

# Remove token
clawgate token remove <id>
  -d, --token-dir <dir>    Token directory

# Show token details
clawgate token show <id>
  -d, --token-dir <dir>    Token directory
```

### File Operations

```bash
# Read file
clawgate cat <path>
  -d, --token-dir <dir>    Token directory
  --offset <n>             Starting byte offset
  --length <n>             Maximum bytes to read

# List directory
clawgate ls <path>
  -d, --token-dir <dir>    Token directory
  --depth <n>              Listing depth (default: 1)
  -l                       Long format with sizes

# Write file
clawgate write <path>
  -d, --token-dir <dir>    Token directory
  -c, --content <text>     Content (or stdin)
  -a, --append             Append mode
  --create                 Fail if file exists

# Get file/directory info
clawgate stat <path>
  -d, --token-dir <dir>    Token directory
  --json                   Output as JSON
```

### Git Operations

```bash
# Run git commands
clawgate git <repo-path> <git-args...>
  -d, --token-dir <dir>    Token directory

# Examples:
clawgate git ~/projects/myapp status
clawgate git ~/projects/myapp diff HEAD~3
clawgate git ~/projects/myapp log --oneline -20
clawgate git ~/projects/myapp commit -m "fix bug"
clawgate git ~/projects/myapp push origin main
```

### Monitoring

```bash
# View audit info
clawgate audit
```

Audit events are logged to stderr with prefix `AUDIT:`:
```
AUDIT: req=req_12345 op=read path=/home/mario/file.txt success=true
```

## Operational Limits

### File Operations

| Limit | Value | Configurable |
|-------|-------|--------------|
| Maximum file size | 100 MB | No |
| Truncation threshold | 512 KB | No |
| Maximum token payload | 16 KB | No |

### Network

| Parameter | Value | Configurable |
|-----------|-------|--------------|
| Default port | 4223 | Yes |
| Max message size | 100 MB | No |
| Length prefix | 4 bytes | No |

### Cryptographic

| Parameter | Value |
|-----------|-------|
| Session ID length | 37 chars (`sess_` + 32 hex) |
| Token ID length | 27 chars (`cg_` + 24 hex) |
| Nonce counter max | 2^64 messages per session |

## Security Considerations

### Token Handling Best Practices

1. **Minimal scope** - Grant only the paths needed, not entire home directory
2. **Minimal TTL** - Use shortest practical lifetime (hours, not days)
3. **Minimal operations** - Don't grant write if only read is needed
4. **Secure transfer** - Use encrypted channel to transfer tokens

### Network Security

1. **Outbound-only** - Resource daemon initiates, no inbound to trusted machine
2. **E2E encryption** - Safe over untrusted networks
3. **Forward secrecy** - Fresh keys per session

### Secret Management

1. **Key permissions** - Secret key should be 0600 (owner read-only)
2. **Memory zeroing** - All secrets zeroed after use
3. **No logging** - Secrets never appear in logs

### Revocation

ClawGate does not implement active token revocation. Tokens expire naturally
at their `exp` timestamp. For immediate revocation:

1. Delete token file from agent's token directory
2. Restart agent daemon
3. Wait for token expiration

Consider using shorter TTLs if revocation needs are anticipated.

## Appendix A: Error Code Reference

| Code | HTTP Equiv. | Description |
|------|-------------|-------------|
| INVALID_TOKEN | 401 | Token malformed or signature invalid |
| TOKEN_EXPIRED | 401 | Token past expiration time |
| SCOPE_VIOLATION | 403 | Path not in token scope |
| INVALID_OP | 400 | Unknown operation |
| INVALID_PATH | 400 | Path failed canonicalization |
| INVALID_REQUEST | 400 | Malformed request JSON |
| FILE_NOT_FOUND | 404 | Target path doesn't exist |
| ACCESS_DENIED | 403 | OS permission denied or forbidden path |
| FILE_TOO_LARGE | 413 | File exceeds 100 MB |
| NOT_A_FILE | 400 | Operation requires file, got directory |
| NOT_A_DIRECTORY | 400 | Operation requires directory, got file |
| IS_SYMLINK | 403 | Symlinks not permitted |
| GIT_ERROR | 500 | Git command execution failed |
| GIT_BLOCKED | 403 | Git command or flag blocked by allowlist |
| GIT_NOT_REPO | 400 | Target path is not a git repository |
| GIT_TIMEOUT | 504 | Git command timed out |
| INTERNAL_ERROR | 500 | Unexpected server error |


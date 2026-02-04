# ClawGate - Secure File Access

Access files on the user's primary machine through ClawGate's secure E2E encrypted bridge.

## Available Commands

### Read File
```bash
clawgate cat /path/to/file
clawgate cat --offset 1024 --length 512 /path/to/file
```
Returns file contents. Large files (>512KB) are automatically truncated.

Options:
- `--offset <bytes>` - Start reading at byte offset
- `--length <bytes>` - Maximum bytes to read

### List Directory
```bash
clawgate ls /path/to/directory
clawgate ls -l --depth 2 /path/to/directory
```
Lists files and subdirectories with type and size information.

Options:
- `-l` - Long format with file sizes
- `--depth <n>` - Listing depth (default: 1)

### Write File
```bash
# From content flag
clawgate write /path/to/file --content "your content here"

# Append instead of overwrite
clawgate write --append /path/to/file --content "appended content"

# Create only (fail if file exists)
clawgate write --create /path/to/file --content "new file content"

# From stdin
echo "content" | clawgate write /path/to/file
```
Creates or overwrites file at the specified path.

Options:
- `--append` or `-a` - Append to file instead of overwriting
- `--create` - Fail if file already exists (exclusive create)

### Get File Info
```bash
clawgate stat /path/to/file
clawgate stat --json /path/to/file
```
Returns file metadata: exists, type, size, modified timestamp.

Options:
- `--json` - Output as JSON

### Check Token Status
```bash
clawgate token list
```
Shows granted paths, permissions, and expiry. Useful to know what's accessible before attempting operations.

---

## Common Patterns

### Browse a project
```bash
clawgate ls -l --depth 2 /home/user/project
clawgate cat /home/user/project/README.md
clawgate cat /home/user/project/src/main.zig
```

### Read large file in chunks
```bash
clawgate cat --offset 0 --length 10000 /path/to/large.log
clawgate cat --offset 10000 --length 10000 /path/to/large.log
```

### Search for a file
```bash
clawgate ls --depth 3 /home/user/projects | grep "README"
```

### Blind drop (write-only access)
If granted `--write` without `--read`, you can leave files but can't peek:
```bash
clawgate write /tmp/results.txt --content "Analysis complete"
# Reading will fail - one-way data flow
```

### Append to a log
```bash
clawgate write --append /path/to/notes.md --content "
## New Entry
Added by agent at $(date)
"
```

---

## Access Scope

You can only access paths the user has explicitly granted. The capability token defines which paths and operations are allowed.

**Permission types:**
- `read` - Read file contents, list directories, stat files
- `write` - Create, overwrite, or append to files

**Scope patterns:**
- `/home/user/file.txt` - Exact file only
- `/home/user/dir/*` - Direct children only
- `/home/user/dir/**` - Recursive (all descendants)

---

## Forbidden Paths

These paths can **NEVER** be accessed, even if granted:
- `~/.ssh/` - SSH keys
- `~/.gnupg/` - GPG keys  
- `~/.aws/` - AWS credentials
- `~/.clawgate/keys/` - ClawGate signing keys

Hardcoded. Ungrantable. Always blocked.

---

## Error Handling

If an operation is denied, you'll receive an error with a code:

| Error | Meaning |
|-------|---------|
| `SCOPE_VIOLATION` | Path not in granted scope |
| `TOKEN_EXPIRED` | Token has expired, user needs to grant again |
| `FORBIDDEN_PATH` | Path is in the forbidden list |
| `NOT_FOUND` | File or directory doesn't exist |
| `IS_SYMLINK` | Path is a symbolic link (symlinks are rejected) |
| `CONNECTION_CLOSED` | Resource daemon not running |

When access is denied, inform the user they may need to grant additional access.

---

## Need More Access?

Ask the user to grant additional paths on their machine:

```bash
# Read access
clawgate grant --read "/path/to/more/**" --ttl 24h

# Write access  
clawgate grant --write "/tmp/output/**" --ttl 24h

# Both
clawgate grant --read --write "/path/to/project/**" --ttl 24h
```

**Hot reload:** Tokens can be added while running - no restart needed!

```bash
clawgate token add "<token>"
```

---

## Security Model

```
Agent Machine                    Primary Machine
     │                                 │
     ├─ Token validation (1st gate)    │
     │                                 │
     ├──── E2E Encrypted Tunnel ──────►├─ Signature check (2nd gate)
     │     X25519 + XChaCha20          │
     │                                 ├─ Scope validation (3rd gate)
     │                                 │
     │                                 ├─ Forbidden paths (final gate)
     │                                 │
     │◄─────── File contents ──────────┤
```

- **Zero trust** - Assumes agent machine may be compromised
- **Least privilege** - Only granted paths accessible
- **Time-bounded** - Tokens expire (1h, 24h, 7d)
- **Full audit** - Every operation logged on resource side

---

*ClawGate - Secure file access for the AI agent era* 🦞

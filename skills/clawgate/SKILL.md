# ClawGate - Secure File & Git Access

Access files and run git commands on the user's primary machine through ClawGate's secure E2E encrypted bridge.

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

### Git Commands
```bash
clawgate git <repo-path> <git-args...>
```
Runs git commands on a repository on the user's primary machine. The repository path must be within the granted scope.

**Three permission tiers** (each includes the previous):

**Read-only** (`--git` token) - inspect without modifying:
```bash
clawgate git /home/user/project status
clawgate git /home/user/project diff HEAD~3
clawgate git /home/user/project log --oneline -20
clawgate git /home/user/project show abc1234
clawgate git /home/user/project blame src/main.zig
clawgate git /home/user/project branch
clawgate git /home/user/project stash list
```

**Write** (`--git-write` token) - modify local repository:
```bash
clawgate git /home/user/project add src/main.zig
clawgate git /home/user/project commit -m "fix: resolve edge case"
clawgate git /home/user/project checkout -b feature/new
clawgate git /home/user/project merge main
clawgate git /home/user/project rebase main
clawgate git /home/user/project stash pop
```

**Full** (`--git-full` token) - interact with remotes:
```bash
clawgate git /home/user/project push origin main
clawgate git /home/user/project pull origin main
clawgate git /home/user/project fetch --all
```

Output behavior:
- stdout and stderr are returned separately
- Output is truncated at 512KB
- Git's exit code is preserved (non-zero = failure)
- 30 second timeout per command

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

### Check repo state before working
```bash
clawgate git /home/user/project status --short
clawgate git /home/user/project log --oneline -5
clawgate git /home/user/project diff --stat
```

### Review and commit changes
```bash
clawgate git /home/user/project diff src/main.zig
clawgate git /home/user/project add src/main.zig
clawgate git /home/user/project commit -m "fix: handle edge case in parser"
```

### Explore git history
```bash
clawgate git /home/user/project log --oneline -20
clawgate git /home/user/project show abc1234
clawgate git /home/user/project blame src/main.zig
clawgate git /home/user/project diff HEAD~3..HEAD
```

### Sync with remote
```bash
clawgate git /home/user/project pull origin main
# ... make changes ...
clawgate git /home/user/project push origin feature/fix
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
- `git` - Read-only git operations (status, diff, log, show, blame, ...)
- `git_write` - Mutating git operations (add, commit, checkout, merge, rebase, ...)
- `git_remote` - Remote git operations (push, pull, fetch)

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
| `GIT_BLOCKED` | Git command or flag not in allowlist |
| `GIT_NOT_REPO` | Path is not a git repository |
| `GIT_ERROR` | Git command execution failed |
| `GIT_TIMEOUT` | Git command exceeded 30s timeout |

When access is denied, inform the user they may need to grant additional access.

**Git-specific:** If you get `GIT_BLOCKED`, the command or a flag you used is not allowed. Some flags are always blocked for security: `-c`, `--git-dir`, `--work-tree`, `--exec-path`, `rebase --exec`, `diff --ext-diff`, `config --global`. The command `filter-branch` is always blocked.

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

# Git only (no file read inside repo)
clawgate grant --git /path/to/repo --ttl 24h

# Git + file read inside repo (most useful)
clawgate grant --git "/path/to/repo/**" --ttl 24h

# Git read+write (includes file read+write)
clawgate grant --git-write "/path/to/repo/**" --ttl 8h

# Git full access (includes push/pull/fetch)
clawgate grant --git-full "/path/to/repo/**" --ttl 4h
```

**Scope note:** Git commands only check the repo root path, so an exact path grant (`/path/to/repo`) is enough for git. But `--git` also enables file read/list/stat - to use `clawgate cat` or `clawgate ls` on files inside the repo, you need the `/**` glob.

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
     │                                 ├─ Forbidden paths (4th gate)
     │                                 │
     │                                 ├─ Git allowlist (5th gate)
     │                                 │
     │◄─────── File/git output ────────┤
```

- **Zero trust** - Assumes agent machine may be compromised
- **Least privilege** - Only granted paths accessible
- **Time-bounded** - Tokens expire (1h, 24h, 7d)
- **Full audit** - Every operation logged on resource side

---

*ClawGate - Secure file & git access for the AI agent era* 🦞

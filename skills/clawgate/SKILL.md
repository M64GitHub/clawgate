# ClawGate - Secure File Access

Access files on the user's primary machine through ClawGate's secure bridge.

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

## Access Scope

You can only access paths the user has explicitly granted. The capability
token defines which paths and operations are allowed.

## Forbidden Paths

These paths can NEVER be accessed, even if granted:
- `~/.ssh/` - SSH keys
- `~/.gnupg/` - GPG keys
- `~/.aws/` - AWS credentials
- `~/.clawgate/keys/` - ClawGate signing keys

## Error Handling

If an operation is denied, you'll receive an error with a code:
- `SCOPE_VIOLATION` - Path not in granted scope
- `TOKEN_EXPIRED` - Token has expired, user needs to grant again
- `FORBIDDEN_PATH` - Path is in the forbidden list
- `NOT_FOUND` - File or directory doesn't exist

When access is denied, inform the user they may need to grant additional
access using `clawgate grant`.

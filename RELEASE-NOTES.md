# ClawGate v0.3.3 Release Notes

This release adds **path-based scope enforcement** for custom tools,
closing a security gap where tool arguments could bypass ClawGate's
file access controls. Tools that access the filesystem must now declare
a `--scope`, and all path-like arguments are validated against it.

## Tool Path Scoping

Previously, custom tool arguments were only checked against flag
allow/deny lists. Positional arguments (including file paths) passed
through unchecked to the subprocess. A tool registered with scope
`projects/webapp` could be invoked as `rg pattern /etc/hosts` - the
subprocess would happily read `/etc/hosts`.

ClawGate now applies three layers of argument security:

| Layer | What it does |
|-------|-------------|
| **Flag validation** | Allow/deny lists for flags (`-x`, `--flag`) |
| **Path scanning** | Path-like args canonicalized and checked against scope |
| **CWD confinement** | Tool subprocess runs with `cwd` set to `$HOME` |

### Scope Declaration

Tools that access the filesystem must declare a `--scope` at
registration time. Scope values are semicolon-separated directories
relative to `$HOME`:

```bash
# Single directory
clawgate tool register rg \
  --command "rg" \
  --scope "projects/webapp" \
  --arg-mode passthrough

# Multiple directories
clawgate tool register wc \
  --command "wc" \
  --scope "projects/webapp;Documents/reports"

# Pure stdin/stdout tool - no scope needed
clawgate tool register calc --command "bc -l"
```

### Path Validation

All non-flag arguments are scanned for path-like patterns (`/...`,
`~/...`, `./...`, `../...`, `.`, `..`). Detected paths are
canonicalized and checked against:

1. The tool's scope entries (must fall within at least one)
2. The forbidden paths list (`.ssh`, `.gnupg`, `.aws`, etc.)

```bash
# In-scope - works:
clawgate tool rg pattern ~/projects/webapp/src/main.zig

# Out-of-scope - blocked:
clawgate tool rg pattern /etc/hosts
# Error: PATH_BLOCKED

# Traversal attempt - blocked:
clawgate tool rg pattern ~/projects/webapp/../../etc/passwd
# Error: PATH_BLOCKED
```

### No Scope = No Filesystem Access

Tools without a `--scope` are blocked from receiving any path-like
argument. This is correct for pure stdin/stdout tools like `bc`, `jq`,
or `python -c` that never need filesystem access.

### Scope Validation at Registration

Invalid scope values are rejected at `tool register` and `tool update`
time:

- `.` - too permissive (grants entire `$HOME`)
- `..` - escapes `$HOME`
- Absolute paths (`/etc`) - scopes must be relative to `$HOME`
- Empty segments (`a;;b`) - malformed

### CWD Confinement

All tool subprocesses now execute with their working directory set to
`$HOME`. This provides defense in depth: even if a relative path
bypasses detection, it resolves within the user's home directory
rather than an attacker-controlled location.

## Scope Management

Update an existing tool's scope:

```bash
clawgate tool update rg --scope "projects/webapp;projects/api"
```

The `--scope` option is also available in `tool update`.

## Documentation Updates

- **README.md** - Updated custom tools section, security defense
  layers table (14 → 16 layers), CLI reference with `--scope`
- **docs/DESIGN.md** - Added complete "Custom Tool Operations"
  section, updated Layer 3: Path Security, Appendix A error codes,
  CLI reference, revocation section
- **docs/TOOL-GUIDE.md** - Added "Tool Scope and Path Security"
  section, updated all examples with scope, new troubleshooting
  entries for `PATH_BLOCKED` and scope errors

## New Error Code

| Code | HTTP Equiv. | Description |
|------|-------------|-------------|
| `PATH_BLOCKED` | 403 | Path argument outside tool scope or forbidden |

## Modified Files

| File | Changes |
|------|---------|
| `src/resource/tool_exec.zig` | Added `isPathLike()`, `parseScopeEntries()`, `validatePaths()`; added `cwd` parameter to `executeTool()` and `executeWithStdin()`; 17 new tests |
| `src/resource/handlers.zig` | Added `PATH_BLOCKED` error code; made `isForbiddenPath` public; threaded `home` parameter through handler chain; added `validatePaths()` call |
| `src/resource/daemon.zig` | Pass `home` to `handleRequestFull()` |
| `src/cli/tool_cmd.zig` | Added `--scope` to register/update; scope validation; path validation in `tool test` |
| `README.md` | Scope documentation, updated defense layers |
| `docs/DESIGN.md` | Custom Tool Operations section, error codes, CLI reference |
| `docs/TOOL-GUIDE.md` | Scope and path security section, updated examples |

## Test Coverage

17 new unit tests covering:
- `isPathLike` detection (absolute, tilde, relative, dot, dotdot,
  bare words, flags)
- `parseScopeEntries` valid and invalid inputs (`.`, `..`, absolute,
  empty segments)
- `validatePaths` for in-scope, out-of-scope, traversal, forbidden
  paths, multi-scope, unscoped tools, tilde expansion, flag
  passthrough

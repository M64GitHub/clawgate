# ClawGate Glob Pattern Matching

This document describes the exact behavior of ClawGate's capability scope
pattern matching system, including all edge cases.

## Overview

ClawGate uses glob patterns to define the scope of capability tokens. When a
token grants access to files, the scope pattern determines which paths are
accessible. All paths must be absolute (starting with `/`).

## Pattern Types

### 1. Exact Match

A pattern without wildcards matches only the exact path.

```
Pattern: /home/user/file.txt
```

| Path                    | Matches |
|-------------------------|---------|
| `/home/user/file.txt`   | YES     |
| `/home/user/other.txt`  | NO      |
| `/home/user/file.txt/`  | NO      |
| `/home/user`            | NO      |

**Key behavior:**
- Trailing slashes matter: `/path` does NOT match `/path/`
- The path must be character-for-character identical

### 2. Single-Level Wildcard (`/*`)

Matches any single path component (direct children only).

```
Pattern: /home/user/*
```

| Path                        | Matches |
|-----------------------------|---------|
| `/home/user/file.txt`       | YES     |
| `/home/user/readme`         | YES     |
| `/home/user/.hidden`        | YES     |
| `/home/user/file.tar.gz`    | YES     |
| `/home/user/sub/file.txt`   | NO      |
| `/home/user`                | NO      |
| `/home/other/file.txt`      | NO      |

**Key behavior:**
- Matches files/directories directly inside the parent
- Does NOT match the parent directory itself
- Does NOT descend into subdirectories
- Hidden files (starting with `.`) ARE matched

### 3. Recursive Wildcard (`/**`)

Matches any path at any depth under the prefix.

```
Pattern: /home/user/**
```

| Path                          | Matches |
|-------------------------------|---------|
| `/home/user`                  | YES     |
| `/home/user/file.txt`         | YES     |
| `/home/user/sub/file.txt`     | YES     |
| `/home/user/a/b/c/deep.txt`   | YES     |
| `/home/other/file.txt`        | NO      |
| `/home/username/file.txt`     | NO      |

**Key behavior:**
- Matches the directory itself AND all descendants
- Respects path boundaries: `/home/m/**` does NOT match `/home/mario`
- Unlimited depth

### 4. Extension Pattern (`*.ext`)

Matches files with a specific extension in a directory.

```
Pattern: /home/user/*.zig
```

| Path                        | Matches |
|-----------------------------|---------|
| `/home/user/main.zig`       | YES     |
| `/home/user/test.zig`       | YES     |
| `/home/user/.zig`           | YES     |
| `/home/user/main.c`         | NO      |
| `/home/user/sub/main.zig`   | NO      |

**Key behavior:**
- Only matches in the specified directory (no subdirectories)
- The `*` matches any characters EXCEPT `/`
- Empty basename is allowed: `*.txt` matches `.txt`

## Root Patterns

Special patterns that operate from the filesystem root.

| Pattern | Behavior |
|---------|----------|
| `/**`   | Matches ALL absolute paths |
| `/*`    | Matches single-level paths like `/file` |

### Examples for `/**`

| Path          | Matches |
|---------------|---------|
| `/`           | YES     |
| `/any/path`   | YES     |
| `/a/b/c/d`    | YES     |

### Examples for `/*`

| Path          | Matches |
|---------------|---------|
| `/file`       | YES     |
| `/toplevel`   | YES     |
| `/top/nested` | NO      |
| `/`           | NO      |

## Path Canonicalization

Before matching, paths are canonicalized to prevent directory traversal
attacks. This happens automatically in the request handler.

### Canonicalization Rules

1. **Absolute paths only**: Relative paths are rejected
2. **`.` components removed**: `/home/./user` becomes `/home/user`
3. **`..` components resolved**: `/home/user/../other` becomes `/home/other`
4. **Consecutive slashes collapsed**: `//home///user` becomes `/home/user`
5. **Root escape rejected**: `/../etc/passwd` returns error
6. **Empty paths rejected**: Empty string returns error

### Canonicalization Examples

| Input                           | Output              |
|---------------------------------|---------------------|
| `/home/user/file.txt`           | `/home/user/file.txt` |
| `/home/./user/./file`           | `/home/user/file`   |
| `/home/user/../other`           | `/home/other`       |
| `//home///user`                 | `/home/user`        |
| `/`                             | `/`                 |
| `/./`                           | `/`                 |
| `/../etc/passwd`                | **REJECTED**        |
| `/home/../../etc`               | **REJECTED**        |
| `relative/path`                 | **REJECTED**        |
| (empty)                         | **REJECTED**        |

### Dot-Like Names

Names that resemble `.` or `..` but aren't are preserved:

| Input           | Output          |
|-----------------|-----------------|
| `/home/...`     | `/home/...`     |
| `/home/..a`     | `/home/..a`     |
| `/home/a..`     | `/home/a..`     |

## Path Boundary Security

ClawGate enforces strict path boundaries to prevent prefix confusion attacks.

### The Problem

Without boundary checking, a pattern like `/home/m/**` could accidentally
match `/home/mario/secret.txt` because `/home/mario` starts with `/home/m`.

### The Solution

After matching the prefix, ClawGate verifies the next character is either:
- End of path (exact match), OR
- A `/` (proper subdirectory)

### Examples

Pattern: `/home/m/**`

| Path                  | Matches | Reason |
|-----------------------|---------|--------|
| `/home/m`             | YES     | Exact match of prefix |
| `/home/m/file.txt`    | YES     | `/` follows prefix |
| `/home/mario`         | NO      | `a` follows prefix, not `/` |
| `/home/mxyz/file.txt` | NO      | `x` follows prefix, not `/` |

## isWithin Function

The `isWithin(base, path)` function checks if a path is contained within a
base directory. This is used internally for scope validation.

### Behavior

| Base       | Path              | Result | Reason |
|------------|-------------------|--------|--------|
| `/home/m`  | `/home/m/file`    | true   | Proper subdirectory |
| `/home/m`  | `/home/m`         | true   | Same path |
| `/home/m/` | `/home/m/sub`     | true   | Trailing slash normalized |
| `/home/m`  | `/home/mario`     | false  | Prefix only, not subdir |
| `/home/m`  | `/home/other`     | false  | Different directory |
| `/`        | `/any/path`       | true   | Root contains all |
| `/`        | `/`               | true   | Root contains itself |
| (empty)    | `/any/path`       | false  | Empty base is invalid |
| (empty)    | (empty)           | false  | Empty base is invalid |

**Security note:** Empty base always returns `false` to prevent accidental
universal access.

## Empty and Invalid Pattern Handling

ClawGate treats empty patterns as invalid to prevent security issues.

| Pattern | Path    | Matches | Reason |
|---------|---------|---------|--------|
| `/**`   | `/a`    | YES     | Root recursive matches all |
| `/*`    | `/a`    | YES     | Root single-level |
| `/a/**` | `/a/b`  | YES     | Normal recursive |
| (empty) | `/a`    | NO      | Empty pattern is invalid |
| (empty) | (empty) | NO      | Empty pattern is invalid |

**Security note:** An empty scope pattern grants no access. This prevents
bugs where an accidentally-empty scope would match all paths.

## Summary Table

| Pattern Type | Syntax        | Matches Directory | Matches Subdirs | Example |
|--------------|---------------|-------------------|-----------------|---------|
| Exact        | `/path/file`  | Only if exact     | NO              | `/home/user/file.txt` |
| Single-level | `/path/*`     | NO                | NO              | `/tmp/*` |
| Recursive    | `/path/**`    | YES               | YES             | `/home/**` |
| Extension    | `/path/*.ext` | NO                | NO              | `/src/*.zig` |

## Security Considerations

1. **Always canonicalize** paths before matching to prevent traversal attacks
2. **Path boundaries** prevent `/home/m/**` from matching `/home/mario`
3. **Symlinks are rejected** at the file operation level (see files.zig)
4. **Forbidden paths** are checked after canonicalization (see handlers.zig)
5. **Empty patterns rejected** to prevent universal access bugs
6. **Tokens expire exactly at exp** (not after) - use `>=` comparison

## Implementation Reference

The glob matching is implemented in `src/capability/scope.zig`:
- `matches(pattern, path)` - Main pattern matching function
- `canonicalizePath(allocator, path)` - Path normalization
- `isWithin(base, path)` - Directory containment check (rejects empty base)
- `normalizePath(path)` - Trailing slash removal

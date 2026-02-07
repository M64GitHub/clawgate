# ClawGate v0.2.3 Release Notes

This release adds human-readable expiration dates to token management
commands, making it easy to see when tokens expire at a glance.

## Token Expiration Display

`clawgate token list` and `clawgate token show` now display expiration
(and issuance) timestamps as ISO 8601 dates instead of raw Unix
timestamps.

**`token list` output:**
```
$ clawgate token list
Stored tokens (6):

  ID:      cg_9ae7ce62f4a5b869a8c120fa
  Issuer:  clawgate:resource
  Subject: clawgate:agent
  Scope:   ~/space/ai/remembra/** [read, list, stat, git]
  Expires: 2026-02-08T05:51:26Z
  Status:  Valid
```

**`token show` output:**
```
$ clawgate token show cg_7ab54be138936dfb8d29b81d
Token: cg_7ab54be138936dfb8d29b81d

  Issuer:  clawgate:resource
  Subject: clawgate:agent
  Issued:  2026-02-07T06:02:28Z
  Expires: 2026-02-08T06:02:28Z

  Capabilities:
    - files: ~/space/ai/tiger-style [read, list, stat, git]

  Status: Valid
```

### Files Changed

- `src/resource/audit_log.zig` - Made `formatEpochBuf` public for reuse
- `src/cli/token.zig` - Added formatted expiration dates to list and
  show commands

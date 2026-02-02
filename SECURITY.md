# Security Policy

## Reporting a Vulnerability

ClawGate is security-critical software. We take security issues seriously.

**Do NOT open a public issue for security vulnerabilities.**

Instead, please report security issues via:

1. **Email:** security@clawgate.io
2. **GitHub Security Advisory:** [Report a vulnerability](https://github.com/M64GitHub/clawgate/security/advisories/new)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

## Response Timeline

- **Initial response:** Within 48 hours
- **Status update:** Within 7 days
- **Fix release:** Depends on severity (critical: ASAP, others: next release)

## Scope

In-scope vulnerabilities include:
- Token signature bypass or forgery
- Path traversal or escape from granted scope
- Unauthorized access to forbidden paths
- Memory safety issues in Zig code
- Denial of service via malformed input
- Information disclosure

Out of scope:
- Issues requiring physical access to the machine
- Social engineering attacks
- Issues in dependencies (report to them directly)

## Security Model

ClawGate assumes the agent machine is compromised. See the README for our
threat model and defense layers.

## Acknowledgments

We appreciate security researchers who help keep ClawGate secure. With your
permission, we'll acknowledge your contribution in release notes.

# Contributing to ClawGate

Thank you for your interest in contributing to ClawGate!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/clawgate`
3. Install Zig 0.16+ from https://ziglang.org
4. Build: `zig build`
5. Run tests: `zig build test`

## Development Setup

```bash
# Build and run
zig build run -- --help

# Run tests
zig build test
```

## Integration Testing

To test the full system, run the daemons in separate terminals:

```bash
# Terminal 1: Generate keys (first time only)
zig build run -- keygen

# Terminal 2: Start agent daemon
zig build run -- --mode agent

# Terminal 3: Start resource daemon (connects to agent)
zig build run -- --mode resource --connect localhost:53280

# Terminal 4: Grant access and test
zig build run -- grant --read /tmp --ttl 1h
# Copy the token output, then:
zig build run -- token add "<token>"
zig build run -- ls /tmp
```

## Code Standards

Key points:

- **Line length:** 80 characters maximum
- **Comments:** Every function needs `///` doc comments
- **Memory:** Never store allocators in structs
- **Formatting:** Run `zig fmt` before committing

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Run tests: `zig build test`
4. Run formatter: `zig fmt src/`
5. Commit with clear message
6. Push and open a PR

## What to Contribute

Good first contributions:
- Bug fixes with test cases
- Documentation improvements
- Additional test coverage
- Performance improvements

Please open an issue first for:
- New features
- Architectural changes
- Breaking changes

## Security

Found a security issue? Please report it privately. See `SECURITY.md`.

## License

By contributing, you agree that your contributions will be licensed under
the MIT License.

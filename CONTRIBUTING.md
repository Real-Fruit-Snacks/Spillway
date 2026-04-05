# Contributing to Spillway

Thank you for your interest in contributing to Spillway! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **Go toolchain:** Install from [go.dev/dl](https://go.dev/dl/) (1.22+)
- **FUSE:** `libfuse` (Linux) or `macFUSE` (macOS) for listener builds
- **Git:** For version control
- **golangci-lint:** For linting: `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Spillway.git
cd Spillway

# Build the listener
make listener

# Build an agent (reverse mode)
./build.sh reverse 127.0.0.1:443

# Run tests
go test ./...

# Run the full lint suite
go vet ./...
golangci-lint run ./...
```

## Code Style

All code must pass the following checks before submission:

- **Formatting:** `gofmt` — all code must be formatted with gofmt
- **Vetting:** `go vet ./...` — zero warnings allowed
- **Linting:** `golangci-lint run ./...` — zero warnings allowed
- **Tests:** `go test ./...` — all tests must pass

Run all checks before submitting a PR:

```bash
gofmt -l .
go vet ./...
go vet -tags agent ./...
golangci-lint run ./...
go test ./...
go test -tags agent ./...
```

## Build Tags

Spillway uses build tags to separate agent and listener code. When adding new features:

1. **Agent code** uses `//go:build agent` — minimal dependencies, stdlib + `x/sys` only.
2. **Listener code** uses `//go:build !agent` — may use `bazil.org/fuse` and CLI libraries.
3. **Test both** with `go test ./...` and `go test -tags agent ./...`.
4. **Update tests** to cover the feature under both build configurations.
5. **Document the feature** in the README if it adds user-facing functionality.

## Testing Requirements

- All existing tests must continue to pass: `go test ./...`
- New features must include tests
- Agent-side tests should also pass: `go test -tags agent ./...`
- Race condition tests: `go test -race ./...`

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   gofmt -l .
   go vet ./...
   go test ./...
   go test -race ./...
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(agent): add xattr support for darwin
fix(transport): handle TLS handshake timeout
docs: update build instructions for ARM64
ci: add cross-compilation job for darwin/arm64
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.

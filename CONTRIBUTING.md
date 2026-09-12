# Contributing to DnsForward

Thanks for considering a contribution.

## Development setup

Requirements:

- Go 1.23 or newer
- Git

Clone the repository and verify the project:

```bash
go mod download
go test ./...
go vet ./...
```

Before opening a pull request, run:

```bash
gofmt -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
```

## Pull requests

- Keep changes focused and reasonably small.
- Add or update tests for behavior changes and bug fixes.
- Update documentation when configuration or user-facing behavior changes.
- Do not commit local runtime configuration, logs, IDE metadata, or generated release artifacts.
- Reference related issues in the pull request description when possible.

## Commit messages

Use concise, imperative commit subjects. Conventional Commit prefixes such as `fix:`, `feat:`, `docs:`, `test:`, `refactor:`, `ci:` and `chore:` are encouraged.

## Reporting bugs

Use the bug report issue form and include a minimal configuration, expected behavior, actual behavior, platform, Go version or release version, and relevant logs with sensitive data removed.

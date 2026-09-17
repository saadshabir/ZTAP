# Contributing

Thanks for contributing to ZTAP.

- Security issues: see `SECURITY.md` (please do not file public issues for vulnerabilities)

## Ways To Contribute

- File bugs and feature requests via GitHub Issues
- Improve documentation (docs, examples, runbooks)
- Submit pull requests for fixes and enhancements

## Development Setup

### Prerequisites

- Go (use the version declared in `go.mod`)
- Optional (Linux/eBPF development): `clang`, `llvm`, `make`
- Optional (proto changes): `buf` (the script installs it via `go install`)
- Optional (anomaly service): Python 3.13+

### Local Build

```bash
go mod download
go build ./...
```

### Tests

```bash
go test ./... -v
go test ./... -race
```

### Coverage gate (ratchet)

CI enforces a per-file coverage ratchet over `internal/` and `cmd/`: a file may
improve but must not drop below its recorded baseline in
`.covergate-baseline.json`. Run it locally with:

```bash
go test ./... -covermode=atomic -coverpkg=./internal/...,./cmd/... -coverprofile=coverage.out
go run ./cmd/covergate -coverprofile coverage.out -repo . -baseline .covergate-baseline.json
```

If your change intentionally restructures code (or you added tests and want to
lock in the improvement), regenerate the baseline and commit it:

```bash
go run ./cmd/covergate -coverprofile coverage.out -repo . -baseline .covergate-baseline.json -update-baseline
```

Files not yet in the baseline are reported but not gated **unless they are
platform-independent and have no covered statements at all** — a brand-new,
untagged file with zero coverage fails the gate. Platform-constrained files
(`//go:build` tags) are exempt: one shared cross-OS baseline cannot track
every OS's conditional files. Add tests, or regenerate the baseline
(`-update-baseline`) once the file has coverage.

### Lint / Format

```bash
gofmt -w .
```

CI runs [`golangci-lint`](https://golangci-lint.run/) **v2.12.2** as the primary lint tool:
`go vet` and the other enabled linters gate every PR, and the gofmt/goimports formatters are
applied and diff-checked (`fmt: true` in the action), so formatting is enforced, not advisory.
See `.github/workflows/ci.yml`.

Use the same version locally (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.12.2`):
older builds (e.g. v2.8.0 on go1.25) refuse to load this repo's config with
"Go language version ... lower than the targeted Go version (1.26.6)".

When editing GitHub Actions, keep `run:` commands shell-agnostic for matrix jobs that include Windows (`pwsh`) and Linux/macOS (bash). Avoid bash-only line continuations (for example trailing `\`) in shared steps.

### Security Audit

Run the project security checks before opening a PR:

```bash
bash scripts/security_check.sh
```

This runs unit tests, `go vet`, `govulncheck`, and `gosec`.

Optional secret scan (recommended):

```bash
gitleaks detect --source . --redact --no-banner
```

## Project-Specific Workflows

### Protobuf / gRPC Codegen

If you change files under `proto/`, regenerate generated Go code:

```bash
./scripts/gen_proto.sh
```

### eBPF (Linux)

If you change `bpf/filter.c` or `bpf/engine.c`, rebuild the objects:

```bash
make -C bpf
```

## Pull Request Guidelines

- Keep PRs focused and small when possible
- Include tests and docs updates for behavior changes
- Make sure `go test ./...` passes locally
- Run `bash scripts/security_check.sh` before submitting
- Run `gofmt` on any Go changes
## Error Handling Conventions

- **API handlers** (REST and gRPC): log full error details server-side; return sanitized messages to clients. For gRPC, use `status.Error(codes.*, "short message")`. Never return `err.Error()` directly.
- **Audit hashing**: `EntryHash` returns `(string, error)`. Callers must check the error.
- **Context propagation**: functions that perform I/O or interact with external stores should accept `context.Context` as the first parameter.
- **Channel lifecycle**: do not use `recover()` to suppress double-close panics. Use explicit close-once coordination (e.g., a `closed` flag under a lock).

By submitting a contribution, you agree that your work will be licensed under
the MIT License (see `LICENSE`).

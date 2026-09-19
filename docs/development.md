# Development

## Prerequisites

Go `1.26.6` or a compatible newer toolchain is required. Linux is required
for privileged eBPF and Kubernetes acceptance tests; a non-Linux checkout is
suitable for the non-privileged unit tests.

## Common targets

```sh
make build            # bin/ztap
make test             # race-enabled unit tests
make vet              # go vet
make fmt-check        # gofmt check
make lint             # golangci-lint and actionlint
make check-generated  # regenerate and compare eBPF bindings
make integration      # privileged Linux engine tests
make docker           # scratch runtime image
make clean            # remove local build and tool artifacts
```

The build writes executables below `bin/`; it does not create generated
executables in the repository root. `make check-generated` requires the
configured clang binary (`BPF2GO_CC`, default `clang-18`).

## Test layers

The default Go suite covers the policy compiler, native engine, flow monitor,
CLI, and Kubernetes agent helpers. The Linux eBPF gate runs the instance-owned
engine with the `integration` build tag and requires host bpffs and the
appropriate privileges. CI also builds the scratch image and exercises the
capability-only DaemonSet in kind.

The `flows` command reads the agent's pinned flow events and is therefore a
Linux runtime check, not a portable unit-test fixture:

```sh
ztap flows --output json
ztap flows --action blocked --direction egress
```

## Generated code and review

The only generated Go bindings retained by the product are the engine eBPF
bindings under `internal/enforcer`. Review generated diffs together with the
source change. Before submitting a change, run:

```sh
make fmt-check
make test
make check-generated
git diff --check
```

Do not add a compatibility command, file configuration layer, platform
backend, or auxiliary service without first updating the product contract and
the removal/retention decisions in `STREAMLINING_PLAN.md`.

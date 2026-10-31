# Development

## Prerequisites

Go `1.26.10` or a compatible newer toolchain with current security patches is
required. Linux is required for privileged eBPF and Kubernetes acceptance
tests; a non-Linux checkout is suitable for the non-privileged unit tests.

The privileged Linux integration gate vet-checks and executes both the
enforcer and CLI integration-tagged package trees, including the native
agent, flow-reader, cgroup-path, and evidence-writer support tests. The
Kubernetes acceptance gate runs separately in a disposable kind cluster.

For the complete local workflow, install `make`, clang/LLVM with the
configured `clang-18` binary, Docker, `kubectl`, and kind. `golangci-lint`,
actionlint, and govulncheck are pinned by the Makefile and installed into
repository-local tool/cache paths; Trivy is pinned and run by CI.

## Repository map

```text
cmd/ztap/                 process entry point
internal/cli/             Cobra commands and user-facing I/O
internal/policy/          native NetworkPolicy validation and compilation
internal/enforcer/        Linux eBPF engine and generated bindings
internal/flow/            pinned flow-map decoding and output
deployments/kubernetes/   admission guard, capability-only DaemonSet, manifest tests
examples/native/          validator fixtures
bpf/                      retained eBPF C source
tools/bpfgen/             source-only binding generator
tools/churnprobe/         sequenced TCP checks for multi-node churn
tools/phase5probe/        measurement environment recorder
tools/phase5verify/       retained performance and hosted-evidence verifier
```

The dependency direction is intentional: Kubernetes resolution feeds the
kernel-neutral policy compiler, and the agent composes the compiler with the
Linux engine. The compiler and engine do not depend on Cobra or each other's
runtime concerns.

## Common targets

```sh
make build            # bin/ztap
make test             # race-enabled unit tests
make vet              # go vet
make fmt-check        # gofmt check
make lint             # golangci-lint and actionlint
make vulncheck        # pinned Go vulnerability scan
make check            # non-privileged merge gate
make check-generated  # regenerate and compare eBPF bindings
make integration      # privileged Linux engine and agent tests
make performance      # real-cgroup performance and agent evidence (Linux only)
make verify-performance # validate retained performance evidence
make docker           # scratch runtime image
make clean-build-cache # remove Go build cache; keep module downloads/evidence
make clean-tools      # remove bin/tools only
make clean-test-outputs # remove disposable outputs in .cache/test-output
make clean            # clean local binaries and caches; keep dist/ and evidence
```

`make clean` preserves evidence in `dist/` and `.cache/`. Remove retained
evidence explicitly after deciding what to archive; tool binaries, Go build
cache, and disposable test outputs have independent cleanup targets.
Keep the tracked `dist/go.mod` marker when removing evidence: its module
boundary excludes archived Go source snapshots from `./...` package checks.
Validation logs under `docs/evidence/` are eligible for normal Git commits.

The build writes executables below `bin/`; it does not create generated
executables in the repository root. `make check-generated` requires the
configured clang binary (`BPF2GO_CC`, default `clang-18`). It snapshots the
working-tree bindings before and after regeneration, so synchronized source
and generated-binding changes can be checked before they are committed while
stale bindings still fail the gate. `make check` runs the portable build,
unit-test, vet, lint, and vulnerability targets; it does not include
`check-generated`, `integration`, or `performance`.

`make build` targets your current host. For a Linux binary from macOS, select
the deployment node's architecture explicitly:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make build
```

Use `GOARCH=arm64` for arm64 nodes. This replaces `bin/ztap` with a Linux
binary; run `make build` again before local offline validation on macOS.

## Test layers

The default Go suite covers the policy compiler, native engine, flow monitor,
CLI, and Kubernetes agent helpers. The Linux eBPF gate runs the persistent
engine with the `integration` build tag and requires host bpffs and the
appropriate privileges. The privileged suite includes the policy-deletion
boundary: deleting the last selecting policy must clear both slots, detach all
owned cgroup links, and allow traffic from the formerly selected cgroup again.
CI also builds the scratch image, runs the offline validator through that image
over stdin, and exercises the capability-only DaemonSet in kind.

The restart gates run continuous sequenced traffic in separate ingress and
egress topologies. The Linux suite exercises TERM/KILL/STOP, delayed API
recovery, every policy transaction checkpoint, compatible mixed program
generations and rollback, capacity and partial-pin failures, incomplete live
identities, cgroup replacement, node-lock contention, and partial uninstall.
Both supported systemd parent layouts have inherited-guard feasibility tests.
Production guard tests cover new descendants and crashes after each of its
three program updates. Real pinned status recovery also verifies flow-reader
reconnection on a new `AgentEpoch` with an unchanged policy epoch.

In kind, `.github/scripts/verify-existing-continuity.sh` tests the actual
capability-only agent's pause, crash, and replacement. The companion
`verify-restart-guard.sh` creates new workloads while that process is paused,
terminated, killed, or disconnected from the API. It requires zero premature
TCP connections and zero prohibited traffic, then working allowed controls,
host-network sockets, node/self exceptions, and unisolated workloads. It records
full container/cgroup identity and directional epoch-keyed kernel counters.
`verify-explicit-uninstall.sh` verifies retained enforcement after DaemonSet
deletion and intentional removal under the node lock. These scripts are fault
injection for a disposable kind cluster, not production diagnostics.

With a host C compiler (`clang` or `cc`), the portable suite also runs the
actual packet C program with deterministic BPF helpers to check TCP
handshakes, half-close, FIN/RST cleanup, tuple reuse, and UDP expiry. This
checks decision logic; Linux integration still validates loading and
attachment. The kind gate additionally tests admission rejection of unsafe
regular, init, and ephemeral containers and verifies that a safe workload's
effective, permitted, and bounding capabilities exclude `NET_RAW`.

The separate **Multi-node sustained churn** CI job creates a control-plane
node and worker with independent bpffs mounts. It disables kindnet's policy
controller on both nodes, installs the shipped agent, and runs
`.github/scripts/verify-multinode-churn.sh`. The gate pins endpoints to different
nodes and exercises ingress and egress in both directions. For at least 120
seconds and six lifecycle cycles it changes remote Pod labels, namespace
labels, and Pod identities/IPs while continuously updating real policy rules.
The changing peer alternates between nodes; its stable counterpart is always
on the opposite node. Evidence requires at least three cycles of Pod-label,
namespace-label, and old-IP denial checks enforced from each node.
Replacement Pods overlap their predecessors, guaranteeing different IPs;
the old IP must become denied while its listener is still alive. Each change
must converge within 30 seconds and pass three consecutive checks in both
directions. Refused connections do not count as policy drops.

The portable regression checks for fixture placement and stream startup run
with `bash .github/scripts/tests/multinode-churn-test.sh` and are part of CI.

Two sequenced TCP streams retain their original sockets throughout churn.
Startup polls their counters for up to 30 seconds and fails if a stream exits
before providing ten echoes and ten denied connection attempts.
They require zero successful handshakes to a permanently denied port and no
availability gap above five seconds. Metadata-only updates must preserve both
nodes' policy epochs; real updates must advance each by at least ten, with at
least 30 policy writes per namespace. Finally, deliberate egress revocation
must stop new echoed payloads on those same sockets after convergence, while
the clients continue sending. This covers reply-state invalidation without
silently reconnecting. A changed global epoch can interrupt an otherwise
allowed stream; this test bounds observed interruption, not zero-loss delivery.

Before sustained churn, a separate long-lived server-push connection establishes
a polled baseline of ten pushes, then sends no new client payloads during a
snapshot change. It records whether replies stop and requires recovery on the
original socket within five seconds of one
explicit client payload. Uninterrupted behavior also passes. This exposes the
availability cost of epoch-scoped reply state separately from the active echo
streams, whose initiating packets can recreate that state.

CI uploads `multinode-churn-evidence`: JSONL stream counters and maximum gaps,
transition convergence times, Pod UIDs/IPs/node placement, policy writes,
before/after epochs, and diagnostics even on failure. To reproduce on a
disposable Linux host with Docker, kind, kubectl, jq, curl, and Go:

```sh
export RUNNER_TEMP="$(mktemp -d)"
export KUBECONFIG="$RUNNER_TEMP/kubeconfig"
export GITHUB_ENV="$RUNNER_TEMP/github-env"
ZTAP_KIND_MULTI_NODE=1 bash .github/scripts/create-kind-cluster.sh
make docker
docker pull busybox:1.36.1
kind load docker-image ztap:dev busybox:1.36.1 --name ztap
bash .github/scripts/disable-kindnet-policy.sh
export ZTAP_KINDNET_NETWORKPOLICY_DISABLED=1
bash .github/scripts/install-kind-agent.sh
bash .github/scripts/verify-multinode-churn.sh
kind delete cluster --name ztap
```

Use a dedicated Docker context without an existing `ztap` cluster. For arm64,
build the agent image with `--build-arg TARGETARCH=arm64` and set
`ZTAP_TEST_ARCH=arm64`. `ZTAP_CHURN_SECONDS` and `ZTAP_CHURN_CYCLES` can extend
the run; their minimums remain 120 seconds and six cycles. The stream deadline
is 15 minutes, and evidence defaults to `churn-evidence/` (override with
`ZTAP_CHURN_EVIDENCE_DIR`). The evidence directory must be empty and the three
`ztap-churn-*` fixture namespaces must not already exist.

The fixed-size binary flow-event decoder has a fuzz target that rejects
unknown sizes and schemas before decoding and exercises conversion of valid
72-byte events without unbounded input-derived allocation. Run it locally with
a bounded time budget when changing the event layout:

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./internal/flow -run '^$' -fuzz '^FuzzParseRawEventNeverPanics$' -fuzztime=10s
```

The evidence tooling also fuzzes hosted fixture YAML splitting/strict decoding
and IPv4 `ipBlock` exclusion expansion. Both targets have bounded inputs and checked-in
regression seeds, so the normal suite runs the seeds without starting an
unbounded fuzz job:

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./tools/phase5verify -run '^$' -fuzz '^FuzzHostedFixtureYAMLNeverPanics$' -fuzztime=10s
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./internal/policy -run '^$' -fuzz '^FuzzExpandNativeIPBlockNeverPanics$' -fuzztime=10s
```

Live flows are a Linux runtime check. See
[live flow diagnostics](deployment.md#live-flow-diagnostics) for node and
DaemonSet commands, filters, and the pinned-map path.

On Linux, the flow reader traverses the bpffs root and `ztap` pin directory
through descriptor-relative no-follow handles and loads each stable pin through
the retained handle. Symlink substitutions fail closed; missing pins are
reported by the kernel loader as the actionable runtime error.

Engine startup uses the same descriptor-relative, no-follow traversal for
configured bpffs and cgroup roots before creating the pin directory, validating
and adopting owned objects, or validating a subject cgroup. This keeps a replaced parent path
from redirecting startup or cleanup into another directory.

Durable ABI 3 journals all enforcement map IDs before pin publication and
registers programs before link updates. The active configuration points at one
of two pinned configuration maps; inactive reuse follows packet-reader
quiescence and advances the epoch. Recovery can therefore validate and open the
committed map through its owned pin with the shipped capabilities, without a
global map-ID lookup requiring `SYS_ADMIN`. `Engine.Close()` releases only local
handles. Tests remove their own enforcement explicitly before deleting fixtures.

## Generated code and review

The only generated Go bindings retained by the product are the engine eBPF
bindings under `internal/enforcer`. Review generated diffs together with the
source change. The Makefile prefers an installed `clang-18`, then resolves the
pinned Homebrew LLVM 18 locations on macOS; CI supplies the explicit
`clang-18` binary. Before submitting a change, run:

```sh
make fmt-check
make test
make check-generated
git diff --check
```

The merge workflow also reruns `go mod tidy` and fails if it changes
`go.mod` or `go.sum`.

## Performance evidence

See [performance evidence](performance.md) for historical reference
measurements, the reference environment, compiler benchmark, Linux harness,
hosted preflight, and verification commands. Measurements refer to their
recorded source commit; later dependency updates need their own Linux evidence.

## Adding policy behavior

Start with the native Kubernetes API field and its documented semantics. Add
or update validator tests for both accepted and rejected forms, then add a
kernel-neutral compiler test before changing the eBPF representation. Keep
unsupported behavior as a typed validation error; do not add a permissive
fallback, compatibility flag, or dormant informer. Update `docs/policies.md`
and the relevant deployment guidance when the supported contract
changes.

## Contribution guidance

Keep changes focused on the retained Linux/Kubernetes product. New commands,
configuration layers, platform backends, or auxiliary services require an
explicit product-contract review. Include the exact local commands used for
verification, and identify Linux-only evidence that still needs hosted CI.

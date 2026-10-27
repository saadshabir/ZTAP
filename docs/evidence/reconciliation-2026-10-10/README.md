# Reconciliation and footprint comparison — October 10, 2026

Baseline: `3657d9fa485c0d510734cf0f52d6b85f75cebce2`. Candidate: the working-tree
runtime changes captured in `runtime.patch` and `runtime-added.tar`, with hashes
in `runtime-source.sha256`. The added-source archive matches the checkout.
This is a local comparison, not a new hosted acceptance or historical reference
measurement. [Raw summary](summary.json) retains values, samples and provenance.

Both revisions used Go 1.26.9, arm64 Linux
`7.0.14-orbstack-00380-ga7e0a2dc9535`, `GOMAXPROCS=2`, and CPU affinity `0,1`.
The same benchmark source was copied into the baseline before compiling both
test binaries. Builds and timing runs were sequential; the disposable kind
cluster and other builds/tests had finished before the final samples. Cold
builds used three separate empty Go build caches and `CGO_ENABLED=0`,
`-trimpath`, `-ldflags='-s -w'`, and `GOFLAGS=-buildvcs=false`.

## Build footprint

| Metric | Before | After |
| --- | ---: | ---: |
| Stripped Linux binary | 57,278,626 B (54.63 MiB) | 40,173,730 B (38.31 MiB) |
| Cold build median, three samples | 39.81 s | 24.69 s |
| Binary dependency packages | 776 | 553 |
| Docker image inspect `.Size` | 14,824,750 B | 12,362,414 B |

The binary decreased 29.9%, cold build median 38.0%, and package graph 28.7%.
Docker's reported image size decreased 16.6%; this is the API `.Size` field,
rather than total Docker disk use. Both images were built with the repository
Dockerfile and its Go 1.26.9 builder. Binary hashes and image identities are
retained. The module graph is unchanged: tests still use the broad fake
clientset, and typed Kubernetes clients retain their shared API scheme. The
production clientset and informer factory imports were removed.

## Snapshot overhead

Each row contains before / after medians over five 500-ms benchmark runs.
Each fixture has 250 local Pods, 25 policies and 2,500 compiled rules. The
selector fixture uses namespace selectors, Pod labels and match expressions.
Pods carry unconsumed annotations/environment fields to expose object-copy
cost. The benchmark asserts fixture size and zero rejected policies.

| Scenario | Time per snapshot/compile | Allocated bytes/op | Allocations/op |
| --- | ---: | ---: | ---: |
| unchanged | 1.915 / 1.624 ms | 1,874,406 / 1,203,984 B | 10,913 / 7,908 |
| policy-change | 1.761 / 1.684 ms | 1,876,457 / 1,205,386 B | 10,935 / 7,930 |
| pod-churn | 1.703 / 1.539 ms | 1,878,764 / 1,206,875 B | 10,930 / 7,925 |
| selectors | 3.605 / 3.473 ms | 2,697,927 / 2,028,760 B | 27,889 / 24,885 |

Unchanged snapshots used 35.8% fewer bytes and 27.5% fewer allocations, with
15.2% lower median time. These are cached snapshot resolution and compilation
measurements with a no-op engine, including filesystem identity checks. They
exclude kernel writes, API delivery and debounce. The compiler itself was not
changed. Identity lookup now uses a snapshot-owned map; filesystem identity
validation remains in place, and conflicts reject publication.

## Real engine and helper measurements

| Three-sample metric | Before | After |
| --- | ---: | ---: |
| Reconciliation p95 | 89.714 ms | 87.579 ms |
| Event-to-active-epoch p95 | 104.506 ms | 105.762 ms |
| Maximum quiet helper RSS | 55.508 MiB | 52.805 MiB |
| Maximum quiet helper CPU | 0.000998 cores | 0.000997 cores |

These use the existing real-engine harness with a fake Kubernetes client and
exact containerd cgroups. Each reported p95 is the maximum of only three
samples. No material kernel/event latency improvement is established: event
p95 increased slightly, and reconciliation p95 changed little. Helper RSS
excludes kernel-map memory and is distinct from deployed-agent cgroup memory.
This run does not replace the full hosted packet/flow/resource evidence.

## Validation and CI changes

- Race-enabled portable and clean-checkout Linux suites passed, including the
  stale identity, recovery, relist, local-node filter and shutdown tests.
- Privileged Linux enforcer and CLI integration passed. The retained logs
  include restart continuity, transactions/rollback, inherited guards and
  cleanup. Performance-only tests/helpers are separately gated as usual.
- Kubernetes 1.36.4/containerd 2.3.4 smoke, admission, existing continuity,
  new-workload guard, live flow and explicit-uninstall gates passed. Existing
  continuity observed zero prohibited packets and more than 5,400 allowed
  responses per direction. New workloads were protected during pause, TERM,
  KILL and API loss. The disposable cluster was deleted afterward.
- Generated bindings, pinned-toolchain lint, workflow lint, shellcheck of all
  scripts, module tidy and `git diff --check` passed. Historical October 9
  restart evidence still validates.
- The verifier split preserved every declaration token, excluding comments
  and whitespace; its existing test/validation contract remains unchanged.

The workflow is 803 lines, down from 1,794. Six setup/acceptance blocks now
live in `.github/scripts`, and CI shellchecks those scripts directly. The
extra Docker build, manifest test, regeneration and default security scan
were removed where another required gate already covered them. The verifier's
3,380-line main file is now 305 lines, with schema, strict JSON, environment,
hosted fixture/resource/transcript and measurement validation in separate files.
Hosted CI duration was not measured; this record claims removed duplication.

## Deferred engine work

No compiler, encoding, map-write or generated-binding optimization was made.
A disposable-map probe on this kernel accepted hash and LPM-trie batch writes.
It also returned one completed entry and an error when a hash batch exceeded
capacity; the first entry remained present. [Probe output](batch-support.txt)
records this partial-write behavior. Batching needs per-map/kernel support
handling, conservative slot accounting and full rollback testing before a
runtime implementation. Profile changed-policy applies before deciding whether
encoding reuse or batching merits that change.

## Reproduce and retain

Apply the captured runtime patch/added-source archive to the baseline commit
for the candidate; use the same benchmark file for both revisions. On an idle,
privileged Linux host, `tools/measure-reconciliation.sh` records fresh build,
benchmark, reconciliation, event and helper-resource output into a new directory.
See [measurement instructions](../../performance.md#reconciliation-and-build-comparison).

Raw JSON, benchmark/build samples, package/module graphs, image metadata and
validation/outage transcripts are retained here. Executables and Docker build
logs remain in `.cache/optimization`; executable hashes are in `summary.json`.
`make clean` preserves this evidence and `dist`; build-cache, tool and disposable
output cleanup have separate targets. The tracked `dist/go.mod` module boundary
excludes archived source snapshots from Go package checks. Makefile source
discovery prunes caches and artifact directories before scanning for Go files.
Git permits retained `.log` transcripts under `docs/evidence/`. The task-only
Linux build cache and disposable measurement container were cleaned up afterward.
Earlier concurrent/reused-output trials are excluded from this comparison. A
retained trial correctly caused the
exclusive evidence writer to reject overwriting; the final run used fresh
`measurements-before` and `measurements-after` directories and passed.

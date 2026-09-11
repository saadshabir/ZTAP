# Phase 0 Baseline and Gate Status

- **Captured:** 2026-09-10
- **Updated:** 2026-09-11
- **Branch at capture:** `main`
- **Baseline commit:** `fc4695d` (`Merge pull request #172 from saadshabir/dependabot/pip/internal/anomaly/python-minor-patch-974410666c`)
- **Gate:** **Open** — Linux/Kubernetes feasibility and CI handoff evidence are still required.

This report distinguishes the clean commit baseline, the already-dirty working
tree at capture, and the local Phase 0 safety work completed afterward. None of
the local results prove that the streamlined Linux enforcer is feasible.

## Baseline identity and working-tree boundary

Commit `fc4695d` has 19 product command areas, plus Cobra's built-in `help` and
`completion` commands:

```text
agent alert api audit aws azure cluster compliance discovery enforce flows
gcp grpc logs metrics policy status user version
```

The working tree was not clean when Phase 0 was captured. It already contained
the uncommitted additive Phase 1 input-contract slice, whose built CLI adds a
twentieth product command, `validate`. Phase 0 does not claim that work as part
of the clean commit baseline.

The Phase 0 review then moved the unchanged working tree to
`codex/streamline-ztap`, added the local safety-net files, removed build debris,
and fixed a flaky dispatcher test. The safety work is committed locally as
`7703a99` (`chore: establish Phase 0 migration gate`).

## Host and runtime observations

- Host: macOS 27.0, Darwin arm64.
- Go: `go1.27.1 darwin/arm64`; `go.mod` declares Go 1.26.6.
- `clang` is available at `/usr/bin/clang`.
- Docker, `kubectl`, kind, minikube, bpftool, and a Linux runtime are not
  available in this checkout environment.
- `/sys/fs/bpf`, `/sys/fs/cgroup`, `/proc/self/cgroup`, and `/dev/bpf` are
  absent.

Therefore these Phase 0 claims remain unverified:

- cgroup v2 and containerd/systemd cgroup layout;
- the cgroup identity returned by `bpf_get_current_cgroup_id()`;
- cgroup ingress/egress packet-data offsets;
- pre- and post-NAT addresses and ports for PodIP and ClusterIP traffic;
- bpffs pin access, program attachment, CNI coexistence, and required
  capabilities under the exact target DaemonSet security context;
- Pod-start-to-classification, restart, and rolling-update enforcement gaps.

## Local safety work completed

- Added a root `Makefile` with pinned `golangci-lint` v2.12.2 and actionlint
  v1.7.12, repository-local caches/tools, race-enabled tests, workflow
  validation, and explicit-path cleanup.
- Added a non-publishing `Migration CI` workflow with a stable `Required CI`
  check. It is pushed and green for the branch event; `Required CI` is now a
  required branch-protection check on `main`.
- Removed approximately 972 MiB of repository-local binaries, test outputs,
  coverage data, Go build data, and lint/Python caches. This includes the
  tracked root `bpfgen` executable; `tools/bpfgen` source is retained, and
  `/bpfgen` is now ignored.
- Kept the generated eBPF bindings and reverified their checksums:

```text
internal/enforcer/bpf_bpfel.go  3dbb83fe9a269e86b0a2981aac86b7369038bd1e05b48243d50f11a44852cccd
internal/enforcer/bpf_bpfeb.go  72b38156fbb6a43cc69e4b752e502a6c2b0e88ba9e8eb2cd6955cbd4bfbb5dca
```

- Made `TestDispatcherEmitDropsWhenFull` deterministic by filling the queue
  before starting any worker. The prior test raced its worker against its
  second enqueue and could intermittently observe no drop.
- Added focused Linux-tagged characterization tests for cgroup-v2/bpffs
  preflight, ingress allow/deny traffic, and flow-map pin/open/cleanup, plus a
  disposable capability-only Kubernetes probe and PR-triggered workflow in
  commits `42b7203` and `9056016`.

No product feature, architecture, old workflow, release workflow, or target
DaemonSet was deleted in this local slice.

## Test evidence

The initial managed-sandbox run mixed one real test race with environmental
failures: loopback IPv4/IPv6 listeners were denied, and a test could not write
the default audit path outside the workspace. After fixing the dispatcher test,
the following checks passed on 2026-09-11 with host permissions where local
sockets required them:

- `TestDispatcherEmitDropsWhenFull`, 1,000 consecutive runs;
- `make build`;
- `make fmt-check`;
- `make test` (`go test -race ./...`);
- `make vet`;
- `make lint` with the pinned linters;
- `make check`, which runs the complete non-privileged local gate above.

The pushed `Migration CI` run `34564093570` passed on commit `b7f8b5a`; both
its build/test/vet/lint job and its `Required CI` job were successful. The
repository now reports `main` as protected with strict `Required CI` status
checks. The separately dispatched legacy run `34564466189` passed its generic
Linux integration job, but failed unrelated Proto/Windows jobs and therefore
skipped its old eBPF verification job; it is not feasibility evidence.

The first PR-triggered `Phase 0 Feasibility` run `34565906626` failed before
the substantive assertions. The Kubernetes job requested
`kindest/node:v1.36.0`, which is not a published image tag. The Linux job's
generated-binding check also detected byte drift because the workflow used the
runner's unpinned clang. Neither failure reached a kernel, packet, cgroup, NAT,
or security-context assertion, so neither is an architecture contradiction.
The workflow now pins clang 18 and the available Kubernetes 1.36.4 node image;
the retry result is the evidence needed for the gate.

This separates locally reproducible source failures from sandbox capability
failures. The pushed `Migration CI` result covers the non-privileged gate; it
does not replace the dedicated Linux eBPF and Kubernetes fixture.

## Retained Linux eBPF assertion checklist

The checked items below mean an executable assertion already exists in the
Linux integration test suite; they were not run on this macOS host:

- [x] Load the eBPF objects, populate a policy map, and attach to a cgroup.
- [x] Populate a cgroup-scoped key and the enforced-cgroups map.
- [x] Keep policy keys isolated between two cgroups.
- [x] Allow a matching selected-cgroup flow, deny its rule miss, and allow the
  same miss from an unselected cgroup, as observed through flow events.
- [x] Allow an in-range egress CIDR and deny an out-of-range destination.
- [x] Reload onto a new enforcer, remove the old rule, and transfer link
  ownership.
- [x] Fail a selected Linux integration run when cgroup v2, bpffs, or basic BPF
  map creation is unavailable.
- [x] Exercise selected-cgroup ingress allow/deny with real UDP traffic.
- [x] Open a pinned flow map and verify the pin is removed on shutdown.
- [ ] Exercise ingress and egress allow/deny through the replacement contract.
- [ ] Prove packet offsets independently at ingress and egress.
- [ ] Record direct PodIP and explicit ClusterIP pre/post-NAT addresses and
  ports.
- [ ] Characterize reply, node, self, and rejected-IPv6 traffic.
- [ ] Verify flow-map pinning, decoding, and stable lifetime.
- [ ] Verify shutdown link and pin cleanup.
- [ ] Verify partial-update atomicity and per-subject quarantine behavior.
- [ ] Prove cgroup identity under containerd with the systemd cgroup driver.
- [ ] Measure Pod-start classification, restart, and rolling-update gaps.

The existing manifest still uses `hostNetwork`, `privileged: true`,
`allowPrivilegeEscalation: true`, `ztap:latest`, and an exec-based `status`
probe. It is characterization input, not the target deployment contract.

## CI and branch state

- The current local branch is `codex/streamline-ztap`; `origin` contains it
  through `9056016`, with the uncommitted Phase 1 implementation intentionally
  outside the branch commits.
- `Migration CI` is green for the pushed branch event and `Required CI` is
  required on `main`; PR #177's default-branch pull-request event is still
  running.
- PR #177 is the review vehicle. Its first `Phase 0 Feasibility` run failed
  only on the invalid image tag and unpinned generated-bytecode toolchain;
  the pinned retry is pending.
- Existing CI and release workflows are intentionally retained until the
  required-check handoff can be performed in order. The migration workflow
  itself has no publishing permissions or steps.

## Gate decision and next evidence

Phase 0 is **not closed**. Safe artifact/tooling cleanup is locally complete,
but broad feature or architecture deletion and target DaemonSet changes remain
blocked.

The next required technical run is the pinned retry of the disposable
Linux/Kubernetes fixture with cgroup v2, containerd using the systemd cgroup
driver, bpffs access, the exact proposed capability-only security context, and
the tested Kubernetes 1.36.x line. It must capture packet offsets, NAT
visibility, cgroup identity, CNI behavior, Pod-start classification delay,
restart recovery, and rolling-update recovery. Separately, the migration
workflow must be proven green on its branch and default-branch pull-request
event, made required, and only then used to hand off and remove the old
publishing/specialized workflows.

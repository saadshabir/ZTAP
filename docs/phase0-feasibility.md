# Phase 0 Baseline and Gate Status

- **Captured:** 2026-09-10
- **Updated:** 2026-09-11
- **Branch at capture:** `main`
- **Baseline commit:** `fc4695d` (`Merge pull request #172 from saadshabir/dependabot/pip/internal/anomaly/python-minor-patch-974410666c`)
- **Gate:** **Open** — the scoped hosted characterization passed, but the full
  Phase 0 traffic and lifecycle contract is not yet exercised.

This report distinguishes the clean commit baseline, the already-dirty working
tree at capture, the local Phase 0 safety work completed afterward, and the
hosted characterization results. Local results alone do not prove that the
streamlined Linux enforcer is feasible.

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

The macOS checkout cannot run those kernel-dependent checks. The hosted run
below verifies cgroup-v2/bpffs availability, the reference containerd/systemd
runtime layout, capabilities, and a meaningful packet-policy subset. These
Phase 0 claims remain unverified:

- equivalence between filesystem cgroup identity and the production
  containerd cgroup path under the target DaemonSet; the hosted eBPF traffic
  test uses disposable host cgroups, while the Kubernetes job verifies the
  runtime layout and security context separately;
- pre- and post-NAT addresses and ports for PodIP and ClusterIP traffic;
- reply, node, self, rejected-IPv6, CNI coexistence, and unsupported-traffic
  behavior;
- the full target DaemonSet lifecycle and security context, including
  Pod-start-to-classification, restart, and rolling-update enforcement gaps;
- partial-update atomicity, quarantine behavior, and stable flow lifetime.

## Local safety work completed

- Added a root `Makefile` with pinned `golangci-lint` v2.12.2 and actionlint
  v1.7.12, repository-local caches/tools, race-enabled tests, workflow
  validation, and explicit-path cleanup.
- Added a non-publishing `Migration CI` workflow with a stable `Required CI`
  check. Its final push and pull-request runs are green; `Required CI` is a
  strict required branch-protection check on `main`.
- Removed approximately 972 MiB of repository-local binaries, test outputs,
  coverage data, Go build data, and lint/Python caches. This includes the
  tracked root `bpfgen` executable; `tools/bpfgen` source is retained, and
  `/bpfgen` is now ignored.
- Kept the generated eBPF bindings and reverified their pinned clang-18
  outputs at the final head:

```text
internal/enforcer/bpf_bpfel.go  05e332d52427943a3567454ada6ca3b2cc019a5f656bda99d8ced40e22253cfb
internal/enforcer/bpf_bpfeb.go  fdbcbc42619e9c49f554b32a4e931b004e75b0e51eb8a8fd770854319c25c670
```

- Made `TestDispatcherEmitDropsWhenFull` deterministic by filling the queue
  before starting any worker. The prior test raced its worker against its
  second enqueue and could intermittently observe no drop.
- Added focused Linux-tagged characterization tests for cgroup-v2/bpffs
  preflight, ingress/egress allow/deny traffic, LPM matching, cgroup
  isolation, graceful reload, and flow-map pin/open/cleanup, plus a disposable
  capability-only Kubernetes probe and PR-triggered workflow. The parser,
  address-normalization, and ingress cgroup-identity corrections are recorded
  in commits through `d25c70e`.

The transitional release workflow is deleted. Product features, the old
specialized CI jobs, and the target DaemonSet were not deleted while the
remaining Phase 0 contract evidence is open.

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

`Migration CI` runs `34634540864` (push) and `34634544640` (pull request) passed
on `d25c70e`; their build/test/vet/lint and stable `Required CI` checks were
successful. `main` is protected with strict `Required CI` status checks, and
the release workflow has now been removed so transitional commits cannot push
product images or releases.

The failure progression was useful characterization rather than evidence of
an architectural contradiction: `34565906626` found an unavailable Kind image
and unpinned clang; `34566705931` found duplicate map assignment and the old
Ethernet-header assumption; `34631955836` found ingress identity was using the
current task rather than the attached cgroup; and `34633722039` found that a
graceful reload needed cgroup-storage map reuse. The fixes are in
`b4c704a`, `4329ef5`, `834d4c2`, `68c3437`, and `d25c70e`.

The authoritative hosted run is `34634544635`. Its Linux job passed the
clang-18 generated-binding drift check, cgroup-v2/bpffs preflight, object load
and attach, cgroup isolation, selected-only semantics, egress CIDR matching,
real UDP ingress allow/deny, graceful reload, and flow-map pin cleanup. It ran
on kernel `6.17.0-1022-azure` with cgroup v2 and the required controllers.

Its Kubernetes job passed with server `v1.36.4`, containerd `2.3.4`,
`SystemdCgroup = true`, the same kernel family, host-mounted cgroup2 and bpffs,
and the non-privileged RuntimeDefault probe carrying exactly `BPF`,
`NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`. This proves the current fixture's
runtime and capability assumptions, not the full target DaemonSet contract.

The final run therefore confirms that the retained cgroup eBPF path is
feasible for the tested packet layout, policy-map behavior, ingress identity,
reload, and Kubernetes runtime assumptions. It does not replace the open
traffic/lifecycle fixture listed below.

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
- [x] Exercise the cgroup-skb parser at the network-layer offset with real
  ingress and egress traffic.
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

The hosted Kubernetes probe also verifies the current reference fixture's
non-privileged capability set, host cgroup2/bpffs mounts, and systemd cgroup
driver. It does not run the eBPF traffic suite inside the target DaemonSet or
observe Service/CNI/lifecycle traffic.

The existing manifest still uses `hostNetwork`, `privileged: true`,
`allowPrivilegeEscalation: true`, `ztap:latest`, and an exec-based `status`
probe. It is characterization input, not the target deployment contract.

## CI and branch state

- The current local branch is `codex/streamline-ztap`; `origin` contains it
  through `d25c70e`, with the uncommitted Phase 1 implementation intentionally
  outside the branch commits.
- `Migration CI` is green for both the final push and pull-request events, and
  `Required CI` is strict and required on `main`.
- PR #177 is the review vehicle. Its final Phase 0 run is `34634544635`; the
  Linux and Kubernetes jobs both passed as recorded above.
- The release workflow is removed. The migration workflow itself has no
  publishing permissions or steps; specialized legacy jobs remain pending the
  still-open feature/contract gate.

## Gate decision and next evidence

Phase 0 safety work and the current Linux/Kubernetes characterization runner
pass. The architecture gate remains **open** because the run did not exercise
the full contract: independent packet-offset capture, PodIP/ClusterIP
pre/post-NAT visibility, reply/node/self/rejected-IPv6 cases, CNI behavior,
stable flow lifetime, partial-update/quarantine behavior, Pod-start delay, or
restart/rollout recovery. None of the assumptions that were actually tested
contradicts the planned Linux/Kubernetes cgroup-enforcer architecture.

Do not begin broad product deletion or claim Phase 1 readiness until those
remaining contract items have executable evidence or the plan is explicitly
revised to narrow the gate.

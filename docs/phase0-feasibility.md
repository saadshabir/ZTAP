# Phase 0 Baseline and Gate Status

- **Captured:** 2026-09-10
- **Updated:** 2026-09-11
- **Branch at capture:** `main`
- **Baseline commit:** `fc4695d` (`Merge pull request #172 from saadshabir/dependabot/pip/internal/anomaly/python-minor-patch-974410666c`)
- **Latest hosted run:** [`34653218849`](https://github.com/saadshabir/ZTAP/actions/runs/34653218849),
  run from `3f4ff4c`
- **Gate:** **Open** — the complete Phase 0 evidence run passed and its raw
  artifacts were reviewed, but self-to-own-PodIP reply traffic is blocked by
  ZTAP, which contradicts the stated `v0.1.0` self-traffic contract.

A follow-up review retains that contract and adds an explicit `(cgroup, PodIP)`
self-bypass plus hard hosted assertions. It also adds executable quarantine,
failed-candidate, and multi-subject ingress-identity checks. Those changes are
not accepted as Phase 0 evidence until a new hosted run passes and its raw
artifacts are reviewed.

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

The macOS checkout cannot run those kernel-dependent checks. The hosted runs
verify cgroup-v2/bpffs availability, the reference containerd/systemd runtime
layout, the Phase 0 DaemonSet security context, the kindnet CNI profile, and
the packet/lifecycle behavior listed below. The remaining Phase 0 contract
item is partial-update atomicity and quarantine; the self-traffic result is
characterized but non-conforming rather than untested.

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
internal/enforcer/bpf_bpfel.go  f24a2a5e8db62d607af2e6bf137b0bb3c25e683458a1be92ff8bbe8bb2bae846
internal/enforcer/bpf_bpfeb.go  40023e6a99d897d0fe67cb83d028caedd2898199775f54fb8b3b428e6fe6998a
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
- Added the Linux fixture for consecutive flow-tuple decoding and explicit
  selected-cgroup IPv6 rejection. Added the deterministic
  `v0.1.0` reference-fixture generator and extended the kind workflow with a
  disposable PodIP/ClusterIP, node, self, reply, rejected-IPv6, CNI, and
  lifecycle probe. It records the client cgroup observation and policy-ready
  timestamps, separate workload/agent/rollout timings, the cgroup-visible
  tuple, and node traffic for Service DNAT comparison. Hosted run
  `34653218849` produced and reviewed the raw evidence. The evidence criterion
  is now complete, while the architecture gate remains open because the
  self-reply result is a documented contract failure.

The transitional release workflow and the old feature-only CI jobs are deleted
from the Phase 0 working tree. Product features and the target DaemonSet remain
in place while the remaining Phase 0 contract evidence is open.

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
- `make phase0-fixture` generated the 250-Pod/25-policy/2,500-rule fixture,
  and `make clean` removed its generated output successfully.

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

The earlier authoritative hosted run was `34634544635`. Its Linux job passed the
clang-18 generated-binding drift check, cgroup-v2/bpffs preflight, object load
and attach, cgroup isolation, selected-only semantics, egress CIDR matching,
real UDP ingress allow/deny, graceful reload, and flow-map pin cleanup. It ran
on kernel `6.17.0-1022-azure` with cgroup v2 and the required controllers.

Its Kubernetes job passed with server `v1.36.4`, containerd `2.3.4`,
`SystemdCgroup = true`, the same kernel family, host-mounted cgroup2 and bpffs,
and the non-privileged RuntimeDefault probe carrying exactly `BPF`,
`NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`. This proved the current fixture's
runtime and capability assumptions, not the full traffic/lifecycle contract.

The complete hosted Phase 0 run is `34653218849` from `3f4ff4c`. Its three jobs
passed. The raw artifacts were `phase0-v0.1.0-reference-fixture`
(`10285240637`), `phase0-linux-evidence` (`10284297558`), and
`phase0-kubernetes-evidence` (`10284577573`). The Kubernetes artifact contains
`phase0-flow.jsonl`, `phase0-service-flow.jsonl`, `phase0-nat.txt`, and
`phase0-lifecycle.txt`.

The raw results are:

- The fixture is `v0.1.0` with 250 Pods, 25 NetworkPolicies, 100 rules per
  policy, and 2,500 expected compiled local rules. The generated manifest
  digests are recorded in the artifact's `manifest.sha256`.
- The kind node is Kubernetes `v1.36.4` on containerd `2.3.4`, kernel
  `6.17.0-1022-azure`, with `SystemdCgroup = true`, cgroup2, bpffs, kindnet,
  and no pre-existing NetworkPolicy objects.
- Direct PodIP traffic is visible as `10.244.0.7:30080 -> 10.244.0.6:8080`
  with the reverse `8080 -> 30080` reply. ClusterIP traffic is visible at the
  cgroup hook before NAT as `10.96.237.253:18080`; the node capture shows the
  backend `10.244.0.6:8080`, and the reverse cgroup event is
  `10.96.237.253:18080 -> 10.244.0.7:30081`. Node traffic is visible as
  `10.244.0.7:30082 -> 172.18.0.2:18082` with the reverse reply.
- Self request egress is allowed and the local listener receives the request,
  but the reply `10.244.0.7:18081 -> 10.244.0.7:30083` is blocked. The
  artifact records `phase0_self_behavior=reply_blocked_by_ztap` and the
  bounded probe fails. This is the observed non-conformance with Section 5.4,
  not a fixture or collection failure.
- IPv6 loopback traffic is captured as blocked egress to `::1:18081`.
- Initial Pod-start timing is 3 seconds to cgroup observation and 4 seconds
  to policy classification. The measured workload restart-to-classification,
  agent-restart-to-classification, and DaemonSet-rollout-to-classification
  intervals are 33, 1, and 2 seconds respectively.

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
- [x] Decode consecutive IPv4 flow tuples from one pinned reader and keep the
  pin present until enforcer shutdown.
- [x] Emit and block a selected-cgroup IPv6 packet when only IPv4 policy is
  configured.
- [x] Exercise ingress and egress allow/deny through the replacement contract.
- [x] Prove packet offsets at ingress and egress with the Linux cgroup-skb
  integration fixture.
- [x] Record direct PodIP and explicit ClusterIP pre/post-NAT addresses and
  ports.
- [x] Characterize reply, node, self, and rejected-IPv6 traffic. Self reply
  behavior is recorded as a failure of the intended contract.
- [x] Verify flow-map pinning, decoding, and stable lifetime.
- [x] Verify shutdown link and pin cleanup.
- [ ] Verify partial-update atomicity and per-subject quarantine behavior.
- [ ] Verify distinct ingress identity when two subject cgroups share one
  program/map collection and have separate link pairs.
- [ ] Verify mapped Pod self traffic is allowed at all four egress/ingress
  request/reply hook events.
- [x] Prove cgroup identity under containerd with the systemd cgroup driver.
- [x] Measure Pod-start classification, restart, and rolling-update gaps.

The latest hosted Kubernetes probe verifies the reference fixture's
non-privileged capability set, host cgroup2/bpffs mounts, systemd cgroup
driver, kindnet CNI configuration, Service DNAT, traffic classes, and
workload/agent/rollout timing. The follow-up hosted run must add
partial-update, per-subject quarantine, multi-attachment ingress identity, and
conforming mapped-self evidence.

The existing manifest still uses `hostNetwork`, `privileged: true`,
`allowPrivilegeEscalation: true`, `ztap:latest`, and an exec-based `status`
probe. It is characterization input, not the target deployment contract.

## CI and branch state

- The current local branch is `codex/streamline-ztap`; the latest hosted run
  used commit `3f4ff4c`, with the uncommitted Phase 1 implementation
  intentionally outside the branch commits.
- `Migration CI` is green for both the final push and pull-request events, and
  `Required CI` is strict and required on `main`.
- PR #177 is the review vehicle. Its final Phase 0 run is `34634544635`; the
  Linux and Kubernetes jobs both passed as recorded above.
- The release workflow and the feature-only legacy CI jobs are removed. The
  migration workflow itself has no publishing permissions or steps; the
  architecture gate still depends on hosted traffic/lifecycle evidence.

## Gate decision and next evidence

Phase 0 safety work and hosted run `34653218849` remain valid evidence for the
packet-offset, NAT/CNI, traffic-class, runtime, capability, and lifecycle
claims recorded above. The follow-up code review found two blockers that the
old run cannot close: its self result violates the retained contract, and its
single direct cgroup attachment does not prove the root-only attachment model
previously described in the plan. Kernel cgroup storage is bound to the
attachment cgroup, so the plan now requires per-subject link pairs.

The revised runner makes mapped self traffic a hard failure and the Linux
suite now exercises per-direction quarantine, a partially populated failed
candidate that must leave active rules unchanged, and two subject cgroups
sharing a program/map collection with distinct ingress identity. The
architecture gate remains **open** until those tests pass on the hosted Linux
runner and the new raw artifacts are reviewed. Do not begin broad product
deletion or resume Phase 1 before that result is recorded here.

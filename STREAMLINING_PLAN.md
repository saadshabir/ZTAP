# ZTAP Streamlining Plan

- **Status:** Draft — blocked on Phase 0 feasibility and the correctness gates in this plan
- **Prepared:** 2026-09-10
- **Last reviewed:** 2026-09-10
- **Change type:** Intentional clean break
- **Target:** Linux/Kubernetes eBPF network-policy enforcer

## 1. Executive summary

ZTAP currently contains several largely independent products in one repository:

- A network-policy parser and validator.
- Linux eBPF, Linux iptables, macOS pf, and Windows WFP enforcement.
- A Kubernetes operator, custom CRD, node agent, and ConfigMap policy relay.
- In-memory and etcd-based coordination.
- REST and gRPC control planes with authentication, authorization, and backups.
- AWS, Azure, and GCP firewall synchronization.
- Audit, compliance, alerting, metrics, dashboards, and anomaly detection.

These areas are individually substantial. Together they create 19 top-level CLI command areas, 15 configuration sections, a large dependency graph, several deployment models, and more documentation than a maintainer can easily keep synchronized. The main problem is therefore product scope, not naming or formatting.

The streamlined project will do one job:

> Watch native Kubernetes `NetworkPolicy` resources on Linux nodes, compile a clearly documented subset into per-container eBPF rules, and expose enough health, metrics, logs, and flow data to operate and verify the enforcer.

The cleanup will remove entire unused or secondary vertical slices instead of moving them into new directories. The result should have one binary, one enforcement backend, one policy API, one deployment manifest, one runtime model, and four primary CLI commands.

## 2. Goals

### 2.1 Product goals

- Make the purpose of ZTAP understandable from the first screen of the README.
- Make the Kubernetes node agent the only policy-enforcement path.
- Use the standard `networking.k8s.io/v1` `NetworkPolicy` API.
- Keep Linux eBPF enforcement as the project's technical focus.
- Apply policies to the containers selected by each policy, not globally to a host.
- Reject unsupported policy behavior explicitly instead of approximating it.
- Preserve last-known-good rules for already classified cgroups when a new desired state cannot be applied, while failing closed for newly classified subjects affected by unsupported policies.
- Measure and document the interval between a container becoming runnable and its cgroup becoming classified; do not imply enforcement begins before the agent can observe it.
- Provide real, minimal operational signals: structured logs, liveness, readiness, metrics, and live flow events.

### 2.2 Engineering goals

- Delete feature packages that are not part of the selected product.
- Remove global mutable enforcement state.
- Replace incremental, cross-package policy mutation with full desired-state reconciliation.
- Keep policy parsing, Kubernetes resolution, compilation, and kernel application as separate responsibilities.
- Reduce direct dependencies to the packages required by the focused product.
- Keep generated eBPF bindings clearly separated from handwritten code.
- Make the common development workflow discoverable through a small Makefile.
- Keep tests proportional to the retained behavior instead of preserving tests for removed products.
- Set reproducible latency, reconciliation, CPU, and memory budgets for the retained path; do not call the result efficient without measurements.

### 2.3 Documentation goals

- Replace the current documentation catalogue with a small task-oriented set.
- Eliminate historical implementation plans and project-status pages from the maintained documentation.
- Avoid duplicating CLI help, configuration defaults, API schemas, and deployment instructions across files.
- Describe the project as experimental until the Linux/Kubernetes integration suite proves otherwise.

## 3. Non-goals

This cleanup will not preserve or replace the following capabilities:

- A remotely accessible REST or gRPC control plane.
- ZTAP-specific users, sessions, RBAC, or backup/restore.
- Multi-node policy distribution through etcd.
- Cloud firewall reconciliation for AWS, Azure, or GCP.
- macOS or Windows enforcement.
- Linux iptables fallback.
- Compliance reports, cryptographic audit logs, Slack/PagerDuty alerts, or ML anomaly detection.
- A bundled Prometheus or Grafana installation.
- Named ports, automatic Service/EndpointSlice frontend translation, and IPv6 enforcement in `v0.1.0`; these are post-`v0.1` roadmap items, not dormant compatibility paths.
- Layer-7/FQDN policy, encryption, service-mesh behavior, bandwidth control, or host-firewall policy.
- `AdminNetworkPolicy`, `BaselineAdminNetworkPolicy`, Cilium/Calico policy CRDs, and `hostNetwork` workload isolation.
- Persistent flow history or a general-purpose packet capture facility.
- NodePort, LoadBalancer, externalIP, or ingress-controller policy translation.
- Crash-persistent, reboot-persistent, or zero-gap rolling-update enforcement in the first release. Links are process-owned, so any agent exit, including a planned DaemonSet update, creates a documented and measured fail-open interval until the replacement agent attaches and reconciles.
- Full Kubernetes NetworkPolicy conformance in the first streamlined release.
- Compatibility shims for removed commands, config keys, APIs, or the old `ztap/v1` format.
- Rewriting Git history to remove artifacts that appeared in old commits.

## 4. Target product contract

### 4.1 Supported platform

- Enforcement runs only on Linux.
- The first release supports IPv4-only clusters. If a selected local workload has an IPv6 PodIP, the affected subject is unsupported and quarantined; isolated IPv6 packets are denied rather than bypassing policy.
- The host must use cgroup v2 and provide the eBPF features used by the bundled program.
- The agent must be able to attach cgroup ingress and egress programs and write to bpffs.
- Kubernetes 1.36.x is the first release's tested control-plane line, matching the repository's existing `k8s.io/* v0.36.3` modules. Compatibility with other minors is not claimed until their integration fixtures pass.
- Runtime support is determined through explicit feature probes at startup. Documentation must list the kernel versions used in CI and manual validation, but runtime behavior must not rely only on a version-number check.
- The first streamlined release supports containerd with the systemd cgroup driver. CRI-O, Docker Engine, cgroupfs-driver layouts, and cgroup v1 are out of scope and must fail with a concise unsupported-runtime error rather than falling back to path guessing.
- Linux is the only supported build and runtime target. Non-Linux binaries are neither tested nor published; offline validation on a non-Linux workstation uses the released container image. This avoids preserving platform stubs solely for CLI portability.
- ZTAP does not disable or replace enforcement performed by a CNI plugin. Running it beside another NetworkPolicy implementation produces the intersection of both enforcement decisions and is unsupported for the first release. Operators must use a test cluster without another policy enforcer or explicitly accept that limitation; ZTAP emits a startup warning because it cannot reliably detect every CNI policy engine.

### 4.2 Primary CLI

The root command will expose four primary commands. Cobra's built-in `help` and `completion` commands remain available but are not counted as product commands.

#### `ztap validate`

Purpose: validate one or more native Kubernetes NetworkPolicy documents without applying them.

Interface:

```text
ztap validate --file <path>
ztap validate -f <path>
ztap validate -f -
```

Behavior:

- `--file` is required; `-` reads stdin.
- Multi-document YAML is accepted.
- Every non-empty document must be a `networking.k8s.io/v1` `NetworkPolicy` or `NetworkPolicyList`.
- Kubernetes API shape and the supported ZTAP subset are both validated.
- Errors identify the document, namespace/name, and field path.
- Exit status is `0` when every document is supported and valid, `1` for invalid or unsupported policy content, and `2` for usage, file-read, or YAML-decode failures.
- Valid output is short and human-readable; no logging configuration is required for validation.

#### `ztap agent`

Purpose: watch cluster state and continuously enforce the desired policy state for containers on one node.

Interface:

```text
ztap agent \
  --node-name <kubernetes-node-name> \
  [--kubeconfig <path>] \
  [--cgroup-root /host/sys/fs/cgroup] \
  [--bpffs-root /host/sys/fs/bpf] \
  [--run-dir /run/ztap] \
  [--listen :9090] \
  [--dry-run]
```

Behavior:

- `--node-name` is required. The DaemonSet injects it from `spec.nodeName`.
- An empty `--kubeconfig` uses in-cluster credentials. Local development must pass a path explicitly; there is no implicit `~/.kube/config` fallback.
- The agent watches all namespaces. Namespace filtering modes are intentionally removed.
- `--dry-run` performs discovery, validation, resolution, and compilation but does not load or attach eBPF programs. It never claims enforcement readiness: `/healthz` may be healthy, `/readyz` returns 503 with reason `dry_run`, and `ztap_agent_enforcing` remains `0`.
- Before doing kernel work, the agent acquires an exclusive lock at `<run-dir>/agent.lock`. A second agent on the same node exits with a distinct already-running error.
- On startup, failure to connect to Kubernetes, synchronize informer caches, probe eBPF support, or attach the initial programs is fatal.
- An initially unsupported policy is not a process-fatal infrastructure error: the agent applies supported state, quarantines affected local subjects, exposes readiness 503 when a local quarantine exists, and waits for a relevant object change. A rejected policy with no local subjects is reported but does not block node readiness.
- A later unsupported policy keeps the process alive, quarantines only the local subjects and directions it affects, applies unrelated accepted changes, and marks readiness false. A kernel apply failure preserves last-known-good rules for already classified cgroups and retries with backoff.
- SIGINT and SIGTERM stop informers and HTTP serving, close eBPF links and objects, and exit cleanly.

#### `ztap flows`

Purpose: stream real flow events from the active node agent's pinned eBPF ring buffer.

Interface:

```text
ztap flows [--action allowed|blocked] \
           [--protocol TCP|UDP] \
           [--direction ingress|egress] \
           [--output table|json]
```

Behavior:

- Streaming begins immediately and continues until interrupted.
- The command reads the stable pinned flow map created by the agent.
- There is no `--follow` switch because streaming is the only mode.
- There is no recent-history mode because ZTAP will not bundle a flow store.
- Synthetic/demo events are removed.
- Only one active flow reader per node is supported. The command enforces this with `<run-dir>/flows.lock`; the operating-system lock is released automatically if the reader crashes.
- Missing permissions, missing pinned maps, and an inactive agent produce distinct errors.

#### `ztap version`

Purpose: print version, commit, build date, Go version, OS, and architecture in a stable one-record format.

### 4.3 Global options

The retained global runtime options are:

```text
--log-level debug|info|warn|error
--log-format json|text
```

- Agent defaults are `info` and `json`.
- Human-oriented commands write their primary results directly to stdout/stderr.
- The old YAML configuration file and all `ZTAP_*` feature configuration are removed.
- Deployment defaults are explicit command arguments in the Kubernetes manifest.

## 5. Native NetworkPolicy subset

### 5.1 Accepted resources

- `apiVersion` must equal `networking.k8s.io/v1`.
- `kind` must equal `NetworkPolicy` or `NetworkPolicyList`.
- `metadata.name` is required on every individual NetworkPolicy, including list items; the list object itself does not need a name.
- Cluster resources use their actual namespace. Offline documents without a namespace use `default` for validation messages.
- Multi-document YAML and `NetworkPolicyList` are supported. Lists are expanded and every item follows the same individual validation path.
- Empty documents between YAML separators are ignored. Any non-empty unrelated object is rejected; it is never silently skipped.
- Offline decoding is strict: duplicate mapping keys, unknown fields, malformed selectors/ports, and trailing non-YAML data are errors. Error messages include the source document index without echoing the entire document.

### 5.2 Subject selection

- `spec.podSelector.matchLabels` is supported.
- `spec.podSelector.matchExpressions` is supported using Kubernetes selector semantics.
- An empty subject selector is supported and selects all pods in the policy namespace.
- On each node, only selected pods scheduled to that node are resolved into subject cgroup IDs.
- Init, regular, and ephemeral container cgroups are considered.
- Pods that are selected but do not yet have container IDs are treated as pending, not as a fatal policy error. Their cgroups are added on the next pod event.
- If running pods on the local node are selected but none of their cgroups can be resolved, reconciliation fails rather than silently leaving them unenforced.
- The watcher-based design cannot classify a container before Kubernetes reports its ID and the cgroup exists. Phase 0 measures this Pod-start-to-classification interval, and the deployment documentation presents it as an experimental fail-open limitation rather than claiming admission-time enforcement.
- A selected local pod with any IPv6 PodIP is unsupported in `v0.1.0`. Once its cgroups are resolvable, the affected directions are quarantined instead of leaving IPv6 traffic unclassified.

### 5.3 Directional isolation

- Kubernetes `policyTypes` defaulting is honored:
  - Ingress is selected when `policyTypes` is omitted.
  - Egress is additionally selected when the policy has egress rules.
- A selected pod becomes isolated only in the directions selected by its policies.
- Empty ingress or egress rule lists implement default deny for the corresponding selected direction.
- A pod not selected by any policy for a direction remains allowed in that direction.
- Multiple policies are additive. Existing structural conflict detection is removed because overlapping allow rules are normal Kubernetes behavior.

### 5.4 Supported semantics and explicit exceptions

The supported subset must retain the native semantics around the rules it accepts:

- Ingress and egress isolation are evaluated independently, and policies combine additively.
- Reply traffic for a connection that ZTAP allowed is implicitly allowed in the reverse direction. The eBPF program uses a bounded LRU connection-state map keyed by a monotonic policy epoch, subject cgroup, protocol, direction, and normalized five-tuple. An allowed packet creates the reverse key; matching packets refresh it. Initial fixed idle timeouts are 30 seconds for UDP and 24 hours for TCP, with TCP RST removing state immediately. LRU eviction and the idle limits are documented experimental constraints.
- Every successful policy commit increments a 64-bit policy epoch. Connection state uses that epoch rather than the reusable policy-map slot, so returning to slot `0` or `1` can never reactivate state from an earlier use of that slot. Physical cleanup may remain lazy because stale epochs cannot match the active epoch.
- The first release approximates the native local-node exception with valid IP-valued `InternalIP` and `ExternalIP` entries from the local Node status; hostname entries are not treated as addresses. This is an explicit non-conformance boundary because those addresses cannot prove every possible local-node traffic path. Failure to resolve at least one local Node IP keeps readiness false.
- If the cluster rewrites an external source to the local Node IP before the ingress hook, that traffic receives the required node exception. ZTAP documents the observed behavior and does not pretend it can recover the original source after SNAT.
- A selected pod cannot block traffic to itself. The compiler associates each subject cgroup with its pod IPs and emits the corresponding self-traffic bypass.
- `hostNetwork` pods are outside the supported subject set and are treated as node traffic. They are excluded from cgroup enforcement and reported once in a bounded warning; the documentation must not claim pod-level isolation for them.
- The stateful and node/self bypasses are part of correctness, not optional observability features. They are applied before ordinary allow-rule lookup and covered by Linux integration tests.

### 5.5 Accepted peers

Each non-empty ingress or egress rule must contain at least one explicit peer.

Supported peer forms:

- IPv4 `ipBlock.cidr`, optionally with IPv4 `ipBlock.except`.
- `podSelector` in the policy namespace.
- `namespaceSelector`, selecting all pods in matching namespaces.
- Combined `namespaceSelector` and `podSelector`.
- Empty selector objects in an explicit peer, with their standard Kubernetes scope semantics.

Rules with no `from`/`to` peers mean "all peers" in Kubernetes. They are intentionally unsupported in the first streamlined release and must be rejected rather than converted to a broad CIDR.

For `ipBlock.except`, the compiler expands the allowed range into normalized prefixes. Expansion is capped at 1,024 generated prefixes per source block. Policies exceeding the cap are rejected before kernel state changes.

### 5.6 Accepted ports

Each non-empty rule must contain at least one explicit port.

- TCP and UDP are supported.
- Omitted protocol defaults to TCP, matching Kubernetes behavior.
- Numeric ports are supported.
- Rule matching always uses the packet destination port for both ingress and egress. Source ports participate only in the reply-connection five-tuple.
- Named ports are rejected in `v0.1.0`; their destination-pod resolution semantics are a post-`v0.1` roadmap item.
- SCTP is rejected.
- `endPort` ranges are rejected.
- A port entry without a concrete numeric port is rejected.
- A rule with no `ports` means "all ports" in Kubernetes and is intentionally rejected in the first streamlined release.

### 5.7 Service VIP and NAT behavior

Direct PodIP traffic is the baseline selector behavior. ClusterIP traffic needs explicit handling because a cgroup hook can observe a Service frontend before destination NAT:

- `v0.1.0` does not watch Services or EndpointSlices and does not infer frontend permissions from selector peers.
- A ClusterIP observed before destination NAT must be allowed explicitly with an IPv4 `ipBlock` and numeric Service port. Direct backend PodIP rules continue to come from selector peers.
- Headless Services need no frontend rule because clients use backend PodIPs directly.
- NodePort, LoadBalancer addresses, `externalIPs`, and `ExternalName` are outside the first-release contract and are never inferred or broadened automatically.
- An `ipBlock` rule continues to match the address visible at the hook; it is not expanded through Service endpoints.
- NodeLocal DNS cache addresses are not inferred from cluster configuration. Clusters using NodeLocal DNS must allow its observed address explicitly with `ipBlock`; the deployment guide includes that variant.
- Phase 0 must verify the exact pre/post-NAT address and port seen at both cgroup hooks on the supported cluster so the explicit ClusterIP guidance is accurate. Automatic safe frontend expansion is deferred until a later milestone with Service and EndpointSlice fixtures.

### 5.8 Packet parsing and unsupported traffic

- Phase 0 must establish the actual packet-data offset at cgroup ingress and egress. The implementation must not assume an Ethernet header is present.
- The parser supports IPv4 carrying TCP or UDP, including safe bounds checks before every header access.
- For an isolated direction, malformed or unparseable IP packets, IPv4 fragments, and every IPv6 packet are denied and counted under a bounded reason code. They must never fall through to allow.
- Protocols outside TCP and UDP, including SCTP and ICMP, are outside the first release contract and are denied for isolated directions. Unisolated directions remain allowed.
- The flow event records whether a decision came from an ordinary rule, connection state, node/self bypass, or default deny without embedding policy names in kernel maps.

### 5.9 Rule expansion and limits

- Multiple peers and ports expand to the union of their combinations.
- Resolved IPs and compiled keys are normalized, sorted, and deduplicated for deterministic output and tests.
- IPv4 is supported. IPv6 policy enforcement is deferred until the packet parser, maps, selector expansion, and dual-stack fixtures can be delivered together.
- First-release active-set limits are 16,384 subject cgroups and 16,384 IPv4 rules per node. Physical policy maps hold twice those counts so an active and candidate slot fit together.
- The reply-state LRU holds 65,536 entries and the flow ring buffer is 1 MiB. These limits are source constants, exported in versioned operational documentation, and are not runtime flags in `v0.1.0`.
- Node/self bypasses and quarantine entries count toward the corresponding subject/rule limits.
- The complete candidate policy set is checked against eBPF map capacities before any inactive-slot entries are written.
- Capacity errors include observed and allowed counts without dumping the entire rule set.
- Offline `ztap validate` enforces per-policy expansion caps but cannot predict a node's cluster-wide aggregate; the agent owns aggregate capacity validation.

### 5.10 Unsupported-policy safety

- Validation and compilation produce typed errors with stable field paths.
- Every observed NetworkPolicy is validated on every agent for consistent diagnostics, but an unsupported policy that selects no local subject does not block unrelated node-local reconciliation. Kernel capacity checks remain node-local.
- If an unsupported policy selects a local subject, the compiler places that subject and the policy's affected directions in the candidate quarantine set. Node/self bypasses remain available, but ordinary rules and prior reply state cannot override quarantine. This intentionally fails closed rather than approximating unsupported allow semantics.
- Accepted policies and quarantines are applied as one complete transactional candidate. Unrelated accepted policies continue updating even while a local subject is quarantined.
- Last-known-good state remains the fallback only when the kernel application itself fails. It protects already classified cgroups but cannot protect a new cgroup that the agent has not yet observed; that interval is measured and documented.
- On initial startup, supported subjects may become enforced while unsupported local subjects are quarantined. Readiness remains false until no local subject is quarantined and the latest candidate has applied successfully.
- Unsupported-policy diagnostics are fingerprinted and reevaluated only after a relevant Kubernetes-object change. Transient API, cgroup, or kernel apply failures retry the same desired candidate with exponential backoff starting at 1 second and capped at 1 minute. Both paths coalesce through the one-item dirty queue and never busy-loop.

### 5.11 Standards baseline

The semantic reference for this release is the upstream [Kubernetes 1.36 NetworkPolicy documentation](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) and the [`networking.k8s.io/v1` API reference](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/). Pin `k8s.io/api`, `k8s.io/apimachinery`, and `k8s.io/client-go` together at `v0.36.3` during the cleanup and record that tested line in `docs/policies.md`. A dependency upgrade is a separate reviewed change with the same semantic and integration gates.

ZTAP intentionally rejects some otherwise valid native features in `v0.1.0`, including IPv6 policy data, named ports, SCTP, `endPort`, peerless allow-all rules, and portless allow-all rules. A rejected feature is a documented subset boundary, never an alternate interpretation of the API.

## 6. Target architecture

```text
Kubernetes API
  |-- NetworkPolicy informer
  |-- Pod informer
  |-- Namespace informer
  `-- local Node informer
             |
             v
      Desired-state snapshot
             |
             v
   Validate and resolve selectors
             |
             v
       Compile normalized rules
             |
             v
   Transactional eBPF Engine.Apply
      |                 |
      v                 v
 cgroup policy maps   pinned flow ring
      |                 |
      v                 v
 ingress/egress       ztap flows
 enforcement

Agent process also exposes /healthz, /readyz, and /metrics.
```

### 6.1 Package responsibilities

The retained code should converge on the following boundaries:

```text
cmd/ztap/                 process entry point and build information
internal/cli/             Cobra commands and user-facing I/O
internal/agent/           lifecycle, reconciliation queue, and component ownership
internal/kube/            informers, snapshots, selector resolution, and cgroup lookup
internal/policy/          subset validation and compilation into kernel-neutral rules
internal/enforcer/        Linux eBPF engine, map encoding, attachment, and cleanup
internal/flow/            ring-buffer decoding and CLI filtering/output
internal/observability/   health state and Prometheus registry/server
bpf/                      eBPF C source
tools/bpfgen/             source-only binding generator
```

Dependency direction must remain one-way:

```text
cmd -> cli
cli -> agent
cli -> flow
cli -> policy       (offline validate only)
agent -> kube
agent -> policy
agent -> enforcer
agent -> observability
enforcer -> policy
```

- `policy` may import Kubernetes API and selector types but must not import client-go clients/informers or eBPF libraries.
- `enforcer` must not import Cobra, Kubernetes clients, or Prometheus.
- `kube` may use Kubernetes API types and clients but must return immutable resolution inputs; it must not import the enforcer.
- `agent` is the composition root. Neither `kube`, `policy`, `enforcer`, nor `observability` may call into it.
- Long-running components receive `*slog.Logger` and explicit dependencies; they do not use package-level service singletons.

### 6.2 Desired-state reconciliation

1. Acquire the node-level agent lock.
2. Start NetworkPolicy, Pod, Namespace, and local Node informers.
3. Wait for every informer cache to synchronize.
4. Build an immutable snapshot from cache state.
5. Filter subject pods to `--node-name`; retain cluster-wide pods for selector-peer resolution.
6. Validate every policy for diagnostics and identify policies selecting local subjects.
7. Resolve selectors, IPv4 pod IPs, local Node IPs, and local container cgroups.
8. Compile accepted direction masks, bypasses, and allow rules; place local subjects affected by unsupported policies or IPv6 workload addresses into the quarantine set.
9. Check capacities for two complete policy slots plus quarantine and connection state.
10. In dry-run mode, record compilation status and stop before kernel mutation; health may be true, but readiness remains false with reason `dry_run` and enforcement remains false.
11. Otherwise call `Engine.Apply` with the complete candidate.
12. Only after success, replace the in-memory last-known-good snapshot. Mark readiness true only when the agent is enforcing and no local subject is quarantined.

Events are coalesced through a bounded, single-consumer reconciliation queue with a short fixed debounce. The queue stores only a dirty signal, not every object event, so event storms cannot create unbounded work. Each reconciliation reads a fresh complete snapshot.

Additions, modifications, deletions, pod scheduling, container-status changes, pod-label changes, namespace-label changes, local Node address changes, and informer relists must all converge through the same path.

### 6.3 Kernel-neutral compiled model

The policy compiler should emit a small model equivalent to:

```go
type Direction uint8

const (
    DirectionEgress Direction = 1 << iota
    DirectionIngress
)

type Subject struct {
    CgroupID uint64
    Isolated Direction
    Quarantined Direction
    PodIPs []netip.Addr
}

type Rule struct {
    CgroupID uint64
    Direction Direction
    Peer netip.Prefix
    Protocol uint8
    Port uint16
}

type PolicySet struct {
    NodeIPs []netip.Addr
    Subjects []Subject
    Rules []Rule
}
```

These fields and semantics form the initial internal contract. A deliberate later change is allowed only when the tests and this plan are updated together. Kubernetes resource objects must not pass into the enforcer.

For `v0.1.0`, every address and prefix reaching the enforcer must be IPv4, and `Quarantined` must be a subset of `Isolated`. The compiler enforces both invariants before `Engine.Apply`.

### 6.4 eBPF engine lifecycle

Replace package-level active enforcer variables with one owned engine:

```go
type Engine interface {
    Apply(context.Context, policy.PolicySet) error
    Close() error
}
```

Required behavior:

- The engine loads one program collection, attaches ingress and egress once, and keeps those links for the process lifetime. Ordinary policy changes must not reload programs or update links.
- Attach the programs to the mounted cgroup v2 root so descendants are covered. Use link-based multi-attach when the supported kernel provides it; never replace or detach an unknown pre-existing cgroup program. An incompatible existing attachment is a fatal startup error.
- After the agent lock is acquired, startup removes the exact known ZTAP pin names left by any prior agent instance beneath `<bpffs-root>/ztap`; it never recursively traverses or deletes unrelated bpffs entries. Policy state is rebuilt from Kubernetes, not inherited from stale pins.
- The flow-event and small agent-status maps are pinned at stable paths for `ztap flows` and remain the same maps for the process lifetime. The status record contains schema version, agent epoch, lifecycle state, and a monotonic heartbeat updated once per second.
- Replace the enforced-cgroup set with a subject-state map whose value contains separate ingress/egress `isolated` and `quarantined` masks. For each packet:
  - If the cgroup is absent or not isolated in that direction, allow it.
  - If isolated, allow a matching documented node/self bypass.
  - If the direction is quarantined, deny it before consulting connection state or ordinary allow rules.
  - Otherwise allow a matching reverse-connection entry or compiled rule.
  - Otherwise deny it.
- Remove the legacy global `cgroup_id=0` behavior, `selected_only` switch, permissive demo programs, exact-map compatibility, and standalone/global enforcement paths.
- Use only the bundled LPM-map layout.
- Add a single-entry configuration map containing `active_slot` (`0` or `1`) and a monotonically increasing 64-bit `policy_epoch`.
- Include the reusable slot in every subject, rule, bypass, and quarantine key. Size policy maps to hold the active and complete candidate slots simultaneously; reject candidates that cannot fit beside the current slot.
- Key reverse-connection state by `policy_epoch`, not by slot. Flow events and suppression/accounting state also report the epoch so reusing a slot cannot reactivate stale state or misidentify a policy version.
- Serialize `Apply` calls. Populate `1-active_slot` completely, verify counts, and delete every partially written inactive entry if population fails.
- Commit a candidate with one atomic configuration-map update that changes both `active_slot` and `policy_epoch`. Until that update succeeds, packets continue to use the complete previous slot and epoch.
- After a successful flip, delete the old slot. Cleanup failure does not roll back the now-active policy; it raises a bounded warning/metric and is retried before the next apply.
- The LRU connection map persists across updates. Entries from older epochs may expire or be evicted lazily but can never match the active epoch. Epoch exhaustion is treated as a fatal condition rather than wrapping.
- `Close` is idempotent and removes links and pins owned by the process.
- Links are intentionally process-owned in `v0.1.0`. A crash or graceful restart detaches enforcement and fails open until the replacement agent completes its initial apply. The README and deployment guide must state this prominently; persistent-link adoption is a future hardening project, not hidden scope in this cleanup.

### 6.5 Container cgroup resolution

- Read container IDs from init, regular, and ephemeral container statuses and accept only full `containerd://<64-hex>` identifiers.
- Search only beneath the mounted cgroup v2 `kubepods.slice` hierarchy for the exact `cri-containerd-<id>.scope` basename. Do not search the whole host filesystem, accept shortened IDs, or follow a match outside `--cgroup-root`.
- Derive the numeric cgroup ID using the method proven against `bpf_get_current_cgroup_id()` in Phase 0. Do not assume an inode number is equivalent without that test.
- Cache resolved paths/IDs by container ID and filesystem identity. Invalidate entries when container status changes or the cgroup disappears.
- Include every live container cgroup for a selected pod. Ignore completed containers; treat containers without IDs as pending; reject the candidate when a running selected container has an ID but its supported cgroup cannot be resolved.
- This first release does not open the containerd socket or implement CRI discovery. A changed runtime layout is an explicit unsupported-runtime error.
- Record the time from observing a running selected container to installing its classification. A container can transmit before Kubernetes reports enough state to resolve it; `v0.1.0` documents and measures this watcher gap instead of claiming admission-time enforcement.

## 7. Operational behavior

### 7.1 Health endpoints

The agent serves an unauthenticated operational HTTP listener, defaulting to `:9090`:

- `GET /healthz`
  - Returns 200 while the process event loop is alive.
  - Returns a small JSON object containing status and version.
- `GET /readyz`
  - Returns 200 after informer synchronization and the latest successful apply when no local subject is quarantined.
  - Returns 503 before initial synchronization, while running in dry-run mode, while any local subject is quarantined, or after an apply failure.
  - Includes a bounded reason code, not raw sensitive object contents.
- `GET /metrics`
  - Exposes the process-local Prometheus registry.

### 7.2 Metrics

Retain only bounded, actionable metrics:

- `ztap_agent_ready` gauge.
- `ztap_agent_enforcing` gauge.
- `ztap_network_policies{state="observed|accepted|rejected"}` gauge.
- `ztap_policy_reconciliations_total{result="success|rejected|error"}` counter.
- `ztap_policy_reconcile_duration_seconds` histogram.
- `ztap_compiled_rules` gauge.
- `ztap_enforced_cgroups` gauge.
- `ztap_quarantined_cgroups` gauge.
- `ztap_active_policy_epoch` gauge.
- `ztap_packet_decisions_total{action,direction,reason}` counter backed by persistent per-CPU kernel counters with a closed reason enum.
- `ztap_flow_events_dropped_total{reason="rate_limited|ring_full"}` counter for intentionally suppressed or unbuffered events.
- `ztap_policy_slot_cleanup_failures_total` counter.

Do not use policy names, namespaces, pod names, IPs, or error strings as metric labels. Use a private Prometheus registry so tests and multiple instances do not collide through global registration.

The agent reads aggregate kernel counters for metrics but does not consume the ring buffer. `ztap flows` remains the only event consumer, so metrics collection cannot steal flow events.

### 7.3 Logging

- Use `log/slog` directly.
- Agent logs default to JSON on stderr.
- Every reconciliation has a stable operation ID and reports observed policies, accepted policies, compiled rules, local cgroups, duration, and result.
- Do not log complete policy YAML, credentials, environment contents, or large resolved IP lists.
- Expected unsupported policies log once per resource generation, not once per retry loop.
- CLI validation errors remain concise text rather than JSON log events.

### 7.4 Flow event contract

- The ring buffer is best-effort diagnostics, not an audit log. Exact packet-decision totals come from the counter map.
- Emit allowed and blocked events for cgroups isolated in at least one direction, subject to a fixed per-CPU rate limit of 100 events per second. First-flow suppression and more elaborate sampling are deferred until after `v0.1.0`.
- Count rate-limited and ring-full events separately. Event loss must never change enforcement behavior.
- Use a fixed, versioned binary record containing monotonic timestamp, policy epoch, cgroup ID, direction, action, bounded reason code, IP family, protocol, source/destination addresses, and source/destination ports. Never include payload bytes, policy YAML, pod names, or namespaces in kernel events.
- `ztap flows --output json` exposes stable field names and includes an event-schema version. Table output is human-oriented and not a compatibility contract.
- Policy updates keep the ring and decoder compatible. An incompatible event-schema change requires a binary version change and stale-pin cleanup at agent startup.
- The reader polls the pinned agent-status heartbeat while consuming events. It exits clearly on shutdown, an incompatible schema, a changed agent epoch, or a heartbeat older than 5 seconds; flow continuity across an agent restart is not promised.

## 8. Kubernetes deployment

Maintain one install manifest containing:

- ServiceAccount.
- ClusterRole and ClusterRoleBinding.
- DaemonSet.

The custom CRD, operator Deployment, leader-election RBAC, policy ConfigMaps, standalone Prometheus/Grafana resources, and duplicate install manifests are removed.

### 8.1 RBAC

The agent receives only `get`, `list`, and `watch` for:

- `networking.k8s.io/networkpolicies`.
- Core Pods.
- Core Namespaces.
- Core Nodes.

It does not create, update, patch, or delete Kubernetes resources.

### 8.2 DaemonSet

- Schedule only on `kubernetes.io/os=linux`.
- Inject `NODE_NAME` using the downward API and pass it through `--node-name=$(NODE_NAME)`.
- Mount host `/sys/fs/cgroup` read-only at `/host/sys/fs/cgroup`.
- Mount host `/sys/fs/bpf` read-write at `/host/sys/fs/bpf`.
- Mount a hostPath `DirectoryOrCreate` at `/run/ztap` for node-wide agent and flow-reader locks.
- Do not use `hostNetwork`.
- Do not set `privileged: true`.
- Run as UID 0 with only the verified capabilities required by the supported kernels: `BPF`, `NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`.
- The final manifest sets `allowPrivilegeEscalation: false` and `seccompProfile.type: RuntimeDefault`; Phase 0 must prove that exact profile permits the required calls before implementation proceeds.
- Set `readOnlyRootFilesystem: true`; the three explicit host mounts are the only writable runtime paths.
- Use HTTP liveness and readiness probes against port 9090.
- Add Prometheus scrape annotations instead of bundling Prometheus.
- Specify CPU/memory requests and limits.
- Use an explicit release version or digest, never `:latest`.
- Use a rolling update with `maxUnavailable: 1` and `maxSurge: 0` so two agent Pods are not intentionally started on the same node. The lock remains the final ownership guard.
- Because links are process-owned, that rollout strategy intentionally stops enforcement on the updated node between old-agent exit and successful replacement reconciliation. The deployment guide and release notes must say so, and the release gate measures the interval; readiness is observability, not a workload-scheduling barrier.

If capability-only operation cannot pass the supported-host integration suite, the implementation must stop and document the exact missing permission. It must not silently restore privileged mode.

### 8.3 Container image

- Keep one multi-stage Dockerfile.
- Build a static Linux binary with version metadata.
- Use a minimal scratch runtime containing the binary and CA certificate bundle required for Kubernetes API TLS.
- Run as UID 0 because the container receives narrowly scoped kernel capabilities.
- Remove iptables, shell utilities, Python, operator, and anomaly images.
- Keep the image entrypoint as `/ztap` and default command as `--help`.

## 9. Feature and file removal inventory

Remove features and their code, tests, docs, config, dependencies, deployment assets, and CI jobs as one unit.

| Area | Removal |
|---|---|
| HTTP control plane | `internal/apihttp`, OpenAPI schema, API CLI, health/auth/policy/enforcement endpoints |
| gRPC control plane | `internal/apigrpc`, `proto`, buf configs, generated protobuf code, gRPC CLI |
| Auth and backup | `internal/auth`, `internal/apiutil`, `internal/configbackup`, users/sessions/config restore |
| Distributed cluster | etcd election and sync, in-memory cluster backend, cluster and policy-sync CLI |
| Custom Kubernetes API | `cmd/ztap-operator`, `internal/operator`, CRD, operator Dockerfile and manifests |
| Cloud integrations | `internal/cloud`, `internal/inventory`, AWS/Azure/GCP/status CLI and SDKs |
| Security extras | `internal/audit`, `internal/compliance`, `internal/alert`, their CLI commands and config |
| Anomaly detection | `internal/anomaly`, Python packaging/tests/image, anomaly wiring and config |
| Extra enforcers | iptables fallback, macOS pf, Windows WFP, Windows flow implementation |
| Standalone services | standalone metrics command, discovery registry CLI, logs command, status command |
| Legacy policy API | custom YAML structs/loader, `ztap/v1` examples, conflict/version/rollback behavior |
| Demo paths | synthetic flows, placeholder Consul backend, simulated enforcement, `demo.sh` |
| Legacy support packages | delete `internal/config`, `internal/discovery`, `internal/health`, `internal/logging`, `internal/metrics`, `internal/paths`, and `internal/ratelimit` after the narrow replacements are wired; fold any genuinely reused helper into its single owner |
| Bundled observability | Docker Compose stack, Grafana dashboards/provisioning, Prometheus config |
| Coverage ratchet | `cmd/covergate`, `.covergate-baseline.json`, generated coverage files |
| Obsolete scripts/config | proto/security shell scripts, `buf*.yaml`, `config.yaml.example`, `osv-scanner.toml`, operator Dockerfile, and obsolete Docker Compose/release entries |
| Code examples | etcd election, policy sync, and every old custom-policy example; retain only the three native YAML manifests named in Section 11 |
| Historical docs | modernization plan, project status, old concepts/reference/runbooks and duplicated indexes |
| Stale AI guidance | delete the 249-line `.github/copilot-instructions.md`; maintained architecture and commands belong in `docs/development.md` |
| Example catalogue | delete `examples/README.md`; the root README links directly to the three self-explanatory manifests |

Expected retained internal areas are CLI, Kubernetes integration, policy compiler, eBPF enforcer, Linux flow decoding, and minimal observability. Any helper package left with one trivial consumer should be folded into that consumer rather than preserved for architectural symmetry.

## 10. Repository hygiene and developer workflow

### 10.1 Immediate artifact cleanup

- Delete ignored root binaries such as `ztap`, `ztap.exe`, `*.test`, and `*.test.exe`.
- Delete `coverage*.out` and local test/lint caches.
- Delete repository-local `.pytest_cache`, `.ruff_cache`, Go build outputs, and other ignored caches left by removed toolchains.
- Remove the tracked 2.6 MB root `bpfgen` executable.
- Add `/bpfgen` to `.gitignore` so building `./tools/bpfgen` at the repository root cannot reintroduce it.
- Do not delete generated eBPF Go bindings required for normal builds.
- Do not rewrite Git history as part of this work.

### 10.2 Makefile

Add a small Makefile with these stable targets:

```text
make build             build bin/ztap
make test              run unit tests with race detection
make lint              run configured static analysis and formatting checks
make generate          regenerate eBPF bindings
make check-generated   regenerate and fail on a Git diff
make integration       run privileged Linux eBPF integration tests
make docker            build the single runtime image
make clean             remove repository-local generated outputs only
make check             run the non-privileged merge gate
```

`make clean` must use explicit repository paths and patterns. It must not clear global Go caches or operate outside the repository.

Pin developer/CI tool versions in one small checked-in source (Makefile variables or `tools.go`) and install them beneath `bin/tools`; no target downloads `latest` or mutates global tool installations. Clang/LLVM and the reference Kubernetes node image are pinned explicitly in CI.

### 10.3 Go module and dependencies

- Change the module path from `ztap` to `github.com/saadshabir/ZTAP`.
- Keep one Go version as the source of truth and use it consistently in `go.mod`, CI, Docker, and documentation.
- Run `go mod tidy` only after removed packages are gone.
- Expected direct dependency families after cleanup:
  - `github.com/cilium/ebpf`.
  - `github.com/prometheus/client_golang`.
  - `github.com/spf13/cobra`.
  - Kubernetes API, apimachinery, and client-go.
  - A YAML decoder only if not already supplied by retained Kubernetes dependencies.
  - Small standard-support modules such as `x/sys` only where actually imported.
- Cloud SDKs, etcd, gRPC/protobuf, SQLite, controller-runtime/logr, crypto used only by removed auth/audit code, and Python dependencies must disappear from the direct graph.

### 10.4 Generated eBPF code

- Keep `tools/bpfgen` as source only.
- Keep `go:generate` on a build-tag-free file.
- Regenerate little- and big-endian bindings in CI and fail on drift.
- Format generated Go source and write it with normal source permissions (`0644`), never executable or owner-only modes.
- Mark generated binding files in `.gitattributes` so code-hosting tools identify them as generated.
- Do not manually refactor embedded byte literals.

## 11. Documentation end state

Keep these maintained documents:

### `README.md`

- One-paragraph description and experimental-status statement.
- Small architecture diagram.
- Prerequisites.
- Five-minute Kubernetes quick start.
- Four-command CLI summary.
- Link to the supported-policy matrix.
- Link to deployment and development documentation.
- No feature marketing table and no claims for removed or unverified platforms.

### `docs/policies.md`

- Exact supported and rejected NetworkPolicy behavior.
- Directional isolation and additive-policy examples.
- Numeric-port rules and explicit named-port rejection.
- Default-deny example.
- Validation error examples.
- Explicit non-conformance statements for rejected wildcard, range, named-port, IPv6, local-node, and automatic Service-frontend behavior.

### `docs/deployment.md`

- Required kernel/cgroup/bpffs conditions.
- Install, verify, observe, upgrade, and uninstall procedures.
- Capability requirements and troubleshooting.
- Health, readiness, metrics, and flow commands.
- Explicit ClusterIP `ipBlock` guidance, the Pod-start classification gap, quarantine behavior, and the planned rolling-update fail-open interval.
- Safe migration warning for deleting the old CRD.

### `docs/development.md`

- Repository map.
- Required tools.
- Make targets.
- eBPF generation flow.
- Unit and integration test instructions.
- How to add support for a new NetworkPolicy behavior without bypassing validation.
- Concise contribution guidance currently duplicated in `CONTRIBUTING.md`.

Retain `LICENSE`, `SECURITY.md`, and a concise `CHANGELOG.md`. Fold useful contribution content into the development guide, then delete `CONTRIBUTING.md`. Delete `docs/index.md`, `docs/project-status.md`, `docs/modernization-plan.md`, API references, old platform runbooks, and obsolete feature guides. `STREAMLINING_PLAN.md` is a temporary execution artifact: after all acceptance items are checked and the outcome is summarized in `CHANGELOG.md`, remove this plan rather than turning it into another maintained historical document.

Curate three examples only:

- `default-deny.yaml`.
- `allow-dns.yaml`.
- `web-to-db.yaml`.

All examples must be native Kubernetes resources and must pass `ztap validate` in CI.

## 12. CI and release simplification

### 12.1 Transitional CI during the streamlining work

Do not remove every GitHub Actions check at the beginning. The streamlining is a high-risk refactor, so the repository must retain one small, independent safety gate throughout the work.

At the start of Phase 0:

1. Perform the work on `codex/streamline-ztap` and merge by reviewed pull request. If that branch already exists, reuse it rather than creating variants.
2. Add a temporary Linux workflow named `Migration CI` and make it green before deleting an existing required check.
3. Change branch protection to require the temporary workflow's stable `Required CI` check, then remove obsolete required-check names. Record this repository-setting change in the pull request because it is not represented by Git files.
4. Delete the release workflow file so intermediate commits cannot publish binaries, images, manifests, or releases through any event or manual dispatch. Recreate it only in Phase 5.
5. Remove specialized workflows and jobs tied only to features scheduled for deletion:
   - macOS and Windows build/test legs;
   - Python anomaly tests and image builds;
   - protobuf generation, buf lint, and breaking checks;
   - operator and anomaly image builds;
   - cloud-specific checks;
   - the custom coverage-ratchet job;
   - Scorecard and overlapping scheduled security workflows.
6. Pause Dependabot version-update pull requests during the destructive refactor. Restore one narrowed monthly configuration for Go modules, Docker, and GitHub Actions in Phase 5.
7. Require `Migration CI` to pass after every implementation phase and before merging that phase.

The temporary workflow contains only:

```text
go build ./...
go test ./...
go vet ./...
golangci-lint run --timeout=5m
```

Rules for the temporary workflow:

- It runs on pushes to `codex/streamline-ztap` and on pull requests from that branch into the default branch. Before the branch is merged, also verify the workflow on a default-branch pull-request event so trigger filters cannot hide the required check.
- It uses the Go version from `go.mod` and caches dependencies.
- It has read-only repository permissions.
- It uses concurrency cancellation for superseded commits.
- Every third-party action is pinned to a full commit SHA, with a version comment for maintainability.
- Its final job/check is named `Required CI`; keep that check name stable when the final workflow replaces the temporary jobs.
- Tests for a removed feature are deleted in the same commit as that feature, so the workflow remains green rather than accumulating expected failures.
- A retained test may be rewritten alongside its production replacement, but it must not be disabled simply because the refactor is incomplete.
- If a phase cannot pass the temporary gate, that phase is not complete.
- Local test results do not replace this gate; GitHub Actions provides the clean, reproducible environment.

At the end of Phase 4, replace the internals of `Migration CI` with the final jobs below while preserving the `Required CI` check name. Rename the workflow/file only after branch protection is verified against the replacement. Do not keep overlapping workflows.

### 12.2 Final pull-request CI

Keep one Linux-focused CI workflow with these jobs:

The pull-request workflow has top-level `permissions: contents: read`, receives no release secrets, and uses dependency caches that cannot execute cached binaries as trusted release inputs.

1. **Lint and unit test**
   - Formatting diff check.
   - `go vet`.
   - Configured `golangci-lint` checks, including `unused` and `staticcheck`.
   - `go test ./... -race`.
   - `govulncheck ./...` as the single dependency-vulnerability gate.
2. **Generated code**
   - Install the pinned clang/LLVM tooling.
   - Run `make check-generated`.
3. **Build assets**
   - Build Linux amd64 and arm64 binaries.
   - Build the Docker image.
   - Scan the built image with one pinned Trivy invocation; retain `.trivyignore` only for documented, expiring exceptions.
   - Validate the Kubernetes manifest.
   - Run `ztap validate` against every retained example.
4. **Linux eBPF integration**
   - Run only on an ephemeral runner or disposable VM that exposes the required cgroup v2 and BPF capabilities.
   - Never execute untrusted fork pull-request code on a persistent self-hosted runner.
   - Run for trusted branch pushes, manual release-candidate validation, and tagged releases; fail rather than silently skip when selected.
5. **Required CI**
   - Depend on every non-privileged merge-gate job and expose one stable branch-protection result.
   - A skipped or failed dependency must not accidentally produce a successful required check.

Remove macOS/Windows matrices, Python jobs, proto/buf jobs, operator/anomaly image builds, custom coverage baseline checks, duplicated security workflows, and checks tied only to removed features. Validate workflow syntax locally with `actionlint`. Restore monthly Dependabot updates only for Go modules, Docker, and GitHub Actions.

### 12.3 Release workflow

- Trigger only from a pushed semantic-version tag after the tagged commit is present on the protected default branch. Scope write permissions to the release job (`contents: write`, `packages: write`, and only any attestation permission actually used).
- Release one `ztap` binary for Linux amd64 and arm64.
- Publish one multi-architecture container image.
- Produce checksums and an SBOM.
- Keep GoReleaser as the single release driver and reduce `.goreleaser.yml` to one Linux binary for amd64/arm64, checksums, and SBOM generation. The workflow must call that configuration rather than duplicate its build matrix in shell steps.
- Update or render the install manifest with the immutable released image digest.
- Require the trusted Linux eBPF integration job and all final acceptance gates before a release job can start.
- Do not publish macOS, Windows, operator, or anomaly artifacts.
- Treat the first streamlined release as `v0.1.0` because the supported surface is intentionally experimental and incompatible with the previous repository state.

## 13. Implementation phases

Each phase should be reviewed and committed separately. Do not mix broad deletion, core semantic changes, and documentation rewrites into one unreviewable commit.

Before each phase, confirm the prior phase's exit criteria on the branch. A phase is the rollback unit: if its exit criteria fail, revert that phase's commits instead of layering compensating code onto an unverified state. Do not force-push away the review history.

### Phase 0: Baseline and safety net

Progress: the local baseline, artifact cleanup, Makefile, deterministic dispatcher test, and temporary workflow definition were reviewed on 2026-09-10 and committed in `7703a99` on 2026-09-11. Focused Linux characterization, the capability-only Kubernetes probe, the PR trigger, pinned toolchains, parser/address fixes, attached-cgroup identity, reload map reuse, and pinned generated bindings are now pushed through `d25c70e` on `codex/streamline-ztap`. `Migration CI` push run `34634540864` and PR run `34634544640` are green; `main` strictly requires `Required CI`; and the transitional release workflow is removed. The authoritative hosted Phase 0 run `34634544635` passed its Linux and Kubernetes jobs, including cgroup-v2/bpffs preflight, real ingress/egress policy traffic, graceful reload, flow-map cleanup, the pinned binding check, Kubernetes `v1.36.4`, containerd `2.3.4`, systemd cgroups, kernel `6.17.0-1022-azure`, and the exact four requested capabilities. Earlier runs exposed and fixed duplicate map assignment, cgroup-skb network-layer offsets, packet-address normalization, ingress cgroup identity, and reload map replacement. The current macOS host still cannot validate Linux kernel, NAT, cgroup, containerd, Kubernetes, or capability assumptions locally. The Phase 0 workflow now includes the reproducible `v0.1.0` fixture, CNI/NAT and traffic-class capture, rejected-IPv6 checks, and separate workload/agent/rollout timing probes; the legacy feature-only CI jobs are removed from the working tree. The scoped safety gate passes, but the architecture gate remains open until the hosted workflow produces raw evidence for the NAT, traffic-class, CNI, lifecycle, flow-lifetime, atomicity, and quarantine contract items; do not begin broad product deletion or claim Phase 1 readiness.

Work:

- [x] Record the baseline commit, its command list, the already-dirty working-tree boundary, and local host limitations.
- [x] Create or reuse the dedicated `codex/streamline-ztap` branch.
- [x] Follow the branch-protection handoff order in Section 12.1.
- [x] Add the temporary non-publishing `Migration CI` definition with a stable `Required CI` result.
- [x] Push `Migration CI`, prove its branch and default-branch pull-request events green, make `Required CI` required, and remove obsolete required-check names.
- [x] Delete the release workflow after the required-check handoff and before pushing transitional product deletions.
- [x] Remove specialized jobs tied only to features that this plan deletes, including the Python, proto/buf, multi-OS, anomaly/operator image, custom coverage, compose, and feature-only fuzz paths.
- [x] Delete the tracked root `bpfgen` executable and ignored root build/test/coverage artifacts, add `/bpfgen` to `.gitignore`, and keep generated Go bindings.
- [x] Add the small Makefile with safe `clean`, current `check`, and pinned-tool targets.
- [x] Run the existing build, race, vet, formatting, and pinned-lint gates in a writable repository-local cache environment.
- [x] Identify retained Linux eBPF integration tests and copy their existing and missing assertions into `docs/phase0-feasibility.md`.
- [ ] Complete the full disposable Linux/Kubernetes feasibility spike before irreversible feature deletion. The workflow now captures direct PodIP/ClusterIP NAT, reply/node/self/rejected-IPv6, CNI, and DaemonSet lifecycle/security-context evidence; hosted execution and raw artifact review remain required.
- [ ] Measure the interval from a selected container becoming runnable to its cgroup being observed, resolved, and classified. The workflow records this separately from workload restart, agent restart, and rolling-update recovery; hosted measurements remain required.
- [x] Add the executable Phase 0 evidence harness for consecutive flow decoding,
  selected-cgroup IPv6 rejection, PodIP/ClusterIP, reply, node, self, CNI, and
  lifecycle characterization. The hosted Linux/kind execution and its raw
  evidence remain required before this phase can close.
- [x] Define the smaller reproducible `v0.1.0` reference fixture from Section 14.5 in `scripts/phase0_reference_fixture.sh` and `testdata/phase0-v0.1.0/README.md`. Do not block policy/compiler work on the later 1,000-Pod/10,000-rule scale fixture.
- [x] Add focused characterization tests for per-cgroup behavior, ingress/egress allow-deny, map population, flow-map pinning/decoding, and shutdown cleanup.
- [x] Record and reverify current generated eBPF checksums.

Exit criteria:

- [x] Retained kernel behavior covered by the current scope has executable tests before its surrounding packages are removed; the remaining contract cases stay open below.
- [x] Failures that depend on unavailable host capabilities are explicitly separated from source failures.
- [x] `Migration CI` is required and green, and no workflow can publish transitional artifacts.
- [ ] The feasibility report records the complete required packet-offset, NAT, cgroup-identity, Pod-start classification, restart/rollout, capability, and supported kernel/runtime evidence. The current report records the passing subset and explicitly keeps the untested contract open; if any core assumption fails, update this plan and its tests before Phase 1.
- [x] Immediate artifact cleanup is committed separately in `7703a99`, and `make phase0-fixture` followed by `make clean` leaves no generated repository-root artifacts.

### Phase 1: Native policy model and compiler

Progress: the additive native input-contract slice was implemented and reviewed on 2026-09-10. Phase 1 remains open until Phase 0 is confirmed, the kernel-neutral compiler, resolution inputs, quarantine behavior, and deterministic object-order tests are complete, and every phase exit criterion passes. Do not begin the remaining Phase 1 work before closing the Phase 0 gate.

Work:

- [x] Add strict native NetworkPolicy decoding for files, stdin, multi-document YAML, and `NetworkPolicyList`.
- [x] Implement the supported-subset validator with typed field errors and stable document/object/field context.
- [ ] Define the kernel-neutral `PolicySet`, subject direction masks, and rules.
- [x] Implement Kubernetes `policyTypes` defaulting and explicit-type consistency checks.
- [ ] Implement deterministic IPv4 selector-peer and numeric-port expansion.
- [x] Implement deterministic IPv4 `ipBlock.except` normalization with the 1,024-prefix cap.
- [ ] Implement additive rule union; remove conflict semantics from the new path.
- [ ] Define kernel-neutral resolution inputs for documented Node-status/self bypasses and the per-subject quarantine model.
- [ ] Build fixture-based resolution inputs for compiler unit tests; `internal/policy` must not own client-go clients, informers, or resolver lifecycle.
- [x] Add `ztap validate` with the documented stdin/file behavior and exit statuses while the old commands still exist internally.

Exit criteria:

- [ ] The three curated native examples pass.
- [ ] Every rejected construct has a direct test and stable error path.
- [ ] Compilation results are deterministic under randomized informer/object ordering.
- [ ] A rejected policy quarantines only the local subjects and directions it selects; unrelated accepted policy state still compiles.
- [ ] The new policy package no longer depends on the custom YAML schema.

### Phase 2: Instance-owned eBPF engine

Work:

- Introduce `Engine.Apply` and `Engine.Close`.
- Change enforced cgroups to a direction bitmask.
- Remove global/default enforcement semantics from the eBPF C program.
- Remove permissive and exact-map compatibility programs.
- Implement bounds-checked IPv4 TCP/UDP parsing and explicit isolated-direction IPv6 denial using the packet offsets proven in Phase 0.
- Implement node/self bypasses, quarantine precedence, and the epoch-scoped LRU reply-connection map.
- Keep the flow ring and aggregate decision counters stable for the engine lifetime.
- Implement two-slot candidate population, atomic slot-plus-epoch commit, partial-write cleanup, and old-slot garbage collection.
- Update and regenerate bindings.
- Adapt Linux integration tests to native compiled inputs.

Exit criteria:

- Direction-specific default deny is verified.
- Unselected cgroups remain allowed.
- Reply traffic, documented Node-status traffic, and self traffic match the stated `v0.1.0` semantics.
- Failed candidate population or configuration flip leaves the old rules active for already classified cgroups.
- A successful slot-plus-epoch flip makes no mixed old/new policy state observable and invalidates old connection state logically, including after slot reuse.
- Repeated apply/close cycles pass race and leak checks.
- Generated sources are reproducible.

### Phase 3: Direct Kubernetes agent

Work:

- Implement NetworkPolicy, Pod, Namespace, and local Node informer caches and immutable snapshots.
- Implement local-node subject resolution, containerd/systemd cgroup lookup, cluster-wide IPv4 peer resolution, and explicit ClusterIP/IPBlock behavior.
- Add the bounded reconciliation queue and debounce.
- Wire compiler results into the engine.
- Implement dry-run behavior, per-subject quarantine, and last-known-good state for kernel-application failure.
- Implement health/readiness state and metrics.
- Wire signal-based shutdown.
- Convert `ztap flows` to real streaming only.

Exit criteria:

- Add/update/delete/relist tests converge to the expected policy set.
- Pod and namespace label changes trigger correct recompilation.
- Node address changes trigger correct recompilation.
- Selector peers do not infer Service frontends; explicit ClusterIP `ipBlock` rules match only the address and numeric port visible at the hook.
- A rejected policy quarantines its selected local subjects, makes readiness false, and does not prevent unrelated accepted policies from updating.
- Deleting or correcting the rejected policy removes quarantine without restart.
- Dry-run remains healthy but never reports readiness or active enforcement.
- Pod-start classification delay is measured and reported separately from reconciliation duration.
- Flow streaming continues across policy replacements.

### Phase 4: Product cutover and deletion

Work:

- Make the new `agent`, `validate`, `flows`, and `version` commands the only primary commands.
- Delete all feature areas listed in the removal inventory.
- Delete the custom config system and use explicit flags.
- Migrate retained logging calls to `slog` and remove the wrapper.
- Remove old deployment assets and produce the single DaemonSet manifest.
- Replace the runtime image with the single minimal image.
- Remove unused direct dependencies and run `go mod tidy`.
- Change the module path.

Exit criteria:

- `ztap --help` exposes only the agreed command surface.
- `rg` finds no source or documentation references to removed commands, APIs, config keys, CRDs, platforms, or services except the breaking-change record.
- `go list -deps` contains none of the removed dependency families.
- The repository builds without generated local executables in its root.

### Phase 5: Documentation, tooling, and release gate

Work:

- Create the four-document end state.
- Convert and validate the three examples.
- Finalize every Makefile target listed in Section 10.2.
- Replace the temporary `Migration CI` with the final Linux CI defined in Section 12.2.
- Recreate the simplified release workflow only after the final CI and acceptance gates pass.
- Restore narrowed monthly Dependabot updates and verify branch protection still requires `Required CI`.
- Verify `make clean` leaves no tracked or ignored workspace debris; artifact deletion itself was completed in Phase 0.
- Add the `v0.1.0` breaking-change entry and migration notes.
- Once all checklist items are recorded as complete, delete this temporary plan in the release-preparation commit.
- Run the full unit, generated-code, Docker, manifest, and Linux integration gates.
- Run the Section 14.5 performance/resource gates and retain raw results with the release artifacts.

Exit criteria:

- A new maintainer can identify the product, build it, run tests, install it, and understand its limitations without reading historical plans.
- Every README command is exercised by CI or a smoke test.
- No maintained document duplicates full command or configuration references.
- The working tree contains only source, required generated bindings, tests, deployment assets, and maintained documentation.

### Post-`v0.1` roadmap

These items are deliberately excluded from the first release and must not leave dormant abstractions, flags, informers, maps, or compatibility branches in `v0.1.0`:

- Named-port resolution against destination Pods.
- IPv6 and dual-stack enforcement, including fragmentation and extension-header behavior.
- Automatic safe ClusterIP expansion from Service and EndpointSlice state.
- More sophisticated flow sampling or first-flow suppression.
- The 1,000-Pod, 100-policy, 10,000-rule scale fixture.

Each item requires its own reviewed milestone and integration evidence. The roadmap does not block completion or deletion work for `v0.1.0`.

## 14. Test matrix

### 14.1 Policy validation tests

- Correct apiVersion/kind and wrong-resource rejection.
- Single and multi-document YAML, `NetworkPolicyList`, empty separators, and unrelated-object rejection.
- Missing name and invalid selectors.
- Duplicate YAML keys, unknown fields, malformed documents, and trailing data.
- Empty subject selector.
- Explicit and defaulted policyTypes.
- Ingress-only, egress-only, and bidirectional isolation.
- Empty rule lists for default deny.
- Multiple policies selecting the same pod.
- Multiple peers and multiple ports.
- Pod, namespace, combined, and IPBlock peers.
- Valid and invalid IPBlock exclusions.
- TCP/UDP defaulting and numeric ports.
- IPv6 CIDR, named-port, SCTP, endPort, peerless, portless, and unnamed port-entry rejection.
- Deterministic output and capacity failures.
- Fuzz targets for YAML document splitting/strict decoding and IPBlock exclusion expansion, with checked-in regression seeds only.
- Documented Node-status/self bypass compilation and hostNetwork exclusion.
- Explicit ClusterIP `ipBlock` handling and proof that selector peers do not synthesize Service frontend rules.
- Per-subject quarantine when an unsupported policy selects local subjects, including unrelated-policy progress.

### 14.2 Kubernetes reconciliation tests

- Successful initial cache synchronization.
- Initial list failure and watch restart.
- NetworkPolicy add, update, and delete.
- Pod add/delete, scheduling, readiness, label, IP, and container-ID changes.
- Namespace label changes.
- Local Node address changes.
- Local-node subject filtering with cluster-wide peer lookup.
- containerd/systemd cgroup-path resolution and explicit rejection of unsupported layouts.
- Pending selected pods versus unresolvable running pods.
- Selected IPv6 or dual-stack workload quarantine.
- Coalesced event storms.
- Unsupported-policy diagnostics logged once per resource generation.
- Permanent validation errors update the affected quarantine only after a relevant object change; transient apply errors back off and recover without an object change.
- Last-known-good retention for already classified cgroups and automatic recovery after apply failure.
- Measured Pod-start-to-classification interval and distinct accounting for a running container whose cgroup cannot be resolved.
- Graceful shutdown without send-on-closed-channel races.

### 14.3 eBPF unit and integration tests

Privileged tests use an explicit `integration` build tag and fail their environment preflight when selected. The ordinary unit-test suite must not require root, bpffs, a Kubernetes cluster, or network access.

- Key serialization for IPv4 rules, policy slots, policy epochs, and quarantine directions.
- Direction-bit behavior for selected cgroups.
- Exact port/protocol matching.
- CIDR LPM matching and IPBlock exclusions.
- Bounds-checked packet parsing at the Phase 0-proven cgroup offsets.
- IPv4 TCP and UDP plus malformed, fragment, IPv6, ICMP, and unsupported-protocol behavior.
- Default deny in only the selected direction.
- Additive allow rules.
- Unselected cgroup default allow.
- Reply-connection creation, reverse lookup, refresh, timeout, capacity eviction, epoch invalidation, and `0 -> 1 -> 0` slot reuse without stale-state reactivation.
- Node-address and self-traffic bypasses.
- Quarantine precedence over reply state and ordinary allow rules.
- Map-capacity preflight.
- Candidate population and atomic slot-plus-epoch configuration flip failures.
- No mixed policy state during concurrent packet traffic and slot/epoch changes.
- Old-slot garbage-collection failure and retry.
- Idempotent cleanup and pin removal.
- Stable flow-map and counter-map identity across successful updates.
- Real UDP/TCP allow and deny events from temporary cgroups on Linux.
- Allowed/blocked event rate limiting, ring-full accounting, and enforcement independence from event loss.
- Direct PodIP and explicit ClusterIP `ipBlock` paths before/after NAT on the supported cluster fixture.

### 14.4 CLI and operational tests

- Help snapshot containing only retained commands.
- Validation from file and stdin with correct exit status.
- Linux-only build contract and containerized offline validation.
- Agent flag validation.
- Exclusive agent and flow-reader lock behavior, including crash release and stale pins.
- Health/readiness transition sequence.
- Dry-run health with readiness 503 and `ztap_agent_enforcing 0`.
- Metrics names, types, and bounded labels.
- Table and JSON flow output plus filters.
- Event-schema version handling and rejection of incompatible pinned-map records.
- Fuzz target for binary flow-event decoding with no panics or unbounded allocation.
- Flow-reader exit on agent shutdown, stale heartbeat, and agent-epoch change.
- SIGINT/SIGTERM shutdown.
- Agent crash/restart and planned DaemonSet rolling-update tests that demonstrate and measure their separate fail-open intervals.
- Kubernetes manifest client-side validation.
- Container startup and non-privileged capability configuration.
- Workflow syntax, stable `Required CI` aggregation, and release dependency gates.

### 14.5 Performance and resource gates

Use one documented 2-vCPU Linux reference environment with 250 Pods, 25 NetworkPolicies, and 2,500 compiled local rules. Run each measured gate three times after warm-up and retain the raw command/output with release artifacts. The 1,000-Pod/100-policy/10,000-rule fixture is a post-`v0.1` scale milestone.

- Full reconciliation completes within 2 seconds at p95, excluding the fixed debounce and Kubernetes API list latency.
- A relevant informer event becomes an active policy epoch within 3 seconds at p95 on a synchronized cache.
- Record Pod-start-to-classification, agent-restart, and rolling-update enforcement gaps independently; the README reports measured values without turning them into stronger availability claims.
- On a quiet reference cluster, the agent uses no more than 0.10 CPU cores and 200 MiB resident memory, excluding kernel-map memory.
- Report calculated and observed kernel-map memory at the configured maximum capacities; unexplained unbounded growth fails the release.
- With the policy programs attached, packet-path p99 latency increases by no more than 10 microseconds and steady TCP throughput falls by no more than 10 percent relative to the same fixture with enforcement disabled.
- At 1,000 packet decisions per second for 60 seconds, the decision counter, delivered flow events, rate-limited events, and ring-full events reconcile without silent loss. Rate limiting is expected; it must be visible in the exported drop counter.
- Benchmarks must use real cgroups and packets for kernel-path claims. Go-only microbenchmarks may support profiling but cannot satisfy these gates.

## 15. Migration and breaking changes

There is no runtime compatibility layer.

- Existing `ZtapNetworkPolicy` objects are not consumed by the new agent.
- Before deleting the old CRD, users must export any custom resources they want to translate. CRD deletion destroys stored custom resources and must be presented as a separate, explicit uninstall step.
- The migration guide provides side-by-side conversions for the three curated examples.
- The old operator and agent must not run alongside the streamlined agent because they use different policy sources and ownership models.
- A CNI NetworkPolicy implementation must also be disabled in the supported test/deployment profile. If an operator knowingly keeps one enabled, the result is intersected enforcement and is outside the first release support contract.
- All old CLI commands and the configuration file disappear immediately.
- REST/gRPC endpoints and their authentication/session data are not migrated.
- Old metrics and dashboards are removed; users must update scrape rules and dashboards to the new bounded metric set.
- Old audit files and local databases are left untouched on user machines, but the new binary does not read them.
- Release notes must list every removed command and deployment component in one compact breaking-change table.

## 16. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Native policy semantics differ from the current custom model | Define the subset first, use Kubernetes types directly, and reject everything outside it |
| A bad update weakens active enforcement | Compile a complete accepted-plus-quarantine candidate; retain last-known-good state for already classified cgroups only when kernel application fails |
| A new or restarted selected container is not yet classified | Measure the watcher delay, expose it operationally, document the fail-open interval, and do not claim admission-time enforcement without future CRI/CNI integration |
| One unsupported policy blocks unrelated enforcement | Quarantine only its selected local subjects and directions while continuing to apply unrelated accepted policy state |
| Policy deletion is missed | Use informer delete events plus full cache-derived reconciliation rather than incremental mutation |
| Remote pods are mistaken for local subjects | Require node name and separate local subject resolution from cluster peer resolution |
| Cgroup layouts differ by runtime | Support only containerd with the systemd cgroup driver initially, test that exact layout, and reject other layouts explicitly |
| Reply traffic is blocked by stateless rules | Maintain a bounded, epoch-scoped reverse-connection map and test TCP/UDP replies, timeouts, and policy-slot reuse |
| Reusing policy slot 0 or 1 revives stale connection state | Keep a monotonic epoch separate from the two rule slots and commit slot plus epoch atomically |
| Required node/self traffic is denied | Compile the documented Node-status and subject self-address bypasses, test both directions, and describe the local-node limitation as non-conformance |
| Service DNAT hides selector destinations | Observe hook behavior in Phase 0, require explicit ClusterIP `ipBlock` rules in `v0.1.0`, and defer automatic Service/EndpointSlice translation |
| A CNI also enforces NetworkPolicy | Document coexistence as unsupported, warn at startup, and test on a cluster profile without another policy enforcer |
| Packet offsets or unsupported IP families are misparsed | Make packet-layout validation a Phase 0 go/no-go gate, bounds-check every access, and deny isolated IPv6 or unsupported traffic |
| Capability-only DaemonSet cannot attach programs | Feature-probe on startup and test the exact manifest; never silently broaden to privileged mode |
| Event storms cause repeated expensive rebuilds | Use a bounded dirty-signal queue and debounce before full reconciliation |
| Generated eBPF code obscures repository size | Mark it generated, keep generation reproducible, and exclude it from handwritten-code review metrics |
| Policy update exposes a mixed ruleset | Store two keyed rule slots and commit the active slot plus monotonic epoch with one configuration-map update |
| Two agents or readers contend for node state | Enforce host-mounted operating-system locks and test crash release |
| Agent exit or planned rolling update temporarily removes enforcement | State the process-owned fail-open behavior prominently, measure crash and rollout recovery separately, and do not claim production-grade availability |
| Flow readers lose events during policy update | Keep one persistent pinned ring buffer and record reservation drops in a counter |
| Broad deletion hides accidental regressions | Implement and test the replacement path before deleting the old vertical slices |
| CI removal leaves regressions unreviewed or blocks merges | Keep `Migration CI`, hand off branch-protection checks in order, and delete publishing until the release gate is rebuilt |
| Documentation drifts again | Keep defaults in flags, generate help from Cobra, and validate every documented example in CI |

## 17. Final acceptance checklist

### Product surface

- [ ] README describes only a Linux/Kubernetes eBPF enforcer.
- [ ] `ztap --help` contains `validate`, `agent`, `flows`, and `version` as the only primary commands.
- [ ] Native Kubernetes NetworkPolicy is the only accepted policy resource.
- [ ] Unsupported semantics are rejected with stable field errors.
- [ ] The documented first-release surface is IPv4 with numeric TCP/UDP ports; named ports, dual-stack enforcement, and automatic Service translation leave no dormant code paths.
- [ ] There is one binary, one container image, and one Kubernetes install manifest.

### Enforcement correctness

- [ ] Policies apply only to selected local container cgroups.
- [ ] Ingress and egress isolation are independent.
- [ ] Multiple policies combine additively.
- [ ] Empty directional rules enforce default deny.
- [ ] Unselected pods remain allowed.
- [ ] Allowed TCP/UDP reply traffic works without a separate reverse policy rule.
- [ ] Reusing policy slot `0` or `1` cannot reactivate connection state from an older policy epoch.
- [ ] Documented Node-status and pod self traffic remain allowed; local-node and hostNetwork limitations are stated explicitly.
- [ ] Explicit IPv4 ClusterIP `ipBlock` rules work, and selector peers never synthesize Service frontend access.
- [ ] Malformed, fragmented, and unsupported packets cannot bypass an isolated direction.
- [ ] Unsupported local policy semantics quarantine only affected subjects and directions while unrelated accepted policies continue updating.
- [ ] Failed kernel updates preserve previous state for already classified cgroups; the limitation for unobserved replacement cgroups is measured and documented.
- [ ] A policy update becomes visible through one atomic slot-plus-epoch flip with no mixed ruleset.
- [ ] Policy deletion removes its contribution on the next reconciliation.

### Operations

- [ ] `/healthz`, `/readyz`, and `/metrics` have the documented behavior.
- [ ] Dry-run never reports enforcement readiness, and `ztap_agent_enforcing` remains `0`.
- [ ] A quarantined local subject changes readiness to 503 and reports bounded metric/log diagnostics without blocking unrelated reconciliation.
- [ ] Real flow streaming works from the pinned map and contains no simulated events.
- [ ] One agent and one flow reader can own node state at a time, with automatic lock release after a crash.
- [ ] Graceful shutdown removes links and owned pins.
- [ ] Pod-start classification, crash/restart, and rolling-update fail-open intervals are measured separately and prominently documented.
- [ ] The DaemonSet operates with explicit capabilities and without privileged mode.

### Repository quality

- [ ] No tracked executable binaries remain.
- [ ] No root build/test/coverage artifacts remain after `make clean`.
- [ ] Removed feature directories, docs, dependencies, workflows, and configuration are gone together.
- [ ] Generated eBPF sources reproduce without a diff.
- [ ] `go test ./... -race`, lint, vet, Docker build, manifest validation, and Linux integration tests pass.
- [ ] Branch protection requires the stable `Required CI` result, and no transitional workflow can publish artifacts.
- [ ] Searches find no stale claims for REST, gRPC, cloud, etcd, anomaly, audit, compliance, macOS, Windows, or iptables support outside release history.

### Efficiency evidence

- [ ] The documented 250-Pod/25-policy/2,500-rule fixture meets the reconciliation, activation, CPU, and memory budgets.
- [ ] Real-packet measurements meet the latency and throughput budgets on the reference environment.
- [ ] The 1,000-decisions/second flow test has no silent loss; delivered, rate-limited, and ring-full accounting reconciles with decision totals.
- [ ] Raw benchmark commands, environment details, and outputs are attached to the release; README claims do not exceed that evidence.

## 18. Fixed assumptions

- This is an intentional breaking redesign, not a deprecation release.
- There are no external interfaces that must be preserved.
- Kubernetes is the only orchestration/control plane.
- The Kubernetes node agent is the only enforcement entry point.
- Linux eBPF is the only enforcement backend.
- The first release supports IPv4 policy enforcement and numeric TCP/UDP ports only.
- Named ports, IPv6/dual-stack enforcement, and automatic Service/EndpointSlice translation are post-`v0.1` work and have no dormant first-release code paths.
- The first release supports cgroup v2 plus containerd with the systemd cgroup driver only.
- The supported cluster profile has no other NetworkPolicy enforcer; automatic CNI detection is not promised.
- Native NetworkPolicy YAML is the only policy format.
- The first release supports the explicit subset in this document, not full conformance.
- Unsupported policies quarantine only the local subjects and directions they select; unrelated accepted policies continue reconciling.
- Watcher-based cgroup discovery and process-owned links create measured fail-open intervals at Pod start, agent restart, and planned rolling update.
- Structured logs, health/readiness, bounded Prometheus metrics, and real flow streaming are retained.
- Audit, alerts, dashboards, and anomaly detection are outside the core.
- Git history will not be rewritten.
- The first streamlined release is versioned as `v0.1.0` and described as experimental.

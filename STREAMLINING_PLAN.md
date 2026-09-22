# ZTAP Streamlining Plan

- **Status:** Phase 5 implementation complete locally — hosted acceptance and release gates pending
- **Prepared:** 2026-09-10
- **Last reviewed:** 2026-09-22
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
           [--run-dir /run/ztap] \
           [--bpffs-root /sys/fs/bpf] \
           [--output table|json]
```

Behavior:

- Streaming begins immediately and continues until interrupted.
- The command reads the stable pinned flow map created by the agent.
- `--bpffs-root` defaults to `/sys/fs/bpf`; the shipped DaemonSet uses
  `/host/sys/fs/bpf` because its host bpffs mount is exposed at that path.
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

- The engine loads one program collection and keeps its programs and maps for the process lifetime. Ordinary policy changes must not reload programs or update existing links.
- Maintain one owned ingress/egress link pair for every resolved subject container cgroup. Do not attach the policy programs only at the mounted cgroup v2 root: [`BPF_MAP_TYPE_CGROUP_STORAGE` is bound to the attachment cgroup](https://docs.kernel.org/bpf/map_cgroup_storage.html) even when a parent program triggers for a descendant, so a root-only attachment cannot provide the receiving subject identity required for ingress. Phase 0 must exercise two subject attachments sharing one program/map collection before this design is accepted.
- Add newly selected subject links after the inactive candidate is complete but before the slot/epoch flip. Before the flip, the old slot has no classification for a new subject and therefore allows it; after the flip, the subject is enforced. If any new attachment or cgroup-storage initialization fails, close only the links created for that candidate and leave the old slot and link set active. Detach removed subjects only after a successful flip.
- Use link-based multi-attach when the supported kernel provides it; never replace or detach an unknown pre-existing cgroup program. An incompatible existing attachment on a selected subject is a fatal apply error.
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
- Search only beneath the mounted cgroup v2 systemd kubepods hierarchy for the exact `cri-containerd-<id>.scope` basename. The supported exact forms are the root `kubepods.slice` hierarchy and the kubelet-scoped `kubelet.slice/kubelet-kubepods.slice` hierarchy. Do not search the whole host filesystem, accept shortened IDs, or follow a match outside `--cgroup-root`.
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
- `ztap_unresolved_running_containers` gauge for running local containers whose
  cgroup identity is not currently resolvable.
- `ztap_pod_start_classification_delay_seconds` histogram for the interval from
  first observation of a running container to its first installed cgroup
  classification.
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
make integration       run privileged Linux enforcer and agent integration tests
make performance       run Linux reference performance gates and write raw evidence
make verify-performance validate the retained Phase 5 JSON evidence
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
- Keep GoReleaser as the single release driver and reduce `.goreleaser.yaml` to one Linux binary for amd64/arm64, checksums, and SBOM generation. The workflow must call that configuration rather than duplicate its build matrix in shell steps.
- Update or render the install manifest with the immutable released image digest.
- Require the trusted Linux eBPF integration job and all final acceptance gates before a release job can start.
- Run the real-cgroup engine-apply, sustained-flow-accounting, and initial
  native-agent activation harnesses and retain their raw output before
publication; synchronized-informer event, Pod-start, packet, resource, and
fail-open measurements stay explicit release blockers until their evidence
exists.
- Do not publish macOS, Windows, operator, or anomaly artifacts.
- Treat the first streamlined release as `v0.1.0` because the supported surface is intentionally experimental and incompatible with the previous repository state.

## 13. Implementation phases

Each phase should be reviewed and committed separately. Do not mix broad deletion, core semantic changes, and documentation rewrites into one unreviewable commit.

Before each phase, confirm the prior phase's exit criteria on the branch. A phase is the rollback unit: if its exit criteria fail, revert that phase's commits instead of layering compensating code onto an unverified state. Do not force-push away the review history.

### Phase 0: Baseline and safety net — Complete

Progress: **complete and merged**. The local baseline, artifact cleanup, Makefile, deterministic dispatcher test, and temporary workflow definition were committed in `7703a99`. Focused Linux characterization, the capability-only Kubernetes probe, pinned toolchains, parser/address fixes, attached-cgroup identity, reload map reuse, and pinned generated bindings followed through `d25c70e`. `main` strictly requires `Required CI`, and the transitional release workflow is removed. Hosted run `34653218849` completed the original evidence collection and exposed the self-reply contract failure during raw artifact review. Phase 0 was merged through reviewed PR #179 in `84c5512`.

The follow-up review retained the `v0.1.0` self-traffic contract and added an explicit `(cgroup, PodIP)` bypass, a hard hosted self assertion, per-direction quarantine, failed-candidate preservation, partial link-update rollback, and multi-subject ingress-identity coverage in `bc636f5`. Test injection was corrected in `3b198a4`, and the hosted DaemonSet observer-selection race was fixed in `091310f`. Final hosted run `34665388860` from `091310f` passed all three jobs, and its raw artifacts were reviewed. Final Migration CI push run `34665381636` is also green. The attachment target is now one link pair per subject cgroup, sharing programs/maps, because cgroup local storage identifies the attachment cgroup. The Phase 0 architecture gate is closed; Phase 1 may resume.

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
- [x] Complete the full disposable Linux/Kubernetes feasibility spike before irreversible feature deletion. Hosted run `34653218849` exposed the self-reply contract failure; final run `34665388860` verifies the fix while retaining direct PodIP/ClusterIP NAT, reply/node/self/rejected-IPv6, CNI, and DaemonSet lifecycle/security-context evidence.
- [x] Measure the interval from a selected container becoming runnable to its cgroup being observed, resolved, and classified. Final hosted run `34665388860` records this separately from workload restart, agent restart, and rolling-update recovery.
- [x] Add the executable Phase 0 evidence harness for consecutive flow decoding,
  selected-cgroup IPv6 rejection, PodIP/ClusterIP, reply, node, self, CNI, and
  lifecycle characterization. Hosted run `34665388860` completed and its raw
  evidence is recorded in `docs/phase0-feasibility.md`.
- [x] Define the smaller reproducible `v0.1.0` reference fixture from Section 14.5 in `scripts/phase0_reference_fixture.sh` and `testdata/phase0-v0.1.0/README.md`. Do not block policy/compiler work on the later 1,000-Pod/10,000-rule scale fixture.
- [x] Add focused characterization tests for per-cgroup behavior, ingress/egress allow-deny, map population, flow-map pinning/decoding, and shutdown cleanup.
- [x] Record and reverify current generated eBPF checksums.
- [x] Review the completed Phase 0 implementation and retain the stronger self-traffic contract. Add explicit self-bypass, per-subject quarantine, failed-candidate preservation, reload rollback protection, and multi-subject ingress-identity coverage.
- [x] Run the revised Linux/Kubernetes characterization on the hosted runner and review the raw self, quarantine, failed-update, and multi-attachment evidence. Run `34665388860` passed all three jobs.

Exit criteria:

- [x] Retained kernel behavior covered by the current scope has executable tests before its surrounding packages are removed; the remaining contract cases stay open below.
- [x] Failures that depend on unavailable host capabilities are explicitly separated from source failures.
- [x] `Migration CI` is required and green, and no workflow can publish transitional artifacts.
- [x] The feasibility report records the complete required packet-offset, NAT, cgroup-identity, Pod-start classification, restart/rollout, capability, and supported kernel/runtime evidence. It records the original self-reply failure from `34653218849` and the conforming final result from `34665388860`.
- [x] Immediate artifact cleanup is committed separately in `7703a99`, and `make phase0-fixture` followed by `make clean` leaves no generated repository-root artifacts.
- [x] Hosted run `34665388860` proves mapped self traffic in all four request/reply hook events, per-direction quarantine without blocking unrelated subjects, failed-candidate last-known-good behavior, partial link-update rollback, and distinct ingress identity for two subject attachments sharing one collection.

### Phase 1: Native policy model and compiler — Complete

Progress: **complete and merged as of 2026-09-12**. The native decoder and validator now feed a kernel-neutral compiler with immutable namespace, pod, cgroup, PodIP, and NodeIP resolution inputs. The compiler emits deterministic subjects and additive IPv4 rules, preserves explicit ClusterIP `ipBlock` entries without Service synthesis, excludes `hostNetwork` subjects, quarantines rejected or IPv6-affected local subjects per direction, and enforces the 16,384-subject and 16,384-rule active-slot limits. Incomplete namespace snapshots are rejected before namespace-selector evaluation, including for negative `NotIn` and `DoesNotExist` selectors. The three curated native examples compile against exact fixture snapshots, randomized object-order tests produce identical output, and `go test -race ./...`, `go vet ./...`, and the pinned lint gate pass. Phase 1 was merged through reviewed PR #180 in `f4753c2`.

Work:

- [x] Add strict native NetworkPolicy decoding for files, stdin, multi-document YAML, and `NetworkPolicyList`.
- [x] Implement the supported-subset validator with typed field errors and stable document/object/field context.
- [x] Define the kernel-neutral `PolicySet`, subject direction masks, and rules.
- [x] Implement Kubernetes `policyTypes` defaulting and explicit-type consistency checks.
- [x] Implement deterministic IPv4 selector-peer and numeric-port expansion.
- [x] Implement deterministic IPv4 `ipBlock.except` normalization with the 1,024-prefix cap.
- [x] Implement additive rule union; remove conflict semantics from the new path.
- [x] Define kernel-neutral resolution inputs for documented Node-status/self bypasses and the per-subject quarantine model.
- [x] Build fixture-based resolution inputs for compiler unit tests; `internal/policy` must not own client-go clients, informers, or resolver lifecycle.
- [x] Add `ztap validate` with the documented stdin/file behavior and exit statuses while the old commands still exist internally.

Exit criteria:

- [x] The three curated native examples pass.
- [x] Every rejected construct has a direct test and stable error path.
- [x] Compilation results are deterministic under randomized informer/object ordering.
- [x] A rejected policy quarantines only the local subjects and directions it selects; unrelated accepted policy state still compiles.
- [x] The new policy package no longer depends on the custom YAML schema.

### Phase 2: Instance-owned eBPF engine

Progress (2026-09-14): The first implementation slice adds an instance-owned
`Engine.Apply`/`Engine.Close` path, two policy slots with an atomic
slot-plus-epoch map swap, per-subject ingress/egress links, bounded packet
parsing, epoch-scoped reply state, and stable flow/counter maps. Flow events
now carry the policy epoch, cgroup, reason, and schema version; the decoder
continues to accept the legacy event shape. Linux packet-path tests now apply
policies produced by the native compiler. They cover direction-specific deny,
attachment-owned identity for selected descendants in both directions,
unselected sibling cgroups, TCP/UDP replies and epoch invalidation, Node/self
bypasses, quarantine precedence, a fixed per-CPU flow-event budget that remains
continuous across policy epochs, stable decision maps, failed candidate
attachment with active-rule retention, repeated apply/close cycles, and live
UDP traffic while alternating policy epochs to detect a mixed slot/epoch
decision. A Linux unit test covers lifecycle-status write ordering against a
concurrent heartbeat.
The privileged CI gate runs the cgroup-v2/bpffs/BPF preflight and the engine
packet, lifecycle, and cleanup suite with the race detector, and uploads the
verbose test output as a reviewable 14-day evidence artifact.
The aggregate check now fails when that privileged job is unexpectedly skipped;
the documented fork-PR restriction remains the only intentional skip.
Focused engine/flow/policy race tests, full vet, pinned lint, actionlint, and
Linux integration cross-builds for amd64 and arm64 pass. CI checks generated
bindings with `clang-18`; the bindings were regenerated locally with Homebrew
LLVM 18. The Linux status regression test, verifier, and privileged packet-path
suite are not runnable on this macOS host; hosted run `35184402760` executed
and passed them, with the uploaded evidence artifacts reviewed below.

The README and deployment guide now document the process-owned link lifecycle:
an agent crash or shutdown detaches enforcement and creates a bounded fail-open
interval until the replacement agent completes its first policy apply.

The standalone and bundled Kubernetes manifests now pass the required node
identity, mount cgroup v2/bpffs and the agent lock directory, grant the
capability-only eBPF set, and authorize the NetworkPolicy/Pod/Namespace/Node
informer reads used by the native agent. They expose host cgroup and bpffs
mounts beneath `/host`, avoid `hostNetwork`, and are covered by a manifest
regression test. The native agent image uses the explicit planned `v0.1.0`
release tag rather than a mutable `latest` tag. Engine startup now validates every owned map's type, capacity,
flags, and key/value ABI widths against the generated collection before loading it. The
native agent also serves `/healthz`, `/readyz`, and `/metrics` from a private
Prometheus registry with bounded readiness and enforcement gauges; readiness
remains false for dry-run, apply failure, or local quarantine, and the manifests
probe those endpoints over the named HTTP port.

The preexisting `filter.c`/`eBPFEnforcer` source remains parked for migration
and regression tests, but its production cutover is now complete: Linux file
enforcement and direct REST/gRPC starts reject the global compatibility path
and point operators to `ztap agent`. The retained cluster-sync helper only
preserves bookkeeping for migration callers and does not invoke the global/demo
program without an explicit attachment scope. Full deletion of the parked
compatibility source belongs to the Phase 4 removal inventory.
Privileged Linux execution of the packet and lifecycle/leak checks completed in
hosted run `35184402760`; the uploaded eBPF evidence was reviewed below.

Agent wiring (2026-09-14): the Linux Kubernetes agent now owns NetworkPolicy,
Pod, Namespace, and Node informer caches, builds one immutable cluster snapshot,
and reconciles it through the instance-owned engine. The Linux subject resolver
converts a caller-provided Node/Namespace/Pod snapshot into compiler input and
retains cgroup-ID-to-path data for per-subject engine attachment. It does not
issue separate API reads, so each candidate is derived from one informer-cache
view. The enforcer reconciliation boundary compiles that input and passes a
complete candidate to `Engine.Apply`; coverage exercises snapshot-to-engine
flow, cgroup-path removal, compile-failure isolation, and apply-error
propagation. The snapshot carries bounded cgroup resolution failures so a
selected running pod with any unresolved cgroup rejects the complete candidate,
while pending and unselected pods remain non-fatal. Resolution now considers
only live containers with full `containerd://<64-hex>` identities and the exact
containerd systemd scope; completed containers and legacy runtime/layout guesses
are ignored or rejected. Resolved container scopes are cached by container/pod
identity and revalidated against device/inode before reuse, with removed scopes
pruned on each complete snapshot. The legacy `filter.c`/`eBPFEnforcer`
implementation is now unreachable from the supported Linux command and API
paths; its source and dedicated migration tests remain parked for
the Phase 4 deletion inventory. Privileged Linux validation completed in hosted
run `35184402760`.

Follow-up (2026-09-15): engine startup now raises the eBPF memlock limit before
creating its collection, matching the capability-only DaemonSet contract. The
flow reader owns an OS lock at `<run-dir>/flows.lock` and validates the pinned
agent-status schema, enforcing lifecycle, heartbeat age, and agent epoch while
consuming the ring buffer; incompatible or stale status stops the reader. The
reader's Linux stop channel is recreated after shutdown so a monitor can be
started again safely. The supported flow command now uses only the real pinned
reader; the legacy synthetic fallback remains parked only for migration and
anomaly compatibility coverage until the Phase 4 removal inventory is deleted.

The native linker now queries each selected cgroup before and after attaching a
direction and rejects an incompatible pre-existing program without replacing or
detaching it. Candidate cancellation after map population also clears the
inactive slot before returning, preserving the previous active configuration.
Engine startup now feature-probes the configured roots as cgroup v2 and bpffs
mounts before loading the collection, so unsupported host layouts fail before
the agent advertises a usable enforcement engine.

Shutdown now publishes the stopping lifecycle state before link detachment, and
Linux attach/population boundaries reject nil or already-cancelled contexts so
teardown and cancellation cannot start additional kernel work.
The agent's HTTP readiness state changes to `503` with reason `stopping`, and
the enforcement gauge drops to zero, at the same shutdown boundary.
Apply and metrics snapshots also honor cancellation while waiting for the
serialized engine lifecycle lock, so a stalled policy update cannot strand a
shutdown or retry context behind another operation.

The native agent now publishes the bounded reconciliation gauges, duration and
result counters, compiled-rule and subject/quarantine counts, active policy
epoch, persistent packet-decision counters, flow-drop counters, and slot
cleanup failures from the instance-owned engine. Counter snapshots are polled
without consuming the flow ring and use reset-aware deltas for the process-local
Prometheus view. The native endpoint uses a private registry containing only
the retained process/runtime collectors and streamlined ZTAP metrics; legacy
anomaly and flow counters are not exposed by the agent path.
At startup it also emits the documented warning that coexistence with another
NetworkPolicy enforcer is unsupported because the agent cannot detect every CNI
implementation.
Each reconciliation now carries a bounded operation ID, observed/accepted/
rejected counts, subject/quarantine counts, rule count, dry-run state, and
duration through its structured success, rejection, and retry logs.
The resolver also records the first observation of each running container and
reports the separate Pod-start-to-classification histogram plus the current
unresolved-running-container gauge; policy-only updates do not count an
already classified cgroup again.
Rejected-policy diagnostics carry the Kubernetes resource generation and are
logged once per generation; transient apply retries retain the diagnostic
identity without repeating the warning, while a corrected or recreated policy
can emit a new diagnostic.

The Linux production cutover now rejects the legacy global enforcement entry
points with one migration sentinel and directs operators to the node-local
agent. This prevents a file-based or cluster-sync caller from silently
reintroducing global/default semantics while the compatibility implementation
stays available only to migration coverage.

Local verification (2026-09-15): full `go test ./...`, full `go test -race ./...`,
`go vet ./...`, pinned lint/actionlint, and reproducible generated-binding checks
pass on the macOS host. The CLI and enforcer packages cross-compile for Linux
amd64 and arm64, including the integration-tagged tests, and Homebrew LLVM 18
compiles both BPF sources. The host cannot execute Linux binaries, and the
privileged verifier, packet, lifecycle, and leak suites still require the Linux
CI runner.

Implementation status (2026-09-17): the Phase 2 engine, native agent wiring,
tests, generated bindings, deployment manifests, and hosted verification jobs
are complete. The privileged verifier, packet, lifecycle, leak, and disposable
kind capability checks are execution-only on this macOS host; hosted run
`35184402760` passed every required job and its Required CI artifacts were
downloaded and reviewed. No local implementation work remains for Phase 2.

Review follow-up (2026-09-16): packet readers now guard the observed policy
slot and recheck its epoch before reading slot data. Reclamation waits only for
readers of the retired slot, so traffic on the newly active slot cannot starve
the next update. The Linux suite now freezes real subject/config kernel maps to
verify that failed candidate population and configuration publication preserve
the active packet policy. Required CI also has a disposable kind job that runs
the shipped capability-only DaemonSet and checks a selected cgroup, an actual
default-denied packet, and its engine counter. Hosted run `35184402760` passed
that smoke and the privileged eBPF suite; no local implementation work remains
for Phase 2.

Local follow-up (2026-09-16): because `ztap agent` intentionally skips the
retired legacy configuration loader, it now initializes its own structured
logging path, defaulting to JSON on stderr while honoring the root logging
flags. A focused regression test covers the default. The exact LLVM 18
generator reproduces all four checked-in bindings byte-for-byte, and the
Linux integration-tagged enforcer tests compile for amd64 and arm64, including
the native-engine isolated IPv6 denial regression. The privileged runtime and
kind smoke evidence are hosted-only on this macOS workstation and completed in
hosted run `35184402760`. Engine collection validation now also checks flags on the outer
and inner active-configuration maps, with portable ABI regression coverage.

Hosted acceptance record (2026-09-17): Required CI run `35184246694` passed
Migration CI for commit `67bab5e`, and full CI run
`35184402760 <https://github.com/saadshabir/ZTAP/actions/runs/35184402760>`
passed all required jobs, including `eBPF Verification (Linux)`,
`Capability-only Agent (Kubernetes)`, and `All Checks Passed`. The reviewed
`ebpf-engine-evidence` artifact contains the cgroup-v2/BPF preflight and passing
direction, IPv6, reply, epoch, failed-candidate, rollback, quiescence, and
repeated Apply/Close cleanup tests. The reviewed `capability-agent-evidence`
artifact confirms the non-privileged capability-only security context,
`CapEff=000000c001001000`, successful native cgroup classification with zero
unresolved running containers, an allowed unselected control path, and a
blocked selected client with the expected default-deny counter.

The resolver explicitly supports both exact containerd/systemd forms observed
in the supported Linux environments: the root `kubepods.slice` hierarchy and
the kubelet-scoped `kubelet.slice/kubelet-kubepods.slice` hierarchy. Both remain
confined beneath `--cgroup-root` and require the full
`cri-containerd-<64-hex>.scope` basename.

Work:

- [x] Introduce `Engine.Apply` and `Engine.Close`.
- [x] Change enforced cgroups to a direction bitmask.
- [x] Remove global/default enforcement semantics from the eBPF C program.
- [x] Remove permissive and exact-map compatibility programs.
- [x] Implement bounds-checked IPv4 TCP/UDP parsing and explicit isolated-direction IPv6 denial using the packet offsets proven in Phase 0.
- [x] Implement node/self bypasses, quarantine precedence, and the epoch-scoped LRU reply-connection map.
- [x] Keep the flow ring and aggregate decision counters stable for the engine lifetime.
- [x] Implement two-slot candidate population, atomic slot-plus-epoch commit, partial-write cleanup, and old-slot garbage collection.
- [x] Update and regenerate bindings.
- [x] Adapt Linux integration tests to native compiled inputs.

Exit criteria:

- [x] Direction-specific default deny is verified.
- [x] Unselected cgroups remain allowed.
- [x] Reply traffic, documented Node-status traffic, and self traffic match the stated `v0.1.0` semantics.
- [x] Failed candidate population or configuration flip leaves the old rules active for already classified cgroups.
- [x] A successful slot-plus-epoch flip makes no mixed old/new policy state observable and invalidates old connection state logically, including after slot reuse.
- [x] Repeated apply/close cycles pass race and leak checks.
- [x] Generated sources are reproducible.

### Phase 3: Direct Kubernetes agent

Progress (2026-09-17): The core Phase 3 implementation slice is in place,
starting with the flow surface cutover. `ztap flows` is now a live stream of
the node-local pinned eBPF ring buffer: the compatibility recent/demo mode,
`--follow`, `--limit`,
non-Linux readers, and synthetic command output are removed. The command
accepts only the documented action, TCP/UDP protocol, direction, output, and
run-directory options, acquires the node flow-reader lock, and returns
distinct errors for lock, pinned-map, inactive-agent, and reader failures.
The shared flow monitor now closes subscribers and exposes terminal reader
errors, so an inactive or stopped agent cannot leave a flow command hanging.
The Kubernetes resolver also treats a running Pod without a reported CRI
container ID as pending (and excludes it from the unresolved-running gauge),
while a known container ID whose exact cgroup cannot be resolved remains a
candidate-blocking resolution error.
The direct-agent retry loop now uses exponential backoff from one second to a
one-minute cap, and the one-item dirty queue has an explicit burst-coalescing
regression test. Snapshot coverage exercises policy add/delete, local Pod label
changes, Namespace selector-label changes, Node address changes, and the
restored desired state across those updates. Startup cancellation during the
initial cache/engine reconciliation now exits without reporting a spurious
apply failure.
The reconciliation loop is now isolated from informer and engine setup, with
coverage for a rejected local policy becoming ready again after correction or
deletion while an unrelated accepted policy remains applied. A fake informer
source also covers a missed watch followed by relist and confirms that the
updated cache object signals the bounded dirty queue; a relisted Pod is also
run through the immutable snapshot and compiler-to-engine boundary.
The Linux-only relist tests (`TestNativeAgentRelistReconcilesUpdatedPodSnapshot`
and `TestNativeAgentPolicyInformerConvergesAddUpdateDeleteRelist`) provide the
full source-level add/update/delete/relist coverage for both Pod and
NetworkPolicy informer paths; execution remains part of the hosted acceptance
gate. The existing Linux `test-go` job runs these tests through
`go test ./... -race`, while the privileged `ebpf-verification` job runs the
`TestLinuxEngine...` flow-continuity coverage against real cgroups, packets,
and the persistent ring map. Hosted run `35301646083` passed the Linux race
suite, privileged eBPF verification, the kind capability-only agent smoke test,
and the aggregate `All Checks Passed` gate.
The production agent now uses a dedicated field-filtered local Node informer;
policy, Pod, and Namespace informers remain cluster-wide for peer resolution.
The client-go request path has a regression test that verifies the Node list is
constrained to `metadata.name=<node-name>`.
Recovery coverage now injects a kernel-apply failure and verifies that the
engine retains its last-known-good candidate, reports `apply_error`, and
recovers on the next object-triggered reconciliation.
The retry regression also verifies timer-driven recovery without a second
Kubernetes event.
The shared flow monitor now gates reader startup against monitor ownership, so
an immediate `Stop` cannot let a reader begin after shutdown; the lifecycle
regression passes under the race detector. It also tags each monitor run so a
stale event processor from a fast stop/start cannot close subscribers or mark
the replacement run stopped, mutate its statistics, deliver late events, or
publish a stale reader error; the restart regression passes under the race
detector as well. `Stop` now waits for the owned reader goroutine to unwind,
and a replacement `Start` waits for the previous reader generation before
launching; the new shutdown/restart regression passes under the race detector.
Startup cancellation during informer synchronization now exits cleanly instead
of returning `context.Canceled`, with a Linux regression test for the signal
shutdown path. Cache synchronization also has a bounded one-minute startup
deadline, so a persistent Kubernetes list/watch failure returns an explicit
fatal error instead of leaving the agent blocked indefinitely; both timeout
and cancellation paths have Linux regressions.
The Phase 3 review also gives the informers a separately cancellable context,
so a cache-sync timeout or initial reconciliation failure stops their workers
before `Shutdown` waits for them. A Linux regression covers the initial-failure
return path. On non-Linux hosts, `ztap flows` now reports platform support
before trying to create the flow-reader lock directory. The reconciliation
debounce now uses one fixed window after the first dirty signal so sustained
informer activity cannot postpone a policy apply indefinitely. Unexpected
Linux ring-buffer read failures now terminate the live stream with an error
instead of looping and hiding a persistent reader failure.
Focused macOS-compatible `go test ./internal/flow` and `go test ./internal/cli`
pass on the development host. The latest repository-wide `go test -race ./...`
run also passes with the host networking/filesystem permissions required by the
existing listener and audit-log tests, including the monitor restart guard;
`go vet ./...` and `git diff --check` pass as well.
The Linux-specific Phase 3 test binary cross-compiles for `linux/amd64` and
`linux/arm64`; the integration-tagged CLI and enforcer test binaries also
compile for both architectures. The execution and the real eBPF/kind
flow-continuity checks passed in hosted run `35301646083`; they remain hosted
Linux evidence rather than macOS claims.
Implementation accounting is currently 10/10 Phase 3 work items complete and
9/9 exit criteria covered by local and hosted tests.

Work:

- [x] Implement NetworkPolicy, Pod, Namespace, and local Node informer caches and immutable snapshots. The foundation was delivered with the Phase 2 agent wiring and is now covered by the Phase 3 convergence tests.
- [x] Implement local-node subject resolution, containerd/systemd cgroup lookup, cluster-wide IPv4 peer resolution, and explicit ClusterIP/IPBlock behavior.
- [x] Add the bounded reconciliation queue and debounce.
- [x] Wire compiler results into the engine.
- [x] Implement dry-run behavior, per-subject quarantine, and last-known-good state for kernel-application failure.
- [x] Implement health/readiness state and metrics.
- [x] Wire signal-based shutdown.
- [x] Convert `ztap flows` to real streaming only; remove the command's
  compatibility recent/demo path and propagate pinned-reader termination
  errors.
- [x] Treat running Pods without reported container IDs as pending, count only
  known-ID cgroup failures as unresolved, and add one-snapshot convergence
  coverage for policy, Pod, Namespace, and Node changes.
- [x] Add bounded exponential retry backoff for transient direct-agent
  reconciliation failures.
- [x] Compile the Linux Phase 3 test binaries for amd64 and arm64, including
  integration-tagged CLI and enforcer tests. Compilation is complete, and
  hosted run `35301646083` passed the runtime convergence and real eBPF
  flow-continuity gates.

Exit criteria:

- [x] Add/update/delete/relist tests converge to the expected policy set. The
  Linux hosted test suite passed in run `35301646083`.
- [x] Pod and namespace label changes trigger correct recompilation.
- [x] Node address changes trigger correct recompilation.
- [x] Selector peers do not infer Service frontends; explicit ClusterIP `ipBlock` rules match only the address and numeric port visible at the hook.
- [x] A rejected policy quarantines its selected local subjects, makes readiness false, and does not prevent unrelated accepted policies from updating.
- [x] Deleting or correcting the rejected policy removes quarantine without restart.
- [x] Dry-run remains healthy but never reports readiness or active enforcement.
- [x] Pod-start classification delay is measured and reported separately from reconciliation duration.
- [x] Flow streaming continues across policy replacements. The privileged
  eBPF verification passed in hosted run `35301646083`.

### Phase 4: Product cutover and deletion

Progress (2026-09-19): The product cutover is implemented. The
command surface exposes only `agent`, `validate`, `flows`, and `version`; the
legacy file configuration, logging wrapper, cluster/control-plane, cloud,
auth, audit, compliance, anomaly, operator, discovery, and platform-specific
enforcement packages and assets are removed. The retained native compiler,
instance-owned eBPF engine, Linux flow reader, and Kubernetes agent use the
canonical module path and standard-library `slog`. The repository now has one
DaemonSet manifest, one scratch runtime image, one retained eBPF program, and
the four maintained documents. Local race, vet, build, Linux cross-compile,
integration-tag compilation, manifest, CLI-help, dependency, and actionlint
checks pass. Hosted run `35418652492` passed the required lint, build, Docker,
unit, integration, eBPF, kind capability-only agent, and aggregate checks; the
`ebpf-engine-evidence` and `capability-agent-evidence` artifacts were uploaded.
Those acceptance checks are execution-only on Linux and are not macOS
implementation gaps.

Review follow-up (2026-09-18): The release-path review is resolved locally.
The image builder now consumes Docker's target OS and architecture, the
deployment guide builds and publishes the same multi-architecture registry tag
with release metadata, and Cobra keeps `help` and `completion` callable under
their standard names while hiding them from the primary command list. Focused
CLI tests, the full unit suite, race tests, vet, and Linux amd64/arm64
cross-builds pass. Docker image execution and privileged Kubernetes/eBPF
behavior remain hosted Linux checks.

Work:

- [x] Make the new `agent`, `validate`, `flows`, and `version` commands the only primary commands.
- [x] Delete the retained-source feature areas listed in the removal inventory.
- [x] Delete the custom config system and use explicit flags.
- [x] Migrate retained logging calls to `slog` and remove the wrapper.
- [x] Remove old deployment assets and produce the single DaemonSet manifest.
- [x] Replace the runtime image with the single minimal image.
- [x] Remove unused direct dependencies and run `go mod tidy`.
- [x] Change the module path.

Exit criteria:

- [x] `ztap --help` lists only `agent`, `validate`, `flows`, and `version`; Cobra's `help` and `completion` commands remain callable but hidden from the primary command list.
- [x] `rg` finds no source or maintained-documentation references to removed commands, APIs, config keys, CRDs, platforms, or services outside this temporary plan and the breaking-change record.
- [x] `go list -deps ./...` contains none of the removed direct dependency families: cloud SDKs, AWS/Azure/GCP clients, etcd, gRPC, SQLite, or controller-runtime. Kubernetes's transitive protobuf and `go-logr` packages remain because `client-go` requires them.
- [x] `go build ./...` and `make build` pass; the latter writes only `bin/ztap`, and `make clean` removes it without creating a repository-root executable.
- [x] Hosted run `35418652492` reports `Required CI` success and records Linux eBPF and kind capability-only agent evidence for this exact diff.

The `main` branch-protection rule was inspected on 2026-09-18 and still
requires `Required CI` from GitHub Actions. The replacement retains the
`Migration CI` workflow file/name and `Required CI` job name. Phase 4 remains
closed by hosted run `35418652492`, which confirms that check is reported and
that `ebpf-engine-evidence` and `capability-agent-evidence` are available. The
target-architecture image build remains a Phase 5 release gate. Non-Linux
checks cannot establish the kernel and container-runtime claims.

### Phase 5: Documentation, tooling, and release gate

Progress (2026-09-19): Phase 5 implementation has started. The maintained
README and guides now state the experimental Linux/Kubernetes contract,
architecture, runtime limitations, digest-based deployment, migration warning,
and contribution workflow. The final `Migration CI` shape now includes
`govulncheck`, pinned generated-code checks, retained-example and manifest
validation including the documented stdin validator path, containerized offline
validation, built-image scanning, and an explicit `Required CI` status
aggregation that treats unexpected skips as failures. The duplicate security
workflows were removed, Dependabot was narrowed to monthly Go, Docker, and
GitHub Actions updates, and a tag-only release workflow now verifies protected
`main` ancestry plus the final CI, privileged eBPF, and capability-only agent
checks before publishing GoReleaser artifacts, one multi-architecture image,
and an immutable install manifest. The release workflow now validates the
multi-architecture image and the exact `Required CI` branch-protection
context in both GitHub required-status representations as the only required
branch-protection check before GoReleaser can publish binaries, binds the final
check results to the successful `Migration CI` push run for the exact tagged
commit, and invokes the checked-in
`.goreleaser.yaml` explicitly. The resolved trusted workflow run ID is passed
through the release job dependency and retained in the performance environment
record, so hosted evidence downloads cannot silently re-resolve a different
successful run for the same SHA. Local syntax,
race, build, vet, CLI smoke, validator-example, manifest, and cleanup
verification now pass, and the aggregate non-privileged `make check` target
passes with zero golangci-lint issues and clean actionlint output. The
unprivileged Linux job compiles the enforcer and
native-agent integration-tag suites; the Linux build-assets job also exercises
the documented `make docker` target in addition to the separately scanned
Buildx image gate; local Linux amd64/arm64 integration-tag binaries also cross-compile
successfully, while the dedicated eBPF job remains the only runtime executor.
Linux-targeted `go vet -tags=integration` also passes for both tagged packages.
Pinned `golangci-lint`, `actionlint`, and `make check-generated` pass locally;
CI continues to use the pinned `clang-18` spelling.
The new `make performance` target correctly refuses to run on this macOS host;
its Linux integration-tag binary compiles successfully, but no real-cgroup
performance result exists locally.
`make check-generated` now resolves the installed Homebrew LLVM 18 compiler at
`/opt/homebrew/opt/llvm@18/bin/clang` automatically when `clang-18` is not on
the macOS `PATH`, matching the pinned CI toolchain; the CI spelling remains
`clang-18`. Docker, kind, and privileged Linux execution remain hosted or
tool-install gates because this macOS checkout has neither those runtime
prerequisites nor the hosted Linux environment. The pinned
`govulncheck@v1.1.4` dependency scan passes locally with no reported
vulnerabilities; the image/Trivy scan remains hosted.
The supporting compiler benchmark now protects and measures the
250-Pod/25-policy/2,500-rule shape; the 2026-09-19 local Apple M4 run completed
three samples at roughly 1.04--1.08 ms, 1.70 MiB, and 11,250 allocations per
compile. Those macOS samples are not release evidence because Section 14.5
requires real Linux cgroups, packets, and resource measurements. A manual
Linux `make performance` harness now runs in
the documented 2-vCPU reference profile (release processes are pinned to CPUs
0 and 1 with `GOMAXPROCS=2`), creates the same subject/rule shape in real
cgroups, measures three warm engine-apply samples, emits raw JSON, and
enforces only the direct engine-apply budget. The same harness applies that
full 250-subject/25-policy/2,500-rule policy set before selecting one subject
for flow measurement, then drives one alternating real-cgroup UDP decision per
millisecond at the documented
1,000-decisions/second target and reconciles delivered events with the
rate-limited and ring-full counters after an unrecorded warm-up interval,
checking every decision and drop counter identity for monotonicity before
summing deltas. The identity-keyed counter-delta helpers and their reset,
shape-drift, and overflow regressions also run in the ordinary package unit
suite, so the accounting guard is exercised on the development host as well
as compiled into the Linux harness;
delivered records are filtered to the post-warm-up policy epoch so late warm-up
events cannot inflate the accounting. A Linux-only native-agent harness now
starts the actual Kubernetes reconciliation loop against the same fixture,
resolves exact containerd/systemd cgroups, applies the first native policy, and
retains three initial-activation samples in `dist/phase5-agent.json`. It also
reads the actual compile-and-apply reconciliation duration after cache
synchronization, retains three samples in `dist/phase5-agent-reconcile.json`,
and enforces the Section 14.5 2-second p95 budget. It then updates a policy
through the synchronized fake informer cache three times and
retains the active-epoch samples in `dist/phase5-agent-event.json`. It also
measures three newly running Pods entering the next active policy and retains
`dist/phase5-agent-pod-start.json`; this excludes API-server and
container-runtime startup latency. It also records orderly process-owned stop/replacement gaps in
`dist/phase5-agent-restart.json`; this does not claim SIGKILL or DaemonSet
rolling-update evidence. A separate crash harness applies the full
250-Pod/25-policy/2,500-rule fixture, SIGKILLs a child process owning the
engine links, and records the first allowed UDP packet after link detachment
in `dist/phase5-agent-crash.json`; Kubernetes restart scheduling and DaemonSet
rollout remain excluded. The kind capability-agent job first
constrains its control-plane reference node to a 2-vCPU cgroup quota. It
asserts that the selected smoke client is denied, then restarts the shipped
DaemonSet and records the first successful selected-smoke
client probe plus the recovery point after two successive blocked probes in
`rolling-fail-open-evidence.txt`. It creates and classifies the real
250-Pod/25-policy/2,500-rule fixture, samples the shipped agent container's
cgroup CPU and `memory.current` counters for three quiet five-second intervals,
polls `memory.current` every 100 milliseconds, retains each interval's peak,
enforces the 0.10-core/200-MiB budgets, and retains
`phase5-reference-fixture.yaml`,
`capability-agent-reference-fixture.txt`, and
`capability-agent-resource.txt`; these are real kind-cluster measurements
from the full reference fixture, while hosted execution is still required for
the result; the kind job now deletes its disposable cluster after evidence
upload even when a gate fails. The fixture generator derives 250 Pods, 25 policies, 10 selected
Pods per policy, and 10 peers per policy, and the resource gate now requires
the resulting 2,500 compiled rules exactly; the generated NetworkPolicy
documents now pass the shipped scratch image's offline validator, and a
client-side dry-run plus offline object/peer-entry count check confirms that
shape before cluster application. The tag-only release workflow runs all performance
harnesses and retains their raw evidence before publication, including
calculated bounded-map capacity bytes, explicit unbounded cgroup-storage
metadata, and kernel-reported map memlock where available;
the reference engine gate establishes map count, types, and configured
capacities after warm-up, retains each warm-up/apply map snapshot, and verifies
that those capacities and available memlock do not grow across repeated
applies;
it also runs a Linux-only helper that samples the active agent's CPU and RSS
for three quiet five-second intervals, enforces the 0.10-core/200-MiB bound
for the test fixture, derives CPU from the measured process tick delta rather
than a fabricated zero value, and retains `dist/phase5-agent-resource.json`.
That helper excludes kernel-map memory and a real API server, so it remains
supporting evidence separate from the fail-closed kind resource gate; the
DaemonSet rolling-update gate remains open, and hosted execution is required
before the resource, rolling-update, and crash evidence is accepted.
Hosted release-gate evidence and execution of the remaining Section 14.5
measurements remain open. A packet-path harness now
compares three real-loopback UDP/TCP samples from one selected subject while
the full 250-subject/2,500-rule engine state is resident, with the cgroup
programs detached and attached. It retains `dist/phase5-packet.json` and
enforces the documented 10-microsecond UDP p99 delta and 10-percent TCP
throughput budgets; rolling-update evidence remains open, while the resource
and crash results still require hosted execution.
The packet-path run performs one unrecorded detached/attached warm-up pass
before retaining its three UDP/TCP samples. The release performance artifact
also retains `phase5-environment.txt` with
the runner's Go, architecture, CPU, kernel, cgroup, and bpffs metadata; the
release gate verifies its recorded Linux/amd64, cgroup-v2, bpffs, `0,1` CPU
affinity, `GOMAXPROCS=2`, positive clock-tick rate, host CPU/kernel metadata,
and two-CPU profile before
publication. The published image uses only explicit release-version aliases,
never `:latest`, and the release gate compares the pushed manifest digest with
the digest rendered into the immutable install manifest. It also parses the raw
registry index to require exactly two runnable descriptors consisting of one
Linux amd64 and one Linux arm64 manifest, requires an attestation descriptor
from the enabled SBOM/provenance build, and verifies that both explicit release
aliases resolve to that same digest. It bundles the
trusted same-commit eBPF and capability-agent artifacts from
`Migration CI`, and attaches the complete raw bundle as
`ztap-<tag>-phase5-evidence.tar.gz` to the GitHub release; the archive is staged
in the runner's temporary directory outside GoReleaser's cleanable `dist/`
directory so publication cannot delete it before upload or leave checkout
debris. Before attachment, the release job also checks content markers for the
privileged eBPF pass, capability-only smoke enforcement, exact fixture shape,
`memory.current` resource sampling and budget success, and the rolling
fail-open interval. The GoReleaser job
fails closed if the hosted eBPF, capability-agent fixture/resource, or
rolling-update evidence files are missing from that bundle.
The capability smoke now exercises the user-facing `ztap flows` reader against
the pinned flow map, and the checked-in verifier performs those hosted checks
as well, including the flow-streaming and offline-validator results, exact
250-Pod/25-policy/2,500-rule fixture, resource-budget values, and rolling
fail-open timestamp arithmetic.
Each required hosted pass marker must occur exactly once, so a duplicated or
contradictory transcript cannot satisfy the release gate by presence alone.
The raw performance log applies the same exact-once rule to each structured
`go test -v` harness pass marker, rejecting prefixed or duplicated test names
both before upload and during the GoReleaser recheck.
The GoReleaser job independently stages and reruns that verifier against the
downloaded bundle, rejects symlink/non-regular entries and duplicate evidence
filenames while staging it, and
binds verification to the tagged commit, release run ID, and trusted Migration
CI run ID before publication; the performance job's required local evidence
list enumerates the ten JSON artifacts exactly once before upload and requires
an exact `go test -v` pass marker for every one of the ten retained Phase 5
harnesses. The GoReleaser recheck repeats those raw-log marker checks before
publication. The release action now installs the exact
GoReleaser `v2.9.0` tool version rather than resolving a floating v2 release.
The fixture transcript check also requires the expected API versions,
`ztap-performance` namespace entries, Pod and NetworkPolicy name prefixes,
and the complete zero-padded Pod and NetworkPolicy name sets plus per-object
bucket markers. The kind fixture generator emits those markers on both the
Pod and NetworkPolicy objects, so a transcript with only matching totals is
rejected; the verifier checks each document's kind-specific API version and
namespace, counts the object-label indentation rather than the repeated
policy-selector fields, validates each policy's selector bucket and exactly
ten peer CIDRs, and regression tests cover omitted markers and per-policy
bucket/peer-shape corruption.
Every fixture document is also parsed as strict, depth-bounded YAML before the
textual shape checks, so duplicate mapping keys, non-string mapping keys,
anchors, aliases, merge keys, malformed or excessively nested documents cannot
hide behind otherwise matching line counts.
The verifier reads names and namespaces from `metadata`, bucket markers from
the object metadata and policy selector mappings, policy types and the TCP port
from their structured `spec` paths, and peers from the structured
`spec.egress[].to[].ipBlock.cidr` sequence rather than accepting those values
from arbitrary matching lines.
Hosted evidence discovery and the direct JSON, environment, and hosted-evidence
readers reject symlink roots/files and non-regular paths before reading their
content; bounded readers reject hosted evidence over the 4 MiB limit without
loading the entire artifact first.
The hosted resource verifier also requires the exact reference-fixture scope,
the quiet-interval transition marker, the shipped `ztap-system` namespace and
`ztap-agent-` Pod identity, and a cgroup path under `/sys/fs/cgroup/`, in
addition to the three ordered
sample records with at least the documented five-second elapsed intervals, raw
CPU-usec and `memory.current` byte counters, a 100-ms memory-peak polling
interval, and parseable derived CPU and memory values. Each sample records its
observed peak memory counter, and the verifier requires that peak to cover both
endpoint readings before recomputing the derived value and the reported
`memory.current` maximum. Resource and rolling transcripts use closed key/value
schemas: malformed lines, unknown keys, and duplicate non-sample keys fail
closed instead of being silently ignored. The verifier rejects CPU counter
resets, recomputes each derived sample, and recomputes the reported CPU and
`memory.current` maxima from those records before applying the budgets.
Rolling evidence must also identify distinct old and replacement Pods and
Kubernetes UIDs, plus a positive, millisecond-resolvable fail-open interval.
The release performance job also validates all ten local JSON artifacts for
Linux/two-CPU environment metadata, fixture shape, sample counts, budgets, and
flow-accounting invariants before the GoReleaser job can publish. The verifier
also recomputes reported maxima and packet aggregates, requires the documented
budget constants, and checks that elapsed and packet measurements are positive,
that the flow decision rate is bounded by the recorded one-packet-per-millisecond
duration, that the recorded duration stays within a fixed five-second tolerance
of the documented 60-second run, and that the native-agent resource artifact has
the exact fixture shape; the privileged
performance step restores workspace ownership before validation.
The verifier now decodes the producer schema strictly, rejects unknown or
case-variant fields, duplicate JSON object keys, multiple JSON values, and
excessive nesting, and
requires RFC3339 evidence timestamps so a malformed or schema-drifting artifact
cannot pass the release gate silently. It also recomputes map shape and
adjacent-snapshot memlock stability from the
retained, ordered `before_warmup`, `after_warmup`, and three `after_apply_*`
snapshots instead of trusting only the producer's summary flag, and binds the
final summary's memlock readings exactly to its retained final snapshot; an
available kernel-memlock reading must also be positive, while an unavailable
reading must carry zero observed bytes. It independently recomputes each
reported map-capacity byte count from the map type, configured entry/key/value
sizes, and recorded CPU profile, and requires every artifact's producer
provenance fields (kernel-path/traffic scope, kernel release, and absolute
agent roots where emitted) to be present. Bounded map entries must use a
recognized type and unique sorted name; the reference artifact must also carry
the exact generated engine map inventory, dimensions, and configured
capacities; the cgroup-storage map is represented as an explicit unbounded
zero-capacity entry rather than being fabricated into a bounded capacity.
The ten retained JSON artifacts now also require the exact checked-in producer
scope literal for their kernel path or measurement path; a merely non-empty or
caller-reworded scope cannot detach a budget from the real harness that
produced it. Focused verifier regressions mutate every retained scope and
confirm the complete bundle is rejected, while the privileged Linux evidence
itself remains a hosted gate.
The verifier also cross-checks all ten JSON artifacts for one run ID, Go
version, Linux architecture, and the exact two-CPU profile, and cross-checks the native-agent
artifacts for one kernel release so measurements cannot be mixed from different
environments or same-host runs. `make performance` enforces `GOMAXPROCS=2` and
creates the shared run ID; it removes only its ten named JSON outputs before
starting, so a failed rerun cannot leave stale measurements available to the
verifier;
the release workflow binds it to the GitHub run, semantic release ref, release
workflow/event, and tagged commit in the retained environment record and
records the exact trusted `Migration CI` run ID used for hosted evidence,
together with the migration workflow, event, and branch provenance used to
resolve it. Individual artifact validation also rejects a
missing run ID before the set-level comparison, and release validation passes
the expected run IDs and commit into `phase5verify`, which now parses and
validates the retained environment record, including its allowed key schema,
and cross-checks its Phase 5 run ID, Go version, Linux target, and reference
CPU count against `phase5-performance.json`, so the JSON set is bound to the
release provenance rather than merely internally consistent.
The retained host metadata is also checked for a Linux Go target, Linux
`uname` record, positive host CPU count, and a valid two-field cgroup CPU quota
before it can satisfy the release gate; the recorded host CPU count must also
be at least the two CPUs used by the pinned reference process.
The native-agent event loop also gives caller cancellation priority over a
simultaneous status-listener error, keeping deliberate shutdown from being
reported as an agent failure.
The merge gate now reruns `go mod tidy` and fails on any `go.mod` or `go.sum`
diff, keeping the dependency cleanup reproducible after future edits.
The fixed-size binary flow-event decoder now has a fuzz target with malformed-size
and schema seeds plus valid-event conversion coverage; the decoder rejects unknown
inputs before touching fixed offsets and the conversion path remains bounded by the
72-byte event shape.
The live branch-protection record was verified with the configured GitHub CLI
token and reports the exact strict `Required CI` context in both the legacy
`contexts` and modern `checks` arrays; the release workflow still requires the
repository secret `BRANCH_PROTECTION_TOKEN` with
Administration-read permission, rejects stale required contexts, restores
workspace ownership even after a failed privileged measurement, and remains
fail-closed until that external verification succeeds.

Hosted CI audit (2026-09-19): Migration CI push run `35420910387` for
committed revision `5eda8d7d2124f25acc1c1c997305550a542e0f66` completed
successfully with lint, actionlint, zizmor, Linux unit/race, integration,
Docker, eBPF, capability-only kind, cross-architecture build, and `Required CI`
jobs successful. This supports the committed baseline only; the working tree
still contains newer uncommitted Phase 5 workflow and verifier edits, and the
real performance/release publication gates remain open.

The final acceptance audit now marks only the product-surface and tracked-binary
items directly supported by the current source review and local tests. Kernel,
container-runtime, hosted branch-protection, and release-evidence items remain
unchecked until their scoped gates execute.

Local contract audit (2026-09-19): the native validator and compiler accept
only IPv4 policy peers with numeric TCP/UDP ports, reject named ports,
`endPort`, SCTP, IPv6, dual-stack policy data, and broad peerless/portless
rules, and the retained flow/parser paths report unsupported traffic as an
explicit deny rather than providing an alternate enforcement backend. The
focused policy tests, CLI smoke validation, and maintained-document review
support the first-release surface; privileged packet execution remains covered
by the hosted gate below.

Repository cleanup audit (2026-09-19): `make clean` completed successfully and
the subsequent `git status --ignored --short` showed no ignored build/test/
coverage debris. The working-tree path audit also found no removed internal
feature directories or obsolete operator/anomaly/proto/buf/compose/cloud/
audit/compliance assets, and the dependency graph contains none of the removed
cloud, etcd, gRPC, SQLite, or controller-runtime families.
Maintained-document searches found no stale claims of the removed REST, gRPC,
cloud, etcd, anomaly, audit, compliance, macOS, Windows, or iptables support;
the remaining CRD/operator references are explicit migration warnings.

Branch-protection verification (2026-09-19): the live GitHub protection record
for `main` reports strict required-status checks with the exact `Required CI`
context in both `contexts` and `checks` (check app id `15368`).

Continuation audit (2026-09-20): release verification now passes the current
semantic tag from `GITHUB_REF_NAME` into both the performance-job verifier and
the GoReleaser re-verification, and rejects retained environment evidence whose
`release_ref` differs from that tag. Focused provenance tests, the full unit and
race suites, `go vet`, formatting, diff, module-tidy, generated-code, workflow
YAML, pinned `golangci-lint`/`actionlint`, pinned `govulncheck@v1.1.4`, and
Linux amd64/arm64 cross-compilation checks pass locally; `make check` also
passes end to end. The image vulnerability scan, Docker, privileged
eBPF, kind, real-cgroup performance, and release-publication gates remain
hosted or tool-gated; no local result is being used to close those acceptance
items.

The pinned `zizmor` 1.16.3 audit also passed after the release performance job
stopped restoring `setup-go` dependency caches into the tag-publication path;
the cache-poisoning finding was fixed rather than suppressed. The release image
publication job also performs a cache-free BuildKit build, so neither Go nor
Docker publication artifacts restore mutable caches. Its pedantic audit also
passes after the single-image Docker job removed attacker-controlled matrix
interpolation and every non-default workflow permission received an inline
purpose comment. The GoReleaser job explicitly downloads and verifies the
checked-in Go module graph before re-verifying retained evidence instead of
relying on a lazy `go run` fetch during publication.
The performance job now rejects symlink and non-regular local or hosted
evidence entries before artifact upload as well as during GoReleaser staging.
The image-publication job also requires a 64-hex SHA-256 digest and exactly
one non-`:latest` image line in the rendered immutable install manifest. The
environment verifier also rejects a zero trusted Migration CI run ID and host
CPU metadata smaller than the exact two-CPU reference profile.

Continuation audit (2026-09-20): the retained environment verifier now
rejects a zero trusted `Migration CI` run ID and rejects host `nproc` metadata
below the exact two CPUs used by the pinned reference process. This closes an
inconsistent-environment path where a transcript could claim a two-CPU
measurement on a host that recorded fewer available CPUs. Focused verifier
tests, the full unit suite, race tests, `go vet`, formatting, module-tidy, and
diff checks pass with the repository-local Go cache. Hosted Linux execution,
real-cgroup performance, and release publication evidence remain open and are
not inferred from these local checks.

Continuation audit (2026-09-20): the live `ztap flows --output json` path now
serializes its machine-readable event record with the standard JSON encoder,
with regression coverage for quoted, escaped, and newline-containing string
fields. This keeps the retained flow-streaming transcript valid at the output
boundary if a future event label changes, while preserving the existing engine
metadata fields. Focused flow tests, the full unit suite, race tests, `go vet`,
formatting, module-tidy, and diff checks remain required locally; hosted flow
streaming and the other Linux/release gates remain open.

Continuation audit (2026-09-20): the live flow reader now rejects symlinked
bpffs roots, the `ztap` pin directory, and existing stable flow/status pin
entries before calling `ebpf.LoadPinnedMap`; missing pins still reach the
kernel loader so its actionable error is preserved. Linux reader regressions
cover all three indirection points and the Linux-targeted package compiles;
hosted pinned-map streaming and the remaining real-cgroup/release gates remain
open.

Continuation audit (2026-09-20): Linux CLI lock coverage now starts a child
test process for both the native-agent and live-flow-reader locks, kills the
child with `SIGKILL`, and verifies a replacement owner can acquire and release
the same lock. This directly exercises the kernel-owned descriptor lifetime
required for crash release rather than inferring it only from same-process
cleanup; the child retains the owner closure for the whole wait so the held
descriptor cannot be collected before the kill. The runtime test still
requires a Linux host.

Continuation audit (2026-09-20): both Linux node locks now create missing run
directory components without following symlinks, reject symlinked run
directories and lock files, require the lock to remain a regular file, and use
`O_NOFOLLOW` when opening it. Regression coverage exercises both lock names and
both indirection points; Linux-targeted compilation remains local evidence, so
the crash and hosted runtime gates still require Linux execution.

Continuation audit (2026-09-20): the eBPF packet path no longer permits an
unsupported IPv4 protocol to take the Node/self bypass before the isolated
direction's unsupported-deny decision. A privileged integration regression now
sends ICMP to an address present in both bypass sets and requires a blocked
`unsupported` event; generated bindings must be refreshed from the changed
source before the hosted packet gate can validate it.

Continuation audit (2026-09-20): the privileged packet suite now also injects
raw IPv4 packets from a test cgroup and requires isolated directions to emit
`fragment` for an incomplete IPv4 fragment and `malformed` for an invalid IP
version. These regressions exercise the parser's early-deny branches alongside
IPv6 and unsupported-protocol coverage; their runtime result still requires the
hosted Linux eBPF job.

Continuation audit (2026-09-20): external cancellation of the shared flow
monitor now follows the same lifecycle path as an explicit stop, closing
subscribers, waiting for the reader generation to unwind, and leaving the
monitor restartable. A regression covers cancellation followed by a fresh
start; hosted pinned-ring streaming and the remaining Linux/release gates stay
open.

Continuation audit (2026-09-20): engine pin cleanup now rejects a real
directory at either owned stable-pin name instead of allowing generic path
removal to delete an empty directory, while symlinks are unlinked without
following their targets. Startup stale-pin removal and shutdown cleanup share
the guard, with Linux regression coverage for directory preservation and safe
symlink unlinking; privileged engine execution and hosted release evidence
remain open.

Continuation audit (2026-09-20): release tags are now required to use
canonical numeric `vMAJOR.MINOR.PATCH` components without leading zeroes in
both the tag workflow and the Phase 5 provenance verifier. Focused verifier
coverage rejects non-canonical tags while retaining `v0.1.0` and ordinary
multi-digit releases; hosted publication evidence remains open.

Continuation audit (2026-09-20): the privileged packet suite now exercises
the unsupported-protocol bypass guard on ingress as well as egress. An ICMP
raw socket owned by the selected cgroup receives a packet sent from outside
that cgroup, and the test requires an ingress `unsupported` deny even when
both Node and self bypass addresses match. The Linux integration package now
compiles for amd64 and arm64, while the real privileged ingress result remains
hosted evidence.

Continuation audit (2026-09-20): standalone environment verification now
requires `release_commit` to be a full 40- or 64-character hexadecimal commit
ID even when no expected commit is supplied by the caller. Regression coverage
rejects a fabricated textual commit while preserving full SHA-1 and SHA-256
shapes, keeping release provenance structurally bound before an external
expected-commit comparison is applied.

Continuation audit (2026-09-20): Linux node-lock acquisition now walks the
validated run directory through directory file descriptors and opens the lock
with `openat`, `O_NOFOLLOW`, and `O_CLOEXEC`. This closes the parent-component
TOCTOU window left by path-only validation while retaining regular-file checks,
symlink rejection, and kernel-owned crash release; the existing lock
regressions remain in the Linux test suite and Linux-targeted compilation
passes, while their runtime and the crash gate remain hosted.

Continuation audit (2026-09-20): engine metrics now use the same checked
`uint64` counter summation discipline as the Phase 5 flow-accounting harness.
Per-CPU counter totals fail closed on overflow instead of wrapping into a
smaller metric value, and host-runnable regression coverage exercises both a
valid sum and the overflow boundary.

Continuation audit (2026-09-20): engine startup now creates the `ztap` bpffs
pin directory through a validated root descriptor and `mkdirat`/`openat` with
no-follow directory semantics. This closes the gap between stale-pin
validation and directory creation; Linux regression coverage verifies both
missing-directory creation and symlink rejection, while privileged engine
startup remains a hosted runtime gate.

Continuation audit (2026-09-20): owned engine-pin cleanup now opens the parent
directory and removes entries with `fstatat`/`unlinkat` no-follow semantics.
Shutdown and stale-pin removal therefore reject a replaced parent symlink and
preserve redirected targets, in addition to rejecting owned-name directories.
Linux regression coverage exercises the parent-indirection case.

Continuation audit (2026-09-20): graceful engine-pin cleanup now traverses all
parent components through the same descriptor-relative no-follow helper used by
startup. Intermediate parent replacement can no longer redirect `unlinkat` to
another directory; Linux regression coverage exercises that intermediate
component case while hosted engine shutdown remains open.

Continuation audit (2026-09-20): the Phase 5 environment-evidence reader now
limits the complete `phase5-environment.txt` input to 1 MiB before scanning
key/value records. This keeps release provenance bounded like the JSON and
hosted-evidence readers, with a regression covering oversized environment
artifacts; the hosted Linux and release-publication gates remain open.

Continuation audit (2026-09-20): startup stale-pin cleanup now opens the
validated `ztap` bpffs directory once with no-follow descriptor semantics and
removes both owned entries relative to that descriptor. This closes the
remaining replacement-directory window between path validation and per-pin
cleanup; Linux regression coverage rejects a symlinked cleanup directory and
preserves its target, while privileged startup and release evidence remain
hosted gates.

Continuation audit (2026-09-20): the hosted resource harness and release
verifier now reject a CPU-usec counter reset between adjacent five-second
samples, not only a decrease within one sample. This prevents a recreated or
reset cgroup from producing a fabricated low-CPU interval; regression coverage
exercises the inter-sample reset while memory.current remains allowed to vary
as a gauge.

Continuation audit (2026-09-20): the hosted capability-only resource gate and
release verifier now require exactly the 250 enforced cgroups represented by
the fixed reference fixture, rather than accepting a larger reported count.
This keeps the retained resource transcript bound to the documented
250-Pod/25-policy/2,500-rule shape; a verifier regression covers the
over-count case while the normal three-sample budget checks remain unchanged.

Continuation audit (2026-09-20): the native-agent resource sampler now
rejects overflow when combining `/proc` user/system CPU ticks or converting
resident pages to bytes. Regression coverage exercises both overflow paths
and an invalid page size, preventing wrapped process-resource evidence from
under-reporting the supporting CPU/RSS measurement.

Continuation audit (2026-09-21): the native-agent resource sampler now polls
RSS every 100 milliseconds during each quiet interval and retains the maximum
observed value, instead of comparing only the interval endpoints. Focused
host-runnable coverage protects the aggregation from dropping a peak that
occurs between the start and end samples; the sampler remains supporting
evidence separate from the authoritative hosted cgroup resource gate.

Continuation audit (2026-09-20): the real-cgroup engine map-memory sampler now
uses checked capacity arithmetic for bounded, per-CPU, ring-buffer, and
unbounded cgroup-storage maps, matching the release verifier's overflow rules.
Host-runnable tests cover valid map shapes, zero CPU metadata, and byte-total
overflow before the Linux harness can write wrapped capacity evidence.

Continuation audit (2026-09-20): release provenance now cross-checks the
native-agent resource artifact's recorded process clock-tick rate against the
retained environment `getconf CLK_TCK` value. A mismatch regression prevents a
resource transcript from using a different clock conversion while still
passing the standalone positive-value checks.

Continuation audit (2026-09-20): the standard-library release verifier now
opens JSON, environment, and hosted evidence files with Unix no-follow
semantics and validates the opened descriptor as a regular file. This closes
the final-file replacement window between the prior path check and read while
retaining a portable non-Unix build fallback.

Continuation audit (2026-09-20): the Linux release evidence opener now
traverses every parent component through no-follow directory descriptors
before opening the final file. This closes the parent-directory replacement
window left by final-component-only protection; Linux regression coverage
rejects a symlinked parent as well as a symlinked file and FIFO. The Darwin
development fallback retains final-component no-follow behavior so standard
macOS paths such as `/var` remain usable.

Continuation audit (2026-09-20): the ten Linux Phase 5 harness writers now
create their JSON outputs with exclusive, no-follow file creation instead of
overwriting an existing path. The Makefile's pre-run deletion remains the
only supported replacement path, so a stale or redirected output cannot be
silently accepted as fresh release evidence.

Continuation audit (2026-09-20): the Linux Phase 5 writers now also traverse
and create parent directories through no-follow descriptors before opening the
final output. Regression coverage rejects symlinked parents while preserving
creation of missing nested parents, closing the parent-path redirection path
left by final-file-only protection.

Continuation audit (2026-09-20): `make performance` now rejects a symlink or
non-directory at the `dist` evidence root before deleting the ten named JSON
outputs. This keeps the output-directory guard consistent with the harness
writers' exclusive file creation and prevents cleanup from being redirected
outside the checkout.

Continuation audit (2026-09-20): the Linux agent performance harness now
creates a supplied `ZTAP_PHASE5_AGENT_RUN_DIR` one component at a time with
the existing no-follow directory opener used by runtime locks, closing the
remaining run-directory symlink redirection path in the harness.

Continuation audit (2026-09-20): the native-agent Phase 5 cgroup fixture
lifecycle now validates existing directories through no-follow descriptors,
creates each fixture directory relative to a validated parent, and removes
only directory entries inspected through that parent. Integration regressions
cover symlinked parent/final paths and the normal create/remove lifecycle.

Continuation audit (2026-09-20): crash-harness process placement now opens
`cgroup.procs` relative to the validated cgroup descriptor with
`O_NOFOLLOW`; regressions cover both a redirected control file and a normal
relative write.

Continuation audit (2026-09-20): the tag release workflow now rejects a
symlinked or non-directory `dist` root and hosted-evidence subdirectory before
`gh run download`, and validates the immutable manifest output path before
rendering it, rejecting stale pre-existing output as well. This closes the workflow-side path redirection gap already
guarded by the local performance target and Linux writers.

The GoReleaser re-verification job applies the same no-symlink/non-directory
guard before downloading the retained raw performance bundle, so the second
publication-time evidence read cannot be redirected through a checked-out
`dist` path.

Continuation audit (2026-09-20): `make check-generated` now snapshots the
working-tree generated bindings before and after pinned regeneration instead of
comparing them directly with `HEAD`. It therefore validates reproducibility on
the intentionally dirty Phase 5 tree without rejecting synchronized generated
changes that belong to the current source diff.

Continuation audit (2026-09-20): the Phase 5 verifier now walks the complete
evidence tree, rejects any extra, duplicate, symlinked, or non-regular
`phase5-*.json` entry, rejects any symlinked evidence-tree entry, and requires
the exact ten named JSON artifacts. This prevents a producer or staging step
from silently adding a similarly named transcript that is never parsed by the
release verifier.

The GoReleaser raw-evidence staging step applies the same exact-set check before
creating the attached archive, so publication cannot retain a different JSON
bundle from the one independently re-verified.

Continuation audit (2026-09-20): Linux cgroup identity validation now requires
the resolved target to be a directory before returning its inode identity or
querying cgroup links. The linker and native resolver therefore fail closed
with an actionable target-type error for a regular-file substitution, while
the existing root-containment and inode-mismatch checks remain in place.
Ordinary-host regressions cover valid in-root directories, non-directory
targets, outside-root targets, and identity mismatches; privileged Linux and
release evidence gates remain open.

Continuation audit (2026-09-20): Linux cgroup attachment now retains the
descriptor opened during root-containment and inode validation instead of
reopening the resolved path through `link.AttachCgroup`. Attachment queries,
bpf-link creation, and the legacy `BPF_PROG_ATTACH` fallback all use that
validated descriptor; legacy fallback links retain their own duplicated
descriptor and cloned program for retryable cleanup. Linux-targeted compilation
and ordinary-host regression coverage pass; privileged attachment and hosted
release evidence remain open.

Continuation audit (2026-09-20): the DaemonSet rolling-update transcript now
retains the replacement Pod's Kubernetes creation timestamp and the first
post-restart observation timestamp. The verifier requires both timestamps to
fall after rollout start and no later than the measured fail-open interval end,
so distinct names and UIDs cannot be supplied by a pre-existing second Pod.
Focused hosted-verifier regressions and workflow syntax checks cover the new
provenance; the real kind rollout remains a hosted gate.

Continuation audit (2026-09-20): the rolling-update transcript now also binds
the replacement Pod to the old Pod's Kubernetes node. The verifier rejects a
cross-node DaemonSet Pod, closing the multi-node evidence substitution where a
pre-existing agent could otherwise satisfy the distinct-name and UID checks.
Focused verifier coverage and workflow syntax checks pass; the real kind
rollout remains a hosted gate.

Continuation audit (2026-09-20): the rolling probe now records the
`smoke-client` node and requires the selected old agent, replacement agent, and
measured client to share it. The verifier rejects an otherwise valid DaemonSet
rollout transcript gathered from an unrelated node; focused regressions, the
full non-privileged `make check` gate, and workflow syntax checks pass, while
the real kind rollout remains hosted.

Continuation audit (2026-09-20): the standalone Phase 5 JSON-directory
verifier now rejects every non-regular evidence-tree entry, not only a
non-regular file using a `phase5-*.json` name. This matches the release
workflow's pre-archive and downloaded-bundle checks and closes a direct-use
path where an unrelated FIFO or socket could remain in the retained evidence
tree; a Unix regression covers the FIFO case.

Continuation audit (2026-09-20): the privileged engine suite now covers
deleting the last policy selecting a real cgroup. The empty candidate clears
both policy slots, detaches the owned cgroup link without leaving an orphan,
and permits traffic to a port that the deleted policy had denied; Linux amd64
and arm64 integration-tag binaries compile, while execution remains a hosted
privileged gate.

Continuation audit (2026-09-20): the Linux amd64 and arm64 integration-tag
test binaries for both the enforcer and CLI packages compile from the current
Phase 5 source tree. The local policy, enforcer, flow, and standalone evidence
verifier suites pass; Docker, kind, privileged eBPF execution, and the
reference performance evidence remain hosted gates because this workstation
does not provide those tools.

Continuation audit (2026-09-20): flow-monitor subscriptions now treat a nil
context as an invalid subscription and return an already-closed channel before
registering a subscriber. This keeps the Phase 5 shutdown path free of
uncancellable subscribers and cancellation-goroutine panics; both the normal
and pre-start subscription APIs have regression coverage.

Continuation audit (2026-09-20): Linux Phase 5 agent performance helpers now
retain the HTTP status listener through startup and pass its descriptor into
the resource and crash helper subprocesses. This removes the close-and-reopen
port race from in-process and child-process reference samples; a Linux unit
regression covers the supplied-listener path and early-startup ownership
cleanup.

Continuation audit (2026-09-20): the pinned `govulncheck@v1.1.4` dependency
scan is now a stable `make vulncheck` target backed by the repository-local
`bin/tools` directory. The aggregate `make check` gate and Migration CI both
invoke that target, so the local and hosted vulnerability gates use the same
tool version and installation boundary instead of maintaining separate
commands.

Continuation audit (2026-09-20): the live flow reader now traverses the bpffs
root and `ztap` pin directory through descriptor-relative `O_NOFOLLOW`
handles, opens each stable pin with an `O_PATH` no-follow descriptor, and
loads the object through that retained descriptor. This removes the
check-then-open path-swap window while preserving distinct missing-pin and
symlink diagnostics, including rejection of symlinked intermediate root
components and invalid descriptor-relative pin names; Linux-targeted reader
tests and cross-compilation remain local evidence, while a real pinned-map
streaming run remains hosted.

Continuation audit (2026-09-20): engine startup and validated cgroup
attachment now reopen canonical bpffs and cgroup roots through
descriptor-relative no-follow traversal. Root-component substitution can no
longer redirect pin creation, stale-pin cleanup, or subject validation between
path validation and the final directory handle; Linux regression coverage
exercises the new helper, while privileged engine execution remains hosted.

Continuation audit (2026-09-20): `Migration CI` now runs both the pinned
`zizmor@1.16.3` default workflow audit and its `--pedantic` audit. Local
actionlint validation covers the added step; hosted zizmor execution remains
part of the workflow gate.

Continuation audit (2026-09-20): Phase 5 JSON evidence discovery now treats
case-variant `phase5-*.json` filenames as artifacts too, so an unexpected
`Phase5-...json` entry cannot sit beside the exact ten-file set unnoticed. The
release staging count uses the same case-insensitive pattern, and verifier
regression coverage rejects the variant locally.

Continuation audit (2026-09-20): the native-agent status server now enforces
the documented `GET`-only contract for `/healthz`, `/readyz`, and `/metrics`,
returning `405 Method Not Allowed` with `Allow: GET` for other methods. Direct
status-server shutdown also marks readiness `stopping` before closing the
listener, so a graceful teardown cannot continue to report an active agent;
Linux handler regressions cover both method rejection and the shutdown state.

Continuation audit (2026-09-20): flow-monitor subscriptions backed by a
non-cancellable context such as `context.Background()` no longer create a
goroutine that can never observe cancellation. The monitor still closes those
subscriptions during its normal stop/reader-termination lifecycle, and the
host-runnable flow tests cover the lifecycle explicitly.

Continuation audit (2026-09-20): standalone hosted-evidence discovery now
rejects every non-regular entry in each evidence tree, including unrelated
FIFOs or sockets rather than checking only the six required filenames. This
matches the release workflow's pre-archive guard and closes the direct verifier
path where an ignored special file could survive into an evidence bundle;
Darwin/Linux regression coverage exercises an unmatched FIFO.

Continuation audit (2026-09-20): the release performance job now validates
the root-level `phase5-environment.txt` and `phase5-performance.txt` output
paths before either `tee` command runs. Existing files, symlinks, and special
entries fail closed, so a checked-out or stale path cannot be touched before
the later evidence verifier rejects it; actionlint covers the workflow change.

Continuation audit (2026-09-20): the release performance job's environment
recording step now enables `set -euo pipefail` explicitly before collecting
host metadata and no longer masks failures from the required clock-tick or
cgroup-quota reads with `|| true`. The retained environment transcript is
therefore either produced from successful metadata commands or the job fails
before performance evidence is accepted; actionlint covers the workflow
change.

Continuation audit (2026-09-20): the hosted `Migration CI` eBPF and
capability-agent jobs now preflight every root-level evidence output before
their `tee`, append, copy, and diagnostic redirections run. Existing files,
symlinks, and special entries fail closed, including the capability-agent
fixture copy and later smoke-log append; this prevents a checked-out or stale
path from being touched before artifact validation.

Continuation audit (2026-09-20): the tag workflow now preflights the
GoReleaser `release-notes.md` output before extracting or synthesizing notes.
An existing, symlinked, or special path fails closed instead of being
overwritten by the release job.

Continuation audit (2026-09-20): privileged engine integration coverage now
also exercises deletion of one contribution from an additive selected policy
set. The retained rule stays allowed after the epoch flip, the deleted rule
becomes default-deny, and the cgroup link set remains singular with no orphan
links; hosted execution remains required for the kernel-path result.

Continuation audit (2026-09-20): the hosted reference-fixture verifier now
requires the exact Pod workload shape emitted by `Migration CI` (one
`busybox:1.36.1` container with the pinned pull policy and sleep command) and
rejects extra Pod runtime fields. The same exact-field-set checking now covers
the Namespace, Pod metadata, NetworkPolicy metadata/spec, selector, peer, and
port mappings, so a semantically changed or expanded fixture cannot pass from
aggregate counts alone; the workflow's real kind fixture remains a hosted
gate.

Continuation audit (2026-09-20): the Phase 5 robustness suite now includes
bounded seed-only fuzz targets for hosted YAML document splitting/strict
decoding and IPv4 `ipBlock` exclusion expansion. The fuzz targets exercise
malformed input without changing the ordinary CI contract, while successful
IPBlock expansions are checked for bounded, sorted, non-overlapping prefixes
inside the base CIDR and outside valid exclusions.

Continuation audit (2026-09-20): every Linux real-cgroup integration helper
now places its child process through `cgroup.procs` opened relative to the
descriptor that passed cgroup-root containment and inode validation. The
packet and ordinary integration measurements therefore receive the same
no-follow control-file protection already used by the crash harness; Linux
privileged execution remains a hosted gate.

Continuation audit (2026-09-20): hosted resource and rolling-update
transcripts now use closed structured key/value contracts. The kind workflow
records the exact reference-fixture status, agent/container/cgroup identity,
and redirects expected rollout-probe command output so malformed or unknown
lines cannot be silently ignored. The verifier rejects malformed records,
unknown keys, duplicate non-sample keys, non-reference fixture scope, and
cgroup paths outside `/sys/fs/cgroup/`; focused regressions cover malformed and
unexpected records while hosted execution remains open.

Continuation audit (2026-09-20): the hosted resource probe now validates the
container runtime ID as a full 64-hex value and passes the derived cgroup name
directly to `docker exec find` instead of interpolating it into a nested shell
command. This keeps runtime metadata from changing the command used to locate
the measured cgroup; the release verifier now applies the same full 64-hex-ID,
matching cgroup-basename, and canonical in-root path checks, while the resource
evidence and hosted kind result remain open.

Continuation audit (2026-09-20): sustained flow delivery is now bound to the
measured policy epoch, selected cgroup, loopback-to-loopback IPv4 UDP egress
tuple, and expected allowed/blocked action. Warm-up epochs remain ignored,
source/destination or action mismatches fail closed, and host-runnable
regressions cover each event filter; the 1,000/s hosted flow gate remains open.

Continuation audit (2026-09-20): the sustained flow matcher now validates both
source and destination loopback addresses, not only the selected destination
port and address. A regression covers a non-loopback source event so unrelated
IPv4/UDP records cannot inflate delivered-event accounting; the hosted flow
gate remains required.

Continuation audit (2026-09-20): the capability-only DaemonSet contract now
rejects host network, PID, or IPC namespace sharing and requires the mounted
cgroup hierarchy to remain read-only. The manifest test covers these source-
level invariants, and the kind smoke job now checks the rendered Pod contract
at runtime with fail-fast shell handling. The hosted eBPF and release
performance transcript pipelines also fail fast, so a failed test cannot be
masked by a later evidence-marker write; privileged eBPF behavior remains a
hosted gate.

Continuation audit (2026-09-21): the kind capability smoke now parses the
rendered agent Pod once and fails closed unless effective false values disable
host network, PID, and IPC sharing and the `/host/sys/fs/cgroup` mount is
read-only. The checked-in manifest regression separately requires those three
fields to be explicit, because Kubernetes serializes false-valued PodSpec
booleans with `omitempty`. The
privileged eBPF transcript and release performance pipelines now use
`set -euo pipefail`, preventing a failed piped test from being hidden by a
later evidence-marker write; actionlint and the local workflow checks pass.

Continuation audit (2026-09-21): the hosted `ztap flows` smoke now parses the
captured output as newline-delimited JSON and requires a blocked-egress record.
This replaces a raw text match, so malformed or incidental output cannot
satisfy the retained `flow_streaming=passed` marker; actionlint covers the
workflow change.

Continuation audit (2026-09-21): the standalone Phase 5 verifier now parses
the archived live-flow transcript independently of the workflow shell check.
It requires a complete schema-versioned flow object with valid timestamps,
addresses, policy epoch, cgroup identity, and a blocked egress decision before
accepting `flow_streaming=passed`; focused verifier regressions cover a marker
without JSON and an incomplete JSON record. Required-field presence and a
non-empty decision reason are checked separately from typed zero-value
validation, so omitted fields cannot pass accidentally.

Continuation audit (2026-09-21): the Phase 5 JSON verifier now derives
required-field presence from each evidence struct, including nested map-memory
objects and snapshot arrays, before typed decoding. Missing fields that would
otherwise become valid Go zero values are rejected; focused regressions cover
both top-level and nested omissions. Required fields containing JSON `null` are
also rejected before typed decoding can turn them into zero values.

Continuation audit (2026-09-21): the archived live-flow JSON parser now uses
the same required-field and non-null contract as the Phase 5 evidence parser.
This closes the nullable numeric-field bypass for protocols where zero is a
valid typed value, while preserving the separate protocol, address, timestamp,
decision, and schema-version checks; focused coverage rejects a null ICMP
source port.

Continuation audit (2026-09-21): the kind capability smoke's runtime Pod
contract now validates effective false values for all three host namespace
fields, while the source manifest regression requires explicit `false` values
before Kubernetes defaulting/serialization. Its `jq` assertion also requires
exactly one container, UID/GID 0, a read-only root filesystem, the documented
security profile, exactly `ALL` in the drop list, and the exact four added eBPF
capabilities; actionlint and the local JSON contract check pass. The manifest
regression now requires the same exact drop list rather than merely checking
that `ALL` is present.

Continuation audit (2026-09-21): the shared Linux no-follow directory opener
now rejects relative paths at its own boundary before traversing from `/`,
instead of relying only on each current caller to normalize input. A focused
Linux regression covers the rejected relative-path case; the existing lock,
bpffs, and evidence-writer callers continue to pass absolute paths.

Continuation audit (2026-09-21): the Phase 5 verifier now binds the native
agent activation artifact to the documented `/sys/fs/cgroup` and `/sys/fs/bpf`
roots instead of accepting arbitrary absolute paths. Focused regressions cover
both substituted roots, so an activation transcript cannot quietly move the
reference measurement to an unreviewed filesystem hierarchy.

Continuation audit (2026-09-21): the native policy compiler now has a focused
full-snapshot deletion regression. Removing one of two additive policies leaves
the other rule contribution intact, while removing both produces no subjects or
rules; this protects the informer-driven replacement path from retaining stale
policy state. Privileged packet execution remains a hosted acceptance gate.

Continuation audit (2026-09-21): the flow monitor now checks the reader's
availability contract before entering its running lifecycle and fails closed
for unavailable readers. The Linux pinned-map wrapper also reports nil or
closed state as unavailable, with a regression proving an unavailable reader
cannot start or make the monitor appear active; real pinned-map streaming still
requires the hosted Linux gate.

Continuation audit (2026-09-21): the Linux ring-buffer reader now fails closed
for nil or zero-value flow-reader state at both the availability and direct
startup boundaries. A Linux-only regression prevents an uninitialized reader
from entering `ringbuf.NewReader`; pinned-map flow streaming still requires the
hosted Linux gate.

Continuation audit (2026-09-21): the archived flow transcript verifier now
treats whitespace-only decision reasons as missing provenance. This keeps the
required reason field semantically non-empty instead of accepting a typed
string that contains no usable decision explanation; focused verifier coverage
rejects the whitespace-only record.

Continuation audit (2026-09-21): the hosted resource producer and release
verifier now require the containerd runtime identity to be exactly 64
hexadecimal characters and bind the canonical cgroup basename to that same
identity before sampling counters. Shortened IDs and mismatched cgroup paths
are rejected; hosted kind execution remains required for the measurement.

Continuation audit (2026-09-21): the reference hosted-evidence regression now
mutates the recorded cgroup basename to a different valid 64-hex container ID
and runs the complete bundle verifier, not only the path helper. This protects
the cross-field identity binding at the release-verification boundary; hosted
kind execution remains required for the real resource measurement.

Continuation audit (2026-09-21): hosted resource identity validation now also
requires the cgroup path to remain in one of the two supported containerd
systemd hierarchies, `kubepods.slice` or
`kubelet.slice/kubelet-kubepods.slice`, matching the runtime resolver contract.
The workflow and release verifier reject a valid-looking container scope under
an unrelated system slice; hosted kind execution remains required.

Continuation audit (2026-09-21): the hosted flow smoke now records the smoke
client and server Pod IPv4 addresses and requires the blocked TCP/8080 flow
record to match that exact tuple. The workflow and archived release verifier
both reject an unrelated blocked egress record, so the success marker cannot be
satisfied by stale or incidental flow traffic; live pinned-map execution
remains a hosted gate.

Continuation audit (2026-09-21): rolling-update evidence now requires the
replacement Pod's first observation timestamp to be at or after its recorded
creation timestamp, in addition to bounding both inside the rollout interval.
Focused verifier coverage rejects an inverted Pod lifecycle; the real
DaemonSet rollout measurement remains hosted.

Continuation audit (2026-09-21): the hosted resource producer now searches
only the two supported containerd hierarchy roots instead of recursively
searching the entire cgroup mount and filtering afterward. It rejects an ID
that appears in both supported roots before sampling counters; the release
verifier and hosted kind measurement remain required.

Continuation audit (2026-09-21): rolling-update evidence now records a
replacement Pod on the old agent's node only after Kubernetes reports it
Running and Ready, retaining the explicit `replacement_ready=true` marker.
The verifier requires that marker and focused coverage rejects a false
readiness result; the real DaemonSet rollout measurement remains hosted.

Continuation audit (2026-09-21): rolling-update evidence now selects the
baseline old Pod uniquely on the smoke-client node only when Kubernetes reports
it Running and Ready, retaining `old_ready=true`. The verifier requires that
baseline marker as well as the replacement marker, preventing an absent or
unready old agent from being presented as the source of the fail-open interval;
the real DaemonSet rollout remains hosted.

Continuation audit (2026-09-21): the tag workflow's publication preflight now
also requires exact `old_ready=true` and `replacement_ready=true` rolling
markers before upload, matching the standalone verifier's closed schema rather
than deferring those readiness checks until the later re-verification step.

Continuation audit (2026-09-21): the capability smoke, resource sampler, and
live flow reader now select an agent Pod only when exactly one labeled Pod is
Running and Kubernetes Ready, instead of relying on DaemonSet list order. This
prevents a terminating or stale Pod from becoming the source of retained
metrics, flow, or security-context evidence; the hosted kind run remains
required.

Continuation audit (2026-09-21): release provenance now explicitly sorts
successful same-commit `Migration CI` push runs by creation time and selects the
newest one, rather than relying on the GitHub API response order when resolving
the trusted hosted-evidence run.

Continuation audit (2026-09-21): the first tag-workflow evidence preflight now
requires exactly one copy of each hosted evidence filename across the downloaded
evidence roots, rejecting duplicates before raw evidence upload instead of
deferring that invariant to the GoReleaser re-verification job.

Continuation audit (2026-09-21): the rolling producer now accepts a replacement
only when exactly one Running/Ready candidate remains on the old Pod's node;
transient multi-Pod overlap is allowed to settle without selecting a candidate
by list order before recording the fail-open evidence.

Continuation audit (2026-09-21): the rolling producer's replacement query now
filters Kubernetes candidates on the Ready condition before selecting the
unique same-node Pod and retains the observed readiness value instead of
unconditionally writing `replacement_ready=true`. This closes the producer-side
gap that the standalone verifier and release preflight could not detect from a
forged but structurally valid transcript; hosted rollout execution remains
required.

Continuation audit (2026-09-21): the image publication gate now parses the raw
registry index instead of relying on platform-name text matches. It requires
exactly two runnable descriptors consisting of one Linux amd64 and one Linux
arm64 manifest, validates each descriptor digest, requires an attestation
descriptor, and confirms that both the full release tag and its short alias
resolve to the digest returned by the push action.

Continuation audit (2026-09-21): the Phase 5 JSON verifier now compares every
retained artifact's kernel-path or measurement scope against the exact literal
emitted by its checked-in harness. Regression coverage for all ten JSON files
proves that replacing a real fixture description with a merely non-empty or
caller-reworded scope fails bundle verification; the focused verifier suite
passes locally, while the privileged Linux measurements remain open.

Continuation audit (2026-09-21): hosted evidence discovery now rejects a
case-variant filename for each required transcript, and GoReleaser staging
uses the same case-insensitive uniqueness check before copying retained files.
This prevents a contradictory `Evidence.txt`-style sibling from being carried
through raw publication while the canonical filename is verified.

Continuation audit (2026-09-21): hosted resource and rolling transcript
validation now requires every recorded resource, old, and replacement Pod name
to use the shipped `ztap-agent-` DaemonSet prefix. A valid cgroup or rollout
timeline attached to an unrelated workload name is rejected before release
verification.

Continuation audit (2026-09-21): hosted resource and rolling producers now
retain the agent namespace and the verifier requires every recorded agent
identity to use the shipped `ztap-system` namespace in addition to the
`ztap-agent-` DaemonSet prefix. A correctly prefixed Pod name from another
namespace can no longer satisfy the release evidence schema.

Continuation audit (2026-09-21): the release performance preflight and the
downloaded raw-evidence check now discover required hosted filenames
case-insensitively, require exactly one match, and require the matched
basename to be canonical. Case-variant evidence siblings therefore fail
before raw upload or archive staging instead of waiting for the later
GoReleaser verifier.

Continuation audit (2026-09-21): the release preflight now also requires the
exact `ztap-system` namespace and `ztap-agent-` Pod-name markers in the
resource and rolling transcripts before it reports hosted evidence ready for
publication, matching the standalone verifier's identity boundary.

Continuation audit (2026-09-21): capability-agent evidence steps now run
inside explicit `set -euo pipefail` subshells piped to `tee`, including the
fixture, resource, rolling, and appended flow transcripts. A `tee` failure or
failed measurement command now reaches the step status instead of relying on
process substitution whose writer exit could be detached from the gate.

Continuation audit (2026-09-21): standalone hosted identity validation now
also enforces the shipped Kubernetes Pod-name shape—lowercase alphanumeric
and hyphen characters, an alphanumeric suffix boundary, and the 253-byte
maximum—so a prefixed but malformed name cannot pass outside the release
shell preflight. Regression coverage exercises malformed and overlong names.

Continuation audit (2026-09-21): the real-cgroup reference, flow, packet,
agent activation/reconciliation/event, and resource harnesses now write their
raw JSON only after their final fixture, accounting, latency, throughput, or
CPU/RSS assertions pass. A failed local measurement therefore cannot leave a
stale success-shaped artifact for a later verifier run; hosted execution and
the final release attachment remain required.

Continuation audit (2026-09-21): `make integration` now runs both the Linux
enforcer and CLI package trees, including Phase 5 agent/flow-reader lock,
cgroup-path, and evidence-writer coverage. The target still refuses to run on
non-Linux hosts, while hosted privileged execution remains required.

Continuation audit (2026-09-21): the hosted privileged eBPF job now executes
the complete integration-tagged enforcer and CLI package trees, rather than
filtering the runtime job to only `TestLinuxEngine`. Phase 5 support tests are
therefore executed on Linux as well as compiled, while the capability-only
kind job remains the authoritative Kubernetes acceptance gate.

Continuation audit (2026-09-21): the Linux integration contract now vet-checks
the integration-tagged enforcer and CLI package trees before execution. This
catches static issues in the Linux-only Phase 5 harnesses that ordinary
non-Linux `go vet ./...` cannot see.

Continuation audit (2026-09-21): the native-agent performance producers now
self-check the normal and SIGKILL fixture object sets before starting a
measurement. They require exactly one default Namespace, one node, 250 Pods,
25 NetworkPolicies, the complete zero-padded Pod and policy name sets, unique
Pod UIDs, Running Pods with one container status, one Pod bucket per policy,
and a 2,500-rule projected subject-to-peer shape, so duplicate, reduced, or
reshaped fake-informer objects fail before they can produce budget-shaped
evidence.

Continuation audit (2026-09-21): native-agent Phase 5 activation predicates
now require exact `ztap_enforced_cgroups` and `ztap_compiled_rules` gauges for
the reference fixture and after synchronized policy-event activation, plus
exact 251 enforced cgroups and 2,510 compiled rules after the Pod-start
addition. Extra stale or incomplete kernel state can no longer satisfy a
fixed-shape measurement through an at-least comparison, and duplicate samples
for any unlabelled gauge are rejected rather than resolved by first-match
parsing.

Continuation audit (2026-09-21): the authoritative kind resource transcript
now samples `memory.current` every 100 milliseconds during each five-second
interval and records `peak_memory_current_bytes` alongside the raw endpoint
counters. The standalone verifier requires the peak to cover both endpoints
and recomputes each memory value and aggregate from it; focused regressions
cover a middle-interval peak and a forged peak below an endpoint. Hosted kind
execution remains required for the actual resource budget result.

Continuation audit (2026-09-21): the hosted capability smoke now probes
`/healthz`, `/readyz`, and `/metrics` after active enforcement, verifies the
ready JSON state, and sends POST requests to all three endpoints to require
`405 Method Not Allowed`. It retains `status_endpoints=passed`, and both the
release preflight and standalone hosted verifier require that marker; local
HTTP tests continue to cover the shutdown and method contracts, while the live
kind probe remains hosted.

Continuation audit (2026-09-21): the sustained flow-accounting producer now
fails closed for every measured-epoch event-contract mismatch, including
schema, cgroup, protocol, direction, family, source, destination, and port
identity. Warm-up epochs remain ignorable, but an unrelated record in the
measured epoch can no longer be silently discarded; ordinary-suite regressions
cover each mismatch class and the hosted real-cgroup gate remains required.

Continuation audit (2026-09-21): native-agent performance polling now accepts
metrics only from an HTTP `200 OK` response. Non-success responses are closed
and retried, so a failure page containing a success-shaped metric body cannot
satisfy an activation, reconciliation, event, Pod-start, restart, crash, or
resource predicate.

Continuation audit (2026-09-21): the hosted resource producer now parses each
reference-fixture gauge as one exact unsigned, unlabelled sample, requires
`ztap_agent_enforcing=1` and a non-zero active policy epoch alongside the exact
250-cgroup/2,500-rule shape, and retains those active-state markers. The
standalone verifier and release preflight require the same markers, preventing
stale or duplicate metric samples from being presented as the resource
measurement boundary; hosted kind execution remains required.

Continuation audit (2026-09-21): the hosted reference-fixture producer now
validates the live Kubernetes objects after apply, not only the generated YAML
and aggregate counts. It requires the exact 250 zero-padded Pod names, Running
and Ready status, unique Pod UIDs, ten Pods in each bucket, the exact 25 policy
names, bucket-matched selectors, ten IPv4 peers per policy, and TCP/10000
egress shape, retaining `fixture_live_shape=verified`. The release preflight and
standalone verifier require that marker; hosted kind execution remains required.

Continuation audit (2026-09-21): the hosted smoke classification probe now
rejects duplicate or labeled gauge samples, requires exact
`ztap_agent_enforcing=1` and `ztap_enforced_cgroups=1`, and requires a
non-zero active policy epoch. Empty endpoint responses remain retryable, while
success-shaped but malformed metric bodies fail closed before the packet smoke.

Continuation audit (2026-09-21): the rolling-update producer now probes the
unselected control client before rollout and during every selected-client
sample. It aborts instead of classifying an unavailable smoke server or
dataplane as policy blocking, so the retained fail-open interval is bounded to
the selected policy path; hosted rollout execution remains required.

Continuation audit (2026-09-21): the release publication preflight now uses
exact-line matching for the smoke, fixture, resource, and rolling success
markers that the standalone verifier treats as exact. A transcript with a
success string embedded in a conflicting or extended line is rejected before
raw evidence upload; hosted release execution remains required.

Continuation audit (2026-09-21): the hosted packet smoke now parses the
blocked-default-deny counter as exactly one unsigned metric sample, treats an
initial zero as retryable until the denied request is observed, rejects
duplicate or malformed matching samples, and retains the normalized positive
value as `packet_decisions_blocked_default_deny`. The standalone verifier and
release preflight require that transcript record as well; hosted execution
remains required.

Continuation audit (2026-09-21): the release publication preflight now applies
the standalone verifier's exact-once and conflicting-key semantics to fixed
hosted success markers. Duplicate `passed` lines or a `failed` line alongside
the expected keyed result therefore fail before the raw evidence is accepted;
hosted release execution remains required.

Continuation audit (2026-09-21): variable-valued hosted release markers now
require exactly one line with the expected key prefix and shape, covering Pod
names, sample records, timestamps, node identities, and fail-open intervals.
Malformed or duplicated variable records fail the publication preflight before
the standalone verifier runs; hosted release execution remains required.

Continuation audit (2026-09-21): the hosted capability smoke now checks both
the `405 Method Not Allowed` response and the `Allow: GET` header for POSTs to
`/healthz`, `/readyz`, and `/metrics`, matching the local GET-only handler
contract; hosted execution remains required.

Continuation audit (2026-09-21): native-agent Phase 5 metric predicates now
reject NaN and infinite samples in addition to duplicate or malformed lines.
This prevents a non-finite active policy epoch from satisfying the predicate's
lower-bound check; regression coverage remains in the Linux integration-tag
test package, while real agent execution remains hosted.

Continuation audit (2026-09-21): Phase 5 metric predicates now reject a
labelled series from the same metric family even when an exact unlabelled
sample is also present. The Linux performance helper and hosted capability
smoke parser therefore cannot ignore an extra labelled gauge or counter while
accepting the canonical sample; focused regression coverage and workflow
syntax checks pass locally, while live agent execution remains hosted.

Continuation audit (2026-09-21): Linux Phase 5 helper status readers now close
their pipe reader before failing a timeout, allowing the blocked read goroutine
to observe EOF and finish. Native-agent metric polling also closes any response
returned alongside a request error before retrying. The Linux integration-tag
source compiles and the local race suite passes; privileged execution remains
hosted.

Continuation audit (2026-09-21): the Linux flow reader now watches its caller
context while the ring-buffer read is blocked and closes the reader on
cancellation, so direct flow-reader users do not wait for a later event or
explicit stop to finish shutdown. A blocking-reader cancellation regression
and the local race suite pass; pinned-map streaming remains a hosted runtime
gate.

Continuation audit (2026-09-21): the pinned `ztap flows` reader wrapper now
rejects an already-canceled command context before checking map ownership or
starting its reader/status goroutines. Linux wrapper regression coverage and
the local race suite pass; the pinned-map runtime gate remains hosted.

Continuation audit (2026-09-21): pinned flow-reader termination now preserves
non-cancellation status, reader-stop, and reader-exit errors regardless of
which monitor finishes first, while suppressing only cancellation generated by
the wrapper's own coordinated shutdown. Table-driven Linux wrapper coverage
passes; pinned-map execution remains hosted.

Continuation audit (2026-09-21): pinned-agent status polling now gives caller
cancellation precedence before its first or next map lookup, preventing an
already-canceled flow command from being reported as a missing or unreadable
status map. Linux regression coverage passes; pinned-map execution remains
hosted.

Continuation audit (2026-09-21): native-agent startup now rejects an empty or
nil informer cache-sync callback set before invoking client-go. This prevents a
miswired agent from treating an empty cache as synchronized and avoids a nil
callback panic; the real informer/cache and privileged runtime gates remain
hosted.

Continuation audit (2026-09-21): the public `flows` command now rejects an
already-canceled context before acquiring the node lock or opening pinned maps.
Linux coverage verifies that cancellation leaves no run-directory side effect;
privileged pinned-map streaming remains hosted.

Continuation audit (2026-09-21): native-agent startup now treats an
already-canceled context as a clean exit before acquiring its node lock or
starting HTTP/informer state, while still closing a transferred status listener.
Linux lifecycle coverage verifies the no-side-effect path; privileged engine and
Kubernetes execution remain hosted.

Continuation audit (2026-09-21): native-agent reconciliation now gives caller
cancellation precedence before publishing a successful snapshot, readiness, or
success telemetry. A regression cancels from inside the reconcile callback and
verifies that the starting state remains unpublished; privileged execution
remains hosted.

Continuation audit (2026-09-21): native-agent cache synchronization now checks
caller cancellation once more after the informer callbacks report success. This
closes the startup race where a callback can return true concurrently with
shutdown and otherwise allow engine or HTTP state creation; the focused
cache-sync regression passes locally, while real informer and privileged engine
execution remain hosted.

Continuation audit (2026-09-21): the shared flow monitor now rejects an
already-canceled context before mutating monitor state, and its reader startup
handoff checks cancellation again before invoking the platform reader. The
host-executable cancellation regression passes locally; pinned-map streaming
and the hosted runtime gate remain required.

Continuation audit (2026-09-21): the hosted live-flow smoke and standalone
verifier now require the exact `default_deny` reason in addition to the blocked
TCP tuple, so quarantine, malformed, or other blocked decisions cannot satisfy
the default-deny flow gate. Focused verifier and workflow syntax checks pass
locally; real pinned-map flow execution remains hosted.

Continuation audit (2026-09-21): the hosted live-flow `jq` predicate now also
requires the non-empty timestamp, positive integer policy epoch and cgroup ID,
numeric source/destination ports, schema version 1, and the exact blocked TCP
tuple/reason. Migration CI therefore rejects malformed flow metadata before
retaining `flow_streaming=passed`; real pinned-map execution remains hosted.

Continuation audit (2026-09-21): the Linux native-agent lifecycle regression
now queries the real status listener during a dry-run reconciliation and
verifies `/readyz` remains HTTP 503 with reason `dry_run` while
`ztap_agent_enforcing` remains zero in `/metrics`. This strengthens the local
dry-run contract check; hosted Kubernetes lifecycle execution remains required.

Continuation audit (2026-09-21): hosted live-flow validation now requires a
non-zero TCP source port in addition to the exact blocked default-deny tuple.
The standalone verifier, Migration CI predicate, and focused regression reject
the malformed zero-port identity before accepting `flow_streaming=passed`;
real pinned-map execution remains hosted.

Continuation audit (2026-09-21): the shared flow monitor now owns a derived
reader context and cancels it during `Stop`, including the handoff window
between marking a reader invoked and entering its `Start` method. This prevents
shutdown from waiting forever when a reader's own `Stop` is a no-op during that
window; a context-blocking reader regression and the local race suite pass.
Pinned-map streaming remains a hosted runtime gate.

Continuation audit (2026-09-21): the `ztap flows` startup path now closes the
pre-start monitor subscription and the already-opened pinned reader when
monitor startup fails, including a cancellation race. Cleanup failures remain
joined with the startup error; focused CLI race coverage passes and live pinned
map execution remains hosted.

Continuation audit (2026-09-21): the Linux ring-buffer reader now rechecks its
caller context after waiting for its state lock and before opening a reader.
This closes the remaining cancellation window between the initial startup
check and ring-reader creation; a locked-start regression verifies that no
reader state is created after cancellation, while pinned-map execution remains
hosted.

Continuation audit (2026-09-21): the pinned flow-reader wrapper now performs
the same post-lock cancellation check before publishing ownership and starting
its inner reader/status pollers. A locked-start regression verifies that a
canceled command creates no running-reader state; pinned-map execution remains
hosted.

Continuation audit (2026-09-21): native-agent startup now rechecks cancellation
after acquiring the node lock and before starting its HTTP listener or informer
factories. A post-lock cancellation regression observes the supplied listener
and verifies that canceled startup creates no HTTP state; Kubernetes and
privileged engine execution remain hosted.

Continuation audit (2026-09-21): all locally executable Phase 5 gates now pass
on the current working tree. The `make check` subcommands pass for build,
race tests, vet, formatting, golangci-lint, actionlint, and the pinned
`govulncheck@v1.1.4` scan; `make check-generated` reproduces the generated
bindings; all three retained validator examples plus the documented stdin path
validate; and the Kubernetes manifest tests pass with the repository-local Go
cache. The Linux integration-tag enforcer and CLI test binaries also compile
for amd64 and arm64, and Linux-targeted vet passes; these are compile-only
checks on this macOS host and do not claim privileged runtime behavior. Docker,
kubectl, and kind are unavailable on this macOS host, so the
Docker/image scan, privileged Linux eBPF and Kubernetes acceptance, Section
14.5 measurements, and release publication/provenance archive remain hosted
gates. The Phase 5 implementation checklist is 90/90 complete (100%), while
the final acceptance checklist is 12/39 complete (30.8%), with 27/39 hosted or
release items still open (69.2% remaining); no unchecked hosted result is
inferred from local source or unit evidence.

Continuation audit (2026-09-21): the connected GitHub repository confirms that
`codex/streamline-ztap` still points to committed SHA
`5eda8d7d2124f25acc1c1c997305550a542e0f66`. Migration CI run `35420912995`
and its `ebpf-engine-evidence` and `capability-agent-evidence` artifacts passed
for that committed SHA, not for the current uncommitted Phase 5 working-tree
diff. The live `main` branch protection record is strict and contains only the
exact `Required CI` context in both required-status representations. The
current Phase 5 implementation count therefore remains 90/90, while final
acceptance remains 12/39; no remote branch, commit, or pull request was changed
during this audit.

Continuation audit (2026-09-22): the release path now keeps the GitHub release
in draft state until the multi-architecture image is published and verified and
the immutable install manifest is attached. Engine map pinning retains the
validated bpffs directory descriptor through `BPF_OBJ_PIN` and shutdown
cleanup, and the legacy cgroup attach path reaches its override fallback when
the kernel reports an unsupported multi-attach flag. Dependabot's monthly
schedules no longer use the weekly-only `day` field. The maintained policy and
deployment guides distinguish cluster-wide selector peers from node-local
subjects, require a CNI without another NetworkPolicy enforcer rather than a
CNI-free cluster, and record that exact Phase 5 CI and manual kernel releases
remain pending hosted validation.

Continuation audit (2026-09-22): `make check-generated` and the full `make
check` passed again on the current Phase 5 working tree. The first aggregate
check attempt stopped only because DNS could not resolve `vuln.go.dev`; the
pinned `govulncheck@v1.1.4` scan then passed with network access and reported no
vulnerabilities, and the aggregate check passed on retry. This confirms local
gates only; Docker, privileged Linux/Kubernetes, Section 14.5 measurements,
and release publication/provenance remain hosted. The Phase 5 implementation
checklist remains 90/90 complete (0% remaining); final acceptance remains
12/39 complete with 27/39 items open (69.2% remaining).

Continuation audit (2026-09-22): the first hosted Migration CI push run for
PR #193 (`35770397484`, commit `f67d917`) failed in lint and actionlint before
Linux, Docker, eBPF, and Kubernetes jobs could run. Its logs identified six
unchecked descriptor closes, one Go import-order issue, and two ShellCheck
findings. Those findings are corrected locally, and the branch is synced with
current `main`; the Phase 5-required narrowed monthly Dependabot configuration
is retained despite its deletion on `main`. The generated-code and aggregate
local gates pass after these fixes, but exact-diff hosted validation is still
pending. Final acceptance remains 12/39 complete, with 27/39 items open
(69.2% remaining); no skipped hosted result is counted as a pass.

Continuation audit (2026-09-22): the next hosted PR run (`35771692888`) and
push run (`35771688053`) for `fba272e` passed generated-code, actionlint, and
workflow-security checks but failed lint; required aggregation consequently
failed and Linux, Docker, eBPF, and Kubernetes jobs were skipped. The lint
logs identified three additional unchecked Linux descriptor closes. A
Linux-targeted `errcheck` pass then exposed one unchecked close in the existing
node-lock helper as well. The three startup-path closes and the lock-directory
close now propagate errors and release any already-open result handle if its
parent descriptor cannot be closed. On the updated working tree,
Linux-targeted `errcheck` reports 0 issues and `make check-generated` passes.
The prior aggregate `make check` passed before the final Linux-only lock-helper
adjustment; macOS does not compile that build-tagged path, so exact-diff hosted
CI remains necessary. The Phase 5 implementation checklist is 90/90 complete
(0% remaining); final acceptance is 12/39 complete, with 27/39 items open
(69.2% remaining). Section 14.5 measurements and release publication and
provenance archive remain hosted gates.

Work:

- [x] Create the four-document end state; final editorial review remains part of the release gate.
- [x] Convert and validate the three examples through `ztap validate`.
- [x] Finalize every Makefile target listed in Section 10.2; build, test, vet, format, pinned `golangci-lint`/`actionlint`, the pinned `govulncheck@v1.1.4` scan, the aggregate `make check`, and the pinned LLVM 18 generated-code checks pass locally, while image vulnerability scanning, Docker, and privileged Linux execution remain environment-gated.
- [x] Replace the temporary `Migration CI` jobs with the Linux CI jobs while preserving the workflow file and `Required CI` check name; hosted acceptance remains open, while the live branch-protection record has been verified separately.
- [x] Add the final generated-code, image-scan, manifest/example, documented stdin-validator, reference-fixture offline validator, live `ztap flows` smoke, explicit `make docker`, and required-job aggregation gates to `Migration CI`; hosted execution remains open.
- [x] Recreate the simplified tag-only release workflow with protected-branch ancestry, final-gate checks bound to the successful `Migration CI` push run for the exact tagged commit, propagation of that trusted run ID into the performance job and retained environment evidence, GoReleaser Linux artifacts, one multi-architecture image, SBOM/provenance, an immutable install manifest, trusted same-commit hosted eBPF/capability-agent evidence, and a persistent raw Phase 5 evidence asset.
- [x] Add a standard-library verifier for the ten Phase 5 JSON artifacts and the required hosted evidence markers, and run it before release publication; raw hosted evidence remains required separately. The verifier uses strict JSON schemas, rejects unknown or case-variant JSON object fields plus trailing or multiple values, validates RFC3339 timestamps, requires every artifact's run ID, accepts expected release and trusted Migration CI provenance, parses the retained environment record with an allowed-key schema, cross-checks its Phase 5 run ID and Go/OS/architecture/CPU metadata against the producer record, recomputes derived aggregates and map-capacity bytes, explicitly models unbounded cgroup storage, requires the exact generated engine map inventory and dimensions, rejects unknown/duplicate/reordered map entries, cross-checks the shared run ID and exact two-CPU environment plus native-agent kernel provenance, validates the hosted flow-streaming marker against the recorded smoke client/server IPv4 TCP/8080 tuple, validates the offline-validator marker, fixture/resource/rolling evidence and timestamp arithmetic, requires three ordered hosted resource sample records with raw CPU-usec and `memory.current` counters, a 100-ms peak-memory polling marker, and the documented five-second intervals, recomputes each hosted resource sample and its maxima from the recorded peak counter before applying budgets, rejects duplicate required hosted keys, requires producer provenance metadata, requires the flow transcript to record the full reference fixture shape and scope, and enforces the fixed fixture/budget constants.
- [x] Bind every retained Phase 5 JSON artifact's kernel-path or measurement scope to the exact literal emitted by its checked-in producer harness; mutate-and-reject regression coverage covers all ten artifacts so a non-empty caller-reworded scope cannot detach a budget from the documented real measurement path. The focused verifier suite passes locally; the underlying privileged Linux/eBPF and hosted acceptance gates remain open.
- [x] Bound strict JSON evidence key scanning to a finite nesting depth, reject case-variant fields that the Go decoder could otherwise match, and cover excessively nested and case-variant retained artifacts with regression tests.
- [x] Tighten Go provenance parsing so recorded environment and JSON evidence must use a dotted numeric Go release token, rather than merely a non-empty or `go`-prefixed string; cover malformed version tokens and a valid Linux toolchain with regression tests.
- [x] Harden the hosted fixture transcript verifier so the exact 250-Pod/25-policy shape also carries kind-specific API versions, the exact `ztap-performance` Namespace and object namespaces, complete zero-padded Pod and NetworkPolicy name sets, and per-object bucket markers; validate every policy's matching selector bucket, exact Egress policy type, TCP port 10000, and ten peer CIDRs from their structured YAML paths so aggregate totals and arbitrary matching lines cannot hide per-policy corruption; parse every fixture document as strict, depth-bounded YAML so duplicate keys, non-string mapping keys, anchors, aliases, merge keys, malformed documents, and excessive nesting cannot hide behind line counts; cover omitted markers, misplaced fields, policy semantic drift, per-policy bucket/peer-shape corruption, non-string keys, indirection, and excessive nesting with regression tests.
- [x] Require the hosted reference fixture's exact kind-specific field sets and Pod workload spec, including the pinned image, pull policy, container name, and command; reject unknown Pod runtime fields and policy/selector/peer/port shape expansion with local semantic-drift regressions.
- [x] Add bounded seed-only fuzz targets for hosted YAML splitting/strict decoding and IPv4 `ipBlock` exclusion expansion, with regression seeds and output invariants.
- [x] Make hosted evidence discovery reject symlink roots, symlink entries, and non-regular matched paths before reading release evidence.
- [x] Keep Linux cgroup attachment on the descriptor validated for root containment and inode identity, including the legacy attach fallback and retryable cleanup; privileged attachment evidence remains hosted.
- [x] Reopen canonical Linux engine bpffs and cgroup roots through descriptor-relative no-follow traversal before pin creation, stale-pin cleanup, or subject validation; privileged execution remains hosted.
- [x] Make direct JSON, environment, and hosted-evidence readers reject symlink files and non-regular paths before reading evidence.
- [x] Bound hosted-evidence reads at the 4 MiB verifier limit and cover oversized artifacts without an unbounded read.
- [x] Bound the complete Phase 5 environment-evidence read at 1 MiB before key/value parsing and cover oversized environment artifacts with a regression test.
- [x] Bind the final reference map-memory summary's memlock availability and byte readings exactly to the retained final snapshot; add a regression test for a forged summary reading.
- [x] Make the hosted kind resource transcript retain raw CPU and memory counters, poll `memory.current` every 100 ms, record each interval's peak counter, reject counter resets or peaks below endpoint readings, and recompute every derived sample before applying the fixed resource budgets.
- [x] Require the hosted resource transcript's non-empty scope provenance before accepting its samples and budget summary.
- [x] Correct the native-agent resource harness to calculate CPU from process tick deltas and reject invalid measurement intervals; add focused calculation tests.
- [x] Make the sustained flow-accounting harness reject per-counter cumulative resets, counter-shape drift, and uint64 summation overflow before writing Phase 5 evidence; bound the recorded duration to the documented 60-second run plus a fixed five-second scheduling tolerance; keep the identity-keyed delta helpers and regression tests in the ordinary package unit suite so those guards execute on the development host as well as in the Linux harness.
- [x] Add a fuzz target for the fixed-size binary flow-event decoder; malformed sizes and schemas are rejected, while valid 72-byte events convert without panics or unbounded input-derived allocation.
- [x] Make `make performance` remove its ten explicit JSON outputs before each run so failed reruns cannot reuse stale evidence.
- [x] Re-run the complete Phase 5 verifier in the GoReleaser job against the downloaded, trusted evidence bundle before publication.
- [x] Require exactly one exact-name `go test -v` pass marker for each of the ten retained Phase 5 harnesses in the raw performance log before upload and repeat that exact-once check in the GoReleaser publication job.
- [x] Reject duplicate local or hosted evidence filenames while staging the publication-time Phase 5 verification bundle.
- [x] Reject case-variant hosted evidence filenames during standalone discovery, release preflight, and GoReleaser staging so canonical transcripts cannot coexist with ignored name variants.
- [x] Make the release preflight and standalone verifier require the exact hosted agent namespace and valid `ztap-agent-` Pod-name markers before raw evidence upload or release verification.
- [x] Make every capability-agent evidence-producing step propagate both measurement and transcript-writer failures through an explicit `pipefail` pipeline.
- [x] Bind hosted resource and rolling transcript Pod identities to the shipped `ztap-agent-` DaemonSet name prefix, with regression coverage for an unrelated workload name.
- [x] Retain and verify the shipped `ztap-system` namespace for hosted resource and rolling transcript Pod identities, with regression coverage for unrelated namespaces.
- [x] Reject symlink and non-regular local or hosted entries before uploading Phase 5 evidence, and repeat the same check in the downloaded evidence tree before archiving or re-verifying release evidence.
- [x] Validate the publication digest shape and require exactly one non-`:latest` image reference in the rendered immutable install manifest before attaching it to the release.
- [x] Parse the published raw image index and require exactly two runnable descriptors consisting of one Linux amd64 and one Linux arm64 manifest plus an attestation descriptor, with both explicit release aliases resolving to the pushed digest.
- [x] Record the semantic release ref, compare it with the current release tag during both performance verification and GoReleaser re-verification, and validate the `release.yml`/`push` provenance in `phase5-environment.txt` so retained performance evidence is bound to the publication workflow as well as its commit and trusted Migration CI run.
- [x] Pin the GoReleaser release binary to an exact checked-in workflow version (`v2.9.0`).
- [x] Make flow-monitor subscriptions reject nil contexts without registering
  an uncancellable subscriber, and cover both normal and pre-start APIs.
- [x] Avoid a permanent cancellation watcher for valid non-cancellable flow
  subscription contexts; the monitor lifecycle still closes those channels.
- [x] Keep the Phase 5 agent performance HTTP listener open through startup,
  including descriptor transfer to the resource and crash helper subprocesses.
- [x] Route every Linux real-cgroup integration helper's `cgroup.procs` write
  through a validated no-follow cgroup descriptor, including packet and
  crash-performance helpers; hosted privileged execution remains required.
- [x] Make hosted resource and rolling-update transcripts closed structured
  key/value evidence: require the exact reference-fixture scope and status,
  retain agent/container/cgroup identity, reject malformed/unknown/duplicate
  records, keep expected rollout-probe output out of the retained schema, and
  validate full 64-hex container IDs whose canonical in-root cgroup basename
  matches the recorded identity and whose path uses a supported containerd
  systemd hierarchy, without nested-shell metadata interpolation; hosted kind
  execution remains required.
- [x] Bind sustained flow-accounting delivery to the measured event contract:
  selected cgroup, policy epoch, loopback-to-loopback IPv4 UDP egress tuple,
  and the expected allowed/blocked action; ignore warm-up epochs and fail
  closed on source/destination or action mismatches, with ordinary-suite
  coverage for each filter.
- [x] Lock down the capability-only DaemonSet contract so manifest validation
  rejects host network, PID, or IPC namespace sharing and requires the mounted
  cgroup hierarchy to remain read-only; the kind smoke job checks the same
  rendered Pod contract, while privileged runtime behavior remains a hosted
  gate.
- [x] Enforce the documented GET-only status endpoint contract and publish the
  bounded `stopping` readiness state before direct status-server shutdown;
  hosted endpoint probes remain part of final acceptance.
- [x] Make standalone hosted-evidence discovery reject every symlink or
  non-regular tree entry, including unmatched special files, before reading the
  required evidence; keep the release workflow's independent pre-archive guard.
- [x] Preflight the release performance job's root-level environment and raw
  log output paths before `tee` writes, rejecting existing, symlinked, or
  special entries instead of relying only on post-write verification.
- [x] Make the release performance environment transcript fail closed when a
  metadata command fails instead of allowing the final `tee` to mask that
  failure.
- [x] Preflight the hosted `Migration CI` eBPF and capability-agent evidence
  output paths before `tee`, append, copy, and diagnostic writes, rejecting
  existing, symlinked, or special entries before privileged evidence runs.
- [x] Preflight the tag workflow's `release-notes.md` output before the
  GoReleaser note extraction/fallback writes, rejecting existing, symlinked,
  or special entries.
- [x] Make the hosted packet smoke retain and independently verify exactly one
  positive blocked-default-deny counter observation, rejecting duplicate or
  malformed metric samples before release publication; hosted execution
  remains required.
- [x] Require the hosted live-flow smoke and standalone verifier to match the
  exact blocked TCP tuple and `default_deny` decision reason, so quarantine or
  other blocked decisions cannot satisfy the default-deny flow gate; hosted
  pinned-map execution remains required.
- [x] Make the hosted live-flow smoke validate the required schema metadata and
  numeric field shapes before writing its success marker, matching the
  standalone verifier's malformed-record rejection; hosted pinned-map
  execution remains required.
- [x] Reject zero TCP source ports in the hosted live-flow smoke and standalone
  verifier, with focused regression coverage for the malformed transport
  identity; hosted pinned-map execution remains required.
- [x] Align fixed hosted success-marker checks in the release preflight with
  the standalone verifier's exact-once and conflicting-key semantics so
  contradictory transcripts fail before publication; hosted execution remains
  required.
- [x] Make variable-valued hosted release markers exact-once and shape-checked
  in the publication preflight, covering Pod names, resource samples,
  timestamps, node identities, and fail-open intervals; hosted execution
  remains required.
- [x] Extend the hosted status smoke to verify the `Allow: GET` header on all
  non-GET endpoint probes in addition to the 405 status; hosted execution
  remains required.
- [x] Add Linux lifecycle coverage that queries the dry-run status listener and
  verifies `dry_run` readiness stays unavailable with zero enforcement metrics;
  hosted Kubernetes lifecycle execution remains required.
- [x] Make native-agent Phase 5 metric predicates reject non-finite Prometheus
  samples, including active policy epochs, with focused integration-tag
  regression coverage; hosted execution remains required.
- [x] Close timed-out Linux Phase 5 helper status readers and response bodies
  returned with metric request errors so failure-path retries do not retain
  blocked read goroutines or HTTP resources; hosted execution remains required.
- [x] Make the Linux flow reader close its ring reader when its caller context
  is canceled during a blocking read, with a blocking-reader cancellation
  regression; hosted pinned-map streaming remains required.
- [x] Give the shared flow monitor ownership of a derived reader context and
  cancel it during `Stop`, covering the reader-start handoff race with a
  context-blocking regression; hosted pinned-map streaming remains required.
- [x] Close the pre-start flow subscription and already-opened pinned reader
  when monitor startup fails, preserving cleanup errors with the startup
  failure; focused CLI race coverage passes and hosted streaming remains
  required.
- [x] Recheck Linux flow-reader cancellation after acquiring its state lock
  before opening the ring reader, with regression coverage for cancellation
  during lock wait; hosted pinned-map streaming remains required.
- [x] Recheck native-agent cancellation after acquiring the node lock before
  starting HTTP and informer state, with post-lock listener coverage; hosted
  Kubernetes and privileged engine execution remain required.
- [x] Make the pinned `ztap flows` reader reject an already-canceled command
  context before entering map ownership or status polling; hosted pinned-map
  streaming remains required.
- [x] Preserve terminal status, reader, and stop errors when the pinned flow
  wrapper's goroutines finish in either order, suppressing only internal
  cancellation; hosted pinned-map streaming remains required.
- [x] Give pinned-agent status polling caller cancellation precedence before
  map lookups, with canceled-before-lookup regression coverage; hosted
  pinned-map streaming remains required.
- [x] Add a privileged regression for deleting one contribution from an
  additive selected policy set while preserving the remaining rule and link
  ownership; hosted execution remains required.
- [x] Restore narrowed monthly Dependabot updates.
- [x] Add a shape-checked compiler benchmark for the documented
  250-Pod/25-policy/2,500-rule fixture; the real-cgroup, packet-path, resource,
  fail-open-interval, and flow-loss gates remain open.
- [x] Run the sustained flow-accounting harness over the full
  250-subject/25-policy/2,500-rule real-cgroup policy set, retain its complete
  fixture shape and scope in the JSON transcript, and reject reduced-shape flow
  evidence in the verifier.
- [x] Run the SIGKILL crash fail-open harness against the full
  250-subject/25-policy/2,500-rule native-agent fixture, retain its shape in
  `phase5-agent-crash.json`, and reject reduced-shape crash evidence.
- [x] Make the parent crash harness own cleanup for all child-created fixture
  cgroups, the helper run directory, and the two stable engine pins so SIGKILL
  samples cannot leak hosted-runner state.
- [x] Carry the complete 250-subject/25-policy/2,500-rule shape through the
  reference-apply, packet, and Pod-start JSON artifacts, and reject reduced
  policy projections in the verifier.
- [x] Harden the DaemonSet rolling-update transcript to select a unique Running
  and Kubernetes Ready baseline Pod on the smoke-client node, retain
  `old_ready=true`, enumerate a Running and Ready replacement Pod on that node,
  retain `replacement_ready=true`, require distinct old/replacement Kubernetes
  UIDs, and retain creation and first-observation timestamps bounded to the
  rollout-to-fail-open interval before accepting the measured fail-open
  interval.
- [x] Add the Linux-only real-cgroup reference apply harness and raw JSON
  output, and require it before tag publication; it enforces only the direct
  engine-apply p95 budget, reports configured map-capacity and available
  kernel-memlock metadata, retains every warm-up/apply map snapshot, and fails
  if those capacities or available memlock grow across repeated applies after
  warm-up. Extend the harness with sustained UDP flow
  accounting at one packet decision per millisecond, initial native-agent
  activation, actual native-agent compile-and-apply reconciliation, and
  synchronized policy-event activation gates over the same fixture, plus an
  orderly restart-gap measurement. Add a separate Pod-start classification
  measurement and raw JSON output, a SIGKILL crash fail-open measurement with raw JSON output, a
  real-packet UDP/TCP comparison gate with raw JSON output, and a supporting
  native-agent CPU/RSS sampler with raw JSON output. Add a kind
  250-Pod/25-policy/2,500-rule reference resource gate, a DaemonSet
  rolling-update fail-open measurement, and upload their raw evidence; hosted
  acceptance remains required for both gates.
- [x] Make the local real-cgroup evidence producers write only after their
  final fixture-shape, accounting, packet-budget, agent-latency, and
  CPU/RSS assertions pass, so failed measurements cannot leave a stale JSON
  artifact for later verification; hosted execution remains required.
- [x] Extend the documented privileged `make integration` gate to execute
  both Linux enforcer and CLI package trees, covering the Phase 5 agent and
  flow-reader support tests; non-Linux execution remains an explicit refusal.
- [x] Make the hosted privileged eBPF job execute the complete integration-tagged
  enforcer and CLI package trees, so Phase 5 support tests run on Linux rather
  than being limited to the engine test-name prefix; kind remains the
  authoritative Kubernetes acceptance job.
- [x] Add tagged Linux `go vet` coverage for the enforcer and CLI integration
  packages in both `make integration` and the Linux CI compile job.
- [x] Make the native-agent activation and SIGKILL performance fixtures assert
  their complete 250-Pod/25-policy/2,500-rule object shape, exact names,
  unique UIDs, Running status, and bucket-matched Egress policies before
  starting a measurement, so producer-side fixture drift cannot emit
  success-shaped evidence.
- [x] Require exact native-agent enforcement and compiled-rule gauges in the
  Phase 5 activation predicates, including the 251-cgroup Pod-start state,
  so stale or extra kernel state cannot masquerade as the fixed fixture.
- [x] Add release-time verification that `main` branch protection is strict and contains only the exact `Required CI` context in both GitHub required-status representations; the hosted API result requires the `BRANCH_PROTECTION_TOKEN` repository secret with Administration-read permission.
- [x] Verify branch protection still requires `Required CI` on the current repository; the live `main` protection record is strict and contains only the exact `Required CI` context in both required-status representations.
- [x] Run the pinned `zizmor` 1.16.3 workflow-security audit and its pedantic mode; disable release-job `setup-go` and BuildKit dependency caching after the cache-poisoning review, remove unnecessary Docker matrix interpolation, document elevated permissions, explicitly download and verify the checked-in module graph before GoReleaser verification, and require clean zizmor/actionlint results.
- [x] Verify `make clean` leaves no tracked or ignored workspace debris; artifact deletion itself was completed in Phase 0.
- [x] Add the `v0.1.0` breaking-change entry and migration notes.
- Once all checklist items are recorded as complete, delete this temporary plan in the release-preparation commit.
- Run the full unit, generated-code, Docker, manifest, and Linux integration gates; local unit and manifest checks pass, while generated-code, Docker, and hosted Linux checks remain required or tool-gated.
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

Use one documented 2-vCPU Linux reference environment with 250 Pods, 25
NetworkPolicies, and 2,500 compiled local rules. The release performance
process is pinned to two CPUs with `taskset` and `GOMAXPROCS=2`; the kind
reference node uses a `200000 100000` cgroup CPU quota. Run each measured gate
three times after warm-up and retain the raw command/output with release
artifacts. The 1,000-Pod/100-policy/10,000-rule fixture is a post-`v0.1` scale
milestone.

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

- [x] README describes only a Linux/Kubernetes eBPF enforcer.
- [x] `ztap --help` contains `validate`, `agent`, `flows`, and `version` as the only primary commands.
- [x] Native Kubernetes NetworkPolicy is the only accepted policy resource.
- [x] Unsupported semantics are rejected with stable field errors.
- [x] The documented first-release surface is IPv4 with numeric TCP/UDP ports; named ports, dual-stack enforcement, and automatic Service translation leave no dormant code paths. The native validator/compiler rejection tests and the 2026-09-19 local contract audit support this source-level item; privileged packet behavior remains a hosted gate.
- [x] There is one binary, one container image, and one Kubernetes install manifest.

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

- [x] No tracked executable binaries remain.
- [x] No root build/test/coverage artifacts remain after `make clean`.
- [x] Removed feature directories, docs, dependencies, workflows, and configuration are gone together. The 2026-09-19 working-tree, dependency-graph, and maintained-document cleanup audit supports this source-level item.
- [x] Generated eBPF sources reproduce without a diff using the pinned LLVM 18 compiler.
- [ ] `go test ./... -race`, lint, vet, Docker build, manifest validation, and Linux integration tests pass.
- [x] Branch protection requires the stable `Required CI` result, and no transitional workflow can publish artifacts. The live `main` protection record is strict with only `Required CI`, and the workflow audit finds publication only in the tag-gated release workflow.
- [x] Searches find no stale claims for REST, gRPC, cloud, etcd, anomaly, audit, compliance, macOS, Windows, or iptables support outside release history; the remaining migration references explicitly describe removed CRD/operator behavior.

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
- Retained Phase 5 JSON artifacts require exact producer scope literals, so a
  non-empty caller-reworded kernel or measurement description cannot be
  detached from the harness path that produced the budgeted result.
- Audit, alerts, dashboards, and anomaly detection are outside the core.
- Git history will not be rewritten.
- The first streamlined release is versioned as `v0.1.0` and described as experimental.

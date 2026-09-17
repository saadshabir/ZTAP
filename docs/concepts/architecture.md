# ZTAP Architecture

System design, component responsibilities, and data-flow overview for ZTAP.

## Overview

ZTAP (Zero Trust Access Platform) implements microsegmentation across hybrid environments using a modular, policy-driven architecture.

## Components

### 0. API Server (`internal/apihttp`)

**Responsibility**: Expose a REST API around core ZTAP capabilities

**Features**:

- Health, auth, and status endpoints
- Enforcement lifecycle endpoints (start/stop/status)
- Compliance report/export endpoints (policy-to-control mapping + evidence)
- Flow streaming over SSE
- Prometheus metrics endpoint (`/metrics`)
- Policy management endpoints (CRUD, revisions, rollback)
- User and cluster management endpoints

### 1. Policy Engine (`internal/policy`)

**Responsibility**: Parse, validate, and manage network policies

**Features**:

- Kubernetes-style YAML parsing
- Bidirectional enforcement (ingress and egress rules)
- Policy validation (CIDR, protocols, ports)
- Conflict detection (intra- and cross-policy overlap)
- Label resolution interface
- Multi-document YAML support

**Key Functions**:

```go
LoadFromFile(filename string) ([]NetworkPolicy, error)
Validate() error
ResolveLabels(labels map[string]string) ([]string, error)
```

### 2. OS Enforcer (`internal/enforcer`)

**Responsibility**: Apply policies using OS-native mechanisms

**Implementations**:

- **Linux**: eBPF (Primary)
  - Attach to cgroup hooks (egress and ingress)
  - Uses `bpf_link` for atomic, graceful policy reloads without connection drops
  - Per-subject policy keys (the Kubernetes agent programs selected pod cgroups)
  - Unselected cgroups remain allowed; selected directions default deny on a rule miss
  - Kernel-level enforcement with BTF support
  - Safe packet parsing using bpf_skb_load_bytes
  - Bidirectional filtering (cgroup_skb/egress and cgroup_skb/ingress)
  - IPv4 TCP/UDP enforcement; isolated IPv6, malformed, fragmented, and other
    unsupported packets are denied explicitly
- **Linux**: iptables (retained compatibility code)
  - The Kubernetes agent fails closed at startup when its cgroup v2/bpffs/eBPF
    prerequisites are unavailable; it never falls back to iptables.
  - The old fallback implementation remains parked for the Phase 4 removal
    inventory.
- **macOS**: pf (Packet Filter)
  - Manages `/etc/pf.anchors/ztap`
  - Updates `/etc/pf.conf`
  - Supports pass in/out rules for ingress/egress
  - Requires sudo for full functionality
- **Windows**: Windows Filtering Platform (WFP)
  - Applies filters via `fwpuclnt.dll` (user-mode WFP API)
  - Uses a ZTAP provider/sublayer and a transactional apply/delete model
  - Supports IPv4/IPv6 `ipBlock.cidr` (arbitrary CIDRs) and TCP/UDP/ICMP (ICMP ignores `port`)
  - Permit-only by default; optional strict default-deny can be enabled with `ZTAP_WFP_STRICT=1`

**Linux agent boundary**:

```go
type Engine interface {
    Apply(context.Context, policy.PolicySet) error
    Close() error
}

// The node agent owns one Engine instance for its full process lifetime.
ztap agent --node-name <node>
// Direct Linux file/API enforcement is retired.
EnforceWithPF(opts EnforcementOptions)
EnforceWithWFP(opts EnforcementOptions) error
StopWFPEnforcement() error
```

**Features**:

- **Dry-run Mode**: Simulate enforcement without applying kernel rules (`--dry-run`)
- **Platform Abstraction**: Unified interface across OSes

### 3. Cloud Integrator (`internal/cloud`)

**Responsibility**: Sync policies to cloud providers

**AWS Integration**:

- Discover EC2 instances via `DescribeInstances`
- Map labels to AWS tags
- Convert policies to Security Group rules (managed prefix + delete stale managed rules)
- Handle stateful firewall differences

**Azure Integration**:

- Reconcile policies into NSG security rules (managed rule prefix + delete stale managed rules)
- Uses Azure Identity default credentials (DefaultAzureCredential chain)

**Key Functions**:

```go
DiscoverResources() ([]Resource, error)
SyncPolicy(policy NetworkPolicy, sgID string) error

// GCP
SyncPolicy(policy NetworkPolicy, projectID, network string) error

// Azure
SyncPolicy(policy NetworkPolicy, resourceGroup, nsgName string) error
```

### 4. Anomaly Detector (`internal/anomaly`)

**Responsibility**: Detect abnormal traffic patterns

**Implementations**:

- **Simple Detector**: Rule-based (suspicious ports, geolocation)
- **Python ML Service**: Isolation Forest algorithm

**Key Functions**:

```go
Detect(flow FlowRecord) (*AnomalyScore, error)
Train(flows []FlowRecord) error
```

### 5. Alerting (`internal/alert`)

**Responsibility**: Deliver alert notifications to external systems

**Features**:

- Async dispatch with a bounded queue
- Webhook sinks: Slack incoming webhooks, PagerDuty Events API v2
- Optional in-memory dedupe (TTL) via `dedup_key`

**Common sources**:

- Policy enforcement success/failure (CLI/API/cluster enforcement)

### 6. Metrics Collector (`internal/metrics`)

**Responsibility**: Export Prometheus metrics

**Metrics**:

- `ztap_policies_enforced_total`
- `ztap_flows_allowed_total`
- `ztap_flows_blocked_total`
- `ztap_anomaly_score`
- `ztap_policy_load_duration_seconds`

**Key Functions**:

```go
GetCollector() *Collector
StartServer(port int) error
```

### 7. Kubernetes Operator + Node Agent

**Responsibility**: Kubernetes-native policy authoring and distribution using a CRD and per-node agents

**Components**:

- **Operator** (`cmd/ztap-operator`)
  - Watches `ZtapNetworkPolicy` (group `ztap.io/v1alpha1`)
  - Converts to internal `ztap/v1` policy YAML and validates via `internal/policy`
  - Publishes validated policies into a ConfigMap “policy store”
- **Node Agent** (`ztap agent --node-name <node>`)
  - Watches NetworkPolicy, Pod, Namespace, and Node informer caches
  - Builds one immutable cluster snapshot and compiles it through the native policy package
  - Resolves live containerd/systemd cgroups for local Pods and applies complete candidates through the instance-owned `Engine`
  - Keeps the last applied candidate when a later snapshot cannot be compiled or attached

## Data Flow

```text
User
│
├─> CLI Command (enforce/status/logs)
│
├─> Kubernetes (WIP)
│   ├─> Operator (CRD -> validated policy state)
│   └─> Node Agent (informers -> immutable snapshot -> native compiler -> Engine)
│
├─> API Server (HTTP/gRPC)
│
├─> Policy Engine
│   ├─> Parse YAML
│   ├─> Validate
│   └─> Resolve Labels (and optionally re-resolve over time)
│
├─> OS Enforcer
│   ├─> eBPF (Linux)
│   ├─> pf (macOS)
│   └─> WFP (Windows)
│
├─> Cloud Integrator (optional)
│   └─> AWS Security Groups
│
├─> Anomaly Detector (optional)
│   └─> Python ML Service
│
├─> Alerting (optional)
│   └─> Slack / PagerDuty webhooks
│
└─> Metrics Collector
    └─> Prometheus (:9090/metrics)
```

## Security Model

### Error Handling

API servers (REST and gRPC) follow a consistent error-handling pattern:

- **Server-side logging**: Full error details including stack context are logged for operators.
- **Client-facing errors**: Sanitized messages with appropriate HTTP status codes or gRPC status codes. Internal details are never returned to clients.
- **Audit hashing**: `EntryHash` returns an error if an entry's `Details` field cannot be serialized, preventing silent creation of incorrect hashes.
- **Discovery watchers**: K8s watchers propagate initial resolve errors to callers, treating `NoMatchesError` as empty initial state rather than a failure.
- **Flow subscribers**: Channel lifecycle is managed by a `subscriber` struct with explicit close-once semantics, avoiding `recover()`-based panic suppression.
- **Auth context**: `Authenticate` accepts a `context.Context` so session creation respects request timeouts and cancellation.

### Threat Model

| Threat              | Mitigation                         |
| ------------------- | ---------------------------------- |
| Policy Bypass       | OS-level enforcement (eBPF/pf/WFP) |
| Label Spoofing      | Trusted inventory (AWS tags, DNS)  |
| Enforcer Compromise | Minimal privileges, sandboxed      |

### Trust Boundaries

- **Policy Files**: Trusted input (review via GitOps)
- **Cloud APIs**: Authenticated via IAM/credentials
- **Anomaly Service**: Internal-only (localhost:5000)

## Performance Considerations

### Policy Load Time

- Target: <100ms for 100 policies
- Optimization: Concurrent validation, caching

### CPU Overhead

- Target: <2% on 4-core system
- eBPF: Near-zero overhead (kernel space)
- pf: Minimal (optimized rule matching)
- WFP: Low overhead (Windows kernel filtering path)

### Memory Usage

- Target: <50 MB
- Policy cache: In-memory (no persistence)

## Distributed Architecture

ZTAP supports multi-node deployments with distributed coordination:

```
+----------------+     +----------------+
|  Leader Node   | <-> |  Follower Node |
| (Coordinates)  |     +----------------+
+----------------+     +----------------+
       ^               |  Follower Node |
       |               +----------------+
       |               +----------------+
       +-------------- |  Follower Node |
                       +----------------+
```

### High Availability

- Leader election: In-memory (dev) or etcd (production)
- Policy sync: Automatic distribution to all nodes with versioned revisions and rollback
- Nodes: Stateless with persistent etcd backend

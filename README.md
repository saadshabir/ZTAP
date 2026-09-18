# ZTAP: Zero Trust Access Platform

## Quick Start

### Installation

```bash
# Build and install (Linux/macOS/Windows)
go build -o ztap ./cmd/ztap
sudo mv ztap /usr/local/bin/

# Note for Linux: The binary includes pre-compiled eBPF bytecode.
# No clang/llvm dependency is required at runtime.
```

### First Steps

```bash
# 1. Authenticate
# On first run ZTAP creates an admin account.
# The initial password comes from ZTAP_BOOTSTRAP_ADMIN_PASSWORD,
# or is generated and written to ~/.ztap/bootstrap_admin_password.txt.
ztap user login admin
ztap user change-password admin

# 2. Register services
ztap discovery register web-1 10.0.1.1 --labels app=web,tier=frontend
ztap discovery register db-1 10.0.2.1 --labels app=database,tier=backend

# 3. Enforce a policy
# Validate the policy first (CI/CD friendly)
ztap policy validate -f examples/web-to-db.yaml

# macOS (pf)
ztap enforce -f examples/web-to-db.yaml

# Windows (WFP)
# Note: run in an elevated terminal (Administrator).
# Supports IPv4/IPv6 `ipBlock.cidr` (arbitrary CIDRs) and TCP/UDP/ICMP.
# For `protocol: ICMP`, the policy `port` is accepted by validation but ignored during enforcement.
# Optional strict default-deny can be enabled with: ZTAP_WFP_STRICT=1
ztap enforce -f policy.yaml

# Linux (eBPF)
# Kubernetes nodes use the instance-owned engine through `ztap agent`.
# The agent owns its cgroup links and detaches them on shutdown; a crash or
# restart therefore creates a fail-open interval until the replacement agent
# completes its first policy apply.
# Direct file-based Linux enforcement is retired. `ztap enforce` returns a
# migration error on Linux; run the node agent with an explicit node identity.
# The agent watches NetworkPolicy, Pod, Namespace, and Node informer caches and
# compiles one immutable snapshot per reconciliation.
sudo ztap agent --node-name "$NODE_NAME"

# Dry-run mode (all platforms)
# Simulate enforcement without making system changes
# macOS/Windows file-policy dry run
ztap enforce -f policy.yaml --dry-run
# Linux agent dry run
ztap agent --node-name "$NODE_NAME" --dry-run

# 4. Check status
ztap status
```

Cluster backend:

- Default: in-memory (single-process)
- Production: configure etcd via `cluster.*` in `config.yaml` (see `config.yaml.example`) or env vars like `ZTAP_ETCD_ENDPOINTS`

**[Full Setup Guide](docs/guides/setup.md)** | **[Architecture](docs/concepts/architecture.md)** | **[eBPF Setup](docs/concepts/ebpf.md)**

---

## Features

<table>
<tr>
<td width="50%">

### Security & Enforcement

- **Kernel-Level Filtering** – Real eBPF on Linux
- **Zero-Downtime Updates** – Graceful, atomic policy reloads using eBPF `bpf_link`
- **Explicit Linux prerequisites** – the Kubernetes agent requires cgroup v2,
  bpffs, and eBPF capabilities and reports startup failures without an iptables
  fallback
- **Bidirectional Enforcement** – Ingress and egress policies
- **Secure Communication** – HTTPS/TLS support for API and gRPC endpoints
- **RBAC** – Admin, Operator, Viewer roles
- **Session Management** – Configurable TTL with persistent sessions (SQLite default)
- **Tamper-Evident Audit Logging** – Cryptographic hash chaining (optional signing + checkpoints)
- **NIST SP 800-207** compliant

### Distributed Architecture

- **Leader Election** – Automatic cluster coordination
- **Policy Synchronization** – Real-time policy distribution with auto-enforcement
- **Multi-Node Support** – High-availability deployments
- **Version Tracking & Rollback** – Revision history with rollback to prior versions
- **Prometheus Metrics** – 7 metrics for sync and enforcement monitoring

### Cloud Integration

- **AWS Security Groups** – Auto-sync policies (supports inventory export + offline selector/IP resolution)
- **Azure NSGs** – Reconcile policies into NSG security rules
- **GCP Firewall Rules** – Reconcile policies into VPC firewall rules
- **EC2 Auto-Discovery** – Tag-based labeling
- **Hybrid View** – Unified on-prem + cloud status

</td>
<td width="50%">

### Observability

- **Flow Monitoring** – Live Linux stream from the node agent's pinned eBPF ring buffer
- **Alerting (Webhooks)** – Slack and PagerDuty notifications
- **Prometheus Metrics** – Pre-built exporters
- **Grafana Dashboards** – Auto-provisioned
- **ML Anomaly Detection** – Isolation Forest
- **Structured Logs** – Filter & follow

### Developer Experience

- **Kubernetes-Style YAML** – Familiar syntax
- **Label-Based Discovery** – Kubernetes API, DNS, and caching
- **Compliance Reporting** – PCI-DSS, SOC2, HIPAA policy mapping exports and reports
- **REST API Server** – Minimal v1 endpoints via `ztap api serve`
- **gRPC API Server** – Minimal v1 RPCs via `ztap grpc serve`
- **Tested** – Run `go test ./... -cover` for current coverage
- **Multi-Platform** – Linux (eBPF) + macOS (pf) + Windows (WFP)

</td>
</tr>
</table>

---

## Documentation

Full documentation lives under [`docs/`](docs/index.md).

| Section       | Key Pages                                                                                                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Guides**    | [Setup](docs/guides/setup.md), [Deployment](docs/guides/deployment.md), [Testing](docs/guides/testing.md), [etcd](docs/guides/etcd.md)                                                        |
| **Concepts**  | [Architecture](docs/concepts/architecture.md), [eBPF](docs/concepts/ebpf.md), [Cluster](docs/concepts/cluster.md), [Audit](docs/concepts/audit.md), [Compliance](docs/concepts/compliance.md) |
| **Reference** | [CLI](docs/reference/cli.md), [Configuration](docs/reference/config.md), [API](docs/reference/api.md)                                                                                         |
| **Runbooks**  | [Windows WFP Reader Tests](docs/runbooks/windows-flow-monitoring.md)                                                                                                                          |
| **Project**   | [Project Status](docs/project-status.md), [Anomaly Detection](internal/anomaly/README.md)                                                                                                          |

---

## Example Policies

<details>
<summary><b>Web to Database (Label-based)</b></summary>

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        podSelector:
          matchLabels:
            app: db
      ports:
        - protocol: TCP
          port: 5432
```

</details>

<details>
<summary><b>PCI Compliant (IP-based)</b></summary>

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: pci-compliant
  annotations:
    ztap.io/compliance.pci-dss: "10.2.1"
spec:
  podSelector:
    matchLabels:
      app: payment-processor
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
```

</details>

<details>
<summary><b>Bidirectional (Ingress + Egress)</b></summary>

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-tier
spec:
  podSelector:
    matchLabels:
      tier: web
  egress:
    - to:
        podSelector:
          matchLabels:
            tier: database
      ports:
        - protocol: TCP
          port: 5432
  ingress:
    - from:
        ipBlock:
          cidr: 10.0.0.0/24
      ports:
        - protocol: TCP
          port: 443
```

</details>

<details>
<summary><b>Compliance Exports</b></summary>

```bash
# JSON export (canonical)
ztap compliance export -f examples/pci-compliant.yaml --format json

# CSV export (spreadsheets)
ztap compliance export -f examples/pci-compliant.yaml --format csv --out compliance.csv

# Human-readable report
ztap compliance report -f examples/pci-compliant.yaml --format md
```

See [Compliance Reporting](docs/concepts/compliance.md) for policy annotations and mapping files.

</details>

**More examples in [examples/](examples/)**

---

## CLI Commands

```bash
ztap [command]

Commands:
  api         Run REST API server (serve)
  grpc        Run gRPC API server (serve)
  aws         AWS Security Group synchronization (sg-sync, inventory)
  azure       Azure NSG synchronization (nsg-sync)
  gcp         GCP firewall rule synchronization (firewall-sync)
  agent       Run node agent (Kubernetes / in-cluster)
  compliance  Compliance mapping exports and reports
  enforce     Enforce zero-trust network policies
  version     Print ZTAP version
  status      Show on-premises and cloud resource status
  cluster     Manage cluster coordination (status, join, leave, list)
  policy      Distributed policy management (sync, list, watch, show, history, rollback)
  flows       Live flow event streaming (--action, --protocol, --direction)
  logs        View ZTAP logs (with --follow, --level, --policy filters)
  metrics     Start Prometheus metrics server
  user        Manage users (create, login, list, change-password)
  discovery   Service discovery (register, resolve, list)
  audit       Audit log management (view, verify, stats, keygen)
```

<details>
<summary><b>API Server</b></summary>

```bash
# Start REST API server (reads config.yaml or file set via ZTAP_CONFIG)
ztap api serve

# Start gRPC API server (default 127.0.0.1:9092)
ztap grpc serve

# Liveness / Readiness
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
```

See [API Reference](docs/reference/api.md) for all endpoints, gRPC services, and rate limiting details.
See [Configuration Reference](docs/reference/config.md) for `api.*` and `grpc.*` settings.

</details>

<details>
<summary><b>User Management</b></summary>

```bash
# Create users with roles (admin, operator, viewer)
echo "password" | ztap user create alice --role operator
ztap user list
ztap user change-password alice
```

</details>

<details>
<summary><b>Service Discovery</b></summary>

```bash
# Register and resolve services by labels
ztap discovery register web-1 10.0.1.1 --labels app=web,tier=frontend
ztap discovery resolve --labels app=web
ztap discovery list
```

Configuration (optional):

```yaml
# config.yaml (or file set via ZTAP_CONFIG)
discovery:
  backend: dns # inmemory (default) or dns
  dns:
    domain: example.com
  cache:
    ttl: 30s # optional cache layer for the selected backend
```

</details>

<details>
<summary><b>Cluster & Policy Management</b></summary>

```bash
# Cluster operations
ztap cluster status                          # View cluster state
ztap cluster join node-2 192.168.1.2:9090   # Join a node
ztap cluster list                            # List all nodes

# Policy synchronization (leader-initiated)
ztap policy sync examples/web-to-db.yaml    # Sync policy to all nodes
ztap policy list                             # List all policies
ztap policy watch                            # Watch real-time updates
ztap policy show web-to-db                   # Show policy details
ztap policy history web-to-db                # Show revision history
ztap policy rollback web-to-db --to 3        # Roll back by creating a new latest version
```

</details>

<details>
<summary><b>Flow Monitoring</b></summary>

```bash
# Stream live flow events from the node-local agent
ztap flows

# Filter by action/protocol/direction
ztap flows --action blocked --protocol TCP
ztap flows --direction egress

  # Output formats
  ztap flows --output table   # Default
  ztap flows --output json
```

On Linux, if `ztap agent` is enforcing, `ztap flows` streams real events from
the pinned eBPF ring buffer map
(`/sys/fs/bpf/ztap/flow_events`). The reader also validates the pinned agent
status heartbeat and holds `/run/ztap/flows.lock` so only one node-local reader
consumes events. JSON records include the policy epoch, subject cgroup ID,
bounded decision reason, and event-schema version. The node agent is the only
Linux producer of the pinned engine flow stream. The command is Linux-only and
does not provide recent-history or simulated output.

</details>

<details>
<summary><b>Audit Logging</b></summary>

```bash
# View audit log with tamper-evident cryptographic verification
ztap audit view                                   # View recent entries
ztap audit view --actor admin                     # Filter by actor
ztap audit view --type policy.created             # Filter by event type
ztap audit view --resource web-policy             # Filter by resource
ztap audit view --limit 100                       # Limit results

# Verify cryptographic integrity
ztap audit verify                                 # Detect tampering
ztap audit keygen --output-dir ~/.ztap             # Generate Ed25519 keypair

# Display statistics
ztap audit stats                                  # Show log stats
```

</details>

---

## Observability

### Prometheus Metrics

| Metric                                     | Description                              |
| ------------------------------------------ | ---------------------------------------- |
| `ztap_policies_enforced_total`             | Number of policies enforced              |
| `ztap_flows_allowed_total`                 | Allowed flows counter                    |
| `ztap_flows_blocked_total`                 | Blocked flows counter                    |
| `ztap_anomaly_score`                       | Current anomaly score (0-100)            |
| `ztap_policy_load_duration_seconds`        | Policy load time histogram               |
| `ztap_policies_synced_total`               | Total policy sync operations             |
| `ztap_policy_sync_duration_seconds`        | Policy sync duration histogram           |
| `ztap_policy_version_current`              | Current version of each policy           |
| `ztap_policy_enforcement_duration_seconds` | Policy enforcement duration histogram    |
| `ztap_policy_subscribers_active`           | Active policy subscribers count          |
| `ztap_flows_total`                         | Flow events by action/protocol/direction |

### Grafana Dashboard

```bash
docker compose up -d  # Access at http://localhost:3000 (admin/ztap)
```

Dashboard auto-provisioned from `deployments/grafana/dashboards/ztap-dashboard.json`

---

## Requirements

| Component      | Requirement                      | Notes                               |
| -------------- | -------------------------------- | ----------------------------------- |
| **OS**         | Linux (kernel ≥5.7) or macOS 12+ | Linux for production, macOS for dev |
| **Go**         | 1.25+                            | Build requirement                   |
| **eBPF Tools** | clang, llvm, make, linux-headers | Only if recompiling eBPF source     |
| **Privileges** | Root or CAP_BPF + CAP_NET_ADMIN  | Linux eBPF enforcement              |
| **AWS**        | EC2/VPC access (optional)        | For cloud integration               |
| **Docker**     | Latest (optional)                | For Prometheus/Grafana stack        |
| **Python**     | 3.13+ (optional)                 | For anomaly detection service       |

**[Full eBPF Setup Guide](docs/concepts/ebpf.md)**

---

## Development

```bash
# Build
go build ./cmd/ztap

# Run tests
go test ./...

# Comprehensive security audit (tests + vet + govulncheck + gosec)
bash scripts/security_check.sh

# eBPF integration test (Linux + root required)
sudo go test -tags=integration ./internal/enforcer -run TestEBPFIntegration -v

# Coverage
go test ./... -cover

# Race detection
go test ./... -race

# Lint (CI uses golangci-lint which includes gofmt + go vet)
go fmt ./...

# Optional: repository secret scan
gitleaks detect --source . --redact --no-banner
```

### Demo

```bash
./demo.sh  # Interactive demo with RBAC, service discovery, and policy enforcement
```

---

## License

MIT License - See [LICENSE](LICENSE)

## Project Hygiene

- Security policy: `SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`
- Changelog: `CHANGELOG.md`

---

## Acknowledgments

- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) Zero Trust Architecture
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) specification
- [Cilium](https://cilium.io/) and [Tetragon](https://tetragon.io/) for eBPF inspiration
- [MITRE ATT&CK](https://attack.mitre.org/) framework

---

<div align="center">

**Note:** macOS enforcement (pf) is for development only. Use Linux + eBPF for production.

[eBPF Setup Guide](docs/concepts/ebpf.md) | [Get Started](docs/guides/setup.md) | [Open an Issue](../../issues)

</div>

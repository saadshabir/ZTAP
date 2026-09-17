# CLI Reference

Complete command reference for the `ztap` binary. Source: [`internal/cli/`](../../internal/cli/); the entrypoint is [`cmd/ztap/`](../../cmd/ztap/).

## Global Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--log-level` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `--log-format` | (config) | Log format (`json` or `text`) |
| `--log-file` | (config) | Path to log file |

## Commands

### `ztap enforce`

Enforce file based policies on macOS (pf) or Windows (WFP). Linux direct
enforcement is retired; use `ztap agent` on Kubernetes nodes.

```
ztap enforce -f <policy-file> [flags]
```

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--file` | `-f` | (required) | Path to policy YAML file |
| `--cgroup` | | `/sys/fs/cgroup` | Retained compatibility flag; Linux command exits before enforcement |
| `--bpf-object` | | (embedded) | Retained compatibility flag; Linux command exits before enforcement |
| `--debug-ebpf` | | `false` | Retained compatibility flag; Linux command exits before enforcement |
| `--resolve-labels` | | `false` | Resolve label selectors to IPs via discovery |
| `--resolve-labels-interval` | | `5s` | Interval for re-resolving selectors (`0` = once) |
| `--dry-run` | | `false` | Simulate enforcement without applying rules |

### `ztap agent`

Run the Linux Kubernetes node agent. It watches NetworkPolicy, Pod, Namespace,
and Node informer caches and applies one immutable snapshot through the
instance-owned eBPF engine.

```text
ztap agent --node-name <node-name> [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--node-name` | (required) | Local Kubernetes node name used for subject selection |
| `--kubeconfig` | | Kubeconfig path; empty uses in-cluster credentials |
| `--cgroup-root` | `/sys/fs/cgroup` | Mounted cgroup v2 root for subject attachment |
| `--cgroup` | | Deprecated alias for `--cgroup-root` |
| `--bpffs-root` | `/sys/fs/bpf` | Mounted bpffs root for stable engine maps |
| `--run-dir` | `/run/ztap` | Directory containing the node-agent lock |
| `--listen` | `:9090` | Local health, readiness, and metrics listen address |
| `--dry-run` | `false` | Simulate enforcement without applying rules |

### `ztap api serve`

Start the REST API server.

```
ztap api serve [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--listen` | (config) | Listen address (e.g. `127.0.0.1:8080`) |
| `--auth` | (config) | Enable authentication |
| `--tls` | `false` | Enable TLS |
| `--tls-cert` | | Path to TLS certificate |
| `--tls-key` | | Path to TLS private key |
| `--rate-limit` | `false` | Enable rate limiting |
| `--rate-limit-per-ip-rps` | `20` | Per-IP requests per second |
| `--rate-limit-per-ip-burst` | `40` | Per-IP burst capacity |
| `--rate-limit-per-token-rps` | `10` | Per-token requests per second |
| `--rate-limit-per-token-burst` | `20` | Per-token burst capacity |
| `--rate-limit-unauth-rps` | `5` | Unauthenticated requests per second |
| `--rate-limit-unauth-burst` | `10` | Unauthenticated burst capacity |

### `ztap grpc serve`

Start the gRPC API server.

```
ztap grpc serve [flags]
```

Flags mirror `ztap api serve` (listen, auth, TLS, rate-limit). Default listen: `127.0.0.1:9092`.

### `ztap policy`

Distributed policy management.

| Subcommand | Description |
| --- | --- |
| `policy validate -f <file>` | Validate a policy file offline |
| `policy sync <file> --name <name>` | Sync a policy to all cluster nodes (leader only) |
| `policy list` | List all synced policies |
| `policy watch` | Watch real-time policy updates |
| `policy show <name>` | Show policy details (accepts `tenant/name`) |
| `policy history <name> [--limit N]` | Show revision history |
| `policy rollback <name> --to <version> [--reason <text>]` | Roll back by creating a new latest revision |

### `ztap cluster`

Manage cluster coordination.

| Subcommand | Description |
| --- | --- |
| `cluster status` | View cluster state |
| `cluster join <node-id> <address>` | Join a node |
| `cluster leave <node-id>` | Remove a node |
| `cluster list` | List all nodes |
| `cluster config set-backend <backend>` | Set cluster backend |
| `cluster config show` | Show cluster config |
| `cluster test-etcd` | Test etcd connectivity |

### `ztap user`

User management.

| Subcommand | Description |
| --- | --- |
| `user create <username> --role <role>` | Create a user (reads password from stdin) |
| `user list` | List all users |
| `user change-password <username>` | Change user password |
| `user disable <username>` | Disable a user account |
| `user enable <username>` | Enable a user account |
| `user login <username>` | Authenticate and store token |
| `user logout` | Clear stored token |

Roles: `admin`, `operator`, `viewer`.

### `ztap audit`

Audit log management.

| Subcommand | Description |
| --- | --- |
| `audit view` | View recent entries |
| `audit verify` | Verify cryptographic integrity |
| `audit stats` | Display audit log statistics |
| `audit keygen --output-dir <dir>` | Generate Ed25519 signing keypair |

`audit view` filters:

| Flag | Description |
| --- | --- |
| `--type` | Filter by event type (e.g. `policy.created`) |
| `--actor` | Filter by actor |
| `--resource` | Filter by resource |
| `--start` | Start time (RFC 3339) |
| `--end` | End time (RFC 3339) |
| `--limit` | Max entries to return |
| `--follow` | Stream new entries |

### `ztap flows`

Real-time flow event monitoring.

```
ztap flows [flags]
```

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--follow` | `-f` | `false` | Stream events in real-time |
| `--action` | `-a` | | Filter by action (`allowed`, `blocked`) |
| `--protocol` | `-p` | | Filter by protocol (`TCP`, `UDP`, `ICMP`) |
| `--direction` | `-d` | | Filter by direction (`egress`, `ingress`) |
| `--limit` | `-n` | | Max events to display |
| `--output` | `-o` | `table` | Output format (`table`, `json`) |
| `--run-dir` | | `/run/ztap` | Directory containing the node-local flow-reader lock |

### `ztap logs`

View ZTAP structured logs.

```
ztap logs [flags]
```

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--policy` | `-p` | | Filter by policy name |
| `--level` | `-l` | | Filter by log level |
| `--contains` | `-c` | | Filter by substring |
| `--follow` | `-f` | `false` | Follow new log entries |
| `--tail` | `-n` | | Number of recent lines |

### `ztap status`

Show on-premises and cloud resource status.

```
ztap status [flags]
```

| Flag | Description |
| --- | --- |
| `--aws` / `-a` | Include AWS resources |
| `--region` / `-r` | AWS region |
| `--profile` | AWS CLI profile |
| `--azure` | Include Azure resources |
| `--azure-subscription-id` | Azure subscription ID |
| `--azure-resource-group` | Azure resource group |
| `--azure-nsg` | Azure NSG name |
| `--gcp` | Include GCP resources |
| `--project-id` | GCP project ID |
| `--network` | GCP VPC network |
| `--verbose` | Show detailed cloud info |

### `ztap aws`

AWS Security Group synchronization and inventory.

| Subcommand | Description |
| --- | --- |
| `aws sg-sync <policy-file>` | Sync policy egress rules into an AWS Security Group |
| `aws inventory export` | Export EC2 inventory to JSON |
| `aws inventory resolve` | Resolve IPs for label selectors |

`aws sg-sync` flags:

| Flag | Description |
| --- | --- |
| `--region` | AWS region |
| `--profile` | AWS CLI profile |
| `--security-group-id` | Target Security Group |
| `--dry-run` | Preview changes only |
| `--watch` | Re-sync on file change |
| `--watch-interval` | Watch poll interval |
| `--replace-egress` | Clear existing egress rules first |
| `--force` / `--yes` | Skip confirmation prompts |
| `--inventory-file` | Use pre-exported inventory |
| `--output` | Output format (`text`, `json`) |
| `--show-resolved` | Show resolved IPs |

### `ztap azure`

Azure NSG synchronization.

```
ztap azure nsg-sync <policy-file> [flags]
```

| Flag | Description |
| --- | --- |
| `--subscription-id` | Azure subscription ID |
| `--resource-group` | Azure resource group |
| `--nsg` | NSG name |
| `--rule-prefix` | Managed rule prefix (default: `ztap-`) |
| `--priority-base` | Starting priority (default: `2000`) |

### `ztap gcp`

GCP VPC firewall rule synchronization.

```
ztap gcp firewall-sync <policy-file> [flags]
```

| Flag | Description |
| --- | --- |
| `--project-id` | GCP project ID |
| `--network` | VPC network name |
| `--rule-prefix` | Managed rule prefix (default: `ztap-`) |
| `--priority-base` | Starting priority (default: `2000`) |
| `--dry-run` | Preview changes only |
| `--watch` | Re-sync on file change |
| `--watch-interval` | Watch poll interval |

### `ztap compliance`

Compliance mapping exports and reports.

| Subcommand | Description |
| --- | --- |
| `compliance export -f <policy>` | Export compliance mappings |
| `compliance report -f <policy>` | Generate a compliance report |

Common flags:

| Flag | Description |
| --- | --- |
| `-f` / `--policy-file` | Policy YAML file(s) |
| `--mapping-file` | Optional mapping YAML file |
| `--framework` | Filter by framework(s) |
| `--audit-log` | Path to audit log (for evidence) |
| `--evidence-window` | Evidence lookback window (e.g. `90d`) |
| `--strict` | Fail on unknown frameworks/control IDs |
| `--format` | Output format (`json`, `csv`, `md`) |
| `--out` / `--out-dir` | Output file/directory path |

### `ztap discovery`

Service discovery management.

| Subcommand | Description |
| --- | --- |
| `discovery register <name> <ip> --labels k=v,...` | Register a service |
| `discovery deregister <name>` | Remove a service |
| `discovery resolve --labels k=v,...` | Resolve services by labels |
| `discovery list` | List all registered services |

### `ztap metrics`

Start a standalone Prometheus metrics server.

```
ztap metrics [--port 9090]
```

### `ztap alert`

Alerting commands.

```
ztap alert test    # Send a test alert to configured sinks
```

### `ztap version`

Print the ZTAP version string.

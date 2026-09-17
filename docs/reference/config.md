# Configuration Reference

All ZTAP runtime settings. Source: [`config.yaml.example`](../../config.yaml.example).

ZTAP reads `config.yaml` from the working directory by default, or the path set via the `ZTAP_CONFIG` environment variable. One typed loader (`internal/config`) parses the file once per invocation; precedence is **flag > env > config > default**. Unknown keys are ignored with a warning; set `ZTAP_CONFIG_STRICT=1` to fail on unknown keys instead.

## Discovery

```yaml
discovery:
  backend: inmemory   # inmemory | dns | k8s
  dns:
    domain: example.com
  k8s:
    namespace: ""     # restrict to a namespace; empty = ZTAP_NAMESPACE or "default"
  cache:
    ttl: ""           # e.g. "30s"; empty disables caching
```

## Logging

```yaml
logging:
  level: info         # debug | info | warn | error
  file: ~/.ztap/ztap.log
  format: json        # json | text
```

Environment variables: `ZTAP_LOG_LEVEL`, `ZTAP_LOG_FORMAT`, `ZTAP_LOG_FILE`.

## Alerting

```yaml
alerting:
  enabled: false
  queue_size: 128
  workers: 2
  timeout: 5s
  dedupe_ttl: 5m
  slack:
    webhook_url: ""
  pagerduty:
    routing_key: ""
    source: ztap
```

Environment variables: `ZTAP_ALERT_SLACK_WEBHOOK_URL`, `ZTAP_ALERT_PAGERDUTY_ROUTING_KEY`, `ZTAP_ALERT_PAGERDUTY_SOURCE`.

## Metrics

```yaml
metrics:
  enabled: true
  port: 9090
  path: /metrics
```

`metrics.enabled` gates the metrics endpoint in `ztap metrics`, `ztap agent`,
and `ztap enforce`; `port`/`path` provide its defaults (overridden by the
`--port` flag for the standalone command). `ZTAP_METRICS_LISTEN` overrides
the full bind address, e.g. `0.0.0.0:9090`.

## REST API Server

```yaml
api:
  listen: 127.0.0.1:8080
  auth:
    enabled: true
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    client_auth: false      # mTLS
    client_ca_file: ""
  rate_limit:
    enabled: false
    trust_proxy_headers: false
    unauthenticated:
      rps: 5
      burst: 10
    per_ip:
      rps: 20
      burst: 40
    per_token:
      rps: 10
      burst: 20
    exempt_paths:
      - /healthz
      - /readyz
      - /metrics
```

## gRPC API Server

```yaml
grpc:
  listen: 127.0.0.1:9092
  auth:
    enabled: true
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    client_auth: false
    client_ca_file: ""
  rate_limit:
    enabled: false
    unauthenticated:
      rps: 5
      burst: 10
    per_ip:
      rps: 20
      burst: 40
    per_token:
      rps: 10
      burst: 20
    exempt_methods:
      - /grpc.health.v1.Health/*
      - /ztap.api.v1.AuthService/Login
```

## Cluster Coordination

```yaml
cluster:
  backend: memory         # memory | etcd
  node_id: ""             # defaults to hostname
  node_address: ""        # defaults to server listen address
  election:
    heartbeat_interval: "" # e.g. "5s"
    election_timeout: ""   # e.g. "15s"
  etcd:
    endpoints: []          # e.g. ["localhost:2379"]
    dial_timeout: ""
    username: ""
    password: ""
    key_prefix: ""         # default: "/ztap"
    leader_election_key: ""
    session_ttl: ""        # default: "60s"
```

Environment variables: `ZTAP_CLUSTER_BACKEND`, `ZTAP_ETCD_ENDPOINTS`, `ZTAP_ETCD_USERNAME`, `ZTAP_ETCD_PASSWORD`, `ZTAP_ETCD_KEY_PREFIX`, `ZTAP_ETCD_SESSION_TTL`, `ZTAP_NODE_ID`, `ZTAP_NODE_ADDRESS`.

## Authentication

```yaml
auth:
  sessions:
    backend: sqlite       # sqlite | memory
    ttl: 24h
    sqlite:
      path: ~/.ztap/sessions.db
```

## AWS

```yaml
aws:
  enabled: false
  region: us-east-1
  profile: default
```

## Azure

```yaml
azure:
  enabled: false
  subscription_id: ""
  resource_group: ""
  nsg: ""
  rule_prefix: ztap-
  priority_base: 2000
```

Environment variables: `ZTAP_AZURE_SUBSCRIPTION_ID`, `ZTAP_AZURE_RESOURCE_GROUP`, `ZTAP_AZURE_NSG`, `ZTAP_AZURE_RULE_PREFIX`, `ZTAP_AZURE_PRIORITY_BASE`.

## GCP

```yaml
gcp:
  enabled: false
  project_id: ""
  network: ""
  rule_prefix: ztap-
  priority_base: 2000
```

Environment variables: `ZTAP_GCP_PROJECT_ID`, `ZTAP_GCP_NETWORK`, `ZTAP_GCP_RULE_PREFIX`, `ZTAP_GCP_PRIORITY_BASE`.

## Anomaly Detection

```yaml
anomaly:
  enabled: false
  # Host-local default; containers use ZTAP_ANOMALY_ENDPOINT.
  endpoint: http://localhost:5000
  threshold: 50.0
  alert_email: security@example.com
  batch_size: 50            # flows per batch sent to the detection service
  flush_interval: 10s       # max time before flushing a partial batch
  auth_token: ""            # Bearer token presented to the detection service
  fail_open: true           # continue enforcement when the service is unreachable
```

Consumed by `ztap agent` and `ztap enforce` when `enabled: true`: flow events
are buffered to `batch_size` / `flush_interval` and scored asynchronously by
the Python service (`internal/anomaly`); flows scoring above `threshold` emit
an alert webhook, an audit entry, and the `ztap_anomaly_score` metric. The
agent and enforcement commands expose that metric from their own process
when anomaly detection and `metrics.enabled` are true; the standalone
`ztap metrics` command is for processes that do not run enforcement.
`fail_open: false` stops the detection pipeline (fail closed) when the
service is unreachable; enforcement itself never blocks on detection.

Service-side environment variables (the Python service): `ZTAP_ANOMALY_TOKEN`
(shared secret; when set every data endpoint requires the bearer token),
`ZTAP_ANOMALY_HOST` / `ZTAP_ANOMALY_PORT` (bind address for host-local dev
runs; the container image binds 0.0.0.0 via gunicorn). The Go process accepts
`ZTAP_ANOMALY_ENDPOINT` and `ZTAP_ANOMALY_AUTH_TOKEN` overrides; use
`http://anomaly-detector:5000` for an agent running in the Compose network.
The anomaly container runs one Gunicorn worker so training and detection share
model state.

## Enforcement

```yaml
enforcement:
  dry_run: false
  default_action: block # block | allow
```

`enforcement.dry_run` defaults `ztap enforce --dry-run`; `enforcement.default_action` defaults `ztap enforce --default-action` (traffic not matching any policy rule; currently honored by the pf backend — eBPF/WFP are default-deny by design). The enforcement backend itself is OS-determined (pf on macOS, eBPF on Linux), not configurable.

Environment variables: `ZTAP_WFP_STRICT` (set to `1` for strict default-deny on
Windows). `ZTAP_FORCE_IPTABLES` and `ZTAP_BPF_OBJECT` are retained for the
parked Linux compatibility loader and have no effect on the supported
`ztap agent` path.

## Audit Logging

```yaml
audit:
  log_path: ""                        # default: ~/.ztap/audit.log
  integrity_mode: "none"              # none | hmac-sha256 | ed25519
  key_id: ""
  hmac_key_file: ""
  ed25519_private_key_file: ""
  checkpoint_path: ""
  checkpoint_interval: "5m"
```

Environment variables: `ZTAP_AUDIT_LOG_PATH`, `ZTAP_AUDIT_INTEGRITY_MODE`, `ZTAP_AUDIT_KEY_ID`, `ZTAP_AUDIT_HMAC_KEY_FILE`, `ZTAP_AUDIT_ED25519_PRIVATE_KEY_FILE`, `ZTAP_AUDIT_CHECKPOINT_PATH`, `ZTAP_AUDIT_CHECKPOINT_INTERVAL`.

## Policy Validation

```yaml
policy:
  strict: true
  allow_empty_egress: false
  resolve_labels: false
```

Defaults for `ztap policy validate --strict` / `--allow-empty-egress` and `ztap enforce --resolve-labels`. With `strict: false`, `ztap policy validate` reports errors as warnings and exits 0; with `allow_empty_egress: true`, policies without egress/ingress rules (pure default-deny) validate successfully.

## Bootstrap

On first run, if no user database exists, ZTAP creates an `admin` account:

- If `ZTAP_BOOTSTRAP_ADMIN_PASSWORD` is set, that value is used as the initial password.
- Otherwise, a random password is generated and written to `~/.ztap/bootstrap_admin_password.txt` (permissions `0600`).

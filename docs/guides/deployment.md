# ZTAP Docker Deployment

This directory contains Docker and Docker Compose configurations for running ZTAP in containerized environments.

## Quick Start

### Using Docker Compose (Recommended)

Run the complete ZTAP stack with Prometheus, Grafana, and Anomaly Detection:

```bash
# Build and start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

### Using Docker Build Directly

Build and run ZTAP container standalone:

```bash
# Build the image
docker build -t ztap:v0.1.0 .

# Run the container
docker run -d \
  --name ztap \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --cap-add=BPF \
  -p 9090:9090 \
  -v $(pwd)/examples:/etc/ztap/examples:ro \
  ztap:v0.1.0 metrics --port 9090
```

## Services

The Docker Compose stack includes:

### ZTAP Core (`ztap`)

- **Port**: 9090 (metrics)
- **Capabilities**: Requires the documented eBPF capabilities and cgroup/bpffs
  mounts for the Linux agent
- **Volumes**: Policy examples, logs, and data
- **Self-Contained**: The container image embeds the pre-compiled eBPF bytecode. No C source code or compiler toolchain is required at runtime.
- **Command**: Runs the standalone metrics server by default. `ztap agent`
  embeds the node health, readiness, and metrics endpoint while it runs.
- **Linux agent lifecycle**: `ztap agent` owns its eBPF links and detaches them
  when it exits. A crash or restart therefore creates a fail-open interval
  until the replacement agent completes its first policy apply; monitor the
  agent restart and reconciliation interval separately from policy health.
- **Linux agent status**: the native agent listens on `--listen` (default
  `:9090`) and serves `/healthz`, `/readyz`, and `/metrics`. Readiness returns
  503 during startup, dry-run, local quarantine, or an apply failure.
- The native `/metrics` endpoint exposes bounded policy reconciliation,
  compiled-rule, subject/quarantine, active-epoch, packet-decision,
  flow-drop, slot-cleanup, unresolved-running-container, and
  Pod-start-to-classification metrics alongside the readiness and enforcement
  gauges. The agent emits a startup warning when it cannot determine whether a
  separate CNI NetworkPolicy implementation is also enforcing traffic; running
  both produces intersected decisions and is outside the supported profile.

ZTAP can also run a REST API server (see `ztap api serve`). If you run it in a container, publish the configured listen port (default `127.0.0.1:8080` in `config.yaml.example`). Secure it using TLS by mounting certificates into the container and configuring `config.yaml`.

ZTAP can also run a gRPC API server (see `ztap grpc serve`). If you run it in a container, publish the configured listen port (default `127.0.0.1:9092`). Secure it using TLS by mounting certificates into the container and configuring `config.yaml`.

### Prometheus (`prometheus`)

- **Port**: 9091 (web UI)
- **Purpose**: Metrics collection and storage
- **Configuration**: `deployments/prometheus.yml`
- **Retention**: 30 days

### Grafana (`grafana`)

- **Port**: 3000 (web UI)
- **Credentials**: admin / ztap
- **Dashboards**: Pre-configured ZTAP dashboards
- **Configuration**: `deployments/grafana/`

### Anomaly Detector (`anomaly-detector`)

- **Port**: 5000 (API)
- **Purpose**: ML-based traffic anomaly detection
- **Technology**: Python + Flask + scikit-learn
- **Health Check**: `/health` endpoint
- **Container address**: `http://anomaly-detector:5000` from the ZTAP network;
  host-local `python service.py` uses `http://localhost:5000`
- **Workers**: One Gunicorn worker so training and detection share model state

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│    ZTAP     │ ──────> │  Prometheus  │ ──────> │   Grafana   │
│  (Metrics)  │  :9090  │   (Storage)  │  :9091  │    (UI)     │
└─────────────┘         └──────────────┘         └─────────────┘
       │                                                 │
       │                                                 │
       v                                                 v
┌─────────────┐                                   Port: 3000
│  Anomaly    │                                   User: admin
│  Detector   │                                   Pass: ztap
│  (ML API)   │
└─────────────┘
   Port: 5000
```

## Configuration

### Environment Variables

Configure ZTAP via environment variables in `docker-compose.yml` (or `compose.yaml`):

```yaml
environment:
  - ZTAP_LOG_LEVEL=info
  - ZTAP_LOG_FORMAT=json
  - ZTAP_LOG_FILE=/var/log/ztap/ztap.log
  - ZTAP_METRICS_PORT=9090
  - ZTAP_AUTH_DB=/var/lib/ztap/auth.db
  # Cluster backend (optional)
  # - ZTAP_CLUSTER_BACKEND=etcd
  # - ZTAP_ETCD_ENDPOINTS=etcd1:2379,etcd2:2379
  # - ZTAP_ETCD_KEY_PREFIX=/ztap
  # - ZTAP_ETCD_SESSION_TTL=60s
  # - ZTAP_NODE_ID=ztap-node-1
  # - ZTAP_NODE_ADDRESS=10.0.1.1:9090
```

### Volumes

Persistent data is stored in Docker volumes:

- `ztap-data`: Policy state and authentication database
- `ztap-logs`: ZTAP logs
- `prometheus-data`: Metrics time-series data
- `grafana-data`: Dashboards and configuration
- `anomaly-data`: ML training data
- `anomaly-models`: Saved ML models

### Network

All services run on a custom bridge network (`ztap-net`) with subnet `172.20.0.0/16`.

## Requirements

### System Requirements

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **OS**: Linux (for eBPF), macOS (development)
- **Memory**: 2GB+ recommended
- **Disk**: 10GB+ for logs and metrics

### Linux-Specific Requirements

For eBPF enforcement on Linux:

- Kernel 5.7+ (for BTF and CO-RE support)
- Privileged container or specific capabilities:
  - `CAP_NET_ADMIN`
  - `CAP_SYS_ADMIN`
  - `CAP_BPF`
- Access to `/sys/fs/cgroup` for cgroup attachment

The Linux agent does not fall back to iptables. The retained iptables code is a
compatibility surface scheduled for the Phase 4 removal inventory.

## Usage Examples

### Apply a Policy

```bash
# Copy policy to container
docker cp examples/web-to-db.yaml ztap:/tmp/

# Start the Kubernetes node agent (instance-owned eBPF engine)
docker exec -it ztap ztap agent --node-name "$NODE_NAME"
```

Notes:

- On Kubernetes Linux nodes, run `ztap agent` for the instance-owned engine.
  Its links are process-owned: stopping or crashing the agent detaches
  enforcement and traffic fails open until the replacement agent completes its
  first policy apply. Pressing Ctrl+C therefore has the same planned fail-open
  interval as a restart.
- Direct Linux file based enforcement through `ztap enforce` is retired. The
  node agent owns the cgroup links and compiles informer snapshots through the
  instance-owned engine; it never falls back to iptables.

Kubernetes multi-namespace agent mode:

- Run one node-local agent with the required node identity:
  `ztap agent --node-name "$NODE_NAME"`
- The agent watches the cluster informer view and selects only Pods scheduled
  on that node; NetworkPolicy namespace and pod selectors determine peers.
- Tenant isolation requires the instance-owned Linux eBPF engine. Attachment
  failure is reported and does not silently fall back to iptables.

### View Status

```bash
docker exec ztap ztap status
```

### Access Grafana Dashboard

1. Navigate to http://localhost:3000
2. Login with `admin` / `ztap`
3. Browse pre-configured ZTAP dashboards

### Train Anomaly Detector

```bash
# Send training data
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [
      {
        "source_ip": "192.168.1.10",
        "dest_ip": "10.0.0.1",
        "protocol": "TCP",
        "port": 443,
        "bytes": 1024,
        "timestamp": "2025-01-01T12:00:00"
      }
    ]
  }'
```

### Check Anomaly Detector Health

```bash
curl http://localhost:5000/health
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose logs ztap

# Verify privileged mode (Linux only)
docker inspect ztap | grep Privileged
```

### eBPF Errors on Linux

If you see eBPF-related errors:

1. Verify kernel version: `uname -r` (should be 5.7+)
2. Check kernel headers: `ls /usr/src/linux-headers-$(uname -r)`
3. Ensure privileged mode or capabilities are granted
4. Check cgroup v2 support: `ls /sys/fs/cgroup/cgroup.controllers`

### Permission Denied

If you encounter permission issues:

```bash
# Run with elevated privileges
sudo docker compose up -d

# Or add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Metrics Not Appearing in Grafana

1. Check Prometheus is scraping: http://localhost:9091/targets
2. Verify ZTAP metrics endpoint: http://localhost:9090/metrics
3. Check Grafana datasource configuration

### Anomaly Detector Not Training

1. Verify Python dependencies are installed
2. Check for sufficient training data (minimum 2 samples)
3. Review logs: `docker compose logs anomaly-detector`

## Development

### Rebuild After Code Changes

```bash
# Rebuild specific service
docker compose build ztap

# Rebuild and restart
docker compose up -d --build ztap
```

### Run Tests in Container

```bash
# Go tests
docker compose run --rm ztap go test ./... -v

# Python tests
docker compose run --rm anomaly-detector python -m pytest test_service.py -v
```

### Debug Mode

```bash
# Run with debug logging
docker compose run --rm ztap ztap --log-level debug status

# Or via environment variable
docker compose run --rm ztap env ZTAP_LOG_LEVEL=debug ztap status

# Interactive shell
docker compose run --rm ztap sh
```

## Production Considerations

### Security

- **Change default passwords**: Update Grafana admin password
- **Use secrets**: Store sensitive config in Docker secrets
- **Network isolation**: Use custom networks with restricted access
- **Read-only volumes**: Mount config files as read-only

### Performance

- **Resource limits**: Set CPU and memory limits in `docker-compose.yml`
- **Volume drivers**: Use optimized volume drivers for production
- **Log rotation**: Configure log rotation to prevent disk fill

### Monitoring

- **Health checks**: All services include health checks
- **Restart policy**: Configured to restart unless stopped
- **Backup**: Regularly backup volumes (especially `prometheus-data` and `grafana-data`)

### Scaling

For production deployments:

1. Use container orchestration (Kubernetes, Docker Swarm)
2. Separate ZTAP agents across multiple nodes
3. Use external Prometheus and Grafana instances
4. Scale anomaly detector horizontally behind a load balancer only after
   adding shared model-state coordination (the default image uses one worker)

## Multi-Platform Support

### Linux (Production)

Full eBPF enforcement supported:

```bash
docker compose up -d
```

### macOS (Development)

Limited to pf (packet filter):

```bash
# Use without privileged mode
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d
```

Create `docker-compose.mac.yml`:

```yaml
version: "3.8"
services:
  ztap:
    privileged: false
    cap_drop:
      - ALL
```

### Windows

Windows hosts are supported via Windows Filtering Platform (WFP) when running `ztap` natively (Administrator required for enforcement).

Notes:

- Docker Compose stack is Linux-first; on Windows, prefer running the stack under WSL2.

> **Compatibility note:** If your Docker installation only provides the legacy `docker-compose` binary (hyphenated), substitute it for `docker compose` throughout this guide.
- Windows flow monitoring uses WFP NetEvents and requires an elevated terminal. See `docs/runbooks/windows-flow-monitoring.md`.

## Related Documentation

- [eBPF Setup](../concepts/ebpf.md)
- [Testing Guide](testing.md)
- [Architecture](../concepts/architecture.md)

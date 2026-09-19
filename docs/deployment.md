# Deployment

ZTAP is deployed as one Linux DaemonSet. The maintained manifest is
[`deployments/kubernetes/ztap-agent.yaml`](../deployments/kubernetes/ztap-agent.yaml).

## Requirements

- Linux nodes with cgroup v2 and a mounted bpffs at `/sys/fs/bpf`.
- A container runtime configured to use the systemd cgroup driver.
- Kubernetes access for the agent ServiceAccount to read Nodes, Namespaces,
  Pods, and NetworkPolicies.
- A node image with the eBPF capabilities required by the kernel and runtime.

The agent does not use host networking. It mounts the host cgroup hierarchy,
bpffs, and `/run/ztap`; it runs as UID 0 without privileged mode or privilege
escalation, drops all capabilities first, and adds only `BPF`, `NET_ADMIN`,
`PERFMON`, and `SYS_RESOURCE`. The root filesystem is read-only.

## Install

Build and publish the image, then apply the manifest:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v0.1.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --tag your-registry/ztap:v0.1.0 \
  --push .
```

Change the `image` field in the manifest to the published image when using a
registry, then run:

```sh
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent
kubectl -n ztap-system get pods -o wide
```

The image is built `CGO_ENABLED=0` from `scratch`. It contains the ZTAP binary
and CA certificates only; use Kubernetes logs, probes, port forwarding, and
node diagnostics rather than expecting a shell inside the container.

## Agent flags

The DaemonSet starts the equivalent of:

```sh
ztap agent \
  --node-name="$NODE_NAME" \
  --cgroup-root=/host/sys/fs/cgroup \
  --bpffs-root=/host/sys/fs/bpf \
  --run-dir=/run/ztap \
  --listen=:9090
```

`--node-name` is required. `--kubeconfig` is optional and defaults to
in-cluster credentials. `--dry-run` compiles snapshots without loading or
attaching eBPF and is intended for development diagnostics.

## Health and metrics

- `GET /healthz` reports process health.
- `GET /readyz` reports active enforcement readiness.
- `GET /metrics` exposes Prometheus text metrics.

The manifest annotates the Pod for a Prometheus-compatible scraper. Port
forward the agent Pod when diagnosing a local installation:

```sh
kubectl -n ztap-system port-forward pod/$POD 9090:9090
curl http://127.0.0.1:9090/metrics
```

## Removal and rollback

To stop enforcement, remove the DaemonSet and its namespace after checking
the cluster's desired policy state:

```sh
kubectl delete -f deployments/kubernetes/ztap-agent.yaml
```

The manifest is the complete shipped deployment surface; there is no
operator, auxiliary control plane, or second runtime image.

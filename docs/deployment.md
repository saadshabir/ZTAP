# Deployment

ZTAP is deployed as one Linux DaemonSet. The maintained manifest is
[`deployments/kubernetes/ztap-agent.yaml`](../deployments/kubernetes/ztap-agent.yaml).

## Requirements

- Linux nodes with cgroup v2 and a mounted bpffs at `/sys/fs/bpf`.
- containerd configured to use the systemd cgroup driver; cgroupfs, cgroup v1,
  Docker Engine, and CRI-O layouts are unsupported.
- Kubernetes 1.36.x with a CNI that does not enforce NetworkPolicy. ZTAP does
  not disable another NetworkPolicy implementation; running both produces
  intersected enforcement and is outside the first-release support contract.
- Kubernetes access for the agent ServiceAccount to read Nodes, Namespaces,
  Pods, and NetworkPolicies.
- A node image with the eBPF capabilities required by the kernel and runtime.

The agent does not share the host network, PID, or IPC namespaces. It mounts
the host cgroup hierarchy read-only, while bpffs and `/run/ztap` are writable
for the engine's pinned state and process-owned runtime directory. It runs as
UID 0 without privileged mode or privilege escalation, drops all capabilities
first, and adds only `BPF`, `NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`. The root
filesystem is read-only.

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

For a published release, prefer the immutable digest rendered by the release
workflow, for example:

```yaml
image: ghcr.io/saadshabir/ztap@sha256:<release-digest>
```

Do not replace it with `:latest` in a deployment under review.

## Upgrade

Build or pull the next released image, update the manifest to its immutable
digest, and apply the manifest again:

```sh
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
kubectl -n ztap-system get pods -l app=ztap-agent -o wide
```

The rolling update uses `maxUnavailable: 1` and `maxSurge: 0`, but links are
process-owned. The node being updated therefore has a measured fail-open
interval between the old agent exiting and the replacement completing its
first successful reconciliation. Check `/readyz` and the agent logs after the
rollout; readiness does not prevent that interval.

A SIGKILL crash has the same process-owned link behavior. The crash interval
is measured separately from orderly restart and DaemonSet rollout; none of
these intervals are zero-gap availability guarantees.

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

These endpoints accept `GET` only; other methods receive `405 Method Not
Allowed`. During graceful shutdown, `/readyz` changes to HTTP 503 with reason
`stopping` before the status listener closes.

The manifest annotates the Pod for a Prometheus-compatible scraper. Port
forward the agent Pod when diagnosing a local installation:

```sh
kubectl -n ztap-system port-forward pod/$POD 9090:9090
curl http://127.0.0.1:9090/metrics
```

Readiness is false during initial cache synchronization, dry-run, an apply
failure, or local quarantine. A selected container can transmit before the
watcher observes its Kubernetes status and cgroup; this Pod-start
classification interval is measured separately from reconciliation duration.
The process-owned links also create separate, documented fail-open intervals
on orderly restart, SIGKILL crash, and during a rolling DaemonSet update.

## Migration warning

The old `ZtapNetworkPolicy` CRD and operator are not consumed by this agent.
Export any objects that need translation before deleting the CRD: CRD deletion
removes its stored custom resources. Stop the old operator and agent before
starting this DaemonSet, then apply native `NetworkPolicy` objects and verify
readiness on every node.

## Troubleshooting

- `unsupported cgroup layout`: verify cgroup v2 and containerd's systemd
  cgroup driver; the agent intentionally does not guess paths.
- `readyz` returns 503 with a quarantine reason: inspect agent logs and correct
  or delete the rejected policy selected on that node.
- Missing eBPF attach or bpffs errors: verify the host mount, kernel feature
  probes, and the four capabilities in the manifest. Do not enable privileged
  mode as a workaround.

## Removal and rollback

To stop enforcement, remove the DaemonSet and its namespace after checking
the cluster's desired policy state:

```sh
kubectl delete -f deployments/kubernetes/ztap-agent.yaml
```

The manifest is the complete shipped deployment surface; there is no
operator, auxiliary control plane, or second runtime image.

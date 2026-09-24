# ZTAP

ZTAP is a Linux node agent that compiles the supported subset of Kubernetes
`NetworkPolicy` and enforces it with per-container eBPF programs. The product
is intentionally small: one binary, one DaemonSet, and explicit command-line
flags. It is experimental `v0.1.0` software; the documented Linux and
Kubernetes acceptance gates are part of the release contract.

## Architecture

```text
Kubernetes API -> informer snapshot -> validate/resolve -> compile
                                                        |
                                                        v
                                             per-container eBPF engine
                                              |                  |
                                              v                  v
                                      ingress/egress cgroups   flow map -> ztap flows
                                              |
                                              v
                                  health/readiness/metrics on :9090
```

## Prerequisites

- Go `1.26.6` for local builds.
- Linux with cgroup v2, bpffs, and a containerd systemd-cgroup runtime for
  enforcement.
- `kubectl` access to a Kubernetes 1.36.x cluster and a registry for the
  published image.
- clang/LLVM and the required kernel capabilities for privileged eBPF tests.

Non-Linux hosts can run the portable unit tests and offline validation, but
cannot establish the kernel, cgroup, container-runtime, or Kubernetes agent
claims.

## Product surface

```text
ztap agent     reconcile Kubernetes NetworkPolicy on one Linux node
ztap validate  validate native NetworkPolicy YAML offline
ztap flows     stream live eBPF flow events
ztap version   print build metadata
```

All commands accept the global `--log-level` (`debug`, `info`, `warn`, or
`error`) and `--log-format` (`json` or `text`) flags. Runtime configuration is
not read from a file; deployment-specific values are explicit flags on
`ztap agent`.

## Quick start

Build the Linux binary and image:

```sh
make build
make docker
```

For a Linux Kubernetes cluster, publish the image with an immutable release
tag or digest, update the manifest's `image` field, and install the node agent:

```sh
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent
```

The release manifest uses the image digest rather than a mutable tag. A
planned DaemonSet update, orderly restart, or agent crash temporarily fails
open on the affected node while the replacement attaches and completes its
first reconciliation; these intervals are measured separately from policy
latency and are not zero-gap availability guarantees.

### Measured Linux reference results

The full-scope [hosted Linux pre-release run](https://github.com/saadshabir/ZTAP/actions/runs/35810441612)
for commit `399b0d8` used Linux `6.17.0-1022-azure`, a process pinned to two
CPUs, real cgroups and packets, and the 250-Pod/25-policy/2,500-rule fixture.
Its raw JSON and hosted Kubernetes/eBPF transcripts are attached to that
workflow run, and the checked-in verifier accepted the combined evidence.

| Measurement | Result | Scope |
| --- | ---: | --- |
| Native reconciliation p95 | 180.467 ms | Synchronized fake informer cache, real engine apply; excludes API list latency and fixed debounce |
| New Pod classification p95 | 207.381 ms | Newly Running Pod in a fake informer cache with a pre-created cgroup; excludes API-server and runtime startup |
| Orderly restart p95 | 421.457 ms | Process-owned engine shutdown, replacement startup, and initial apply |
| SIGKILL to first allowed packet p95 | 4.672 ms | Link-owning child process and one selected cgroup; measures onset of fail-open, not recovery |
| Same-node DaemonSet rollout fail-open interval | 2,084 ms | Shipped capability-only agent in kind, from first allowed probe to restored deny |
| Quiet shipped-agent maximum | 0.000548 CPU cores, 50.137 MiB `memory.current` | Three five-second kind samples; `memory.current` includes non-RSS charges |
| Packet latency p99 increase; maximum sampled TCP regression | 3.697 µs; 0% | Three loopback samples from one selected cgroup with enforcement on and off |
| Flow decisions | 60,100 accounted | 11,967 delivered, 48,133 rate-limited, 0 ring-full over 60.101 seconds |

These are measurements of the linked reference fixtures, not an availability
guarantee for other nodes or workloads. A separate [failed-update
test](https://github.com/saadshabir/ZTAP/actions/runs/35810441612) preserved
the policy on an already classified cgroup while a newly created cgroup was
unobserved; its first allowed probe to blocked probe after a controlled retry
spanned 2,046.5 ms. See [deployment limits](docs/deployment.md) for the
operational implications.

A later [packet and flow follow-up](https://github.com/saadshabir/ZTAP/actions/runs/35812615459)
for implementation commit `af4cfae` used three loopback samples, each with
10,000 UDP round trips and a 128 MiB TCP transfer. The maximum UDP p99 increase
was 1.329 µs (10 µs budget), and the maximum sampled TCP throughput regression
was 3.906% (10% budget). Its 60.100-second flow run reconciled 60,099 decisions
as 11,800 delivered, 48,299 rate-limited, and zero ring-full. This follow-up
passed the checked-in verifier together with same-run hosted eBPF and
capability-agent evidence. These pre-release workflow artifacts have limited
retention and are not the tagged release's provenance archive; the release
workflow must produce and attach that archive before these claims are final.
The follow-up used the earlier 128 MiB TCP sample; the release gate now uses
1 GiB transfers so each throughput measurement runs longer.

The DaemonSet mounts the host cgroup v2 hierarchy and bpffs, requests only the
capabilities needed by the eBPF engine, and exposes health, readiness, and
Prometheus-compatible metrics on port `9090`. The runtime image is `scratch`,
so it intentionally contains no shell or debugging tools.

Validate a policy before applying it:

```sh
ztap validate --file examples/native/web-to-db.yaml
ztap validate --file - < examples/native/default-deny.yaml
```

On Linux with an active agent, stream live flow events with:

```sh
ztap flows --output json
ztap flows --action blocked --direction egress
```

The command reads `/sys/fs/bpf` by default. When run inside the shipped
DaemonSet container, use `--bpffs-root=/host/sys/fs/bpf` because the manifest
mounts the host bpffs hierarchy at that path.

## Supported policy model

The compiler accepts native `networking.k8s.io/v1` `NetworkPolicy` documents.
The supported enforcement model is IPv4 TCP/UDP rules with numeric ports,
pod and namespace selectors, and explicit `ipBlock` peers. The node-local
agent resolves cluster objects and attaches the compiled policy to local
container cgroups. Unsupported or rejected policies are reported by the
agent and do not silently become allow rules.

The examples in [`examples/native`](examples/native) are valid input for the
offline validator and are useful fixtures for development.

See the [supported-policy matrix](docs/policies.md#supported-policy-matrix) for
the exact accepted and rejected native API behavior. See
[`docs/deployment.md`](docs/deployment.md) for the runtime requirements,
upgrade procedure, and safe migration warning for the removed custom CRD.

## Development

```sh
make test
make vet
make lint
make vulncheck
make check-generated
```

The privileged Linux eBPF integration gate requires a Linux host with bpffs,
cgroup v2, clang, and the capabilities needed to load and attach programs.
The Kubernetes acceptance gate runs in a disposable kind cluster. A
non-Linux checkout can run the non-privileged unit tests, but cannot prove
those kernel or kind properties.

See [`docs/policies.md`](docs/policies.md),
[`docs/deployment.md`](docs/deployment.md), and
[`docs/development.md`](docs/development.md) for the maintained guides.

## License

ZTAP is released under the MIT license; see [`LICENSE`](LICENSE).

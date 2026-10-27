# ZTAP

ZTAP is a Linux node agent that compiles the supported subset of Kubernetes
`NetworkPolicy` and enforces it with per-container eBPF programs. The product
is intentionally small: one binary, two DaemonSets, and explicit command-line
flags. It is experimental software; the documented Linux and
Kubernetes acceptance gates are part of the supported product contract.

Pinned maps and links retain the last committed policy during agent outages
within the current kernel boot. An inherited guard blocks new containers until
their verified identity and classification are committed. Compatible replacements
recover those objects before synchronizing Kubernetes caches. See
[deployment boundaries](docs/deployment.md#upgrade), including first migration,
explicit cleanup, and the separate reboot requirement.

| Guide | Contents |
| --- | --- |
| [Deployment](docs/deployment.md) | Install, upgrade, inspect readiness and flows, troubleshoot, and remove the agent |
| [Policies](docs/policies.md) | Supported semantics, selector behavior, examples, and offline validation |
| [Development](docs/development.md) | Build, test, regenerate eBPF bindings, and contribute |
| [Performance evidence](docs/performance.md) | Reference measurements, fixture limits, and evidence verification |

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

- Go `1.26.10` or a compatible newer toolchain with current security patches
  for local builds.
- Linux with cgroup v2, bpffs, and a containerd systemd-cgroup runtime for
  enforcement.
- `kubectl` access to a Kubernetes 1.36.x cluster with no other NetworkPolicy
  enforcer. The CI cluster is pinned to `kindest/node:v1.36.4`.
- clang/LLVM 18 for regenerating eBPF bindings; the required kernel
  capabilities for privileged Linux tests. Normal builds use the checked-in
  bindings.

Non-Linux hosts can run the portable unit tests and offline validation, but
cannot establish the kernel, cgroup, container-runtime, or Kubernetes agent
claims.

## Product surface

```text
ztap agent     reconcile Kubernetes NetworkPolicy on one Linux node
ztap node-init authenticate node bootstrap identities and API endpoints
ztap cleanup   intentionally remove owned enforcement under the node lock
ztap validate  validate native NetworkPolicy YAML offline
ztap flows     stream live eBPF flow events
ztap version   print build metadata
```

All commands accept the global `--log-level` (`debug`, `info`, `warn`, or
`error`) and `--log-format` (`json` or `text`) flags. Runtime configuration is
not read from a file; deployment-specific values are explicit flags on
`ztap agent`.

## Quick start

From a source checkout, build a binary for your current host and validate a
policy offline:

```sh
git clone https://github.com/saadshabir/ZTAP.git
cd ZTAP
make build
./bin/ztap version
./bin/ztap validate --file examples/native/web-to-db.yaml
./bin/ztap validate --file - < examples/native/default-deny.yaml
```

`make build` writes `bin/ztap`; it does not install the command on your PATH.
On macOS, this binary supports offline validation, while `agent` and `flows`
require Linux. The Dockerfile builds a Linux image on either host; see
[source builds](docs/deployment.md#build-your-own-image) to publish one.

For a cluster that meets the [deployment requirements](docs/deployment.md#requirements),
build a Linux image from the checkout and use the checked-in manifest.
It includes a cluster-wide admission guard:
non-host-network containers must drop `NET_RAW` (or `ALL`), disable privilege
escalation, and avoid privileged mode and added `NET_RAW` or `SYS_ADMIN`.
Existing unsafe Pods must be recreated; the agent refuses enforcement
readiness while they remain. See [deployment requirements](docs/deployment.md#requirements)
and [source-build installation](docs/deployment.md#build-your-own-image).

For an existing disposable kind cluster named `ztap`, build and load the
image before applying the manifest:

```sh
make docker
kind load docker-image ztap:dev --name ztap
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
```

The manifest uses the same `ztap:dev` tag as `make docker`. For other
clusters, publish your source-built image to a registry reachable by the
nodes and set the manifest's image to its digest; see
[source builds](docs/deployment.md#build-your-own-image).

The agent DaemonSet mounts the host cgroup v2 hierarchy and bpffs, requests only the
capabilities needed by the eBPF engine, and exposes health, readiness, and
Prometheus-compatible metrics on port `9090`. The runtime image is `scratch`,
so it intentionally contains no shell or debugging tools.

The node initializer uses the same image, shares the node network namespace,
drops all capabilities, and publishes protected bootstrap metadata. It does not
mount bpffs. The agent keeps its separate network, PID, and IPC namespaces.

On a Linux node with an active agent and permission to read its pinned maps,
stream live flow events with:

```sh
sudo ./bin/ztap flows --output json
sudo ./bin/ztap flows --action blocked --direction egress
```

For reading flows inside the DaemonSet, see
[live flow diagnostics](docs/deployment.md#live-flow-diagnostics).

## Measured Linux reference results

Historical measurements at commit
`1b196c068b9ea42d545303dc56c77c1c5dc1ff44` used the
250-Pod/25-policy/2,500-rule fixture. Native
reconciliation p95 was 146.319 ms using a synchronized fake informer cache
and real engine apply, excluding API list latency and the fixed debounce.
Three loopback samples measured a 0.996 µs UDP p99 increase and a maximum
4.113% TCP throughput regression. The same-node kind DaemonSet rollout had
a 1,652 ms fail-open interval.

These results apply to the measured fixtures and source commit. See
[performance evidence](docs/performance.md) for the environment,
scope, resource and flow results, and verification commands.

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

See [development](docs/development.md) for prerequisites and test layers.

## License

ZTAP uses the MIT license; see [`LICENSE`](LICENSE).

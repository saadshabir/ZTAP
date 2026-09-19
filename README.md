# ZTAP

ZTAP is a Linux node agent that compiles the supported subset of Kubernetes
`NetworkPolicy` and enforces it with per-container eBPF programs. The product
is intentionally small: one binary, one DaemonSet, and explicit command-line
flags.

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

Install the node agent on a Linux Kubernetes cluster after publishing the
image as `ztap:v0.1.0` (or changing the image in the manifest):

```sh
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent
```

The DaemonSet mounts the host cgroup v2 hierarchy and bpffs, requests only the
capabilities needed by the eBPF engine, and exposes health, readiness, and
Prometheus-compatible metrics on port `9090`. The runtime image is `scratch`,
so it intentionally contains no shell or debugging tools.

Validate a policy before applying it:

```sh
ztap validate --file examples/native/web-to-db.yaml
ztap validate --file - < examples/native/default-deny.yaml
```

## Supported policy model

The compiler accepts native `networking.k8s.io/v1` `NetworkPolicy` documents.
The supported enforcement model is IPv4 TCP/UDP rules with numeric ports,
pod and namespace selectors, and explicit `ipBlock` peers. The node-local
agent resolves cluster objects and attaches the compiled policy to local
container cgroups. Unsupported or rejected policies are reported by the
agent and do not silently become allow rules.

The examples in [`examples/native`](examples/native) are valid input for the
offline validator and are useful fixtures for development.

## Development

```sh
make test
make vet
make lint
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

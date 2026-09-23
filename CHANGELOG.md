# Changelog

## [0.1.0] - 2026-09-23

ZTAP is a Linux Kubernetes node agent that enforces native
`NetworkPolicy` with cgroup eBPF. This is an intentional breaking redesign of
the earlier CRD/operator product.

### Breaking changes

- The primary commands are `agent`, `validate`, `flows`, and `version`.
  Removed services, commands, file configuration, and environment keys have
  no compatibility aliases.
- Native Kubernetes `NetworkPolicy` replaces `ZtapNetworkPolicy`. Export
  custom resources before removing the old CRD; removing it deletes stored
  policies. Stop the old operator and agent before installing this release.
- The Go module path is `github.com/saadshabir/ZTAP`. Only Linux amd64 and
  arm64 binaries and one multi-architecture image are released.

### Supported first-release contract

- Linux with cgroup v2, bpffs, and containerd's systemd cgroup driver;
  Kubernetes 1.36.x is the tested control-plane line.
- IPv4 policy enforcement with numeric TCP/UDP ports. Named ports, IPv6
  enforcement, automatic Service translation, and other CRI/cgroup layouts
  are outside this release. Explicit IPv4 ClusterIP `ipBlock` rules work;
  selector peers cover backend Pod IPs, not Service frontends.
- One capability-only, non-privileged DaemonSet owns each node's process-owned
  eBPF links. Run it with a CNI that does not also enforce `NetworkPolicy`;
  simultaneous enforcers intersect their decisions.
- Selected local container cgroups receive additive ingress and egress
  isolation. Unsupported local policy semantics quarantine the affected
  subjects or directions and change readiness, while accepted policies keep
  updating.

### Operational limits and measurements

The [hosted Phase 5 preflight](https://github.com/saadshabir/ZTAP/actions/runs/35810441612)
used Linux `6.17.0-1022-azure`, two pinned CPUs, and the
250-Pod/25-policy/2,500-rule reference fixture. The checked-in verifier
accepted the raw packet, flow, agent, resource, privileged eBPF, and kind
evidence. Reconciliation p95 was 180.467 ms; packet p99 latency increased
3.697 µs; the maximum TCP throughput regression in three samples was 0%.
The 60.101-second flow run accounted for all 60,100 decisions. The shipped
kind agent peaked at 0.000548 CPU cores and 50.137 MiB `memory.current`
across three quiet samples.

Watcher discovery and process-owned links cause fail-open windows. In the
linked fixtures, newly Running Pod classification was 207.381 ms p95, an
orderly agent restart was 421.457 ms p95, SIGKILL to the first allowed packet
was 4.672 ms p95, and a same-node DaemonSet replacement was fail-open for
2,084 ms. These intervals measure different boundaries; the Pod-start harness
excludes API-server and container-runtime startup, and the SIGKILL result
measures onset rather than recovery. After an injected kernel candidate-link
failure, an already classified cgroup kept its active policy, while a new
unobserved cgroup was fail-open until a controlled retry; its first allowed
probe to blocked probe spanned 2,046.500 ms. See
[deployment guidance](docs/deployment.md) for the operational scopes.

### Release process

`Migration CI` retains the stable `Required CI` check and validates Go,
generated eBPF, the scratch image, privileged Linux behavior, and the shipped
DaemonSet in kind. A semantic-version tag on protected `main` reruns the
real-cgroup performance gates, verifies same-commit CI provenance, and
requires the complete raw evidence set. GoReleaser creates a draft release
with Linux artifacts, SBOM, and provenance. The workflow publishes that
release only after the multi-architecture image digest is verified and an
immutable, digest-pinned install manifest and raw evidence archive are
attached.

[0.1.0]: https://github.com/saadshabir/ZTAP/releases/tag/v0.1.0

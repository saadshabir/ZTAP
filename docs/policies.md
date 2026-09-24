# Policies

ZTAP consumes native Kubernetes `networking.k8s.io/v1` `NetworkPolicy`
objects. The node agent watches the cluster, resolves selectors and local
container cgroups, then replaces the node-local eBPF policy snapshot
atomically.

The first release tracks the Kubernetes 1.36.x API line used by the repository
(`k8s.io/* v0.36.3`). It implements a deliberate IPv4-only subset; unsupported
native features are rejected instead of being broadened into an allow rule.

## Accepted input

- A document is a `NetworkPolicy` or `NetworkPolicyList` with the exact native
  API version and a name on every individual policy.
- `podSelector` selects subjects in the policy namespace.
- `namespaceSelector` and `podSelector` select peer Pods.
- `ipBlock` selects IPv4 addresses; `except` ranges are supported.
- Empty subject selectors select every Pod in the policy namespace.
- `Ingress` and `Egress` isolation are independent.
- Omitted `policyTypes` follows Kubernetes defaulting: ingress is selected,
  and egress is selected when egress rules are present.
- Policies combine additively. Empty directional rule lists implement
  default-deny for that direction.
- TCP and UDP rules use numeric destination ports.
- Explicit ClusterIP access must use an IPv4 `ipBlock` and numeric Service
  port; selector peers do not synthesize Service frontend access.

The compiler normalizes duplicate addresses and rules, bounds the number of
subjects and rules, and rejects malformed or unsupported input. A rejected
policy quarantines only the local subjects and directions that it selects;
other accepted policies continue to reconcile.

## Supported policy matrix

| Native behavior | `v0.1.0` result | Notes |
| --- | --- | --- |
| IPv4 `ipBlock`, including bounded `except` ranges | Supported | Matches the address visible at the cgroup hook. |
| `podSelector` and `namespaceSelector` peers | Supported | Selector results are resolved into cluster-wide IPv4 Pod addresses; only enforced subjects are node-local. |
| Ingress and egress isolation | Supported | Directions are independent and policies combine additively. |
| Empty directional rule list | Supported | Implements default-deny for the selected direction. |
| Numeric TCP/UDP destination ports | Supported | Omitted protocol defaults to TCP. |
| Explicit IPv4 ClusterIP `ipBlock` | Supported | No Service or EndpointSlice frontend synthesis occurs. |
| Named ports or `endPort` ranges | Rejected | Destination-Pod port resolution is post-release scope. |
| SCTP, IPv6, or dual-stack policy data | Rejected | Isolated unsupported traffic is denied; it never bypasses policy. |
| Peerless or portless allow-all rule | Rejected | Broad implicit wildcards are not approximated. |
| `hostNetwork` subject | Outside subject set | Treated as node traffic, not as a cgroup-isolated Pod. |

## Examples

```sh
ztap validate --file examples/native/allow-dns.yaml
ztap validate --file examples/native/default-deny.yaml
ztap validate --file examples/native/web-to-db.yaml
```

Validation is offline and does not contact Kubernetes. It prints the
namespace and name of every accepted `NetworkPolicy` document. Pass `-` to
read YAML from standard input.

For example, a named port is rejected with a field-specific error rather than
being guessed:

```text
document 1 (default/web-to-db): spec.egress[0].ports[0].port: named ports are not supported in v0.1.0
```

Duplicate YAML keys, unknown fields, malformed selectors, unrelated objects,
peerless rules, and portless rules are likewise validation errors. The agent
reports the same unsupported-policy boundary and quarantines affected local
subjects while continuing unrelated accepted reconciliation.

## Deliberate limits

The first product cut supports IPv4 TCP/UDP enforcement with numeric ports.
The following valid Kubernetes features are explicitly rejected in `v0.1.0`:

- named ports and `endPort` ranges;
- SCTP and IPv6/dual-stack policy data;
- peerless "all peers" rules and portless "all ports" rules;
- automatic Service/EndpointSlice frontend expansion; and
- complete local-node semantics beyond the valid local Node IP addresses
  observed in Node status.

Host-networked Pods are node traffic rather than supported cgroup subjects.
These boundaries, plus advanced flow sampling, are post-release roadmap items;
they are not silently approximated by the compiler.

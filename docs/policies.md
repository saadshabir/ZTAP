# Policies

ZTAP consumes native Kubernetes `networking.k8s.io/v1` `NetworkPolicy`
objects. The node agent watches the cluster, resolves selectors and local
container cgroups, then replaces the node-local eBPF policy snapshot
atomically.

## Accepted input

- `podSelector` selects subjects in the policy namespace.
- `namespaceSelector` and `podSelector` select peer Pods.
- `ipBlock` selects IPv4 addresses; `except` ranges are supported.
- `Ingress` and `Egress` isolation are independent.
- TCP and UDP rules use numeric destination ports.
- Empty rule lists are valid default-deny rules for their direction.

The compiler normalizes duplicate addresses and rules, bounds the number of
subjects and rules, and rejects malformed or unsupported input. A rejected
policy quarantines only the local subjects and directions that it selects;
other accepted policies continue to reconcile.

## Examples

```sh
ztap validate --file examples/native/allow-dns.yaml
ztap validate --file examples/native/default-deny.yaml
ztap validate --file examples/native/web-to-db.yaml
```

Validation is offline and does not contact Kubernetes. It prints the
namespace and name of every accepted `NetworkPolicy` document. Pass `-` to
read YAML from standard input.

## Deliberate limits

The first product cut supports IPv4 TCP/UDP enforcement with numeric ports.
Named ports, IPv6 and dual-stack behavior, automatic Service expansion, and
advanced flow sampling are post-release roadmap items. They are not silently
approximated by the compiler.

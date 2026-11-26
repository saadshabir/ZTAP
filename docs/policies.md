# Policies

ZTAP consumes native Kubernetes `networking.k8s.io/v1` `NetworkPolicy`
objects. The node agent watches the cluster, resolves selectors and local
container cgroups, then replaces the node-local eBPF policy snapshot
atomically.

The tested cluster profile is Kubernetes `1.36.4`. The current checkout uses
`k8s.io/* v0.37.1` client libraries; that dependency version does not establish
support for another cluster version. ZTAP implements a deliberate IPv4-only
subset, with explicit rejection of unsupported native features.

## Accepted input

- A document is a `NetworkPolicy` or `NetworkPolicyList` with the exact native
  API version and a name on every individual policy.
- YAML may contain multiple documents separated by `---`. An omitted policy
  namespace defaults to `default` for offline validation.
- Offline validation accepts at most 16 MiB of input across all documents.
  Oversized files and stdin streams fail with exit code 2 before YAML decoding.
- `podSelector` selects subjects in the policy namespace.
- `namespaceSelector` and `podSelector` select peer Pods.
- `ipBlock` selects IPv4 addresses; `except` ranges are supported.
- Empty subject selectors select every Pod in the policy namespace.
- `Ingress` and `Egress` isolation are independent.
- Omitted `policyTypes` follows Kubernetes defaulting: ingress is selected,
  and egress is selected when egress rules are present.
- Policies combine additively. Empty directional rule lists implement
  default-deny for that direction.
- TCP and UDP rules use numeric destination ports, named destination ports,
  or inclusive `endPort` ranges.
- Explicit ClusterIP access must use an IPv4 `ipBlock` and numeric Service
  port; selector peers do not synthesize Service frontend access.

The compiler normalizes duplicate addresses and rules, bounds the number of
subjects and rules, and rejects malformed or unsupported input. A rejected
policy quarantines only the local subjects and directions that it selects;
other accepted policies continue to reconcile.

## Selector and rule semantics

- A peer with only `podSelector` matches Pods in the policy's own namespace.
- A peer with only `namespaceSelector` matches Pods in the selected namespaces.
- Both selectors in one peer are an AND: the Pod must match in a selected
  namespace. Separate peer entries are an OR.
- Empty selectors match all Pods or namespaces in their respective scope.
  `matchLabels` and the standard `In`, `NotIn`, `Exists`, and `DoesNotExist`
  expressions are accepted.
- Peers and ports within a rule combine: any listed peer may use any listed
  destination port. Different rules and accepted policies add their allows.
- Policy isolation applies to selected local container cgroups. All ordinary
  local containers pass through the classification guard first. Peer selectors resolve
  non-host-networked Pods across the cluster, including remote nodes.
- `Succeeded` and `Failed` Pods are excluded from peer and subject resolution.
  Their retained addresses cannot grant access to a new Pod reusing the IP.
  Live terminating Pods remain eligible until they reach a terminal phase.

For a connection between two isolated Pods, the source's egress policy and
the destination's ingress policy must both permit the initiating traffic.
Traffic allowed by an explicit TCP/UDP rule creates bounded,
policy-epoch-scoped connection state so replies do not require an independent
reverse rule. State expires, can be evicted, and is invalidated by a
policy-epoch change. An unchanged compiled snapshot preserves its epoch and
existing reply state, even when an informer reports unrelated updates.
Every new TCP SYN requires an explicit rule in its initiating direction.
TCP reset removes state; once FINs are observed in both directions, final
ACKs and retransmits have a 120-second closing interval that cannot be
extended by more traffic. Half-closed streams keep their ordinary idle
timeout. Traffic in an unisolated direction does not create this
reply exemption.

Workloads must satisfy the [packet-socket security prerequisite](deployment.md#requirements).
The install manifest enforces it at admission; the agent checks existing Pods
before applying a snapshot.

Valid IPv4 TCP/UDP traffic to or from the local Node IPs recorded in Node
status, and traffic whose source and destination both equal the subject's
own Pod IP, bypass ordinary deny rules. These exceptions also precede
quarantine. Other isolated traffic is denied when malformed, fragmented,
IPv6, or an unsupported protocol; ICMP is not an allowed policy protocol.

## Supported policy matrix

| Native behavior | Result | Notes |
| --- | --- | --- |
| IPv4 `ipBlock`, including bounded `except` ranges | Supported | Matches the address visible at the cgroup hook. |
| `podSelector` and `namespaceSelector` peers | Supported | Selector results are resolved into cluster-wide IPv4 Pod addresses; only enforced subjects are node-local. |
| Ingress and egress isolation | Supported | Directions are independent and policies combine additively. |
| Empty directional rule list | Supported | Implements default-deny for the selected direction. |
| Numeric TCP/UDP destination ports and `endPort` ranges | Supported | Both endpoints are inclusive. Omitted protocol defaults to TCP. |
| Explicit IPv4 ClusterIP `ipBlock` | Supported | No Service or EndpointSlice frontend synthesis occurs. |
| Named TCP/UDP destination ports | Supported | Ingress resolves names on the selected Pod. Egress resolves them on each destination Pod. |
| SCTP or IPv6 CIDRs | Rejected | Isolated unsupported traffic is denied. |
| Selected IPv6 or dual-stack Pod | Quarantined | The selected directions are quarantined; IPv4 node/self exceptions still apply. |
| Peerless or portless allow-all rule | Rejected | Broad implicit wildcards are not approximated. |
| `hostNetwork` subject | Outside subject set | Treated as node traffic, not as a cgroup-isolated Pod. |

## Examples

```sh
make build
./bin/ztap validate --file examples/native/allow-dns.yaml
./bin/ztap validate --file examples/native/default-deny.yaml
./bin/ztap validate --file examples/native/web-to-db.yaml
```

| Example | Selected Pods | Effect |
| --- | --- | --- |
| [default-deny.yaml](../examples/native/default-deny.yaml) | All Pods in `default` | Isolates ingress and egress with no ordinary allows; node/self exceptions still apply |
| [allow-dns.yaml](../examples/native/allow-dns.yaml) | `app=client` in `default` | Allows egress TCP/UDP port 53 to the explicit DNS address |
| [web-to-db.yaml](../examples/native/web-to-db.yaml) | `app=web` and `app=db` in `default` | Two policies allow web egress and database ingress on TCP port 5432 |

These files are policy examples; they do not create workloads. Adapt their
namespaces, labels, and addresses to your cluster. `allow-dns.yaml` uses
`10.96.0.10/32` as a DNS Service placeholder. Find your cluster's DNS Service
IP and replace it before applying the policy, for example in a cluster using
the `kube-system/kube-dns` Service:

```sh
kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}{"\n"}'
```

`web-to-db.yaml` permits direct database Pod IP traffic. A database Service
ClusterIP needs its own explicit IPv4 `ipBlock` rule and numeric Service
port; the Pod selector alone does not grant frontend access.

After adapting and validating a file, apply it with `kubectl apply -f <file>`
and check the agent's readiness and logs on the affected nodes. A default-deny
policy isolates the selected directions even before another example adds
allows.

Validation is offline and does not contact Kubernetes. It prints the
namespace and name of every accepted `NetworkPolicy` document. Pass `-` to
read YAML from standard input:

```sh
./bin/ztap validate --file - < examples/native/default-deny.yaml
```

A successful validation checks the file's supported shape, not live selector
matches, Service addresses, cgroup resolution, or whether the node-wide
compiled snapshot fits the engine. The offline decoder accepts policy
metadata `name`, `namespace`, `labels`, and `annotations`; unknown fields,
including server-generated metadata in exported objects, are rejected.

| Exit status | Meaning |
| --- | --- |
| `0` | Every input policy is valid for the supported subset |
| `1` | Invalid or unsupported policy content |
| `2` | Input read/YAML decode failure or invalid command usage |

For example, combining a named port with `endPort` produces a field-specific
error.

```text
document 1 (default/web-to-db): spec.egress[0].ports[0].endPort: requires a numeric port
```

Duplicate YAML keys, unknown fields, malformed selectors, unrelated objects,
peerless rules, and portless rules are likewise validation errors. The agent
reports the same unsupported-policy boundary and quarantines affected local
subjects while continuing unrelated accepted reconciliation.

## Deliberate limits

SCTP, IPv6 CIDRs, peerless "all peers" rules, and
portless "all ports" rules are rejected. A selected IPv6 or dual-stack Pod
is quarantined in the policy's selected directions. Automatic
Service/EndpointSlice frontend expansion is not performed, and full local-node
semantics beyond observed Node status addresses are outside the supported
contract. Host-networked Pods are node traffic rather than cgroup subjects.

Each active snapshot is limited to 16,384 subject cgroups and 16,384 total
rule entries, including node/self bypass entries. One `ipBlock` may expand to
at most 1,024 IPv4 prefixes after exclusions. Counts are taken after
deduplication. A broad selector can expand one YAML rule into many entries.
A numeric range requires `1 <= port <= endPort <= 65535`. Each range is
compiled into at most 30 aligned port blocks per peer prefix, subject cgroup,
direction, and protocol. For example, `1–65535` uses 16 entries for each such
combination.

Named ports use the destination Pod's application containers and restartable
init containers. A missing name or protocol match contributes no allow for
that Pod. Egress names are tied to individual IPv4 Pod addresses, including
when an `ipBlock` supplies the address constraint. An external address or
Service frontend cannot supply a Pod port declaration. An ingress peer may
be an `ipBlock` because the selected local Pod supplies the name.
A capacity or kernel-apply failure retains the last committed snapshot. The
parent guard blocks unclassified new containers in both directions until their
verified identity, explicit classification, and any required subject links are
committed. Classification is also explicit for unisolated local containers;
those regain default allow after the commit. At most 16,384 local container
identities may be classified in an active slot.

During controller outages, policy, label, and peer changes not yet observed are
outside the last-committed-policy contract. Missing or pending identity facts
for a committed live container defer the complete candidate. Host-network
exclusions and node/self exceptions retain their documented scope. See
[deployment boundaries](deployment.md#upgrade), including initial installation
and reboot limitations.

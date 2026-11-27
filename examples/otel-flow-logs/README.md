# Cluster-wide ZTAP decision logs

Each ZTAP agent can send its node's eBPF packet decisions to an OpenTelemetry
Collector over OTLP/HTTP. This example uses mutual TLS from the agents to a
ClusterIP Collector, and sends logs from the Collector to a single Loki
instance. Loki storage is ephemeral. Use an existing Collector and log backend
for durable storage.

## Run the example

Install the shipped ZTAP DaemonSets and wait for the agents to become Ready.
The example uses the IPv4 `kube-system/kube-dns` Service for name resolution
and assumes the standard agent Pod labels and mount paths.

```sh
bash examples/otel-flow-logs/install-backend.sh
kubectl -n ztap-system patch daemonset ztap-agent --type=strategic \
  --patch-file examples/otel-flow-logs/agent-patch.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent
kubectl -n ztap-telemetry port-forward deployment/loki 3100:3100
```

The patch targets the shipped DaemonSet. Carry over any customized flags when
applying it to your installation. The backend installer creates 30-day example
certificates in Kubernetes Secrets. A reinstall generates fresh credentials.
Restart the Collector and the agents after replacing the Secrets so they read
the new files.

The patch excludes the backend and agent namespaces from export to prevent
decisions about telemetry uploads from generating more uploads. Those local
decisions still appear in `ztap flows` and the kernel counters.

Generate traffic that a ZTAP NetworkPolicy denies in the egress direction, then
query from another terminal.

```sh
curl --fail --silent --get http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode "query=$(cat examples/otel-flow-logs/blocked-egress.logql)"
```

Loki indexes `service_name` and stores decision and workload attributes as
structured metadata. Append a filter such as
`| k8s_node_name="ztap-worker"` or
`| ztap_subject_k8s_pod_uid="<pod UID>"` to narrow the result.
[OpenTelemetry logs in Loki](https://grafana.com/docs/loki/latest/send-data/otel/)

The two-node acceptance fixture runs the query for a real cross-node deny. It
also verifies allowed traffic, ingress deny, and recovery after a Collector
outage. Its evidence contains the node, local Pod UID, policy epoch, packet
tuple, and decision-to-query delay for each case.
[Acceptance script](../../.github/scripts/verify-flow-telemetry.sh)

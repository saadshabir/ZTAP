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

The installer uses kubectl's current context. Replace `YOUR_CONTEXT` with
the context where you installed ZTAP. Run the install and patch together
after checking the context. The patch replaces the agent's args
array, so carry over any customized flags before applying it.

```sh
test "$(kubectl config current-context)" = YOUR_CONTEXT &&
bash examples/otel-flow-logs/install-backend.sh &&
kubectl --context YOUR_CONTEXT -n ztap-system patch daemonset ztap-agent --type=strategic \
  --patch-file examples/otel-flow-logs/agent-patch.yaml &&
kubectl --context YOUR_CONTEXT -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
```

The backend installer creates 30-day certificates in Kubernetes Secrets.
A reinstall generates fresh credentials.
Restart the Collector and the agents after replacing the Secrets so they read
the new files.

The patch excludes the backend and agent namespaces from export to prevent
decisions about telemetry uploads from generating more uploads. It also omits
records whose subject namespace the agent cannot verify. Those local
decisions still appear in `ztap flows` and the kernel counters.

## Verify a blocked egress decision

Choose a source Pod outside the two excluded namespaces with an egress
policy that denies a specific destination. Set `NS` and `POD` to its
namespace and name. Forward the metrics port from the agent on that Pod's
node and keep the forward running.

```sh
NODE=$(kubectl --context YOUR_CONTEXT -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')
agent=$(kubectl --context YOUR_CONTEXT -n ztap-system get pods -l app=ztap-agent \
  --field-selector "spec.nodeName=$NODE,status.phase=Running" -o name)
kubectl --context YOUR_CONTEXT -n ztap-system port-forward "$agent" 9090:9090
```

In a second terminal, read the exporter metrics before generating traffic.

```sh
curl -fsS http://127.0.0.1:9090/metrics | grep -E \
  '^(ztap_flow_export_config_valid |ztap_flow_reader_active |ztap_flow_export_records_total\{outcome="acknowledged"\} )'
```

Both gauges should read `1`. A zero configuration gauge points to an
exporter setup error in the agent log. If only the reader is inactive,
check `ztap_flow_reader_lock_busy` for a competing node-local flow reader.
Note the acknowledged count, record the start time with
`start=$(date +%s)`, then send traffic from the source Pod to the denied
destination. Repeat the metrics command after the batch flushes. An
increase means the Collector acknowledged records from that node. If it
stays flat, check the agent's [export and loss metrics](../../docs/deployment.md#cluster-wide-opentelemetry-logs).

To verify the specific deny in Loki, stop the metrics forward and start
this forward in the first terminal.

```sh
kubectl --context YOUR_CONTEXT -n ztap-telemetry port-forward deployment/loki 3100:3100
```

In the second terminal, set `NS` and `POD` to the same source workload.
Query for its Pod UID and the time of the probe.

```sh
pod_uid=$(kubectl --context YOUR_CONTEXT -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}')
query=$(cat examples/otel-flow-logs/blocked-egress.logql)
curl -fsS --get http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode "start=${start}000000000" \
  --data-urlencode "query=$query | ztap_subject_k8s_pod_uid=\"$pod_uid\""
```

Look for the probe's destination address and port in the returned records.
If the result is empty, allow for ingestion delay and repeat the query.

Loki indexes `service_name` and stores decision and workload attributes as
structured metadata. Append `| k8s_node_name="ztap-worker"` to filter by node.
[OpenTelemetry logs in Loki](https://grafana.com/docs/loki/latest/send-data/otel/)

The two-node acceptance fixture runs the query for a real cross-node deny. It
also verifies allowed traffic, ingress deny, and recovery after a Collector
outage. Its evidence contains the node, local Pod UID, policy epoch, packet
tuple, and decision-to-query delay for each case.
[Acceptance script](../../.github/scripts/verify-flow-telemetry.sh)

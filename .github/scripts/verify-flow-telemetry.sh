#!/usr/bin/env bash
# Run on the disposable two-node kind fixture after installing the shipped agent.
set -euo pipefail
test "${ZTAP_KINDNET_NETWORKPOLICY_DISABLED:-}" = 1
test "$(kubectl config current-context)" = kind-ztap
example=examples/otel-flow-logs
evidence="${ZTAP_TELEMETRY_EVIDENCE_DIR:-flow-telemetry-evidence}"
test ! -L "$evidence"
mkdir -p "$evidence"
test -z "$(find "$evidence" -mindepth 1 -maxdepth 1 -print -quit)"
ns=ztap-flow-test
node_a=ztap-control-plane
node_b=ztap-worker
loki=http://127.0.0.1:19133
metrics_a=http://127.0.0.1:19131
metrics_b=http://127.0.0.1:19132
pids=()
metrics_pids=()
cli_pid=
agent_a=
agent_b=

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"} ${metrics_pids[@]+"${metrics_pids[@]}"} "$cli_pid"; do
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT

kubectl create namespace "$ns"
for role in client server; do
  node="$node_a"
  if [ "$role" = server ]; then node="$node_b"; fi
  kubectl -n "$ns" apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $role
  labels: {app: ztap-flow-test, role: $role}
spec:
  nodeName: $node
  tolerations: [{operator: Exists}]
  containers:
    - name: endpoint
      image: busybox:1.36.1
      command: [sh, -c, 'while [ ! -x /tmp/churnprobe ]; do sleep 1; done; exec /tmp/churnprobe -mode=serve-flow']
      env:
        - name: POD_IP
          valueFrom:
            fieldRef: {fieldPath: status.podIP}
      readinessProbe:
        exec:
          command: [sh, -c, '/tmp/churnprobe -address="\$POD_IP:8080"']
        periodSeconds: 1
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
YAML
done
probe="$RUNNER_TEMP/ztap-flow-churnprobe"
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$probe" ./tools/churnprobe
for role in client server; do
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Running "pod/$role" --timeout=120s
  kubectl -n "$ns" cp "$probe" "$role:/tmp/churnprobe"
  kubectl -n "$ns" exec "$role" -- chmod 0755 /tmp/churnprobe
  kubectl -n "$ns" wait --for=condition=Ready "pod/$role" --timeout=120s
done

kubectl -n "$ns" get pods -o json | jq '[.items[] | {
  role: .metadata.name, uid: .metadata.uid, node: .spec.nodeName, ip: .status.podIP
}]' > "$evidence/workloads.json"
workload() { jq -er --arg role "$1" --arg field "$2" '.[] | select(.role == $role) | .[$field]' "$evidence/workloads.json"; }
client_ip="$(workload client ip)"
server_ip="$(workload server ip)"
client_uid="$(workload client uid)"
server_uid="$(workload server uid)"
test "$(workload client node)" = "$node_a"
test "$(workload server node)" = "$node_b"
kubectl get nodes -o json | jq '[.items[] | {name: .metadata.name, kernel: .status.nodeInfo.kernelVersion,
  arch: .status.nodeInfo.architecture, k8s: .status.nodeInfo.kubeletVersion,
  runtime: .status.nodeInfo.containerRuntimeVersion}]' > "$evidence/nodes.json"

fresh() {
  local port="$1"
  shift
  timeout 5s kubectl -n "$ns" exec client -- /tmp/churnprobe -address="$server_ip:$port" "$@"
}

probe_denied() {
  local status=0
  fresh 8080 -deny || status=$?
  # churnprobe reserves exit 3 for an observed successful handshake.
  if [ "$status" -eq 3 ]; then
    printf 'Prohibited TCP handshake succeeded after the deny epoch was published.\n' >&2
    exit 1
  fi
  return "$status"
}

set_policy() {
  local direction="$1" state="$2" extra="${3:-}" role=client peer=server peer_key=to kind=Egress
  if [ "$direction" = ingress ]; then role=server peer=client peer_key=from kind=Ingress; fi
  {
    cat <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: flow-$direction
  namespace: $ns
spec:
  podSelector: {matchLabels: {role: $role}}
  policyTypes: [$kind]
  $direction:
    - $peer_key:
        - podSelector: {matchLabels: {role: $peer}}
      ports:
        - {port: 8081, protocol: TCP}
        - {port: 8081, protocol: UDP}
YAML
    if [ "$state" = allow ]; then printf '        - {port: 8080, protocol: TCP}\n'; fi
    if [ -n "$extra" ]; then printf '        - {port: %s, protocol: TCP}\n' "$extra"; fi
  } | kubectl apply -f -
}

agent_for() {
  kubectl -n ztap-system get pods -l app=ztap-agent -o json | jq -er --arg node "$1" '
    [.items[] | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null)
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | if length == 1 then .[0].metadata.name else error("expected one ready agent on node") end'
}

metric() {
  curl --fail --silent --max-time 2 "$1/metrics" |
    awk -v name="$2" '$1 == name {print $2; found++} END {if(found!=1) exit 1}'
}
epoch() { metric "$1" ztap_active_policy_epoch; }

forward_agents() {
  for pid in ${metrics_pids[@]+"${metrics_pids[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  metrics_pids=()
  agent_a="$(agent_for "$node_a")"
  agent_b="$(agent_for "$node_b")"
  kubectl -n ztap-system port-forward --address 127.0.0.1 "pod/$agent_a" 19131:9090 >> "$evidence/agent-a-forward.log" 2>&1 &
  metrics_pids+=("$!")
  kubectl -n ztap-system port-forward --address 127.0.0.1 "pod/$agent_b" 19132:9090 >> "$evidence/agent-b-forward.log" 2>&1 &
  metrics_pids+=("$!")
  for ((attempt=0; attempt<80; attempt++)); do
    if epoch "$metrics_a" >/dev/null && epoch "$metrics_b" >/dev/null; then return 0; fi
    sleep .25
  done
  return 1
}

wait_epoch() {
  local active attempt
  for ((attempt=0; attempt<120; attempt++)); do
    active="$(epoch "$1")"
    if [ "$active" -gt "$2" ]; then printf '%s\n' "$active"; return 0; fi
    sleep .2
  done
  printf 'Policy epoch did not advance from %s at %s\n' "$2" "$1" >&2
  return 1
}

now_ns() { python3 -c 'import time; print(time.time_ns())'; }
require_traffic() {
  local try
  local probe=(fresh 8080)
  if [ "${1:-}" = deny ]; then probe=(probe_denied); fi
  for ((try=0; try<30; try++)); do
    if "${probe[@]}" && fresh 8081; then return 0; fi
    sleep .25
  done
  return 1
}

measure() {
  local phase="$1" extra_port="$2" start after before_epoch active cpu_before cpu_after rss high_water begin end
  before_epoch="$(epoch "$metrics_a")"
  start="$(now_ns)"
  set_policy egress allow "$extra_port"
  active="$(wait_epoch "$metrics_a" "$before_epoch")"
  after="$(now_ns)"
  begin="$(now_ns)"
  cpu_before="$(metric "$metrics_a" process_cpu_seconds_total)"
  timeout 30s kubectl -n "$ns" exec client -- /tmp/churnprobe -mode=measure-flow \
    -address="$server_ip:8081" -duration=3s > "$evidence/traffic-$phase.json"
  cpu_after="$(metric "$metrics_a" process_cpu_seconds_total)"
  end="$(now_ns)"
  rss="$(metric "$metrics_a" process_resident_memory_bytes)"
  high_water="$(metric "$metrics_a" ztap_flow_export_queue_high_water || printf 'null')"
  curl --fail --silent "$metrics_a/metrics" > "$evidence/metrics-$phase-client.txt"
  curl --fail --silent "$metrics_b/metrics" > "$evidence/metrics-$phase-server.txt"
  jq -c --arg phase "$phase" --arg epoch "$active" --argjson reconcile "$((after-start))" \
    --argjson elapsed "$((end-begin))" --argjson cpu_before "$cpu_before" --argjson cpu_after "$cpu_after" \
    --argjson rss "$rss" --argjson queue "$high_water" \
    '. + {phase:$phase, policy_epoch:$epoch, api_to_epoch_ms:($reconcile / 1e6),
      client_agent_avg_cpu_cores:(($cpu_after - $cpu_before) / ($elapsed / 1e9)),
      client_agent_rss_bytes:$rss, client_agent_queue_high_water:$queue}' \
    "$evidence/traffic-$phase.json" >> "$evidence/performance.jsonl"
}

query_logs() {
  curl --fail --silent --max-time 4 --get "$loki/loki/api/v1/query_range" \
    --data-urlencode "query=$1" --data-urlencode "start=$2" --data-urlencode limit=100
}

record_decision() {
  local phase="$1" found="$2" since="$3" arrival="$4" node="$5" uid="$6" wanted_epoch="$7"
  local action="$8" direction="$9" reason="${10}"
  python3 - "$phase" "$found" "$since" "$arrival" "$node" "$uid" "$wanted_epoch" "$client_ip" "$server_ip" "$action" "$direction" "$reason" <<'PY' >> "$evidence/decisions.jsonl"
import json, sys
phase, record, since, observed, node, uid, epoch, src, dst, action, direction, reason = sys.argv[1:]
value = json.loads(record)
stamp, body, *_ = value["entry"]
attrs = value["attrs"]
expected = dict(k8s_node_name=node, ztap_subject_k8s_pod_uid=uid, ztap_policy_epoch=epoch,
                ztap_subject_k8s_namespace_name="ztap-flow-test", ztap_subject_identity_status="resolved",
                source_address=src, destination_address=dst, destination_port="8080", network_transport="tcp",
                ztap_decision_action=action, ztap_decision_direction=direction, ztap_decision_reason=reason)
assert all(attrs.get(k) == v for k, v in expected.items()), attrs
assert body == "ztap.policy.decision" and 0 < int(attrs["source_port"]) <= 65535, value
assert int(since) <= int(stamp) <= int(attrs["observed_timestamp"]) <= int(observed), value
print(json.dumps(dict(phase=phase, decision_unix_ns=stamp, queried_unix_ns=observed,
                      decision_to_query_ms=(int(observed)-int(stamp))/1e6,
                      node=node, subject_uid=uid, policy_epoch=epoch,
                      cgroup_id=attrs["ztap_subject_cgroup_id"], source_ip=src,
                      source_port=int(attrs["source_port"]), destination_ip=dst, destination_port=8080,
                      action=action, direction=direction, reason=reason)))
PY
}

tuple_filter() {
  printf ' | source_address="%s" | destination_address="%s" | destination_port="8080" | network_transport="tcp"' \
    "$client_ip" "$server_ip"
}

wait_record() {
  local phase="$1" since="$2" action="$3" direction="$4" reason="$5" node="$6" uid="$7" wanted_epoch="$8"
  local query result found poll
  query='{service_name="ztap-agent"}'
  if [ "$phase" = egress_revoked ]; then
    query="$(cat "$example/blocked-egress.logql")"
  else
    query+=" | ztap_decision_action=\"$action\" | ztap_decision_direction=\"$direction\" | ztap_decision_reason=\"$reason\""
  fi
  query+=" | k8s_node_name=\"$node\" | ztap_subject_k8s_pod_uid=\"$uid\" | ztap_policy_epoch=\"$wanted_epoch\""
  query+="$(tuple_filter)"
  for ((poll=0; poll<160; poll++)); do
    if result="$(query_logs "$query" "$since")" &&
       found="$(jq -ce '[.data.result[] | .stream as $attrs | .values[] | {attrs:$attrs, entry:.}] | first' <<< "$result")"; then
      record_decision "$phase" "$found" "$since" "$(now_ns)" "$node" "$uid" "$wanted_epoch" "$action" "$direction" "$reason"
      return 0
    fi
    # A probe can fall in a rate-limited window or a saturated queue after
    # the load sample. Refresh blocked traffic while waiting for evidence.
    if [ "$action" = blocked ] && [ "$((poll % 8))" = 7 ]; then
      probe_denied || true
    fi
    sleep .25
  done
  printf 'Loki did not return the expected decision for %s\n%s\n' "$phase" "$query" >&2
  return 1
}

wait_allowed_connection() {
  local since="$1" epoch_a="$2" epoch_b="$3"
  local deadline=$((SECONDS + 60)) next_probe=$SECONDS
  local source_port result matched arrival query
  local ports="$evidence/allowed-source-ports.txt"
  : > "$ports"
  query='{service_name="ztap-agent"} | ztap_decision_action="allowed" | ztap_decision_reason="rule"'
  query+="$(tuple_filter)"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$SECONDS" -ge "$next_probe" ]; then
      if source_port="$(fresh 8080 -print-source-port)"; then
        [[ "$source_port" =~ ^[0-9]+$ ]]
        printf '%s\n' "$source_port" >> "$ports"
      fi
      next_probe=$((SECONDS + 2))
    fi
    if result="$(query_logs "$query" "$since")" &&
       matched="$(jq -ce --slurpfile ports "$ports" --slurpfile cli "$evidence/healthy-cli.jsonl" \
         --arg a "$node_a" --arg b "$node_b" --arg uid_a "$client_uid" --arg uid_b "$server_uid" \
         --arg epoch_a "$epoch_a" --arg epoch_b "$epoch_b" --arg src "$client_ip" --arg dst "$server_ip" '
          def records:
            .data.result[] | .stream as $attrs | .values[] | {attrs:$attrs, entry:.};
          def side($direction; $node; $uid; $epoch):
            select(.attrs | .ztap_decision_direction == $direction and .k8s_node_name == $node and
              .ztap_subject_k8s_pod_uid == $uid and .ztap_policy_epoch == $epoch);
          [records | select((.attrs.source_port | tonumber) as $port | $ports | index($port))]
          | group_by(.attrs.source_port) | map(
            ([.[] | side("egress"; $a; $uid_a; $epoch_a)] | first) as $egress
            | ([.[] | side("ingress"; $b; $uid_b; $epoch_b)] | first) as $ingress
            | select($egress != null and $ingress != null)
            | ($cli | map(select(.action == "allowed" and .reason == "rule" and
                (.policy_epoch | tostring) == $epoch_a and (.cgroup_id | tostring) == $egress.attrs.ztap_subject_cgroup_id and
                (.src_port | tostring) == $egress.attrs.source_port and .dst_port == 8080 and
                .src_ip == $src and .dst_ip == $dst)) | first) as $local
            | select($local != null)
            | {egress:$egress, ingress:$ingress, local:$local})
          | first' <<< "$result")"; then
      arrival="$(now_ns)"
      record_decision allowed_egress "$(jq -c .egress <<< "$matched")" "$since" "$arrival" "$node_a" "$client_uid" "$epoch_a" allowed egress rule
      record_decision allowed_ingress "$(jq -c .ingress <<< "$matched")" "$since" "$arrival" "$node_b" "$server_uid" "$epoch_b" allowed ingress rule
      jq -c .local <<< "$matched" > "$evidence/healthy-cli-match.jsonl"
      return 0
    fi
    sleep .25
  done
  printf 'Expected a successful TCP echo with matching local and Loki records on both nodes.\n' >&2
  return 1
}

start_cli() {
  local label="$1"
  timeout 90s kubectl -n ztap-system exec "$agent_a" -- /ztap flows --protocol TCP \
    --direction egress --output json > "$evidence/$label-cli.jsonl" 2> "$evidence/$label-cli.stderr" &
  cli_pid="$!"
  sleep 1
  kill -0 "$cli_pid"
}

stop_cli() {
  kill "$cli_pid" 2>/dev/null || true
  wait "$cli_pid" 2>/dev/null || true
  cli_pid=
}

check_cli() {
  local label="$1" action="$2" reason="$3" active="$4" matched=
  for ((try=0; try<40; try++)); do
    if matched="$(jq -ce --arg source "$client_ip" --arg dest "$server_ip" --arg action "$action" \
      --arg reason "$reason" --argjson epoch "$active" \
      'select(.action==$action and .reason==$reason and .policy_epoch==$epoch and
        .src_ip==$source and .dst_ip==$dest and .dst_port==8080)' "$evidence/$label-cli.jsonl")"; then
      printf '%s\n' "$matched" > "$evidence/$label-cli-match.jsonl"
      break
    fi
    sleep .25
  done
  test -n "$matched"
  stop_cli
}

set_policy egress allow
set_policy ingress allow
forward_agents
# Wait for both directions to enforce before measuring an export-disabled baseline.
kubectl -n "$ns" exec server -- /tmp/churnprobe -address="$server_ip:8080"
require_traffic

# Selecting the agent for egress makes its own OTLP traffic produce decisions.
# Allow IPv4 TCP and UDP so its Kubernetes API, DNS, and OTLP paths all work.
agent_epoch_a="$(epoch "$metrics_a")"
agent_epoch_b="$(epoch "$metrics_b")"
kubectl apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: flow-agent-egress
  namespace: ztap-system
spec:
  podSelector: {matchLabels: {app: ztap-agent}}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock: {cidr: 0.0.0.0/0}
      ports:
        - {protocol: TCP, port: 1, endPort: 65535}
        - {protocol: UDP, port: 1, endPort: 65535}
YAML
wait_epoch "$metrics_a" "$agent_epoch_a" >/dev/null
wait_epoch "$metrics_b" "$agent_epoch_b" >/dev/null
filter_since="$(now_ns)"
measure disabled 9081

bash "$example/install-backend.sh" > "$evidence/backend-install.log" 2>&1
queue_patch="$RUNNER_TEMP/ztap-flow-test-agent-patch.yaml"
awk '{print} /- --otlp-flow-logs$/ {print "            - --otlp-flow-queue-capacity=64"}' \
  "$example/agent-patch.yaml" > "$queue_patch"
kubectl -n ztap-system patch ds ztap-agent --type=strategic --patch-file "$queue_patch"
kubectl -n ztap-system rollout status ds/ztap-agent --timeout=180s
forward_agents
for ((attempt=0; attempt<40; attempt++)); do
  if [ "$(metric "$metrics_a" ztap_flow_reader_active)" = 1 ] &&
     [ "$(metric "$metrics_b" ztap_flow_reader_active)" = 1 ]; then break; fi
  sleep .25
done
test "$attempt" -lt 40
kubectl -n ztap-telemetry port-forward --address 127.0.0.1 deployment/loki 19133:3100 > "$evidence/loki-forward.log" 2>&1 &
pids+=("$!")
start_cli healthy
allowed_since="$(now_ns)"
epoch_a="$(epoch "$metrics_a")"
epoch_b="$(epoch "$metrics_b")"
fresh 8081
wait_allowed_connection "$allowed_since" "$epoch_a" "$epoch_b"
stop_cli
agent_ip="$(kubectl -n ztap-system get pod "$agent_a" -o jsonpath='{.status.podIP}')"
jq -se --arg ip "$agent_ip" 'any(.[]; .src_ip == $ip and .dst_port == 4318 and .action == "allowed")' \
  "$evidence/healthy-cli.jsonl" >/dev/null
filtered_a="$(metric "$metrics_a" ztap_flow_export_filtered_total)"
filtered_b="$(metric "$metrics_b" ztap_flow_export_filtered_total)"
awk -v a="$filtered_a" -v b="$filtered_b" 'BEGIN {exit !(a+b>0)}'
measure healthy 9082
query_logs '{service_name="ztap-agent"} | ztap_subject_k8s_namespace_name=~"ztap-system|ztap-telemetry" or ztap_subject_identity_status="unresolved"' "$filter_since" \
  | jq -e '.status == "success" and (.data.result | length == 0)' > "$evidence/agent-export-filter.txt"

epoch_a="$(epoch "$metrics_a")"
set_policy egress deny
epoch_a="$(wait_epoch "$metrics_a" "$epoch_a")"
egress_since="$(now_ns)"
require_traffic deny
wait_record egress_revoked "$egress_since" blocked egress default_deny "$node_a" "$client_uid" "$epoch_a"

set_policy egress allow 9082
wait_epoch "$metrics_a" "$epoch_a" >/dev/null
epoch_b="$(epoch "$metrics_b")"
set_policy ingress deny
epoch_b="$(wait_epoch "$metrics_b" "$epoch_b")"
ingress_since="$(now_ns)"
require_traffic deny
wait_record ingress_revoked "$ingress_since" blocked ingress default_deny "$node_b" "$server_uid" "$epoch_b"

collector_pod="$(kubectl -n ztap-telemetry get pods -l app=ztap-otel-collector -o name)"
kubectl -n ztap-telemetry scale deployment/otel-collector --replicas=0
kubectl -n ztap-telemetry wait --for=delete "$collector_pod" --timeout=90s
queue_loss='ztap_flow_userspace_dropped_total{stage="export_queue_full"}'
loss_before="$(metric "$metrics_a" "$queue_loss")"
epoch_b="$(epoch "$metrics_b")"
set_policy ingress allow
wait_epoch "$metrics_b" "$epoch_b" > "$evidence/outage-restored-ingress-epoch.txt"
require_traffic
measure outage 9083
loss_after="$(metric "$metrics_a" "$queue_loss")"
awk -v before="$loss_before" -v after="$loss_after" 'BEGIN {exit !(after>before)}'
jq -n --argjson before "$loss_before" --argjson after "$loss_after" \
  '{export_queue_dropped_before:$before, export_queue_dropped_after:$after}' > "$evidence/outage-loss.json"

start_cli outage
epoch_a="$(epoch "$metrics_a")"
set_policy egress deny
epoch_a="$(wait_epoch "$metrics_a" "$epoch_a")"
require_traffic deny
check_cli outage blocked default_deny "$epoch_a"
curl --fail --silent "$metrics_a/readyz" | jq -e '.ready and .enforcing' > "$evidence/outage-ready-client.txt"
curl --fail --silent "$metrics_b/readyz" | jq -e '.ready and .enforcing' > "$evidence/outage-ready-server.txt"
test "$(agent_for "$node_a")" = "$agent_a"
test "$(agent_for "$node_b")" = "$agent_b"

kubectl -n ztap-telemetry scale deployment/otel-collector --replicas=1
kubectl -n ztap-telemetry rollout status deployment/otel-collector --timeout=120s
# Wait out any old batch retry so the fresh probe has room to enter the queue.
for ((attempt=0; attempt<100; attempt++)); do
  if [ "$(metric "$metrics_a" ztap_flow_export_queue_depth)" = 0 ]; then break; fi
  sleep .25
done
test "$attempt" -lt 100
recovered_since="$(now_ns)"
require_traffic deny
wait_record recovered "$recovered_since" blocked egress default_deny "$node_a" "$client_uid" "$epoch_a"
test "$(agent_for "$node_a")" = "$agent_a"
test "$(agent_for "$node_b")" = "$agent_b"
kubectl -n ztap-system get pod "$agent_a" "$agent_b" -o json |
  jq -e '.items | map({name: .metadata.name, uid: .metadata.uid, image_id: .status.containerStatuses[0].imageID,
    restart_count: .status.containerStatuses[0].restartCount}) | select(all(.[]; .restart_count==0))' > "$evidence/agents.json"
printf 'Cluster-wide decision logs, policy revocation, and Collector recovery verified.\n'

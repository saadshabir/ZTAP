#!/usr/bin/env bash
# Destructive fixture changes: use only the disposable two-node kind CI cluster.
set -euo pipefail
source .github/scripts/lib/multinode-churn.sh
evidence="${ZTAP_CHURN_EVIDENCE_DIR:-churn-evidence}"
test ! -L "$evidence"
mkdir -p "$evidence"
existing="$(find "$evidence" -mindepth 1 -maxdepth 1 -print -quit)"
if [ -n "$existing" ]; then
  printf 'churn evidence directory must be empty: %s\n' "$evidence" >&2
  exit 1
fi
(
set -euo pipefail
test "${ZTAP_KINDNET_NETWORKPOLICY_DISABLED:-}" = 1
duration="${ZTAP_CHURN_SECONDS:-120}"
cycles="${ZTAP_CHURN_CYCLES:-6}"
[[ "$duration" =~ ^[0-9]+$ ]] && test "$duration" -ge 120
[[ "$cycles" =~ ^[0-9]+$ ]] && test "$cycles" -ge 6
nodes="$(kubectl get nodes -o json)"
test "$(jq '.items | length' <<< "$nodes")" -eq 2
fixtures="$(kubectl get namespace ztap-churn-a ztap-churn-b ztap-churn-remote --ignore-not-found -o name)"
if [ -n "$fixtures" ]; then
  printf 'churn fixture namespaces must not already exist\n' >&2
  exit 1
fi
node_a=ztap-control-plane
node_b=ztap-worker
for node in "$node_a" "$node_b"; do
  kubectl wait --for=condition=Ready "node/$node" --timeout=60s
  agent="$(kubectl -n ztap-system get pods -l app=ztap-agent -o json | jq -er --arg node "$node" '
    [.items[] | select(.spec.nodeName == $node and .status.phase == "Running")
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | if length == 1 then .[0].metadata.name else error("agent missing or ambiguous") end')"
  printf '%s %s\n' "$node" "$agent" >> "$evidence/agents.txt"
done
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$RUNNER_TEMP/ztap-churnprobe" ./tools/churnprobe
pids=()
writer_pid=
# shellcheck disable=SC2317,SC2329
cleanup() {
  touch "$evidence/writer.stop"
  for ns in ztap-churn-a ztap-churn-b; do
    timeout 5s kubectl -n "$ns" exec endpoint -- touch /tmp/churn.stop >/dev/null 2>&1 || true
  done
  if [ -n "$writer_pid" ]; then kill "$writer_pid" 2>/dev/null || true; wait "$writer_pid" 2>/dev/null || true; fi
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# Both directions are isolated. Only initiating TCP/8080 traffic is explicit;
# replies to ephemeral ports must use the epoch-scoped connection state.
for ns in ztap-churn-a ztap-churn-b ztap-churn-remote; do
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $ns
  labels:
    ztap-churn-access: enabled
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: peers
  namespace: $ns
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              ztap-churn-access: enabled
          podSelector:
            matchLabels:
              ztap-churn-peer: allowed
      ports: [{protocol: TCP, port: 8080}]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              ztap-churn-access: enabled
          podSelector:
            matchLabels:
              ztap-churn-peer: allowed
      ports: [{protocol: TCP, port: 8080}]
    - to: [{ipBlock: {cidr: 198.18.0.1/32}}]
      ports: [{protocol: TCP, port: 8080}]
YAML
done
create_endpoint() {
  local ns="$1" pod="$2" node="$3"
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: $ns
  labels:
    ztap-churn-peer: allowed
spec:
  nodeName: $node
  tolerations: [{operator: Exists}]
  containers:
    - name: endpoint
      image: busybox:1.36.1
      imagePullPolicy: IfNotPresent
      command: [sh, -c, 'while [ ! -x /tmp/churnprobe ]; do sleep 1; done; exec /tmp/churnprobe -mode=serve']
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
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Running "pod/$pod" --timeout=120s
  kubectl cp "$RUNNER_TEMP/ztap-churnprobe" "$ns/$pod:/tmp/churnprobe"
  kubectl -n "$ns" exec "$pod" -- chmod 0755 /tmp/churnprobe
  kubectl -n "$ns" wait --for=condition=Ready "pod/$pod" --timeout=120s
  # Prove the denied control port has a live listener, using the self-IP
  # exception rather than mistaking a missing listener for policy enforcement.
  local pod_ip
  pod_ip="$(ip_of "$ns" "$pod")"
  kubectl -n "$ns" exec "$pod" -- /tmp/churnprobe -address="$pod_ip:8081"
  kubectl -n "$ns" get pod "$pod" -o json | jq -c '{namespace:.metadata.namespace,pod:.metadata.name,uid:.metadata.uid,ip:.status.podIP,node:.spec.nodeName}' >> "$evidence/pods.jsonl"
}
ip_of() { kubectl -n "$1" get pod "$2" -o jsonpath='{.status.podIP}'; }
fresh() {
  local ns="$1" pod="$2" ip="$3" expectation="$4"
  local args=()
  if [ "$expectation" = denied ]; then args+=(-deny); fi
  timeout 5s kubectl -n "$ns" exec "$pod" -- /tmp/churnprobe -address="$ip:8080" ${args[@]+"${args[@]}"}
}
# Require three successive results in both directions after each mutation.
wait_pair() {
  churn_wait_pair "$1" "$2" "$3" "$4" "$evidence" "$node_a" "$ip_a" "$node_b" "$ip_b"
}
create_endpoint ztap-churn-a endpoint "$node_a"
create_endpoint ztap-churn-b endpoint "$node_b"
remote='remote-0'
remote_node="$node_b"
create_endpoint ztap-churn-remote "$remote" "$remote_node"
ip_a="$(ip_of ztap-churn-a endpoint)"
ip_b="$(ip_of ztap-churn-b endpoint)"
remote_ip="$(ip_of ztap-churn-remote "$remote")"
test "$ip_a" != "$ip_b"
test "$(kubectl -n ztap-churn-a get pod endpoint -o jsonpath='{.spec.nodeName}')" != "$(kubectl -n ztap-churn-b get pod endpoint -o jsonpath='{.spec.nodeName}')"
wait_pair "$remote" "$remote_ip" allowed baseline
fresh ztap-churn-a endpoint "$ip_b" allowed
fresh ztap-churn-b endpoint "$ip_a" allowed

port=19091
while read -r node agent; do
  kubectl -n ztap-system port-forward "pod/$agent" "$port:9090" > "$evidence/port-forward-$node.log" 2>&1 &
  pids+=("$!")
  port=$((port + 1))
done < "$evidence/agents.txt"
epoch() {
  curl --fail --silent --max-time 2 "http://127.0.0.1:$1/metrics" | awk '$1 == "ztap_active_policy_epoch" && $2 ~ /^[0-9]+$/ {value=$2; count++} END {if(count != 1) exit 1; print value}'
}
for ((attempt = 0; attempt < 30; attempt++)); do
  if epoch_a="$(epoch 19091)" && epoch_b="$(epoch 19092)"; then break; fi
  sleep 1
done
test "$attempt" -lt 30
start_stream() {
  local ns="$1" ip="$2" name="$3"
  kubectl -n "$ns" exec endpoint -- /tmp/churnprobe -mode=stream \
    -address="$ip:8080" -denied-address="$ip:8081" -duration=15m -max-gap=5s \
    -stop-file=/tmp/churn.stop -revoking-file=/tmp/churn.revoking -revoke-file=/tmp/churn.revoked \
    > "$evidence/stream-$name.jsonl" 2> "$evidence/stream-$name.err" &
  pids+=("$!")
}
start_stream ztap-churn-a "$ip_b" a-to-b
stream_a_pid="${pids[${#pids[@]}-1]}"
start_stream ztap-churn-b "$ip_a" b-to-a
stream_b_pid="${pids[${#pids[@]}-1]}"
churn_wait_probe_ready "$evidence/stream-a-to-b.jsonl" "$stream_a_pid"
churn_wait_probe_ready "$evidence/stream-b-to-a.jsonl" "$stream_b_pid"
kubectl -n ztap-churn-a exec endpoint -- /tmp/churnprobe -mode=reply-state \
  -address="$ip_b:8080" -changed-file=/tmp/churn.changed -duration=1m -max-gap=5s \
  > "$evidence/reply-state.jsonl" 2> "$evidence/reply-state.err" &
reply_pid=$!
pids+=("$reply_pid")
churn_wait_probe_ready "$evidence/reply-state.jsonl" "$reply_pid" 30 reply-state
# Metadata-only events must preserve the compiled snapshot and reply state.
epoch_a="$(epoch 19091)"; epoch_b="$(epoch 19092)"
for ns in ztap-churn-a ztap-churn-b; do
  kubectl -n "$ns" annotate networkpolicy peers ztap-churn-metadata=unchanged
 done
sleep 2
test "$(epoch 19091)" = "$epoch_a"
test "$(epoch 19092)" = "$epoch_b"
printf '%s\n' 'metadata_only_epoch=preserved'
# Characterize a stream receiving server pushes with no new client payloads.
# A single explicit payload must restore any epoch-invalidated reply state on
# the original socket; uninterrupted behavior also satisfies this check.
for ns in ztap-churn-a ztap-churn-b; do
  kubectl -n "$ns" patch networkpolicy peers --type=json \
    -p '[{"op":"replace","path":"/spec/egress/1/to/0/ipBlock/cidr","value":"198.18.0.201/32"}]'
done
for ((attempt = 0; attempt < 30; attempt++)); do
  if test "$(epoch 19091)" -gt "$epoch_a" && test "$(epoch 19092)" -gt "$epoch_b"; then break; fi
  sleep 0.2
done
test "$attempt" -lt 30
kubectl -n ztap-churn-a exec endpoint -- touch /tmp/churn.changed
wait "$reply_pid"
jq -se '.[-1] | .finished and .connections == 1 and .baseline_received >= 10 and .changed_ns > 0
  and (if .interrupted then .recovered and .resume_ns > 0 else .resume_ns == 0 end)' "$evidence/reply-state.jsonl" >/dev/null
epoch_a="$(epoch 19091)"; epoch_b="$(epoch 19092)"

# Apply real rule changes continuously while every lifecycle test runs. The
# extra ipBlock never overlaps a fixture IP; every update changes the snapshot.
policy_writer() {
  local update=0 ns octet
  while [ ! -f "$evidence/writer.stop" ]; do
    update=$((update + 1))
    octet=$((update % 200 + 2))
    for ns in ztap-churn-a ztap-churn-b ztap-churn-remote; do
      kubectl -n "$ns" patch networkpolicy peers --type=json \
        -p "[{\"op\":\"replace\",\"path\":\"/spec/egress/1/to/0/ipBlock/cidr\",\"value\":\"198.18.0.$octet/32\"}]" >> "$evidence/policy-writer.log" 2>&1
      jq -nc --arg ns "$ns" --argjson update "$update" --argjson timestamp "$(date +%s)" \
        '{namespace:$ns,update:$update,timestamp:$timestamp}' >> "$evidence/policy-updates.jsonl"
    done
    sleep 0.5
  done
}
policy_writer &
writer_pid=$!
started=$SECONDS
cycle=0
while [ "$((SECONDS - started))" -lt "$duration" ] || [ "$cycle" -lt "$cycles" ]; do
  cycle=$((cycle + 1))
  kill -0 "$writer_pid"
  kill -0 "$stream_a_pid"
  kill -0 "$stream_b_pid"
  kubectl -n ztap-churn-remote label pod "$remote" ztap-churn-peer=excluded --overwrite
  wait_pair "$remote" "$remote_ip" denied "pod-label-remove-$cycle"
  # The retired peer remains a live listener; denial is not a dead endpoint.
  fresh ztap-churn-remote "$remote" "$remote_ip" allowed
  kubectl -n ztap-churn-remote label pod "$remote" ztap-churn-peer=allowed --overwrite
  wait_pair "$remote" "$remote_ip" allowed "pod-label-restore-$cycle"
  kubectl label namespace ztap-churn-remote ztap-churn-access=disabled --overwrite
  wait_pair "$remote" "$remote_ip" denied "namespace-label-remove-$cycle"
  kubectl label namespace ztap-churn-remote ztap-churn-access=enabled --overwrite
  wait_pair "$remote" "$remote_ip" allowed "namespace-label-restore-$cycle"
  next="remote-$cycle"
  # Rotate the peer so each node must resolve and enforce a changing remote
  # identity. The observer always lives on the opposite node (see wait_pair).
  if [ "$remote_node" = "$node_b" ]; then next_node="$node_a"; else next_node="$node_b"; fi
  create_endpoint ztap-churn-remote "$next" "$next_node"
  next_ip="$(ip_of ztap-churn-remote "$next")"
  test "$next_ip" != "$remote_ip"
  wait_pair "$next" "$next_ip" allowed "replacement-allow-$cycle"
  kubectl -n ztap-churn-remote label pod "$remote" ztap-churn-peer=excluded --overwrite
  wait_pair "$remote" "$remote_ip" denied "old-ip-remove-$cycle"
  fresh ztap-churn-remote "$remote" "$remote_ip" allowed
  kubectl -n ztap-churn-remote delete pod "$remote" --wait=true --timeout=60s
  remote="$next"; remote_ip="$next_ip"; remote_node="$next_node"
  printf 'completed_churn_cycle=%s elapsed_seconds=%s\n' "$cycle" "$((SECONDS - started))"
done
elapsed=$((SECONDS - started))
touch "$evidence/writer.stop"
wait "$writer_pid"
writer_pid=
final_epoch_a="$(epoch 19091)"; final_epoch_b="$(epoch 19092)"
test "$final_epoch_a" -ge "$((epoch_a + 10))"
test "$final_epoch_b" -ge "$((epoch_b + 10))"
jq -se 'group_by(.namespace) | length == 3 and all(.[]; length >= 30)' "$evidence/policy-updates.jsonl" >/dev/null
# At least three cycles must independently exercise each node's ingress and
# egress decisions for label, namespace, and retired-IP removal.
churn_verify_coverage "$evidence/transitions.jsonl" "$node_a" "$node_b"
jq -n --argjson seconds "$elapsed" --argjson cycles "$cycle" \
  --argjson before_a "$epoch_a" --argjson after_a "$final_epoch_a" \
  --argjson before_b "$epoch_b" --argjson after_b "$final_epoch_b" \
  '{duration_seconds:$seconds,cycles:$cycles,epochs:{a:[$before_a,$after_a],b:[$before_b,$after_b]}}' > "$evidence/summary.json"

# Deliberately end the availability window, revoke both initiating directions,
# then test new payloads on the SAME sockets after convergence.
for ns in ztap-churn-a ztap-churn-b; do
  kubectl -n "$ns" exec endpoint -- touch /tmp/churn.revoking
done
for ns in ztap-churn-a ztap-churn-b; do
  kubectl -n "$ns" patch networkpolicy peers --type=json -p '[{"op":"replace","path":"/spec/egress","value":[]}]'
done
for ((attempt = 0; attempt < 30; attempt++)); do
  if fresh ztap-churn-a endpoint "$ip_b" denied >> "$evidence/checks.log" 2>&1 &&
     fresh ztap-churn-b endpoint "$ip_a" denied >> "$evidence/checks.log" 2>&1 &&
     test "$(epoch 19091)" -gt "$final_epoch_a" && test "$(epoch 19092)" -gt "$final_epoch_b"; then break; fi
  sleep 0.2
done
test "$attempt" -lt 30
for ns in ztap-churn-a ztap-churn-b; do kubectl -n "$ns" exec endpoint -- touch /tmp/churn.revoked; done
sleep 4
for ns in ztap-churn-a ztap-churn-b; do kubectl -n "$ns" exec endpoint -- touch /tmp/churn.stop; done
wait "$stream_a_pid"
wait "$stream_b_pid"
for file in "$evidence"/stream-*.jsonl; do
  jq -se 'length > 100 and all(.[]; .connections == 1 and .prohibited_connections == 0 and .post_revocation_replies == 0 and .max_gap_ms <= 5000)
    and .[-1].finished and .[-1].received >= 100 and .[-1].sent_after_revocation >= 10 and .[-1].revoked_ns > 0' "$file" >/dev/null
done
printf '%s\n' 'multinode_churn_gate=passed'
) 2>&1 | tee "$evidence/suite.log"

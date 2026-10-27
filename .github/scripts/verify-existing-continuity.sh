#!/usr/bin/env bash
# Run only against the disposable kind release-gate cluster.
set -euo pipefail
kind_node="${ZTAP_KIND_NODE:-ztap-control-plane}"
(
set -euo pipefail
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
service_ip="$(kubectl -n ztap-smoke get service smoke-server -o jsonpath='{.spec.clusterIP}')"
client_ip="$(kubectl -n ztap-smoke get pod smoke-client -o jsonpath='{.status.podIP}')"
smoke_client_node="$(kubectl -n ztap-smoke get pod smoke-client -o jsonpath='{.spec.nodeName}')"
old_pod="$(kubectl -n ztap-system get pods -l app=ztap-agent -o json | jq -r --arg node "$smoke_client_node" '[.items[] | select(.spec.nodeName == $node) | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | if length == 1 then .[0].metadata.name else empty end')"
test -n "$old_pod"
old_uid="$(kubectl -n ztap-system get pod "$old_pod" -o jsonpath='{.metadata.uid}')"
original_image="$(kubectl -n ztap-system get pod "$old_pod" -o jsonpath='{.spec.containers[0].image}')"
container_ref="$(kubectl -n ztap-system get pod "$old_pod" -o jsonpath='{.status.containerStatuses[0].containerID}')"
container_id="${container_ref#containerd://}"
agent_pid="$(docker exec "$kind_node" crictl inspect "$container_id" | jq -r '.info.pid')"
test "$agent_pid" -gt 1
kubectl apply -f - >/dev/null <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: smoke-client-continuity-ingress
  namespace: ztap-smoke
spec:
  podSelector:
    matchLabels:
      app: smoke-client
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: smoke-control
      ports:
        - protocol: TCP
          port: 8090
YAML
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$RUNNER_TEMP/ztap-rollout-probe" ./tools/phase5probe
probe_pids=()
paused=0
lock_held=0
# shellcheck disable=SC2317,SC2329
cleanup_continuity() {
  if [ "$paused" -eq 1 ]; then docker exec "$kind_node" kill -CONT "$agent_pid" || true; fi
  if [ "$lock_held" -eq 1 ]; then docker exec "$kind_node" sh -c 'kill "$(cat /run/ztap/restart-proof-lock.pid)"; rm -f /run/ztap/restart-proof-lock.pid' || true; fi
  for pod in smoke-client smoke-control; do timeout 5s kubectl -n ztap-smoke exec "$pod" -- touch /tmp/continuity.stop >/dev/null 2>&1 || true; done
  for pid in ${probe_pids[@]+"${probe_pids[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
}
trap cleanup_continuity EXIT
for pod in smoke-client smoke-control; do
  kubectl cp "$RUNNER_TEMP/ztap-rollout-probe" "ztap-smoke/$pod:/tmp/continuity-probe"
  kubectl -n ztap-smoke exec "$pod" -- chmod 0755 /tmp/continuity-probe
  kubectl -n ztap-smoke exec "$pod" -- rm -f /tmp/continuity.stop
done
# Wait for the two-direction policy before launching the outage probe.
for ((attempt = 0; attempt < 60; attempt++)); do
  if kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 1 "http://$client_ip:8090/" >/dev/null 2>&1 &&
    ! kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 1 "http://$client_ip:8091/" >/dev/null 2>&1; then break; fi
  sleep 1
done
start_probe() {
  local pod="$1" denied="$2" allowed="$3" output="$4"
  kubectl -n ztap-smoke exec "$pod" -- /tmp/continuity-probe -continuity     -url="$denied" -allowed-url="$allowed" -request-timeout=100ms -max-duration=5m     -stop-file=/tmp/continuity.stop > "$output" 2> "$output.err" &
  probe_pids+=("$!")
}
start_probe smoke-client "http://$server_ip:8080/" "http://$service_ip:8080/" rolling-continuity-egress.jsonl
start_probe smoke-control "http://$client_ip:8091/" "http://$client_ip:8090/" rolling-continuity-ingress.jsonl
sleep 2
baseline_ingress="$(tail -n 1 rolling-continuity-ingress.jsonl | jq -er 'select(.prohibited == 0 and .prohibited_attempts > 0 and .allowed > 0) | .allowed')"
baseline_egress="$(tail -n 1 rolling-continuity-egress.jsonl | jq -er 'select(.prohibited == 0 and .prohibited_attempts > 0 and .allowed > 0) | .allowed')"
printf 'schema_version=2\nbaseline_selected_smoke_client=blocked\nsmoke_client_node=%s\nold_namespace=ztap-system\nold_pod=%s\nold_uid=%s\nold_node=%s\nold_ready=true\n' "$smoke_client_node" "$old_pod" "$old_uid" "$smoke_client_node"
printf 'kernel_release=%s\ncontainerd_version=%s\n' "$(docker exec "$kind_node" uname -r)" "$(docker exec "$kind_node" containerd --version)"
outage_started_ns="$(date +%s%N)"
docker exec "$kind_node" kill -STOP "$agent_pid"
paused=1
sleep 3
docker exec "$kind_node" kill -CONT "$agent_pid"
paused=0
# Hold the node lock to delay replacement while kubelet and probes stay live.
docker exec "$kind_node" rm -f /run/ztap/restart-proof-lock.pid
docker exec --detach "$kind_node" flock -x /run/ztap/agent.lock sh -c 'echo $$ > /run/ztap/restart-proof-lock.pid; exec sleep 240'
sleep 1
lock_held=1
docker exec "$kind_node" kill -KILL "$agent_pid"
for ((attempt = 0; attempt < 30; attempt++)); do
  if docker exec "$kind_node" test -f /run/ztap/restart-proof-lock.pid; then break; fi
  sleep 1
done
test "$attempt" -lt 30
sleep 3
during_ingress="$(tail -n 1 rolling-continuity-ingress.jsonl | jq -er 'select(.prohibited == 0) | .allowed')"
during_egress="$(tail -n 1 rolling-continuity-egress.jsonl | jq -er 'select(.prohibited == 0) | .allowed')"
test "$during_ingress" -gt "$baseline_ingress"
test "$during_egress" -gt "$baseline_egress"
docker exec "$kind_node" sh -c 'kill "$(cat /run/ztap/restart-proof-lock.pid)"; rm -f /run/ztap/restart-proof-lock.pid'
lock_held=0
rollout_started_ns="$(date +%s%N)"
if [ -n "${ZTAP_COMPATIBLE_ROLLBACK_IMAGE:-}" ]; then
  kubectl -n ztap-system set image daemonset/ztap-agent "agent=$ZTAP_COMPATIBLE_ROLLBACK_IMAGE" >/dev/null
  kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s >/dev/null
  kubectl -n ztap-system set image daemonset/ztap-agent "agent=$original_image" >/dev/null
  kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s >/dev/null
  jq -n --arg original "$original_image" --arg compatible "$ZTAP_COMPATIBLE_ROLLBACK_IMAGE" \
    '{schema_version:2,original_image:$original,compatible_image:$compatible,rollback_completed:true}' > rolling-compatible-upgrade.json
else
  kubectl -n ztap-system rollout restart daemonset/ztap-agent >/dev/null
  kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s >/dev/null
fi
replacement="$(kubectl -n ztap-system get pods -l app=ztap-agent -o json | jq -cer --arg old "$old_uid" --arg node "$smoke_client_node" '[.items[] | select(.metadata.uid != $old and .spec.nodeName == $node) | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | if length == 1 then .[0] else error("ambiguous replacement") end')"
replacement_observed_ns="$(date +%s%N)"
sleep 2
for pod in smoke-client smoke-control; do kubectl -n ztap-smoke exec "$pod" -- touch /tmp/continuity.stop; done
for pid in ${probe_pids[@]+"${probe_pids[@]}"}; do wait "$pid"; done
for evidence in rolling-continuity-{ingress,egress}.jsonl; do
  jq -se 'length > 10 and all(.[]; .schema_version == 2 and .prohibited == 0 and .prohibited_attempts > 0) and .[-1].allowed > .[0].allowed' "$evidence" >/dev/null
 done
probe_pids=()
printf 'outage_started_ns=%s\noutage_finished_ns=%s\nrollout_started_ns=%s\nreplacement_namespace=ztap-system\nreplacement_pod=%s\nreplacement_uid=%s\nreplacement_created_at=%s\nreplacement_node=%s\nreplacement_ready=true\nreplacement_observed_ns=%s\n' \
  "$outage_started_ns" "$(date +%s%N)" "$rollout_started_ns" "$(jq -r '.metadata.name' <<< "$replacement")" "$(jq -r '.metadata.uid' <<< "$replacement")" "$(jq -r '.metadata.creationTimestamp' <<< "$replacement")" "$smoke_client_node" "$replacement_observed_ns"
printf 'ingress_prohibited=%s\negress_prohibited=%s\ningress_allowed=%s\negress_allowed=%s\n' \
  "$(tail -n 1 rolling-continuity-ingress.jsonl | jq -er '.prohibited')" "$(tail -n 1 rolling-continuity-egress.jsonl | jq -er '.prohibited')" \
  "$(tail -n 1 rolling-continuity-ingress.jsonl | jq -er '.allowed')" "$(tail -n 1 rolling-continuity-egress.jsonl | jq -er '.allowed')"
) 2>&1 | tee rolling-fail-open-evidence.txt

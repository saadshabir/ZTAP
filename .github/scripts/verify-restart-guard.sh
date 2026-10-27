#!/usr/bin/env bash
# Destructive fault injection is restricted to the disposable kind CI node.
set -euo pipefail
kind_node="${ZTAP_KIND_NODE:-ztap-control-plane}"
test "$(docker inspect "$kind_node" | jq -r '.[0].Config.Labels["io.x-k8s.kind.role"]')" = control-plane
evidence=restart-guard-evidence
mkdir -p "$evidence"
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$RUNNER_TEMP/ztap-guard-probe" ./tools/phase5probe
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$RUNNER_TEMP/ztap-restart-inspect" ./tools/restartinspect
docker cp "$RUNNER_TEMP/ztap-restart-inspect" "$kind_node:/usr/local/bin/ztap-restart-inspect"
node_ip="$(kubectl get node "$kind_node" -o json | jq -r '.status.addresses[] | select(.type == "InternalIP") | .address')"
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
service_ip="$(kubectl -n ztap-smoke get service smoke-server -o jsonpath='{.spec.clusterIP}')"
parents="$(docker exec "$kind_node" cat /run/ztap/node-bootstrap.json | jq -r '.parents[]')"
peers="$(docker exec "$kind_node" cat /run/ztap/node-bootstrap.json | jq -r '.api_peers[]')"
paused=0
api_blocked=0
lock_held=0
agent_pid=0
probe_pods=()
probe_pids=()
created_pods=()

agent_snapshot() {
  kubectl -n ztap-system get pods -l app=ztap-agent -o json | jq -cer --arg node "$kind_node" '
    [.items[] | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null)
     | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | if length == 1 then .[0] else error("no unique ready controller") end'
}

api_rules() {
  local operation="$1" peer address port
  while read -r peer; do
    address="${peer%:*}"; port="${peer##*:}"
    docker exec "$kind_node" nsenter -t "$agent_pid" -n iptables "$operation" OUTPUT -p tcp -d "$address" --dport "$port" -m comment --comment ztap-restart-proof -j DROP
    docker exec "$kind_node" nsenter -t "$agent_pid" -n iptables "$operation" INPUT -p tcp -s "$address" --sport "$port" -m comment --comment ztap-restart-proof -j DROP
  done <<< "$peers"
}

release_controller() {
  if [ "$paused" = 1 ]; then docker exec "$kind_node" kill -CONT "$agent_pid"; paused=0; fi
  if [ "$api_blocked" = 1 ]; then api_rules -D; api_blocked=0; fi
  if [ "$lock_held" = 1 ]; then
    docker exec "$kind_node" sh -c 'pid=$(cat /run/ztap/restart-proof-lock.pid); test "$pid" -gt 1; kill "$pid"; rm -f /run/ztap/restart-proof-lock.pid'
    lock_held=0
  fi
}

# shellcheck disable=SC2329
cleanup_guard() {
  release_controller || true
  for pod in ${probe_pods[@]+"${probe_pods[@]}"}; do timeout 5s kubectl -n ztap-smoke exec "$pod" -- touch /tmp/guard.stop >/dev/null 2>&1 || true; done
  for pid in ${probe_pids[@]+"${probe_pids[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  for pod in ${created_pods[@]+"${created_pods[@]}"}; do kubectl -n ztap-smoke delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true; done
}
trap cleanup_guard EXIT

start_probe() {
  local pod="$1" denied="$2" allowed="$3"
  kubectl cp "$RUNNER_TEMP/ztap-guard-probe" "ztap-smoke/$pod:/tmp/guard-probe"
  kubectl -n ztap-smoke exec "$pod" -- sh -c 'chmod 0755 /tmp/guard-probe; rm -f /tmp/guard.stop /tmp/guard.release'
  local direction=egress
  if [ "$pod" = smoke-control ]; then direction=ingress; fi
  kubectl -n ztap-smoke exec "$pod" -- /tmp/guard-probe -continuity -url="$denied" -allowed-url="$allowed"     -unclassified-until=/tmp/guard.release -request-timeout=100ms -max-duration=5m -stop-file=/tmp/guard.stop     > "$evidence/$mode-$direction.jsonl" 2> "$evidence/$mode-$direction.err" &
  probe_pids+=("$!")
  probe_pods+=("$pod")
}

create_pod() {
  local name="$1" label="$2" host="$3" port="$4"
  created_pods+=("$name")
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: ztap-smoke
  labels: {app: $label}
spec:
  nodeName: $kind_node
  hostNetwork: $host
  containers:
    - name: traffic
      image: busybox:1.36.1
      command: [sh, -c, "mkdir /tmp/www; printf 'ok\\n' > /tmp/www/index.html; httpd -p $port -h /tmp/www; httpd -p 8091 -h /tmp/www; exec sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
YAML
  kubectl -n ztap-smoke wait --for=condition=Ready "pod/$name" --timeout=90s
}

for mode in pause term kill api; do
  snapshot="$(agent_snapshot)"
  old_container="$(jq -r '.status.containerStatuses[0].containerID | sub("containerd://"; "")' <<< "$snapshot")"
  agent_pid="$(docker exec "$kind_node" crictl inspect "$old_container" | jq -r '.info.pid')"
  test "$agent_pid" -gt 1
  printf 'Testing new containers during %s (controller PID %s)\n' "$mode" "$agent_pid"
  case "$mode" in
    pause) paused=1; docker exec "$kind_node" kill -STOP "$agent_pid" ;;
    api) api_blocked=1; api_rules -I ;;
    term|kill)
      docker exec "$kind_node" rm -f /run/ztap/restart-proof-lock.pid
      # Queue the test's node-lock holder before stopping the real agent.
      # Kubelet stays running so newly created workloads can start.
      docker exec --detach "$kind_node" flock -x /run/ztap/agent.lock sh -c 'echo $$ > /run/ztap/restart-proof-lock.pid; exec sleep 240'
      sleep 1
      lock_held=1
      if [ "$mode" = term ]; then docker exec "$kind_node" kill -TERM "$agent_pid"; else docker exec "$kind_node" kill -KILL "$agent_pid"; fi
      for ((attempt = 0; attempt < 30; attempt++)); do
        if docker exec "$kind_node" test -f /run/ztap/restart-proof-lock.pid; then break; fi
        sleep 1
      done
      test "$attempt" -lt 30
      ;;
  esac
  sleep 2
  pod="guard-$mode"
  host_pod="guard-host-$mode"
  unisolated="guard-unisolated-$mode"
  create_pod "$pod" smoke-client false 8090
  create_pod "$host_pod" guard-host true 19090
  create_pod "$unisolated" guard-unisolated false 8090
  # Newly created host-network sockets are excluded using their actual
  # namespace, including accepted TCP sockets cloned from the listener.
  kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$node_ip:19090/" | grep -qx ok
  pod_json="$(kubectl -n ztap-smoke get pod "$pod" -o json)"
  pod_ip="$(jq -r '.status.podIP' <<< "$pod_json")"
  container="$(jq -r '.status.containerStatuses[0].containerID | sub("containerd://"; "")' <<< "$pod_json")"
  test "${#container}" = 64
  cgroup_path="$(while read -r parent; do docker exec "$kind_node" find "/sys/fs/cgroup/$parent" -type d -name "cri-containerd-$container.scope"; done <<< "$parents")"
  test "$(wc -l <<< "$cgroup_path" | tr -d ' ')" = 1
  cgroup_id="$(docker exec "$kind_node" stat -c %i "$cgroup_path")"
  probe_pods=()
  probe_pids=()
  start_probe "$pod" "http://$server_ip:8080/" "http://$service_ip:8080/"
  start_probe smoke-control "http://$pod_ip:8091/" "http://$pod_ip:8090/"
  observation_started_ns="$(date +%s%N)"
  sleep 3
  for direction in egress ingress; do
    if [ "$direction" = egress ]; then source="$pod"; else source=smoke-control; fi
    cp "$evidence/$mode-$direction.jsonl" "$evidence/$mode-$direction-before.jsonl"
    jq -se 'length >= 8 and all(.[]; .schema_version == 2 and .unknown_tcp_connections == 0 and .prohibited == 0 and .allowed == 0) and .[-1].allowed_attempts > 0 and .[-1].prohibited_attempts > 0' "$evidence/$mode-$direction-before.jsonl" >/dev/null
  done
  observation_finished_ns="$(date +%s%N)"
  docker exec "$kind_node" /usr/local/bin/ztap-restart-inspect -cgroup="$cgroup_id" > "$evidence/$mode-kernel.json"
  jq -e '.schema_version == 2 and .policy_epoch > 0 and .blocked_ingress > 0 and .blocked_egress > 0' "$evidence/$mode-kernel.json" >/dev/null
  # Release markers precede controller restoration. They never grant network
  # access: the sole network release remains the atomic policy/class flip.
  for source in "$pod" smoke-control; do kubectl -n ztap-smoke exec "$source" -- touch /tmp/guard.release; done
  release_controller
  for ((attempt = 0; attempt < 180; attempt++)); do
    if tail -n 1 "$evidence/$mode-egress.jsonl" | jq -e '.allowed > 0 and .prohibited == 0 and .unknown_tcp_connections == 0' >/dev/null &&
      tail -n 1 "$evidence/$mode-ingress.jsonl" | jq -e '.allowed > 0 and .prohibited == 0 and .unknown_tcp_connections == 0' >/dev/null; then break; fi
    sleep 1
  done
  test "$attempt" -lt 180
  sleep 2
  for direction in egress ingress; do
    if [ "$direction" = egress ]; then source="$pod"; else source=smoke-control; fi
    kubectl -n ztap-smoke exec "$source" -- touch /tmp/guard.stop
    jq -se 'all(.[]; .unknown_tcp_connections == 0 and .prohibited == 0) and .[-1].allowed > 0 and .[-1].prohibited_attempts > 0' "$evidence/$mode-$direction.jsonl" >/dev/null
  done
  for pid in ${probe_pids[@]+"${probe_pids[@]}"}; do wait "$pid"; done
  probe_pids=()
  # Explicit classification restores default allow for unselected workloads.
  unisolated_ip="$(kubectl -n ztap-smoke get pod "$unisolated" -o jsonpath='{.status.podIP}')"
  kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$unisolated_ip:8091/" | grep -qx ok
  kubectl -n ztap-smoke exec "$unisolated" -- wget -qO- -T 3 "http://$server_ip:8080/" | grep -qx ok
  # Preserve the documented node and self exceptions after classification.
  kubectl -n ztap-smoke exec "$pod" -- wget -qO- -T 3 "http://$node_ip:19090/" | grep -qx ok
  kubectl -n ztap-smoke exec "$pod" -- wget -qO- -T 3 "http://$pod_ip:8091/" | grep -qx ok
  for ((attempt = 0; attempt < 180; attempt++)); do
    if replacement="$(agent_snapshot 2>/dev/null)"; then break; fi
    sleep 1
  done
  test "$attempt" -lt 180
  replacement_container="$(jq -r '.status.containerStatuses[0].containerID | sub("containerd://"; "")' <<< "$replacement")"
  if [ "$mode" = term ] || [ "$mode" = kill ]; then test "$replacement_container" != "$old_container"; fi
  jq -n --arg mode "$mode" --arg kernel "$(docker exec "$kind_node" uname -r)" \
    --arg runtime "$(docker exec "$kind_node" containerd --version)" --arg uid "$(jq -r '.metadata.uid' <<< "$pod_json")" \
    --arg container "$container" --arg path "$cgroup_path" --argjson cgroup "$cgroup_id" \
    --argjson start "$observation_started_ns" --argjson end "$observation_finished_ns" \
    --arg old_container "$old_container" --arg replacement_container "$replacement_container" --argjson controller "$replacement" --slurpfile counters "$evidence/$mode-kernel.json" \
    '{schema_version:2,mode:$mode,kernel:$kernel,containerd:$runtime,pod_uid:$uid,container_id:$container,cgroup_id:$cgroup,cgroup_path:$path,observation_started_ns:$start,observation_finished_ns:$end,kernel_evidence:$counters[0],replacement_uid:$controller.metadata.uid,old_controller_container_id:$old_container,replacement_container_id:$replacement_container}' > "$evidence/$mode.json"
  probe_pods=()
  kubectl -n ztap-smoke delete pod "$pod" "$host_pod" "$unisolated" --grace-period=1 --wait=true --timeout=90s >/dev/null
  printf '%s: both directions blocked before classification; allowed controls, host network, node/self, and unisolated traffic passed\n' "$mode"
done

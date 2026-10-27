#!/usr/bin/env bash
set -euo pipefail
(
set -euo pipefail
agent_pods="$(kubectl -n ztap-system get pods -l app=ztap-agent -o json)"
agent_pod="$(jq -r '
  [
    .items[]
    | select(.status.phase == "Running")
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    | .metadata.name
  ]
  | if length == 1 then .[0] else empty end
' <<< "$agent_pods")"
client_ip="$(kubectl -n ztap-smoke get pod smoke-client -o jsonpath='{.status.podIP}')"
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
test -n "$client_ip"
test -n "$server_ip"
printf 'flow_expected_src_ip=%s\nflow_expected_dst_ip=%s\nflow_expected_dst_port=8080\n' \
  "$client_ip" "$server_ip"
flow_output="$RUNNER_TEMP/ztap-flows.json"
flow_error="$RUNNER_TEMP/ztap-flows.err"
kubectl -n ztap-system exec "$agent_pod" -- /ztap flows --output json --action blocked --direction egress \
  --bpffs-root=/host/sys/fs/bpf \
  > "$flow_output" 2> "$flow_error" &
flow_pid=$!
flow_seen=0
for ((attempt = 0; attempt < 30; attempt++)); do
  if ! kill -0 "$flow_pid" 2>/dev/null; then
    wait "$flow_pid" || true
    cat "$flow_error" >&2
    exit 1
  fi
  kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/" >/dev/null 2>&1 || true
  if jq -e -s --arg expected_src "$client_ip" --arg expected_dst "$server_ip" '
    any(.[];
      (.timestamp | type) == "string" and
      (.timestamp | length) > 0 and
      (.policy_epoch | type) == "number" and
      (.policy_epoch > 0) and
      ((.policy_epoch | floor) == .policy_epoch) and
      (.cgroup_id | type) == "number" and
      (.cgroup_id > 0) and
      ((.cgroup_id | floor) == .cgroup_id) and
      .action == "blocked" and
      .direction == "egress" and
      .protocol == "TCP" and
      .reason == "default_deny" and
      (.src_ip | type) == "string" and
      .src_ip == $expected_src and
      (.src_port | type) == "number" and
      (.src_port > 0) and
      (.src_port <= 65535) and
      ((.src_port | floor) == .src_port) and
      (.dst_ip | type) == "string" and
      .dst_ip == $expected_dst and
      (.dst_port | type) == "number" and
      .dst_port == 8080 and
      (.schema_version | type) == "number" and
      .schema_version == 1)
  ' "$flow_output" >/dev/null 2>&1; then
    flow_seen=1
    break
  fi
  sleep 1
done
kill "$flow_pid" 2>/dev/null || true
wait "$flow_pid" 2>/dev/null || true
test "$flow_seen" -eq 1
cat "$flow_output"
printf '%s\n' 'flow_streaming=passed'
) 2>&1 | tee -a capability-agent-smoke.txt

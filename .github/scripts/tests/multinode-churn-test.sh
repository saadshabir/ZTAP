#!/usr/bin/env bash
# Portable regression checks; no Docker or Kubernetes access is needed.
set -euo pipefail
source .github/scripts/lib/multinode-churn.sh
test_dir="$(mktemp -d)"
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  rm -rf "$test_dir"
}
trap cleanup EXIT
fail() { printf '%s\n' "$*" >&2; exit 1; }

healthy='{"connections":1,"received":10,"denied_attempts":10,"prohibited_connections":0,"max_gap_ms":101,"finished":false}'
# This producer starts after the old fixed three-second wait would have failed.
(
  sleep 3.2
  printf '%s\n' "$healthy" > "$test_dir/delayed.jsonl"
  sleep 30
) &
pids+=("$!")
churn_wait_probe_ready "$test_dir/delayed.jsonl" "$!" 8

# Ignore a partially written report until the complete JSON line is available.
(
  printf '%s' '{"connections":1,' > "$test_dir/partial.jsonl"
  sleep 0.3
  printf '%s\n' '"received":10,"denied_attempts":10,"prohibited_connections":0,"max_gap_ms":101,"finished":false}' >> "$test_dir/partial.jsonl"
  sleep 30
) &
pids+=("$!")
churn_wait_probe_ready "$test_dir/partial.jsonl" "$!" 5

for scenario in insufficient leak finished; do
  case "$scenario" in
    insufficient) jq '.denied_attempts = 9' <<< "$healthy" ;;
    leak) jq '.prohibited_connections = 1' <<< "$healthy" ;;
    finished) jq '.finished = true' <<< "$healthy" ;;
  esac > "$test_dir/$scenario.jsonl"
  sleep 30 &
  pid=$!
  pids+=("$pid")
  if churn_wait_probe_ready "$test_dir/$scenario.jsonl" "$pid" 1 2> "$test_dir/$scenario.err"; then
    fail "accepted invalid startup evidence: $scenario"
  fi
done
(sleep 0.1; exit 7) &
pid=$!
pids+=("$pid")
if churn_wait_probe_ready "$test_dir/exited.jsonl" "$pid" 5 2> "$test_dir/exited.err"; then
  fail 'accepted a stream that exited before startup'
fi
[[ "$(< "$test_dir/exited.err")" = *'probe exited'* ]]

printf '%s\n' '{"connections":1,"received":10,"changed_ns":0,"resume_ns":0,"max_gap_ms":101,"finished":false}' > "$test_dir/reply.jsonl"
sleep 30 &
pid=$!
pids+=("$pid")
churn_wait_probe_ready "$test_dir/reply.jsonl" "$pid" 1 reply-state
if churn_wait_probe_ready "$test_dir/reply.jsonl" "$pid" 1 2> "$test_dir/reply.err"; then
  fail 'accepted reply-state evidence as an echo stream baseline'
fi

# Model the actual selector policy: egress selects the destination's labels;
# ingress selects the source's labels. A fail-open observer direction must
# make the denied pair fail, rather than being masked by the other endpoint.
node_a=ztap-control-plane
node_b=ztap-worker
ip_a=10.244.0.10
ip_b=10.244.2.10
broken_node=
broken_direction=
kubectl() { printf '%s' "$fixture_peer_node"; }
fresh() {
  local ns="$1" pod="$2" ip="$3" expected="$4"
  local source_node destination_node destination_excluded=0 source_excluded=0
  if [ "$ns" = ztap-churn-remote ]; then
    test "$pod" = remote && test "$ip" = "$fixture_observer_ip" || return 1
    source_node="$fixture_peer_node"; destination_node="$fixture_observer_node"; source_excluded="$excluded"
  else
    test "$ns" = "$fixture_observer_ns" && test "$pod" = endpoint && test "$ip" = "$fixture_peer_ip" || return 1
    source_node="$fixture_observer_node"; destination_node="$fixture_peer_node"; destination_excluded="$excluded"
  fi
  local allowed=true
  if [ "$destination_excluded" = 1 ] && { [ "$broken_node" != "$source_node" ] || [ "$broken_direction" != egress ]; }; then allowed=false; fi
  if [ "$source_excluded" = 1 ] && { [ "$broken_node" != "$destination_node" ] || [ "$broken_direction" != ingress ]; }; then allowed=false; fi
  if [ "$expected" = allowed ]; then [ "$allowed" = true ]; else [ "$allowed" = false ]; fi
}
for fixture_peer_node in "$node_a" "$node_b"; do
  if [ "$fixture_peer_node" = "$node_a" ]; then
    fixture_observer_node="$node_b"; fixture_observer_ns=ztap-churn-b; fixture_observer_ip="$ip_b"; fixture_peer_ip=10.244.0.30
  else
    fixture_observer_node="$node_a"; fixture_observer_ns=ztap-churn-a; fixture_observer_ip="$ip_a"; fixture_peer_ip=10.244.2.30
  fi
  for excluded in 0 1; do
    if [ "$excluded" = 1 ]; then expectation=denied; else expectation=allowed; fi
    churn_wait_pair remote "$fixture_peer_ip" "$expectation" baseline "$test_dir" "$node_a" "$ip_a" "$node_b" "$ip_b" 5
    jq -se --arg node "$fixture_observer_node" --arg peer "$fixture_peer_node" \
      '.[-1] | .observer_node == $node and .peer_node == $peer and .attempts == 3' "$test_dir/transitions.jsonl" >/dev/null
  done
  for broken_direction in ingress egress; do
    broken_node="$fixture_observer_node"
    if churn_wait_pair remote "$fixture_peer_ip" denied broken "$test_dir" "$node_a" "$ip_a" "$node_b" "$ip_b" 1 2> "$test_dir/broken.err"; then
      fail "missed fail-open $broken_direction on $fixture_observer_node"
    fi
  done
  broken_node=
  broken_direction=
done

jq -nc --arg a "$node_a" --arg b "$node_b" '
  [$a, $b][] as $node | ["pod-label-remove-", "namespace-label-remove-", "old-ip-remove-"][] as $phase |
  range(1; 4) as $cycle | {observer_node:$node,peer_node:(if $node == $a then $b else $a end),
    expected:"denied",phase:($phase + ($cycle | tostring))}' > "$test_dir/coverage.jsonl"
churn_verify_coverage "$test_dir/coverage.jsonl" "$node_a" "$node_b"
for scenario in missing-node missing-phase same-node; do
  case "$scenario" in
    missing-node) jq -c --arg a "$node_a" 'select(.observer_node == $a)' "$test_dir/coverage.jsonl" ;;
    missing-phase) jq -c 'select(.phase != "old-ip-remove-3")' "$test_dir/coverage.jsonl" ;;
    same-node) jq -c '.peer_node = .observer_node' "$test_dir/coverage.jsonl" ;;
  esac > "$test_dir/$scenario.jsonl"
  if churn_verify_coverage "$test_dir/$scenario.jsonl" "$node_a" "$node_b"; then fail "accepted $scenario coverage"; fi
done
printf '%s\n' 'multinode_churn_regressions=passed'

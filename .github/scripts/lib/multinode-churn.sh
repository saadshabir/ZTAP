# shellcheck shell=bash
# Shared checks for the disposable multi-node fixture and its regression tests.

churn_wait_pair() {
  local pod="$1" ip="$2" expectation="$3" phase="$4" evidence="$5"
  local node_a="$6" ip_a="$7" node_b="$8" ip_b="$9" limit="${10:-30}"
  local peer_node observer_node observer_ns observer_ip
  peer_node="$(kubectl -n ztap-churn-remote get pod "$pod" -o jsonpath='{.spec.nodeName}')" || return 1
  case "$peer_node" in
    "$node_a") observer_node="$node_b"; observer_ns=ztap-churn-b; observer_ip="$ip_b" ;;
    "$node_b") observer_node="$node_a"; observer_ns=ztap-churn-a; observer_ip="$ip_a" ;;
    *) printf 'unexpected churn peer node: %s\n' "$peer_node" >&2; return 1 ;;
  esac
  local deadline=$((SECONDS + limit)) consecutive=0 attempts=0 started=$SECONDS
  while [ "$SECONDS" -lt "$deadline" ]; do
    attempts=$((attempts + 1))
    if fresh "$observer_ns" endpoint "$ip" "$expectation" >> "$evidence/checks.log" 2>&1 &&
       fresh ztap-churn-remote "$pod" "$observer_ip" "$expectation" >> "$evidence/checks.log" 2>&1; then
      if [ "$SECONDS" -ge "$deadline" ]; then break; fi
      consecutive=$((consecutive + 1))
      if [ "$consecutive" -eq 3 ]; then
        jq -nc --arg phase "$phase" --arg expected "$expectation" --arg pod "$pod" \
          --arg observer_node "$observer_node" --arg peer_node "$peer_node" \
          --argjson attempts "$attempts" --argjson seconds "$((SECONDS - started))" \
          '{phase:$phase,expected:$expected,pod:$pod,observer_node:$observer_node,peer_node:$peer_node,
            attempts:$attempts,convergence_seconds:$seconds}' >> "$evidence/transitions.jsonl"
        return 0
      fi
    else
      consecutive=0
    fi
    sleep 0.2
  done
  printf 'convergence failed: phase=%s pod=%s expected=%s observer=%s\n' "$phase" "$pod" "$expectation" "$observer_node" >&2
  return 1
}

churn_wait_probe_ready() {
  local file="$1" pid="$2" limit="${3:-30}" deadline=$((SECONDS + ${3:-30}))
  local mode="${4:-stream}"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      printf 'probe exited before startup evidence was ready: %s\n' "$file" >&2
      return 1
    fi
    # A report may be empty or partially written while its producer is running.
    if jq -se --arg mode "$mode" 'length > 0 and (.[-1] | .connections == 1 and .received >= 10
      and .max_gap_ms <= 5000 and .finished == false
      and (if $mode == "stream" then .denied_attempts >= 10 and .prohibited_connections == 0
        else $mode == "reply-state" and .changed_ns == 0 and .resume_ns == 0 end))' "$file" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  printf 'probe startup evidence was not ready within %ss: %s\n' "$limit" "$file" >&2
  return 1
}

churn_verify_coverage() {
  local file="$1" node_a="$2" node_b="$3"
  jq -se --arg a "$node_a" --arg b "$node_b" '
    . as $transitions | all([$a, $b][]; . as $node |
      all(["pod-label-remove-", "namespace-label-remove-", "old-ip-remove-"][]; . as $phase |
        [$transitions[] | select(.observer_node == $node and .peer_node != $node and .expected == "denied"
          and (.phase | startswith($phase)))] | length >= 3))' "$file" >/dev/null
}

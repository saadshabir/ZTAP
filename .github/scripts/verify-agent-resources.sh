#!/usr/bin/env bash
set -euo pipefail
(
set -euo pipefail
expected_pods=250
expected_policies=25
expected_rules=2500
retained_smoke_client_cgroups=1
retained_smoke_client_rules=1
expected_enforced_cgroups=$((expected_pods + retained_smoke_client_cgroups))
expected_total_rules=$((expected_rules + retained_smoke_client_rules))
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
observed_pods="$(kubectl -n ztap-performance get pods --no-headers | wc -l | tr -d ' ')"
observed_policies="$(kubectl -n ztap-performance get networkpolicies --no-headers | wc -l | tr -d ' ')"
test "$observed_pods" -eq "$expected_pods"
test "$observed_policies" -eq "$expected_policies"
printf 'observed_fixture_pods=%s\nobserved_fixture_policies=%s\n' \
  "$observed_pods" "$observed_policies"
cpu_max="$(docker exec ztap-control-plane cat /sys/fs/cgroup/cpu.max)"
printf 'reference_cpu_max=%s\n' "$cpu_max"
test "$cpu_max" = '200000 100000'
kubectl -n ztap-system port-forward pod/"$agent_pod" 19091:9090 > "$RUNNER_TEMP/ztap-resource-port-forward.log" 2>&1 &
port_forward_pid=$!
trap 'kill "$port_forward_pid" 2>/dev/null || true' EXIT
read_uint_metric() {
  local metric="$1"
  local text="$2"
  local value
  value="$(awk -v metric="$metric" '
    {
      sample=$1
      base=sample
      sub(/\{.*$/, "", base)
    }
    base == metric {
      matches++
      if (sample != metric || NF != 2 || $2 !~ /^[0-9]+$/ || matches > 1) {
        invalid=1
      } else {
        value=$2
      }
    }
    END {
      if (invalid || matches != 1) {
        exit 1
      }
      print value
    }
  ' <<< "$text")" || {
    printf 'resource sample failed: metrics must contain exactly one unsigned %s sample\n' "$metric" >&2
    return 1
  }
  printf '%s\n' "$value"
}
reference_ready=0
for ((attempt = 0; attempt < 180; attempt++)); do
  metrics="$(curl --fail --silent http://127.0.0.1:19091/metrics 2>/dev/null || true)"
  if [ -z "$metrics" ]; then
    sleep 2
    continue
  fi
  if ! agent_enforcing="$(read_uint_metric ztap_agent_enforcing "$metrics")"; then
    exit 1
  fi
  if ! enforced="$(read_uint_metric ztap_enforced_cgroups "$metrics")"; then
    exit 1
  fi
  if ! rules="$(read_uint_metric ztap_compiled_rules "$metrics")"; then
    exit 1
  fi
  if ! active_policy_epoch="$(read_uint_metric ztap_active_policy_epoch "$metrics")"; then
    exit 1
  fi
  if [ "$agent_enforcing" -eq 1 ] &&
    [ "$enforced" -eq "$expected_enforced_cgroups" ] &&
    [ "$rules" -eq "$expected_total_rules" ] &&
    [ "$active_policy_epoch" -ge 1 ]; then
    fixture_enforced_cgroups=$((enforced - retained_smoke_client_cgroups))
    test "$fixture_enforced_cgroups" -eq "$expected_pods"
    fixture_compiled_rules=$((rules - retained_smoke_client_rules))
    test "$fixture_compiled_rules" -eq "$expected_rules"
    reference_ready=1
    printf 'reference_fixture_agent_enforcing=%s\nreference_fixture_active_policy_epoch=%s\nreference_total_enforced_cgroups=%s\nretained_smoke_client_cgroups=%s\nreference_fixture_enforced_cgroups=%s\nreference_total_compiled_rules=%s\nretained_smoke_client_rules=%s\nreference_fixture_compiled_rules=%s\n' \
      "$agent_enforcing" "$active_policy_epoch" "$enforced" "$retained_smoke_client_cgroups" \
      "$fixture_enforced_cgroups" "$rules" "$retained_smoke_client_rules" "$fixture_compiled_rules"
    break
  fi
  sleep 2
done
test "$reference_ready" -eq 1
printf '%s\n' 'reference_fixture_status=active_waiting_for_quiet_interval'
sleep 10
container_ref="$(kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.status.containerStatuses[0].containerID}')"
container_id="${container_ref#containerd://}"
case "$container_id" in
  ''|*[!0-9a-fA-F]*)
    printf 'resource sample failed: container ID is not hexadecimal: %s\n' "$container_id" >&2
    exit 1
    ;;
esac
if [ "${#container_id}" -ne 64 ]; then
  printf 'resource sample failed: container ID must contain exactly 64 hex characters: %s\n' "$container_id" >&2
  exit 1
fi
cgroup_name="cri-containerd-${container_id}.scope"
cgroup_path=''
for hierarchy in \
  /sys/fs/cgroup/kubepods.slice \
  /sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice; do
  if ! docker exec ztap-control-plane test -d "$hierarchy"; then
    continue
  fi
  candidate="$(docker exec ztap-control-plane find "$hierarchy" -type d -name "$cgroup_name" -print -quit)"
  if [ -n "$candidate" ]; then
    if [ -n "$cgroup_path" ] && [ "$cgroup_path" != "$candidate" ]; then
      printf '%s\n' 'resource sample failed: container ID matched multiple supported cgroup hierarchies' >&2
      exit 1
    fi
    cgroup_path="$candidate"
  fi
done
printf 'agent_namespace=ztap-system\nagent_pod=%s\ncontainer_id=%s\ncgroup_path=%s\n' \
  "$agent_pod" "$container_id" "$cgroup_path"
if [ -z "$cgroup_path" ]; then
  printf '%s\n' 'resource sample failed: container cgroup path was not visible in the kind node'
  exit 1
fi
case "$cgroup_path" in
  /sys/fs/cgroup/kubepods.slice/*|/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/*)
    if [ "${cgroup_path##*/}" != "$cgroup_name" ]; then
      printf 'resource sample failed: cgroup path does not end in the measured container ID: %s\n' "$cgroup_path" >&2
      exit 1
    fi
    ;;
  *)
    printf 'resource sample failed: cgroup path is outside a supported containerd hierarchy: %s\n' "$cgroup_path" >&2
    exit 1
    ;;
esac
if ! docker exec ztap-control-plane test -r "$cgroup_path/cpu.stat" ||
  ! docker exec ztap-control-plane test -r "$cgroup_path/memory.current"; then
  printf '%s\n' 'resource sample failed: container cgroup counters were not readable'
  exit 1
fi

read_cpu_usec() {
  docker exec ztap-control-plane cat "$cgroup_path/cpu.stat" |
    awk '$1 == "usage_usec" { print $2 }'
}
read_memory_current_bytes() {
  docker exec ztap-control-plane cat "$cgroup_path/memory.current"
}
require_uint() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*)
      printf 'resource sample failed: %s is not an unsigned integer: %s\n' "$name" "$value" >&2
      exit 1
      ;;
  esac
}
max_cpu=0
max_memory_current=0
previous_end_cpu=''
memory_peak_sample_interval_ns=100000000
for sample in 1 2 3; do
  start_cpu="$(read_cpu_usec)"
  start_ns="$(date +%s%N)"
  start_memory_current="$(read_memory_current_bytes)"
  if [ -z "$start_cpu" ] || [ -z "$start_memory_current" ]; then
    printf '%s\n' 'resource sample failed: cgroup counters were empty'
    exit 1
  fi
  require_uint start_cpu_usec "$start_cpu"
  require_uint start_memory_current_bytes "$start_memory_current"
  memory_peak="$start_memory_current"
  sample_deadline_ns=$((start_ns + 5000000000))
  while :; do
    now_ns="$(date +%s%N)"
    if [ "$now_ns" -ge "$sample_deadline_ns" ]; then
      break
    fi
    remaining_ns=$((sample_deadline_ns - now_ns))
    sleep_seconds="$(awk -v remaining="$remaining_ns" -v interval="$memory_peak_sample_interval_ns" 'BEGIN { if (remaining < interval) remaining = interval; printf "%.3f", remaining / 1000000000 }')"
    sleep "$sleep_seconds"
    memory_sample="$(read_memory_current_bytes)"
    if [ -z "$memory_sample" ]; then
      printf '%s\n' 'resource sample failed: memory.current became empty during sampling'
      exit 1
    fi
    require_uint memory_peak_sample_bytes "$memory_sample"
    if [ "$memory_sample" -gt "$memory_peak" ]; then
      memory_peak="$memory_sample"
    fi
  done
  end_cpu="$(read_cpu_usec)"
  end_ns="$(date +%s%N)"
  end_memory_current="$(read_memory_current_bytes)"
  if [ -z "$end_cpu" ] || [ -z "$end_memory_current" ]; then
    printf '%s\n' 'resource sample failed: cgroup counters became empty'
    exit 1
  fi
  require_uint end_cpu_usec "$end_cpu"
  require_uint end_memory_current_bytes "$end_memory_current"
  if [ "$end_cpu" -lt "$start_cpu" ]; then
    printf 'resource sample failed: CPU counter decreased from %s to %s\n' "$start_cpu" "$end_cpu"
    exit 1
  fi
  if [ -n "$previous_end_cpu" ] && [ "$start_cpu" -lt "$previous_end_cpu" ]; then
    printf 'resource sample failed: CPU counter reset between samples from %s to %s\n' "$previous_end_cpu" "$start_cpu"
    exit 1
  fi
  elapsed_ns=$((end_ns - start_ns))
  if [ "$elapsed_ns" -le 0 ]; then
    printf 'resource sample failed: elapsed interval was not positive: %s\n' "$elapsed_ns"
    exit 1
  fi
  cpu_cores="$(awk -v delta="$((end_cpu - start_cpu))" -v elapsed="$elapsed_ns" 'BEGIN { printf "%.9f", delta * 1000 / elapsed }')"
  if [ "$end_memory_current" -gt "$memory_peak" ]; then
    memory_peak="$end_memory_current"
  fi
  memory_current_mib="$(awk -v bytes="$memory_peak" 'BEGIN { printf "%.6f", bytes / 1048576 }')"
  printf 'sample=%s start_cpu_usec=%s end_cpu_usec=%s start_memory_current_bytes=%s end_memory_current_bytes=%s peak_memory_current_bytes=%s cpu_cores=%s memory_current_mib=%s elapsed_ns=%s\n' \
    "$sample" "$start_cpu" "$end_cpu" "$start_memory_current" "$end_memory_current" "$memory_peak" "$cpu_cores" "$memory_current_mib" "$elapsed_ns"
  if awk -v value="$cpu_cores" -v max="$max_cpu" 'BEGIN { exit !(value > max) }'; then
    max_cpu="$cpu_cores"
  fi
  if awk -v value="$memory_current_mib" -v max="$max_memory_current" 'BEGIN { exit !(value > max) }'; then
    max_memory_current="$memory_current_mib"
  fi
  previous_end_cpu="$end_cpu"
done
printf 'scope=real capability-only DaemonSet in kind with %s Pods, %s policies, and %s rules\n' \
  "$expected_pods" "$expected_policies" "$expected_rules"
printf 'quiet_settle_seconds=10\nsample_interval_seconds=5\nmemory_peak_sample_interval_ms=100\nsamples=3\n'
printf 'memory_metric=memory.current (conservative cgroup memory upper bound; includes non-RSS charges)\n'
printf 'max_cpu_cores=%s\nmax_memory_current_mib=%s\n' "$max_cpu" "$max_memory_current"
printf 'cpu_budget_cores=0.10\nmemory_current_budget_mib=200\n'
if awk -v value="$max_cpu" 'BEGIN { exit !(value > 0.10) }'; then
  printf '%s\n' 'budget_result=failed'
  exit 1
fi
if awk -v value="$max_memory_current" 'BEGIN { exit !(value > 200) }'; then
  printf '%s\n' 'budget_result=failed'
  exit 1
fi
printf '%s\n' 'budget_result=passed'
) 2>&1 | tee capability-agent-resource.txt

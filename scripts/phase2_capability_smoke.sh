#!/usr/bin/env bash
# Exercise the shipped capability-only DaemonSet profile in a disposable kind cluster.
set -euo pipefail

kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s
kubectl apply -f deployments/kubernetes/phase2-capability-smoke.yaml
kubectl -n ztap-smoke wait --for=condition=Ready pod/smoke-server pod/smoke-control pod/smoke-client --timeout=180s

agent_pod="$(kubectl -n ztap-system get pods -l app=ztap-agent -o jsonpath='{.items[0].metadata.name}')"
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
test -n "$agent_pod"
test -n "$server_ip"

printf '%s\n' '--- agent security context and effective capabilities ---'
kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.spec.containers[0].securityContext}'
printf '\n'
privileged="$(kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.spec.containers[0].securityContext.privileged}')"
allow_privilege_escalation="$(kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}')"
seccomp_type="$(kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.spec.containers[0].securityContext.seccompProfile.type}')"
cap_drop="$(kubectl -n ztap-system get pod "$agent_pod" -o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[0]}')"
printf 'privileged=%s allowPrivilegeEscalation=%s seccompProfile=%s drop=%s\n' \
  "$privileged" "$allow_privilege_escalation" "$seccomp_type" "$cap_drop"
test "$privileged" = false
test "$allow_privilege_escalation" = false
test "$seccomp_type" = RuntimeDefault
test "$cap_drop" = ALL
capabilities=(BPF NET_ADMIN PERFMON SYS_RESOURCE)
for index in "${!capabilities[@]}"; do
  capability="${capabilities[$index]}"
  cap_add="$(kubectl -n ztap-system get pod "$agent_pod" -o "jsonpath={.spec.containers[0].securityContext.capabilities.add[$index]}")"
  printf 'capability[%s]=%s\n' "$capability" "$cap_add"
  test "$cap_add" = "$capability"
done
kubectl -n ztap-system exec "$agent_pod" -- id
kubectl -n ztap-system exec "$agent_pod" -- grep '^Cap' /proc/self/status
kubectl -n ztap-system exec "$agent_pod" -- stat -f -c %T /host/sys/fs/cgroup
kubectl -n ztap-system exec "$agent_pod" -- stat -f -c %T /host/sys/fs/bpf
read -r _ cap_eff <<< "$(kubectl -n ztap-system exec "$agent_pod" -- grep '^CapEff:' /proc/self/status)"
printf 'CapEff=%s\n' "$cap_eff"
test "${cap_eff,,}" = 000000c001001000

printf '%s\n' '--- wait for native cgroup classification ---'
classified=0
for ((attempt = 0; attempt < 90; attempt++)); do
  metrics="$(kubectl -n ztap-system exec "$agent_pod" -- wget -qO- http://127.0.0.1:9090/metrics 2>/dev/null || true)"
  if grep -Fxq 'ztap_agent_enforcing 1' <<< "$metrics" &&
    grep -Fxq 'ztap_enforced_cgroups 1' <<< "$metrics"; then
    classified=1
    break
  fi
  sleep 2
done
if test "$classified" -ne 1; then
  printf '%s\n' 'agent did not attach the selected smoke-client cgroup' >&2
  exit 1
fi

printf '%s\n' '--- unselected control must reach the server ---'
control_response="$(kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$server_ip:8080/")"
test "$control_response" = ok

printf '%s\n' '--- selected client must be blocked ---'
if kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/"; then
  printf '%s\n' 'selected smoke-client reached the server despite default-deny egress' >&2
  exit 1
fi

printf '%s\n' '--- wait for the engine default-deny counter ---'
observed_deny=0
for ((attempt = 0; attempt < 30; attempt++)); do
  metrics="$(kubectl -n ztap-system exec "$agent_pod" -- wget -qO- http://127.0.0.1:9090/metrics 2>/dev/null || true)"
  if grep -Eq '^ztap_packet_decisions_total\{action="blocked",direction="egress",reason="default_deny"\} [1-9][0-9]*(\.0+)?$' <<< "$metrics"; then
    observed_deny=1
    break
  fi
  sleep 2
done
if test "$observed_deny" -ne 1; then
  printf '%s\n' 'engine did not report a blocked egress packet' >&2
  exit 1
fi

printf '%s\n' 'capability-only DaemonSet attached and enforced the smoke policy'

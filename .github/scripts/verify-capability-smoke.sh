#!/usr/bin/env bash
set -euo pipefail
(
set -euo pipefail
test "${ZTAP_KINDNET_NETWORKPOLICY_DISABLED:-}" = 1
printf '%s\n' 'kindnet_networkpolicy_controller=disabled'
# Harden the pre-existing non-host-network system workload before
# the agent audits the cluster's packet-socket prerequisite.
kubectl -n kube-system patch deployment coredns --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"coredns","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n kube-system rollout status deployment/coredns --timeout=180s
kubectl -n local-path-storage patch deployment local-path-provisioner --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"local-path-provisioner","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n local-path-storage rollout status deployment/local-path-provisioner --timeout=180s
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-node-init --timeout=180s
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s
bash .github/scripts/verify-admission.sh
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ztap-smoke
---
apiVersion: v1
kind: Pod
metadata:
  name: smoke-server
  namespace: ztap-smoke
  labels:
    app: smoke-server
spec:
  containers:
    - name: server
      image: busybox:1.36.1
      command: ["sh", "-c", "mkdir -p /www && printf 'ok\\n' > /www/index.html && exec httpd -f -p 8080 -h /www"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [NET_RAW]
---
apiVersion: v1
kind: Service
metadata:
  name: smoke-server
  namespace: ztap-smoke
spec:
  type: ClusterIP
  selector:
    app: smoke-server
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: smoke-control
  namespace: ztap-smoke
  labels:
    app: smoke-control
spec:
  containers:
    - name: control
      image: busybox:1.36.1
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [NET_RAW]
---
apiVersion: v1
kind: Pod
metadata:
  name: smoke-client
  namespace: ztap-smoke
  labels:
    app: smoke-client
spec:
  containers:
    - name: client
      image: busybox:1.36.1
      command: ["sh", "-c", "mkdir -p /tmp/continuity-www; printf 'ok\\n' > /tmp/continuity-www/index.html; httpd -p 8090 -h /tmp/continuity-www; httpd -p 8091 -h /tmp/continuity-www; exec sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [NET_RAW]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: smoke-client-deny-egress
  namespace: ztap-smoke
spec:
  podSelector:
    matchLabels:
      app: smoke-client
  policyTypes:
    - Egress
  egress: []
EOF
kubectl -n ztap-smoke wait --for=condition=Ready pod/smoke-server pod/smoke-control pod/smoke-client --timeout=180s

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
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
service_ip="$(kubectl -n ztap-smoke get service smoke-server -o jsonpath='{.spec.clusterIP}')"
test -n "$agent_pod"
test -n "$server_ip"
test -n "$service_ip"
test "$service_ip" != None
service_endpoint_ip=
for ((attempt = 0; attempt < 30; attempt++)); do
  service_endpoint_ip="$(kubectl -n ztap-smoke get endpoints smoke-server -o jsonpath='{.subsets[*].addresses[*].ip}')"
  if [ "$service_endpoint_ip" = "$server_ip" ]; then
    break
  fi
  sleep 1
done
test "$service_endpoint_ip" = "$server_ip"
printf 'service_cluster_ip=%s\nservice_backend_pod_ip=%s\n' "$service_ip" "$server_ip"

printf '%s\n' '--- agent security context ---'
agent_json="$(kubectl -n ztap-system get pod "$agent_pod" -o json)"
jq -e '
  (.spec.hostNetwork // false) == false and
  (.spec.hostPID // false) == false and
  (.spec.hostIPC // false) == false and
  (.spec.containers | length) == 1 and
  .spec.containers[0].securityContext.runAsUser == 0 and
  .spec.containers[0].securityContext.runAsGroup == 0 and
  .spec.containers[0].securityContext.privileged == false and
  .spec.containers[0].securityContext.allowPrivilegeEscalation == false and
  .spec.containers[0].securityContext.readOnlyRootFilesystem == true and
  .spec.containers[0].securityContext.seccompProfile.type == "RuntimeDefault" and
  (.spec.containers[0].securityContext.capabilities.drop | sort) == ["ALL"] and
  (.spec.containers[0].securityContext.capabilities.add | sort) == ["BPF", "NET_ADMIN", "PERFMON", "SYS_RESOURCE"] and
  any(.spec.containers[0].volumeMounts[]?;
    .name == "cgroup" and
    .mountPath == "/host/sys/fs/cgroup" and
    .readOnly == true)
' <<< "$agent_json" >/dev/null
printf '%s\n' 'host namespace isolation and read-only cgroup mount verified'
printf 'agent_security_context_json=%s\n' "$(jq -c '.spec.containers[0].securityContext' <<< "$agent_json")"
printf '\n'
privileged="$(jq -r '.spec.containers[0].securityContext.privileged' <<< "$agent_json")"
allow_privilege_escalation="$(jq -r '.spec.containers[0].securityContext.allowPrivilegeEscalation' <<< "$agent_json")"
seccomp_type="$(jq -r '.spec.containers[0].securityContext.seccompProfile.type' <<< "$agent_json")"
cap_drop="$(jq -r '.spec.containers[0].securityContext.capabilities.drop[0]' <<< "$agent_json")"
printf 'privileged=%s allowPrivilegeEscalation=%s seccompProfile=%s drop=%s\n' \
  "$privileged" "$allow_privilege_escalation" "$seccomp_type" "$cap_drop"
test "$privileged" = false
test "$allow_privilege_escalation" = false
test "$seccomp_type" = RuntimeDefault
test "$cap_drop" = ALL
capabilities=(BPF NET_ADMIN PERFMON SYS_RESOURCE)
for index in "${!capabilities[@]}"; do
  capability="${capabilities[$index]}"
  cap_add="$(jq -r --argjson index "$index" '.spec.containers[0].securityContext.capabilities.add[$index]' <<< "$agent_json")"
  printf 'capability[%s]=%s\n' "$capability" "$cap_add"
  test "$cap_add" = "$capability"
done

kubectl -n ztap-system port-forward pod/"$agent_pod" 19090:9090 > "$RUNNER_TEMP/ztap-port-forward.log" 2>&1 &
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
    printf 'smoke probe failed: metrics must contain exactly one unsigned %s sample\n' "$metric" >&2
    return 1
  }
  printf '%s\n' "$value"
}
read_counter_metric() {
  local metric="$1"
  local text="$2"
  local value
  if value="$(awk -v specification="$metric" '
    BEGIN {
      part_count = split(specification, parts, "{")
      expected_base = parts[1]
      expected_count = 0
      if (part_count > 1) {
        label_text = parts[2]
        sub(/}$/, "", label_text)
        expected_count = split(label_text, expected_pairs, ",")
        for (i = 1; i <= expected_count; i++) {
          separator = index(expected_pairs[i], "=")
          if (separator == 0) {
            invalid = 1
            continue
          }
          expected_name = substr(expected_pairs[i], 1, separator - 1)
          expected_value = substr(expected_pairs[i], separator + 1)
          if (expected_name == "" || expected_name in expected_labels) {
            invalid = 1
          }
          expected_names[i] = expected_name
          expected_labels[expected_name] = expected_value
        }
      }
    }
    {
      sample=$1
      base=sample
      sub(/\{.*$/, "", base)
    }
    base == expected_base {
      actual_label_text=sample
      sub(/^[^{]*\{/, "", actual_label_text)
      if (actual_label_text == sample) {
        next
      }
      sub(/}$/, "", actual_label_text)
      actual_count=split(actual_label_text, actual_pairs, ",")
      if (actual_count != expected_count) {
        next
      }
      for (name in actual_labels) {
        delete actual_labels[name]
      }
      candidate=1
      for (i = 1; i <= actual_count; i++) {
        separator=index(actual_pairs[i], "=")
        if (separator == 0) {
          candidate=0
          continue
        }
        actual_name=substr(actual_pairs[i], 1, separator - 1)
        actual_value=substr(actual_pairs[i], separator + 1)
        if (actual_name == "" || actual_name in actual_labels) {
          candidate=0
        }
        actual_labels[actual_name]=actual_value
        if (!(actual_name in expected_labels) || expected_labels[actual_name] != actual_value) {
          candidate=0
        }
      }
      for (i = 1; i <= expected_count; i++) {
        if (!(expected_names[i] in actual_labels)) {
          candidate=0
        }
      }
      if (!candidate) {
        next
      }
      matches++
      if (matches > 1) {
        invalid=1
        next
      }
      if (NF != 2 || $2 !~ /^[0-9]+(\.0+)?$/) {
        invalid=1
      } else {
        value=$2
      }
    }
    END {
      if (matches == 0) {
        exit 2
      }
      if (invalid) {
        exit 1
      }
      sub(/\..*$/, "", value)
      print value
    }
  ' <<< "$text")"; then
    printf '%s\n' "$value"
    return 0
  else
    local status=$?
    if [ "$status" -eq 2 ]; then
      return 2
    fi
    printf 'smoke probe failed: metrics must contain exactly one unsigned %s sample\n' "$metric" >&2
    return 1
  fi
}
wait_for_policy_epoch_after() {
  local previous_epoch="$1"
  local current_epoch
  local updated=0
  for ((attempt = 0; attempt < 30; attempt++)); do
    metrics="$(curl --fail --silent http://127.0.0.1:19090/metrics 2>/dev/null || true)"
    if [ -n "$metrics" ] && current_epoch="$(read_uint_metric ztap_active_policy_epoch "$metrics")"; then
      if [ "$current_epoch" -gt "$previous_epoch" ]; then
        updated=1
        break
      fi
    fi
    sleep 2
  done
  if [ "$updated" -ne 1 ]; then
    printf 'smoke probe failed: active policy epoch did not advance beyond %s\n' "$previous_epoch" >&2
    return 1
  fi
  printf '%s\n' "$current_epoch"
}
classified=0
for ((attempt = 0; attempt < 90; attempt++)); do
  metrics="$(curl --fail --silent http://127.0.0.1:19090/metrics 2>/dev/null || true)"
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
  if ! active_policy_epoch="$(read_uint_metric ztap_active_policy_epoch "$metrics")"; then
    exit 1
  fi
  if [ "$agent_enforcing" -eq 1 ] &&
    [ "$enforced" -eq 1 ] &&
    [ "$active_policy_epoch" -ge 1 ]; then
    classified=1
    break
  fi
  sleep 2
done
test "$classified" -eq 1

health="$(curl --fail --silent http://127.0.0.1:19090/healthz)"
jq -e '.status == "ok" and (.version | type == "string") and (.version | length > 0)' <<< "$health" >/dev/null
ready="$(curl --fail --silent http://127.0.0.1:19090/readyz)"
jq -e '.status == "ready" and .ready == true and .enforcing == true and .reason == "ok"' <<< "$ready" >/dev/null
for endpoint in healthz readyz metrics; do
  method_headers="$RUNNER_TEMP/ztap-status-${endpoint}.headers"
  method_status="$(curl --silent --dump-header "$method_headers" --output /dev/null --write-out '%{http_code}' --request POST "http://127.0.0.1:19090/$endpoint")"
  test "$method_status" = 405
  method_allow="$(awk 'tolower($1) == "allow:" { gsub("\r", "", $2); print $2; exit }' "$method_headers")"
  test "$method_allow" = GET
done
printf '%s\n' 'status_endpoints=passed'

printf '%s\n' '--- unselected control must reach the server ---'
control_response="$(kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$server_ip:8080/")"
test "$control_response" = ok
control_service_response="$(kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$service_ip:8080/")"
test "$control_service_response" = ok

printf '%s\n' '--- selected client must be blocked ---'
if kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/"; then
  printf '%s\n' 'selected smoke-client reached the server despite default-deny egress' >&2
  exit 1
fi

observed_deny=0
packet_decisions_blocked_default_deny=
for ((attempt = 0; attempt < 30; attempt++)); do
  metrics="$(curl --fail --silent http://127.0.0.1:19090/metrics 2>/dev/null || true)"
  if packet_decisions_blocked_default_deny="$(read_counter_metric 'ztap_packet_decisions_total{action="blocked",direction="egress",reason="default_deny"}' "$metrics")"; then
    if [ "$packet_decisions_blocked_default_deny" -gt 0 ]; then
      observed_deny=1
      break
    fi
  else
    metric_status=$?
    if [ "$metric_status" -ne 2 ]; then
      exit "$metric_status"
    fi
  fi
  sleep 2
done
test "$observed_deny" -eq 1
printf 'packet_decisions_blocked_default_deny=%s\n' "$packet_decisions_blocked_default_deny"

printf '%s\n' '--- selector peer permits only the backend PodIP, not the Service frontend ---'
previous_policy_epoch="$active_policy_epoch"
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: smoke-client-deny-egress
  namespace: ztap-smoke
spec:
  podSelector:
    matchLabels:
      app: smoke-client
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: smoke-server
      ports:
        - protocol: TCP
          port: 8080
EOF
active_policy_epoch="$(wait_for_policy_epoch_after "$previous_policy_epoch")"
printf 'selector_peer_policy_epoch=%s\n' "$active_policy_epoch"
selector_pod_response="$(kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/")"
test "$selector_pod_response" = ok
printf '%s\n' 'selector_peer_direct_podip=allowed'
if kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$service_ip:8080/"; then
  printf '%s\n' 'selector peer unexpectedly allowed Service ClusterIP access' >&2
  exit 1
fi
printf '%s\n' 'selector_peer_service_clusterip=blocked'

printf '%s\n' '--- explicit ClusterIP ipBlock permits the Service frontend, not the backend PodIP ---'
previous_policy_epoch="$active_policy_epoch"
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: smoke-client-deny-egress
  namespace: ztap-smoke
spec:
  podSelector:
    matchLabels:
      app: smoke-client
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: ${service_ip}/32
      ports:
        - protocol: TCP
          port: 8080
EOF
active_policy_epoch="$(wait_for_policy_epoch_after "$previous_policy_epoch")"
printf 'explicit_clusterip_policy_epoch=%s\nexplicit_clusterip_ipblock_cidr=%s/32\n' \
  "$active_policy_epoch" "$service_ip"
explicit_service_response="$(kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$service_ip:8080/")"
test "$explicit_service_response" = ok
printf '%s\n' 'explicit_clusterip_ipblock_service=allowed'
if kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/"; then
  printf '%s\n' 'explicit ClusterIP ipBlock unexpectedly allowed direct backend PodIP access' >&2
  exit 1
fi
printf '%s\n' 'explicit_clusterip_ipblock_podip=blocked'
printf '%s\n' 'capability-only DaemonSet attached and enforced the smoke policy'
) 2>&1 | tee capability-agent-smoke.txt

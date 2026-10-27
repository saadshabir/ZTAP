#!/usr/bin/env bash
set -euo pipefail
(
set -euo pipefail
fixture="$RUNNER_TEMP/phase5-reference-fixture.yaml"
reference_pods=250
reference_policies=25
test $((reference_pods % reference_policies)) -eq 0
pods_per_policy=$((reference_pods / reference_policies))
peers_per_policy=10
reference_rules=$((reference_policies * pods_per_policy * peers_per_policy))
test "$reference_rules" -eq 2500
{
  cat <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ztap-performance
EOF
  for ((index = 0; index < reference_pods; index++)); do
    bucket=$((index / pods_per_policy))
    printf '%s\n' '---'
    printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: reference-pod-%03d\n  namespace: ztap-performance\n  labels:\n    phase5-bucket: "%02d"\nspec:\n  containers:\n    - name: workload\n      image: busybox:1.36.1\n      imagePullPolicy: IfNotPresent\n      command: ["sh", "-c", "sleep 3600"]\n      securityContext:\n        allowPrivilegeEscalation: false\n        capabilities:\n          drop: [NET_RAW]\n' \
      "$index" "$bucket"
  done
  for ((policy = 0; policy < reference_policies; policy++)); do
    printf '%s\n' '---'
    printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: reference-policy-%02d\n  namespace: ztap-performance\n  labels:\n    phase5-bucket: "%02d"\nspec:\n  podSelector:\n    matchLabels:\n      phase5-bucket: "%02d"\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n' "$policy" "$policy" "$policy"
    for ((peer = 0; peer < peers_per_policy; peer++)); do
      printf '        - ipBlock:\n            cidr: 198.18.%d.%d/32\n' "$policy" "$peer"
    done
    printf '%s\n' '      ports:' '        - protocol: TCP' '          port: 10000'
  done
} > "$fixture"
policy_fixture="$RUNNER_TEMP/phase5-reference-policies.yaml"
awk '/^apiVersion: networking\.k8s\.io\/v1$/ { seen=1 } seen { print }' \
  "$fixture" > "$policy_fixture"
test "$(grep -c '^kind: NetworkPolicy$' "$policy_fixture")" -eq "$reference_policies"
docker run --rm -i ztap:dev validate --file - < "$policy_fixture"
kubectl apply --dry-run=client -f "$fixture" >/dev/null
test "$(grep -c '^kind: Pod$' "$fixture")" -eq "$reference_pods"
test "$(grep -c '^kind: NetworkPolicy$' "$fixture")" -eq "$reference_policies"
test "$(grep -c '^[[:space:]]*cidr: 198\.18\.' "$fixture")" -eq "$((reference_policies * peers_per_policy))"
printf 'offline_fixture_shape=pods=%s policies=%s compiled_rules=%s\n' \
  "$reference_pods" "$reference_policies" "$reference_rules"
cp "$fixture" phase5-reference-fixture.yaml
kubectl apply -f "$fixture"
kubectl -n ztap-performance wait --for=condition=Ready pod --all --timeout=300s
test "$(kubectl -n ztap-performance get pods --no-headers | wc -l | tr -d ' ')" -eq "$reference_pods"
test "$(kubectl -n ztap-performance get networkpolicies --no-headers | wc -l | tr -d ' ')" -eq "$reference_policies"
live_pods="$(kubectl -n ztap-performance get pods -o json)"
jq -e --argjson expected_pods "$reference_pods" --argjson expected_policies "$reference_policies" '
  . as $root
  | ($root.items | length == $expected_pods)
  and (
    $root.items
    | (map(.metadata.name) | sort) ==
      ([range(0; $expected_pods) | "reference-pod-\(("000" + tostring)[-3:])"] | sort)
  )
  and (
    $root.items
    | all(.[];
        .status.phase == "Running" and
        any(.status.conditions[]?; .type == "Ready" and .status == "True") and
        (.status.containerStatuses | length) == 1 and
        .status.containerStatuses[0].ready == true
      )
  )
  and (
    $root.items
    | (map(.metadata.uid) | map(select(type == "string" and length > 0)) | unique | length) == $expected_pods
  )
  and (
    $root.items
    | (map(.metadata.labels["phase5-bucket"]) | sort | group_by(.) | all(.[]; length == 10))
  )
  and (
    $root.items
    | (map(.metadata.labels["phase5-bucket"]) | unique | sort) ==
      ([range(0; $expected_policies) | (("00" + tostring)[-2:])] | sort)
  )
' <<< "$live_pods" >/dev/null
live_policies="$(kubectl -n ztap-performance get networkpolicies -o json)"
jq -e --argjson expected_policies "$reference_policies" --argjson expected_peers "$peers_per_policy" '
  . as $root
  | ($root.items | length == $expected_policies)
  and (
    $root.items
    | (map(.metadata.name) | sort) ==
      ([range(0; $expected_policies) | "reference-policy-\(("00" + tostring)[-2:])"] | sort)
  )
  and (
    $root.items
    | all(.[];
        (.metadata.labels["phase5-bucket"] | type == "string") and
        (.spec | keys | sort == ["egress", "podSelector", "policyTypes"]) and
        (.spec.policyTypes == ["Egress"]) and
        (.spec.podSelector | keys | sort == ["matchLabels"]) and
        (.spec.podSelector.matchLabels | keys | sort == ["phase5-bucket"]) and
        (.spec.podSelector.matchLabels["phase5-bucket"] == .metadata.labels["phase5-bucket"]) and
        (.spec.egress | length == 1) and
        (.spec.egress[0] | keys | sort == ["ports", "to"]) and
        (.spec.egress[0].ports |
          (length == 1 and
           .[0].protocol == "TCP" and
           .[0].port == 10000 and
           (.[0] | keys | sort == ["port", "protocol"]))) and
        (.spec.egress[0].to |
          (length == $expected_peers and
           all(.[];
             (keys | sort == ["ipBlock"]) and
             (.ipBlock | keys | sort == ["cidr"]) and
             (.ipBlock.cidr | test("^198\\.18\\.[0-9]+\\.[0-9]+/32$")))))
      )
  )
' <<< "$live_policies" >/dev/null
printf '%s\n' 'fixture_live_shape=verified'
printf 'fixture_shape=pods=%s policies=%s pods_per_policy=%s peers_per_policy=%s compiled_rules=%s\n' \
  "$reference_pods" "$reference_policies" "$pods_per_policy" "$peers_per_policy" "$reference_rules"
kubectl -n ztap-performance get pods -o wide
kubectl -n ztap-performance get networkpolicies
) 2>&1 | tee capability-agent-reference-fixture.txt

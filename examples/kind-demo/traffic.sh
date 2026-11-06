#!/usr/bin/env bash
# Exercise the same client and server before and after installing NetworkPolicy.
set -euo pipefail
cd "$(dirname "$0")/../.."

kubectl apply -f examples/kind-demo/workloads.yaml
kubectl -n ztap-demo wait --for=condition=Ready pod/server pod/client --timeout=180s
server="$(kubectl -n ztap-demo get pod server -o jsonpath='{.status.podIP}')"
test -n "$server"
agent="$(kubectl -n ztap-system get pods -l app=ztap-agent -o jsonpath='{.items[0].metadata.name}')"

request() {
  kubectl -n ztap-demo exec client -- sh -c '
    if reply="$(wget -qO- -T 2 "http://$1:$2/")"; then
      printf "%s\n" "$reply"
    else
      printf "unreachable\n"
    fi
  ' sh "$server" "$1"
}

denied_packets() {
  kubectl get --raw "/api/v1/namespaces/ztap-system/pods/$agent:9090/proxy/metrics" |
    awk '/^ztap_packet_decisions_total\{action="blocked",direction="egress",reason="default_deny"\} / { count = $2 } END { printf "%.0f\n", count }'
}

for port in 8080 8081; do
  for ((attempt = 0; attempt < 20; attempt++)); do
    reply="$(request "$port")"
    if [ "$reply" = demo-ok ]; then
      break
    fi
    sleep 1
  done
  test "$reply" = demo-ok
  printf 'Before policy: TCP %s allowed (%s)\n' "$port" "$reply"
done

before="$(denied_packets)"
kubectl apply -f examples/kind-demo/policies.yaml
for ((attempt = 0; attempt < 20; attempt++)); do
  allowed="$(request 8080)"
  denied="$(request 8081)"
  after="$(denied_packets)"
  if [ "$allowed" = demo-ok ] && [ "$denied" = unreachable ] && [ "$after" -gt "$before" ]; then
    printf 'After policy: TCP 8080 allowed (%s)\n' "$allowed"
    printf 'After policy: TCP 8081 blocked (ZTAP egress default-deny counter %s -> %s)\n' "$before" "$after"
    exit 0
  fi
  sleep 1
done
printf 'Expected TCP 8080 allowed and TCP 8081 denied, got %s / %s (ZTAP deny counter %s -> %s)\n' \
  "$allowed" "$denied" "$before" "$after" >&2
exit 1

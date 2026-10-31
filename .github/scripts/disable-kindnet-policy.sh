#!/usr/bin/env bash
set -euo pipefail
policy_count="$(kubectl get networkpolicies.networking.k8s.io --all-namespaces -o json | jq '.items | length')"
test "$policy_count" -eq 0
kubectl -n kube-system rollout status daemonset/kindnet --timeout=180s
nodes=()
cni_configs=()
for node in $(kind get nodes --name ztap); do
  nodes+=("$node")
  cni_config="$(docker exec "$node" find /etc/cni/net.d -maxdepth 1 -type f \
    \( -name '*.conf' -o -name '*.conflist' \) -print -quit)"
  test -n "$cni_config"
  cni_configs+=("$cni_config")
done
test "${#nodes[@]}" -gt 0
kubectl -n kube-system delete daemonset kindnet --wait=true
kindnet_pods=1
for ((attempt = 0; attempt < 180; attempt++)); do
  kindnet_pods="$(kubectl -n kube-system get pods -o json | jq '[
    .items[]
    | select(any(.metadata.ownerReferences[]?; .kind == "DaemonSet" and .name == "kindnet"))
  ] | length')"
  if [ "$kindnet_pods" -eq 0 ]; then
    break
  fi
  sleep 1
done
test "$kindnet_pods" -eq 0
for index in "${!nodes[@]}"; do
  docker exec "${nodes[$index]}" test -s "${cni_configs[$index]}"
  kubectl wait --for=condition=Ready "node/${nodes[$index]}" --timeout=60s
  printf 'kindnet_cni_config_retained[%s]=%s\n' "${nodes[$index]}" "${cni_configs[$index]}"
done
printf 'kindnet_networkpolicy_controller=disabled\n'
printf 'ZTAP_KINDNET_NETWORKPOLICY_DISABLED=1\n' >> "$GITHUB_ENV"

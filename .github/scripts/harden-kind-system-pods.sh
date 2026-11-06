#!/usr/bin/env bash
# Harden stock kind workloads in a disposable cluster.
set -euo pipefail

wait_for_terminating_pods() {
  local namespace="$1" selector="$2" terminating pod
  terminating="$(kubectl -n "$namespace" get pods -l "$selector" -o json |
    jq -r '.items[] | select(.metadata.deletionTimestamp != null) | "pod/" + .metadata.name')"
  if [ -n "$terminating" ]; then
    while IFS= read -r pod; do
      kubectl -n "$namespace" wait --for=delete "$pod" --timeout=180s
    done <<< "$terminating"
  fi
}

# Harden pre-existing system workloads before the packet-socket audit.
# Rollout status counts active replicas, so old Pods may still be terminating.
kubectl -n kube-system patch deployment coredns --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"coredns","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n kube-system rollout status deployment/coredns --timeout=180s
wait_for_terminating_pods kube-system k8s-app=kube-dns
kubectl -n local-path-storage patch deployment local-path-provisioner --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"local-path-provisioner","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n local-path-storage rollout status deployment/local-path-provisioner --timeout=180s
wait_for_terminating_pods local-path-storage app=local-path-provisioner

#!/usr/bin/env bash
set -euo pipefail
multi_node="${ZTAP_KIND_MULTI_NODE:-0}"
test "$multi_node" = 0 || test "$multi_node" = 1
cat > "$RUNNER_TEMP/kind-config.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
      SystemdCgroup = true
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: KubeletConfiguration
        apiVersion: kubelet.config.k8s.io/v1beta1
        cgroupDriver: systemd
        maxPods: 300
      - |
        kind: ClusterConfiguration
        apiVersion: kubeadm.k8s.io/v1beta4
        controllerManager:
          extraArgs:
            - name: node-cidr-mask-size-ipv4
              value: "23"
EOF
if [ "$multi_node" = 0 ]; then
  cat >> "$RUNNER_TEMP/kind-config.yaml" <<'EOF'
    extraMounts:
      - hostPath: /sys/fs/bpf
        containerPath: /sys/fs/bpf
        readOnly: false
        propagation: HostToContainer
EOF
else
  cat >> "$RUNNER_TEMP/kind-config.yaml" <<'EOF'
  - role: worker
EOF
fi
kind create cluster --name ztap --image kindest/node:v1.36.4 \
  --config "$RUNNER_TEMP/kind-config.yaml" --wait 180s
if [ "$multi_node" = 1 ]; then
  # Each agent owns /sys/fs/bpf/ztap. Sharing the host mount between kind
  # containers would make the agents contend for the same pins and links.
  for node in $(kind get nodes --name ztap); do
    docker exec "$node" mount -t bpf bpffs /sys/fs/bpf
    test "$(docker exec "$node" stat -f -c %T /sys/fs/bpf)" = bpf_fs
  done
fi

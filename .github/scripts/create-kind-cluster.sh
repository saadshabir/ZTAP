#!/usr/bin/env bash
set -euo pipefail
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
    extraMounts:
      - hostPath: /sys/fs/bpf
        containerPath: /sys/fs/bpf
        readOnly: false
        propagation: HostToContainer
EOF
kind create cluster --name ztap --image kindest/node:v1.36.4 \
  --config "$RUNNER_TEMP/kind-config.yaml" --wait 180s

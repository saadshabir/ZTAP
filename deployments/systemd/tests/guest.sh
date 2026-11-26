#!/usr/bin/env bash
set -euo pipefail

grep -Fxq 'ztap test VM' /etc/ztap-disposable-reboot-test
fixture=/usr/local/libexec/ztap-reboot-guest
kubelet=/usr/local/libexec/ztap-reboot-fixture/kubelet
layout_failure=/etc/systemd/system/kubelet.service.d/90-test-layout.conf
partial_failure=/etc/systemd/system/ztap-boot-guard.service.d/90-test-partial.conf
binary=/usr/local/libexec/ztap-reboot-enforcer.test

if [[ ${0##*/} == kubelet ]]; then
  set -- probe kubelet kubelet.slice/kubelet-kubepods.slice
fi

case "$1" in
  prepare)
    for service in containerd kubelet; do
      if [[ $(systemctl show "$service.service" -p LoadState --value) != not-found ]]; then
        grep -Fxq 'Description=ZTAP reboot test runtime' "/etc/systemd/system/$service.service"
      fi
    done
    install -m 0755 "$2/ztap" /usr/local/bin/ztap
    install -D -m 0755 "$2/enforcer.test" "$binary"
    install -D -m 0755 "$0" "$fixture"
    install -d "$(dirname "$kubelet")"
    ln -sf "$fixture" "$kubelet"
    for unit in kubepods.slice kubelet-kubepods.slice ztap-boot-guard.service; do
      install -m 0644 "$2/systemd/$unit" "/etc/systemd/system/$unit"
    done
    for service in containerd kubelet; do
      install -D -m 0644 "$2/systemd/$service.service.d/50-ztap-boot-guard.conf" \
        "/etc/systemd/system/$service.service.d/50-ztap-boot-guard.conf"
      command="$fixture probe containerd kubepods.slice"
      if [[ $service == kubelet ]]; then
        command="$kubelet --cgroup-driver=systemd --cgroups-per-qos=true --cgroup-root=/kubelet"
      fi
      cat > "/etc/systemd/system/$service.service" <<EOF
[Unit]
Description=ZTAP reboot test runtime

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$command

[Install]
WantedBy=multi-user.target
EOF
    done
    rm -f "$layout_failure" "$partial_failure"
    systemctl daemon-reload
    systemctl enable containerd.service kubelet.service
    ;;
  probe)
    service=$2
    export ZTAP_BOOT_TEST_PARENT="/sys/fs/cgroup/$3"
    touch "/run/ztap-reboot-$service.started"
    ZTAP_BOOT_TEST_PRIVATE=0 "$binary" -test.run '^TestLinuxBootGuardFirstTraffic$' -test.v
    # The inner shell receives the binary as an argument.
    # shellcheck disable=SC2016
    ZTAP_BOOT_TEST_PRIVATE=1 unshare --net sh -ec 'ip link set lo up
      exec "$1" -test.run "^TestLinuxBootGuardFirstTraffic$" -test.v' sh "$binary"
    cat /proc/sys/kernel/random/boot_id > "/run/ztap-reboot-$service.ok"
    ;;
  verify)
    deadline=$((SECONDS + 90))
    while systemctl list-jobs --no-legend --no-pager ztap-boot-guard.service containerd.service kubelet.service |
          grep -qE '^[[:space:]]*[0-9]+[[:space:]]'; do
      if (( SECONDS >= deadline )); then
        printf 'Startup jobs still pending for the guard or runtime services\n' >&2
        exit 1
      fi
      sleep 1
    done
    journal=$(journalctl -b --no-pager -u ztap-boot-guard.service -u containerd.service -u kubelet.service)
    printf '%s\n' "$journal"
    boot=$(cat /proc/sys/kernel/random/boot_id)
    if [[ $2 == protected ]]; then
      systemctl is-active --quiet ztap-boot-guard.service
      guard_started=$(systemctl show ztap-boot-guard.service -p ActiveEnterTimestampMonotonic --value)
      for service in containerd kubelet; do
        systemctl is-active --quiet "$service.service"
        [[ $(cat "/run/ztap-reboot-$service.ok") == "$boot" ]]
        started=$(systemctl show "$service.service" -p ExecMainStartTimestampMonotonic --value)
        (( guard_started > 0 && started >= guard_started ))
      done
    else
      systemctl is-failed --quiet ztap-boot-guard.service
      case "$2" in
        layout-rejected)
          grep -Fq 'the final kubelet argument must be --cgroup-root=/ or --cgroup-root=/kubelet' <<< "$journal"
          ;;
        partial-pins)
          grep -Fq 'validate map pin active_config' <<< "$journal"
          [[ -e /sys/fs/bpf/ztap/durable_v3 ]]
          ;;
        *) exit 2 ;;
      esac
      for service in containerd kubelet; do
        if systemctl is-active --quiet "$service.service"; then
          printf 'Runtime service %s started after the guard failed\n' "$service" >&2
          exit 1
        fi
        [[ ! -e /run/ztap-reboot-$service.started ]]
        grep -Fq "Job $service.service/start failed with result 'dependency'" <<< "$journal"
      done
    fi
    printf 'boot=%s kernel=%s result=%s\n' "$boot" "$(uname -r)" "$2"
    ;;
  break-layout)
    cat > "$layout_failure" <<EOF
[Service]
ExecStart=
ExecStart=$kubelet --cgroup-driver=systemd --cgroups-per-qos=true --cgroup-root=/unguarded
EOF
    ;;
  repair-layout)
    rm -f "$layout_failure"
    ;;
  break-partial)
    install -d "$(dirname "$partial_failure")"
    cat > "$partial_failure" <<EOF
[Service]
ExecStartPre=$fixture seed-partial
EOF
    ;;
  seed-partial)
    [[ ! -e /sys/fs/bpf/ztap/durable_v3 ]]
    status=0
    ZTAP_BOOT_TEST_PARTIAL_ROOT=/sys/fs/bpf "$binary" -test.run '^TestLinuxBootGuardPartialPublication$' || status=$?
    [[ $status == 86 && -e /sys/fs/bpf/ztap/durable_v3 ]]
    ;;
  repair-partial)
    rm -f "$partial_failure"
    systemctl daemon-reload
    /usr/local/bin/ztap cleanup
    systemctl start containerd.service kubelet.service
    ;;
  *) exit 2 ;;
esac

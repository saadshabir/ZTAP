#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
  printf 'Usage: %s SSH_TARGET LINUX_ZTAP_BINARY LINUX_ENFORCER_TEST_BINARY\n' "$0" >&2
  exit 2
fi

target=$1
test_dir=$(cd -- "$(dirname -- "$0")" && pwd)
connect=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3)
if [[ -n ${ZTAP_REBOOT_SSH_CONFIG:-} ]]; then
  connect+=(-F "$ZTAP_REBOOT_SSH_CONFIG")
fi

remote() { "${connect[@]}" -- "$target" "$@"; }
remote 'sudo grep -Fxq "ztap test VM" /etc/ztap-disposable-reboot-test'

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cp -- "$2" "$stage/ztap"
cp -- "$3" "$stage/enforcer.test"
cp -R -- "$test_dir/.." "$stage/systemd"
# The archive is unpacked into a temporary directory on the guest.
# shellcheck disable=SC2016
tar -C "$stage" -cf - . | remote 'set -eu
  dir=$(mktemp -d)
  trap '\''rm -rf -- "$dir"'\'' EXIT
  tar -C "$dir" -xf -
  sudo bash "$dir/systemd/tests/guest.sh" prepare "$dir"'

boot_id() { remote 'cat /proc/sys/kernel/random/boot_id'; }

reboot_and_verify() {
  local previous current deadline
  previous=$(boot_id)
  remote 'sudo systemctl reboot' || true
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    if current=$(boot_id 2>/dev/null) && [[ -n $current && $current != "$previous" ]]; then
      remote sudo /usr/local/libexec/ztap-reboot-guest verify "$1"
      return
    fi
    sleep 2
  done
  printf 'No new Linux boot ID after reboot request\n' >&2
  return 1
}

reboot_and_verify protected
remote 'sudo /usr/local/libexec/ztap-reboot-guest break-layout'
reboot_and_verify layout-rejected
remote 'sudo /usr/local/libexec/ztap-reboot-guest repair-layout'
remote 'sudo /usr/local/libexec/ztap-reboot-guest break-partial'
reboot_and_verify partial-pins
partial_boot=$(boot_id)
remote 'sudo /usr/local/libexec/ztap-reboot-guest repair-partial'
[[ $(boot_id) == "$partial_boot" ]]
remote 'sudo /usr/local/libexec/ztap-reboot-guest verify protected'

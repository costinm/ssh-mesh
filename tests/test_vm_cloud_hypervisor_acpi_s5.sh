#!/usr/bin/env bash
set -euo pipefail

if [[ ! -e /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "skipping cloud-hypervisor ACPI/S5 diagnostic; /dev/kvm is not usable"
  exit 0
fi

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

POD="${POD:-chs5}"
VM_STATE="${VM_STATE:-${PROJECT_ROOT}/target/vm/${POD}}"
SRC="${SRC:-${VM_STATE}/src}"
PROFILE="${PROFILE:-${PROJECT_ROOT}/target/vm/vm-cloud-profile}"
SERIAL_LOG="${SERIAL_LOG:-${VM_STATE}/run/serial.log}"
TIMEOUT="${TIMEOUT:-90}"
S5_EXIT_WAIT="${S5_EXIT_WAIT:-20}"
POWEROFF_ARGS="${POWEROFF_ARGS:--f}"

rm -rf "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"
mkdir -p "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"

cat > "${SRC}/initos-pod" <<'EOF'
#!/opt/busybox/bin/sh
set -eu

bb=/opt/busybox/bin/busybox

section() {
  echo
  echo "=== $* ==="
}

show_path() {
  p="$1"
  section "$p"
  if [ -e "$p" ]; then
    ls -la "$p" 2>&1 || true
  else
    echo "missing"
  fi
}

find_path() {
  p="$1"
  depth="$2"
  section "find $p -maxdepth $depth"
  if [ -e "$p" ]; then
    find "$p" -maxdepth "$depth" -print 2>&1 || true
  else
    echo "missing"
  fi
}

case "${1:-start}" in
  start)
    echo "CH-S5-DIAG: begin"

    section "kernel"
    uname -a 2>&1 || true
    cat /proc/cmdline 2>&1 || true

    section "mounts"
    cat /proc/mounts 2>&1 || true

    show_path /sys
    show_path /sys/firmware
    show_path /sys/firmware/acpi
    show_path /sys/firmware/acpi/tables
    show_path /sys/bus/acpi
    show_path /sys/bus/acpi/devices
    show_path /sys/module/acpi
    show_path /sys/power

    find_path /sys/firmware/acpi 3
    find_path /sys/bus/acpi/devices 2
    find_path /sys/module/acpi 2

    section "/sys/power/state"
    cat /sys/power/state 2>&1 || true

    section "/proc/iomem acpi"
    grep -i acpi /proc/iomem 2>&1 || true

    section "/proc/interrupts acpi|button|rtc"
    grep -Ei 'acpi|button|rtc' /proc/interrupts 2>&1 || true

    section "/proc/devices"
    cat /proc/devices 2>&1 || true

    section "/dev snapshot"
    find /dev -maxdepth 2 -print 2>&1 || true

    section "dmesg acpi|s5|power|reboot"
    dmesg 2>&1 | grep -Ei 'acpi|s5|power|reboot|shutdown|pnp|rtc' || true

    section "attempt kernel poweroff"
    echo "CH-S5-DIAG: sync"
    sync
    echo "CH-S5-DIAG: busybox poweroff __POWEROFF_ARGS__"
    "$bb" poweroff __POWEROFF_ARGS__

    echo "CH-S5-DIAG: poweroff returned with status $?"
    section "fallback sleep"
    while true; do
      "$bb" sleep 60
    done
    ;;
  *)
    echo "unsupported command: $1" >&2
    exit 1
    ;;
esac
EOF
sed -i "s|__POWEROFF_ARGS__|${POWEROFF_ARGS}|g" "${SRC}/initos-pod"
chmod 755 "${SRC}/initos-pod"

if [[ ! -x "${PROFILE}/bin/initos-vrun" ]]; then
  nix build "path:${PROJECT_ROOT}/linux#vm-cloud-profile" -o "${PROFILE}"
fi

env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  vm_mem="${vm_mem:-512M}" vm_cpu="${vm_cpu:-1}" vm_balloon="${vm_balloon:-0}" \
  NO_NET=1 SERIAL_LOG="${SERIAL_LOG}" \
  "${PROFILE}/bin/initos-vrun" start

deadline=$((SECONDS + TIMEOUT))
while [[ $SECONDS -lt $deadline ]]; do
  if [[ -f "${SERIAL_LOG}" ]] && grep -q "CH-S5-DIAG: busybox poweroff ${POWEROFF_ARGS}" "${SERIAL_LOG}"; then
    break
  fi
  sleep 0.2
done

if [[ ! -f "${SERIAL_LOG}" ]] || ! grep -q "CH-S5-DIAG: busybox poweroff ${POWEROFF_ARGS}" "${SERIAL_LOG}"; then
  echo "cloud-hypervisor ACPI/S5 diagnostic did not reach the poweroff step" >&2
  if [[ -f "${SERIAL_LOG}" ]]; then
    cat "${SERIAL_LOG}" >&2
  fi
  env POD="${POD}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
    "${PROFILE}/bin/initos-vrun" vmkill 2>/dev/null || true
  exit 1
fi

result="no-vm-pid"
pid_file="${VM_STATE}/run/vm.pid"
if [[ -f "${pid_file}" ]]; then
  vm_pid="$(cat "${pid_file}")"
  exit_deadline=$((SECONDS + S5_EXIT_WAIT))
  while [[ $SECONDS -lt $exit_deadline ]] && kill -0 "${vm_pid}" 2>/dev/null; do
    sleep 0.2
  done
  if kill -0 "${vm_pid}" 2>/dev/null; then
    result="still-running"
  else
    result="exited"
  fi
fi

echo "cloud-hypervisor ACPI/S5 diagnostic result: ${result}"
echo "serial log: ${SERIAL_LOG}"

if [[ "${result}" = "still-running" ]]; then
  env POD="${POD}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
    "${PROFILE}/bin/initos-vrun" vmkill 2>/dev/null || true
else
  rm -f "${VM_STATE}/run/vm.pid" "${VM_STATE}/run/virtiofsd.pid" "${VM_STATE}/run/virtiofs.sock.pid"
  rm -f "${VM_STATE}/run/ch.sock" "${VM_STATE}/run/serial.socket" "${VM_STATE}/run/virtiofs.sock"
fi

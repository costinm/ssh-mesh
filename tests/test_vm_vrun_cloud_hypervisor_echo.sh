#!/usr/bin/env bash
set -euo pipefail

if [[ ! -e /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "skipping cloud-hypervisor VM test; /dev/kvm is not usable"
  exit 0
fi

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

POD="${POD:-echoch}"
VM_STATE="${VM_STATE:-${PROJECT_ROOT}/target/vm/${POD}}"
SRC="${SRC:-${VM_STATE}/src}"
NIX_PROFILE="${NIX_PROFILE:-}"
if [[ -z "${NIX_PROFILE}" ]]; then
  NIX_PROFILE="${PROJECT_ROOT}/target/nix/profile"
fi
PROFILE="${PROFILE:-${NIX_PROFILE}}"
SERIAL_LOG="${VM_STATE}/run/serial.log"
PHASES="${VM_STATE}/run/phases.tsv"

now_ns() {
  date +%s%N
}

elapsed_ms() {
  local start_ns="$1"
  local end_ns="$2"
  echo $(((end_ns - start_ns) / 1000000))
}

rm -rf "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"
mkdir -p "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"

cat > "${SRC}/initos-pod" <<'EOF'
#!/opt/busybox/bin/sh
set -eu

case "${1:-start}" in
	  start)
	    echo "hi"
	    echo "hi" > /dev/kmsg 2>/dev/null || true
    ;;
  *)
    echo "unsupported command: $1" >&2
    exit 1
    ;;
esac
EOF
chmod 755 "${SRC}/initos-pod"

if [[ ! -x "${PROFILE}/bin/initos-vrun" ]]; then
  echo "Error: VM profile not found at ${PROFILE}. Run scripts/build.sh test vm_vrun_cloud_hypervisor_echo." >&2
  exit 1
fi

start_ns="$(now_ns)"
env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  vm_mem="${vm_mem:-512M}" vm_cpu="${vm_cpu:-1}" vm_balloon="${vm_balloon:-0}" NO_NET=1 SERIAL_LOG="${SERIAL_LOG}" \
  "${PROFILE}/bin/initos-vrun" start > "${SERIAL_LOG}" 2>&1
launched_ns="$(now_ns)"

deadline=$((SECONDS + ${TIMEOUT:-90}))
printed=0
while [[ $SECONDS -lt $deadline ]]; do
  if [[ -f "${SERIAL_LOG}" ]] && tr -d '\r' < "${SERIAL_LOG}" | grep -qx "hi"; then
    printed=1
    hi_ns="$(now_ns)"
    break
  fi
  sleep 0.1
done

if [[ "${printed}" != 1 ]]; then
  env POD="${POD}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
    "${PROFILE}/bin/initos-vrun" vmkill 2>/dev/null || true
  if [[ -f "${SERIAL_LOG}" ]]; then
    cat "${SERIAL_LOG}" >&2
  fi
  echo "cloud-hypervisor one-shot echo was not printed to the serial console" >&2
  exit 1
fi

pid_file="${VM_STATE}/run/vm.pid"
exit_ns=""
if [[ -f "${pid_file}" ]]; then
  vm_pid="$(cat "${pid_file}")"
  exit_deadline=$((SECONDS + ${CH_EXIT_WAIT:-30}))
  while [[ $SECONDS -lt $exit_deadline ]] && kill -0 "${vm_pid}" 2>/dev/null; do
    sleep 0.1
  done
  if kill -0 "${vm_pid}" 2>/dev/null; then
    echo "cloud-hypervisor did not exit after guest poweroff" >&2
    env POD="${POD}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
      "${PROFILE}/bin/initos-vrun" vmkill 2>/dev/null || true
    exit 1
  fi
  exit_ns="$(now_ns)"
fi

if [[ -n "${exit_ns}" ]]; then
  {
    printf 'phase\tms\n'
    printf 'launch_return\t%s\n' "$(elapsed_ms "${start_ns}" "${launched_ns}")"
    printf 'hi_observed\t%s\n' "$(elapsed_ms "${start_ns}" "${hi_ns}")"
    printf 'exit_observed\t%s\n' "$(elapsed_ms "${start_ns}" "${exit_ns}")"
    printf 'hi_to_exit\t%s\n' "$(elapsed_ms "${hi_ns}" "${exit_ns}")"
  } > "${PHASES}"
  cat "${PHASES}"
fi

rm -f "${VM_STATE}/run/vm.pid" "${VM_STATE}/run/virtiofsd.pid" "${VM_STATE}/run/virtiofs.sock.pid"
rm -f "${VM_STATE}/run/ch.sock" "${VM_STATE}/run/serial.socket" "${VM_STATE}/run/virtiofs.sock"

echo "cloud-hypervisor one-shot echo test passed"

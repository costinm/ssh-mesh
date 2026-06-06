#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

VM_STATE="${PROJECT_ROOT}/target/vm/stop-cleanup"
RUN="${VM_STATE}/run"
rm -rf "${VM_STATE}"
mkdir -p "${RUN}"

sleep 300 &
vm_pid=$!
sleep 300 &
virtiofsd_pid=$!

cleanup() {
  kill "${vm_pid}" "${virtiofsd_pid}" 2>/dev/null || true
}
trap cleanup EXIT

echo "${vm_pid}" > "${RUN}/vm.pid"
echo "${virtiofsd_pid}" > "${RUN}/virtiofsd.pid"
echo 999999 > "${RUN}/virtiofs.sock.pid"
touch "${RUN}/ch.sock" "${RUN}/serial.socket" "${RUN}/virtiofs.sock"

env POD=stopcleanup WORK="${RUN}" IMGDIR="${VM_STATE}/images" VIRT="${VM_STATE}/missing" \
  linux/bin/vrun stop
wait "${vm_pid}" 2>/dev/null || true
wait "${virtiofsd_pid}" 2>/dev/null || true

for pid_file in vm.pid virtiofsd.pid virtiofs.sock.pid; do
  if [[ -e "${RUN}/${pid_file}" ]]; then
    echo "${pid_file} was not removed" >&2
    exit 1
  fi
done

for sock in ch.sock serial.socket virtiofs.sock; do
  if [[ -e "${RUN}/${sock}" ]]; then
    echo "${sock} was not removed" >&2
    exit 1
  fi
done

if kill -0 "${vm_pid}" 2>/dev/null || kill -0 "${virtiofsd_pid}" 2>/dev/null; then
  echo "recorded helper processes are still alive" >&2
  exit 1
fi

trap - EXIT
echo "vrun stop cleanup test passed"

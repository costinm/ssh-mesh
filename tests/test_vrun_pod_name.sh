#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

VM_STATE="${PROJECT_ROOT}/target/vm/pod-name"
mkdir -p "${VM_STATE}/run" "${VM_STATE}/images"

env POD=abcdefghijkl VIRT="${VM_STATE}/missing" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  sidecar/bin/vrun start 2>"${VM_STATE}/ok.err" && {
    echo "expected missing VM artifact error for 12-byte POD" >&2
    exit 1
  }
if grep -q "POD is too long" "${VM_STATE}/ok.err"; then
  echo "12-byte POD should fit vm-\$POD within the 15-byte interface limit" >&2
  exit 1
fi

env POD=abcdefghijklm VIRT="${VM_STATE}/missing" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  linux/bin/vrun start 2>"${VM_STATE}/bad.err" && {
    echo "expected 13-byte POD to fail" >&2
    exit 1
  }
grep -q "Linux network interface names are limited to 15 bytes" "${VM_STATE}/bad.err"

echo "vrun pod-name limit test passed"

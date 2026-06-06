#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

POD="${POD:-echo-hi-qemu-test}"
VM_STATE="${VM_STATE:-${PROJECT_ROOT}/target/vm/${POD}}"
SRC="${SRC:-${VM_STATE}/src}"
LOG="${VM_STATE}/qemu.log"
PROFILE="${PROFILE:-${PROJECT_ROOT}/target/vm/vm-cloud-profile}"

rm -rf "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"
mkdir -p "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"

cat > "${SRC}/initos-pod" <<'EOF'
#!/opt/busybox/bin/sh
set -eu

case "${1:-start}" in
	  start)
	    echo "hi from qemu"
	    echo "hi from qemu" > /dev/kmsg 2>/dev/null || true
    ;;
  *)
    echo "unsupported command: $1" >&2
    exit 1
    ;;
esac
EOF
chmod 755 "${SRC}/initos-pod"

nix build "path:${PROJECT_ROOT}/linux#vm-cloud-profile" -o "${PROFILE}"

timeout --foreground "${TIMEOUT:-90}s" \
  env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  "${PROFILE}/bin/initos-vrun" qemuvirt 2>&1 | tee "${LOG}"

grep -q "hi from qemu" "${LOG}"
echo "qemu one-shot echo test passed"

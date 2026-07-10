#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

POD="${POD:-echo-hi-qemu-test}"
VM_STATE="${VM_STATE:-${PROJECT_ROOT}/target/vm/${POD}}"
SRC="${SRC:-${VM_STATE}/src}"
LOG="${VM_STATE}/qemu.log"
NIX_PROFILE="${NIX_PROFILE:-}"
if [[ -z "${NIX_PROFILE}" ]]; then
  if [[ -d "${PROJECT_ROOT}/target/nix/profile" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix/profile"
  elif [[ -d "${PROJECT_ROOT}/target/nix" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix"
  else
    NIX_PROFILE="/ws/initos/target/nix"
  fi
fi
PROFILE="${PROFILE:-${NIX_PROFILE}}"
VRUN="${VRUN:-}"
if [[ -z "${VRUN}" ]]; then
  if [[ -x "${PROJECT_ROOT}/target/dist/opt/ssh-mesh/bin/initos-vrun" ]]; then
    VRUN="${PROJECT_ROOT}/target/dist/opt/ssh-mesh/bin/initos-vrun"
  elif command -v initos-vrun >/dev/null 2>&1; then
    VRUN="$(command -v initos-vrun)"
  fi
fi

if [[ -z "${VRUN}" ]] ||
   ! PATH="${PROFILE}/bin:${PATH}" VIRT="${PROFILE}" VIRT_ROOTFS="${PROJECT_ROOT}/target/dist/img/ssh-mesh.erofs" "${VRUN}" available qemuvirt; then
  echo "skipping qemu VM test; vrun, optional VM profile, custom kernel, rootfs, or qemu is missing"
  exit 0
fi

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

timeout --foreground "${TIMEOUT:-90}s" \
  env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
    PATH="${PROFILE}/bin:${PATH}" VIRT="${PROFILE}" VIRT_ROOTFS="${PROJECT_ROOT}/target/dist/img/ssh-mesh.erofs" \
  "${VRUN}" qemuvirt 2>&1 | tee "${LOG}"

grep -q "hi from qemu" "${LOG}"
echo "qemu one-shot echo test passed"

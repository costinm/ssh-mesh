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
  if [[ -d "${PROJECT_ROOT}/target/nix/profiles" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix/profiles"
  elif [[ -d "${PROJECT_ROOT}/target/nix" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix"
  else
    NIX_PROFILE="/ws/initos/target/nix"
  fi
fi
PROFILE="${PROFILE:-${NIX_PROFILE}}"

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

if [[ ! -x "${PROFILE}/bin/initos-vrun" ]]; then
  echo "Error: VM profile not found at ${PROFILE}. Build it first (e.g. scripts/build.sh vm)." >&2
  exit 1
fi

timeout --foreground "${TIMEOUT:-90}s" \
  env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
  "${PROFILE}/bin/initos-vrun" qemuvirt 2>&1 | tee "${LOG}"

grep -q "hi from qemu" "${LOG}"
echo "qemu one-shot echo test passed"

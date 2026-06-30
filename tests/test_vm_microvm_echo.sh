#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

FLAKE_DIR="${PROJECT_ROOT}/tests/microvm-echo"
WORK="${WORK:-${PROJECT_ROOT}/target/vm/microvm-echo}"
SHARE="${WORK}/share"
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
MICROVM_HYPERVISOR="${MICROVM_HYPERVISOR:-crosvm}"
RUNNER_PACKAGE="runner-${MICROVM_HYPERVISOR}"
RUNNER_LINK="${WORK}/${RUNNER_PACKAGE}"
LOG="${WORK}/microvm-${MICROVM_HYPERVISOR}.log"
STAMP="${WORK}/${RUNNER_PACKAGE}.sha256"

case "${MICROVM_HYPERVISOR}" in
  qemu|crosvm|cloud-hypervisor) ;;
  *)
    echo "unsupported MICROVM_HYPERVISOR=${MICROVM_HYPERVISOR}" >&2
    exit 1
    ;;
esac

cleanup() {
  if [[ -n "${virtiofsd_pid:-}" ]] && kill -0 "${virtiofsd_pid}" 2>/dev/null; then
    kill "${virtiofsd_pid}" 2>/dev/null || true
    wait "${virtiofsd_pid}" 2>/dev/null || true
  fi
  rm -f "${WORK}/src.sock"
}
trap cleanup EXIT

rm -rf "${SHARE}"
mkdir -p "${SHARE}/initos" "${WORK}"

cat > "${SHARE}/initos/initos-pod" <<'EOF'
#!/opt/busybox/bin/sh

case "${1:-start}" in
  start)
    echo "hi from microvm"
    echo "<6>hi from microvm" > /dev/kmsg 2>/dev/null || true
    ;;
  *)
    echo "unsupported command: $1" >&2
    exit 1
    ;;
esac
EOF
chmod 755 "${SHARE}/initos/initos-pod"

if [[ ! -x "${PROFILE}/bin/initos-vrun" ]]; then
  echo "Error: VM profile not found at ${PROFILE}. Build it first (e.g. scripts/build.sh vm)." >&2
  exit 1
fi
PROFILE_REAL="$(readlink -f "${PROFILE}")"

flake_hash="$(printf '%s\n' "${PROFILE_REAL}" "${MICROVM_HYPERVISOR}" "$(sha256sum "${FLAKE_DIR}/flake.nix" | awk '{print $1}')" | sha256sum | awk '{print $1}')"
if [[ ! -x "${RUNNER_LINK}/bin/microvm-run" ]] || [[ ! -f "${STAMP}" ]] || [[ "$(cat "${STAMP}")" != "${flake_hash}" ]]; then
  rm -f "${RUNNER_LINK}"
  echo "Error: microvm runner not built." >&2; exit 1
  printf '%s\n' "${flake_hash}" > "${STAMP}"
fi

if [[ "${MICROVM_HYPERVISOR}" = "cloud-hypervisor" ]]; then
  rm -f "${WORK}/src.sock"
  "${PROFILE}/bin/virtiofsd" \
    --socket-path="${WORK}/src.sock" \
    --shared-dir="${SHARE}" \
    --cache=auto \
    --thread-pool-size=0 \
    --sandbox none \
    --inode-file-handles=never \
    --log-level=error \
    --allow-direct-io > "${WORK}/virtiofsd.log" 2>&1 &
  virtiofsd_pid=$!
  for _ in $(seq 1 100); do
    [[ -S "${WORK}/src.sock" ]] && break
    sleep 0.05
  done
  if [[ ! -S "${WORK}/src.sock" ]]; then
    cat "${WORK}/virtiofsd.log" >&2 || true
    echo "microvm cloud-hypervisor virtiofsd socket was not created" >&2
    exit 1
  fi
fi

(
  cd "${FLAKE_DIR}"
  timeout --foreground "${TIMEOUT:-90}s" "${RUNNER_LINK}/bin/microvm-run"
) 2>&1 | tee "${LOG}"

grep -q "hi from microvm" "${LOG}"
echo "microvm ${MICROVM_HYPERVISOR} one-shot echo test passed"

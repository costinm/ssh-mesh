#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_artifacts() {
  if [ "${SSH_MESH_TEST_REUSE_RESULTS:-0}" = "1" ] && \
    [ -x "${root}/result-ssh-mesh-full/bin/ssh-mesh" ] && \
    [ -d "${root}/result-bob-vm/share/bob-vm" ]; then
    return
  fi

  nix build "${root}#ssh-mesh-full" -o "${root}/result-ssh-mesh-full"
  nix build "${root}#bob-vm" -o "${root}/result-bob-vm"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

wait_for() {
  local label="$1"
  local timeout_secs="$2"
  shift 2

  local deadline=$((SECONDS + timeout_secs))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if "$@" >/dev/null 2>&1; then
      echo "ok: ${label}"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for ${label}" >&2
  return 1
}

http_ok() {
  curl -fsS --max-time 2 "$1" >/dev/null
}

uds_http_ok() {
  curl -fsS --max-time 2 --unix-socket "$1" "$2" >/dev/null
}

uds_http_post_ok() {
  curl -fsS --max-time 2 -X POST --unix-socket "$1" "$2" >/dev/null
}

tcp_open() {
  timeout 2 bash -c ":</dev/tcp/127.0.0.1/$1"
}

port_free() {
  ! tcp_open "$1"
}

cleanup() {
  local status=$?
  if [ -n "${suite_pid:-}" ] && kill -0 "${suite_pid}" 2>/dev/null; then
    kill "${suite_pid}" 2>/dev/null || true
    wait "${suite_pid}" 2>/dev/null || true
  fi
  if [ -n "${state_root:-}" ] && [ -d "${state_root}" ]; then
    echo "example logs: ${state_root}/logs"
    if [ "${status}" -ne 0 ]; then
      for log in "${state_root}"/logs/*.log; do
        [ -f "${log}" ] || continue
        echo "===== ${log} =====" >&2
        tail -200 "${log}" >&2 || true
      done
    fi
    chmod -R u+rwX "${state_root}" 2>/dev/null || true
    rm -rf "${state_root}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

build_artifacts

export PATH="${root}/result-ssh-mesh-full/bin:${root}/result-bob-vm/share/bob-vm/bin:${PATH}"
export SSH_MESH_EXAMPLE_BIN_DIR="${root}/result-ssh-mesh-full/bin"
export SSH_MESH_BOB_VM_DIR="${root}/result-bob-vm/share/bob-vm"
export SSH_MESH_BOB_ENABLE_VSOCK="${SSH_MESH_BOB_ENABLE_VSOCK:-0}"
export SSH_MESH_BOB_QEMU_MEMORY="${SSH_MESH_BOB_QEMU_MEMORY:-768}"
export SSH_MESH_BOB_QEMU_CPUS="${SSH_MESH_BOB_QEMU_CPUS:-1}"
export SSH_MESH_BOB_HOST_SSH_PORT="${SSH_MESH_BOB_HOST_SSH_PORT:-29322}"
export SSH_MESH_BOB_HOST_HTTP_PORT="${SSH_MESH_BOB_HOST_HTTP_PORT:-29380}"

need bwrap
need curl
need qemu-system-x86_64
need mesh-init
need ssh-mesh
need pmond
need lmesh
need mcp-pmond
need h2t

if [ "${SSH_MESH_TEST_SKIP_PORT_CHECK:-0}" != "1" ]; then
  for port in 18222 18280 "${SSH_MESH_BOB_HOST_SSH_PORT}" "${SSH_MESH_BOB_HOST_HTTP_PORT}" 18422 18480 19002 19005 19102 19105; do
    if ! port_free "${port}"; then
      echo "required test port is already in use: ${port}" >&2
      exit 1
    fi
  done
fi

state_root="$(mktemp -d -t ssh-mesh-examples.XXXXXX)"
export SSH_MESH_EXAMPLE_ROOT="${state_root}"

"${root}/docs/examples/start_all.sh" &
suite_pid=$!

wait_for "alice HTTP admin" 60 http_ok "http://127.0.0.1:18280/_m/api/ssh/clients"
wait_for "user HTTP admin" 60 http_ok "http://127.0.0.1:18480/_m/api/ssh/clients"
wait_for "bob HTTP admin" 180 http_ok "http://127.0.0.1:${SSH_MESH_BOB_HOST_HTTP_PORT}/_m/api/ssh/clients"
wait_for "bob SSH port" 60 tcp_open "${SSH_MESH_BOB_HOST_SSH_PORT}"

wait_for "alice trusted UDS" 30 test -S "${state_root}/shared/alice/trusted.sock"
wait_for "bob trusted UDS" 60 test -S "${state_root}/shared/bob/trusted.sock"
wait_for "user trusted UDS" 30 test -S "${state_root}/shared/user/trusted.sock"

wait_for "alice local forward to user SSH" 60 tcp_open 19002
wait_for "user local forward to alice SSH" 60 tcp_open 19005
wait_for "alice remote forward HTTP" 60 http_ok "http://127.0.0.1:19102/_m/api/ssh/clients"
wait_for "user remote forward HTTP" 60 http_ok "http://127.0.0.1:19105/_m/api/ssh/clients"

wait_for "alice pmond UDS" 60 uds_http_ok \
  "${state_root}/alice/home/alice/.run/pmond/control.sock" \
  "http://localhost/_m/pmon/_ps"
wait_for "user pmond UDS" 60 uds_http_ok \
  "${state_root}/user/home/user/.run/pmond/control.sock" \
  "http://localhost/_m/pmon/_ps"
if ! wait_for "alice lmesh UDS" 10 uds_http_post_ok \
  "${state_root}/alice/home/alice/.run/lmesh/control.sock" \
  "http://localhost/nodes"; then
  echo "warn: alice lmesh UDS unavailable; multicast can be disabled in restricted namespaces"
fi

echo "example suite smoke test passed"

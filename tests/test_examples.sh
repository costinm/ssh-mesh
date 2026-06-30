#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_bin_dir="${root}/target/x86_64-unknown-linux-musl/release"
artifact_dir="${root}/target/dist"
example_bin_dir="${artifact_dir}/opt/ssh-mesh/bin"

build_artifacts() {
  if [ "${SSH_MESH_TEST_REUSE_RESULTS:-0}" = "1" ] && \
    [ -x "${example_bin_dir}/ssh-mesh" ] && \
    [ -x "${release_bin_dir}/ssh-mesh" ] && \
    [ -f "${artifact_dir}/img/ssh-mesh.erofs" ]; then
    return
  fi

  echo "Building Rust binaries and staging examples with build.sh..."
  "${root}/scripts/build.sh"

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

uds_jsonl_ok() {
  printf '%s\n' "$2" | timeout 2 nc -U "$1" | grep -q '"success":true\|"result"'
}

tcp_open() {
  timeout 2 bash -c ":</dev/tcp/127.0.0.1/$1"
}

ssh_exec_ok() {
  local host="$1"
  local command="$2"
  shift 2

  (
    cd "${root}/docs/examples"
    ssh -F ssh_config "$@" "${host}" "${command}"
  )
}

ssh_shell_ok() {
  local host="$1"
  shift

  (
    cd "${root}/docs/examples"
    local output
    local status
    set +e
    output="$(printf 'printf "shell-"; printf "ok\\n"; exit\n' | timeout 15 ssh -tt -F ssh_config "$@" "${host}" 2>&1)"
    status=$?
    set -e
    [ "${status}" -eq 0 ] || return "${status}"
    printf '%s\n' "${output}" | grep -q "shell-ok"
  )
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

export PATH="${example_bin_dir}:${PATH}"
export SSH_MESH_HOST3_VM_ENABLE_VSOCK="${SSH_MESH_HOST3_VM_ENABLE_VSOCK:-0}"
export SSH_MESH_HOST3_VM_QEMU_MEMORY="${SSH_MESH_HOST3_VM_QEMU_MEMORY:-768}"
export SSH_MESH_HOST3_VM_QEMU_CPUS="${SSH_MESH_HOST3_VM_QEMU_CPUS:-1}"
export SSH_MESH_HOST3_VM_HOST_SSH_PORT="${SSH_MESH_HOST3_VM_HOST_SSH_PORT:-29322}"
export SSH_MESH_HOST3_VM_HOST_HTTP_PORT="${SSH_MESH_HOST3_VM_HOST_HTTP_PORT:-29380}"

need bwrap
need curl
need nc
need qemu-system-x86_64
need mesh-init
need ssh-mesh
need pmond
need lmesh
need h2t

if [ "${SSH_MESH_TEST_SKIP_PORT_CHECK:-0}" != "1" ]; then
  for port in 15101 15102 18222 18280 "${SSH_MESH_HOST3_VM_HOST_SSH_PORT}" "${SSH_MESH_HOST3_VM_HOST_HTTP_PORT}" 18422 18480 19002 19005 19102 19105; do
    if ! port_free "${port}"; then
      echo "required test port is already in use: ${port}" >&2
      exit 1
    fi
  done
fi

state_root="$(mktemp -d -t ssh-mesh-examples.XXXXXX)"
export SSH_MESH_EXAMPLE_ROOT="${state_root}"

"${root}/docs/examples/start_all.sh" "${state_root}" &
suite_pid=$!

wait_for "host2 HTTP admin" 60 http_ok "http://127.0.0.1:18280/_m/api/ssh/clients"
wait_for "host1 HTTP admin" 60 http_ok "http://127.0.0.1:18480/_m/api/ssh/clients"
wait_for "host1 mesh9p activation port" 60 tcp_open 15101
wait_for "host2 mesh9p activation port" 60 tcp_open 15102
wait_for "host3-vm HTTP admin" 180 http_ok "http://127.0.0.1:${SSH_MESH_HOST3_VM_HOST_HTTP_PORT}/_m/api/ssh/clients"
wait_for "host3-vm SSH port" 60 tcp_open "${SSH_MESH_HOST3_VM_HOST_SSH_PORT}"
wait_for "host3-vm /nix over SSH" 60 ssh_exec_ok \
  host3-vm-direct \
  "test -d /nix && test -e /nix/store" \
  -p "${SSH_MESH_HOST3_VM_HOST_SSH_PORT}"
wait_for "host2 routed SSH exec" 60 ssh_exec_ok \
  host2 \
  "echo host2-routed-ok"
wait_for "host3-vm routed SSH exec" 60 ssh_exec_ok \
  host3-vm \
  "echo host3-routed-ok"
wait_for "host3-vm routed root SSH exec" 60 ssh_exec_ok \
  host3-vm-root \
  "test \"$(id -u)\" = 0 && echo host3-root-routed-ok"
wait_for "host3-vm direct root SSH exec" 60 ssh_exec_ok \
  host3-vm-root-direct \
  "test \"$(id -u)\" = 0 && echo host3-root-direct-ok" \
  -p "${SSH_MESH_HOST3_VM_HOST_SSH_PORT}"
wait_for "host3-vm sees host1 and host2 9p exports" 60 ssh_exec_ok \
  host3-vm-root-direct \
  'test "$(cat /tmp/mesh/9p/host1/host1/mesh9p-export/host1.txt)" = "host1-9p-export-ok" && test "$(cat /tmp/mesh/9p/host2/host2/mesh9p-export/host2.txt)" = "host2-9p-export-ok"' \
  -p "${SSH_MESH_HOST3_VM_HOST_SSH_PORT}"
wait_for "host1 SSH shell" 30 ssh_shell_ok host1
wait_for "host2 routed SSH shell" 60 ssh_shell_ok host2
wait_for "host3-vm routed SSH shell" 60 ssh_shell_ok host3-vm
wait_for "app1-bwrap routed SSH exec" 60 ssh_exec_ok \
  app1-bwrap \
  "echo app1-routed-ok"
wait_for "app1-bwrap routed SSH shell" 60 ssh_shell_ok app1-bwrap
if [ "${SSH_MESH_TEST_SKIP_APP5_9P:-0}" != "1" ]; then
  wait_for "app5-vm no-TCP 9p mount" 180 ssh_exec_ok \
    app5-vm \
    "test -d /tmp/mesh/9p/nix/store && echo app5-9p-ok"
fi

wait_for "host3-vm trusted UDS" 60 test -S "${state_root}/shared/host3-vm/trusted.sock"
wait_for "host1 trusted UDS" 30 test -S "${state_root}/shared/host1/trusted.sock"
wait_for "app1-bwrap activation UDS" 30 test -S "${state_root}/shared/app1-bwrap/trusted.sock"
wait_for "app2-qemu activation UDS" 30 test -S "${state_root}/shared/app2-qemu/trusted.sock"

wait_for "host1 local forward to host2 SSH" 60 tcp_open 19005
wait_for "host1 remote forward HTTP" 60 http_ok "http://127.0.0.1:19105/_m/api/ssh/clients"

wait_for "host2 pmond JSONL UDS" 60 uds_jsonl_ok \
  "${state_root}/host2/home/system/run/pmond/control.sock" \
  '{"jsonrpc":"2.0","method":"ps","id":1}'
wait_for "host1 pmond JSONL UDS" 60 uds_jsonl_ok \
  "${state_root}/host1/home/system/run/pmond/control.sock" \
  '{"jsonrpc":"2.0","method":"ps","id":1}'
wait_for "host2 pmond HTTP proxy" 60 http_ok "http://127.0.0.1:18280/_m/pmon/_ps"
wait_for "host1 pmond HTTP proxy" 60 http_ok "http://127.0.0.1:18480/_m/pmon/_ps"
if ! wait_for "host2 lmesh UDS" 10 uds_jsonl_ok \
  "${state_root}/host2/home/system/run/lmesh/control.sock" \
  '{"jsonrpc":"2.0","method":"nodes","id":1}'; then
  echo "warn: host2 lmesh UDS unavailable; multicast can be disabled in restricted namespaces"
fi

echo "example suite smoke test passed"

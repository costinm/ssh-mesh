#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_port=19422
http_port=19480
admin_port=19481
fixture_dir="${root}/tests/ssh_mesh_activation"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

tcp_open() {
  timeout 2 bash -c ":</dev/tcp/127.0.0.1/$1" >/dev/null 2>&1
}

port_free() {
  ! tcp_open "$1"
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

http_contains() {
  local url="$1"
  local text="$2"
  curl -fsSL --max-time 2 "$url" | grep -F "$text" >/dev/null
}

http_redirects_to() {
  local url="$1"
  local location="$2"
  local headers
  headers="$(curl -fsS --max-time 2 -D - -o /dev/null "$url" | tr -d '\r')"
  printf '%s\n' "$headers" | grep -q '^HTTP/.* 307 ' &&
    printf '%s\n' "$headers" | grep -Fxq "location: ${location}"
}

listens_on_wildcard_v4() {
  local port="$1"
  ss -ltn | awk -v port=":${port}" '
    $1 == "LISTEN" && index($4, port) {
      if ($4 ~ ("(^|\\[::ffff:|\\*)0?0?0?0?\\.0?0?0?0?\\.0?0?0?0?\\.0?0?0?0?:" port "$") ||
          $4 ~ ("^0\\.0\\.0\\.0" port "$") ||
          $4 ~ ("^\\*" port "$")) {
        found = 1
      }
    }
    END { exit found ? 0 : 1 }
  '
}

stop_mesh_init() {
  local pid="${mesh_init_pid:-}"
  [ -n "$pid" ] || return 0

  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 15); do
      if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        mesh_init_pid=""
        return 0
      fi
      sleep 1
    done

    # The test starts mesh-init in its own session. This fallback cannot kill
    # unrelated processes and ensures a broken shutdown never leaks listeners.
    kill -KILL -- "-${pid}" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  wait "$pid" 2>/dev/null || true
  mesh_init_pid=""
}

cleanup() {
  local status=$?
  stop_mesh_init || true
  if [ -n "${state_root:-}" ] && [ -d "${state_root}" ]; then
    chmod -R u+rwX "${state_root}" 2>/dev/null || true
    rm -rf "${state_root}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need curl
need mesh-init
need ssh-mesh
need ss
need timeout
need setsid

if ! port_free "${ssh_port}"; then
  echo "required test port is already in use: ${ssh_port}" >&2
  exit 1
fi
if ! port_free "${http_port}"; then
  echo "required test port is already in use: ${http_port}" >&2
  exit 1
fi
if ! port_free "${admin_port}"; then
  echo "required test port is already in use: ${admin_port}" >&2
  exit 1
fi

state_root="$(mktemp -d -t ssh-mesh-activation.XXXXXX)"
home="${state_root}/home/system"
app_home="${state_root}/home/ssh-mesh"
config_dir="${home}/etc/mesh-init"
ssh_base="${state_root}/home/system/.ssh"
ssh_config_dir="${state_root}/home/system/etc/ssh-mesh"
mkdir -p "${config_dir}" "${ssh_base}" "${ssh_config_dir}" "${app_home}"
cp -f "${fixture_dir}/ssh-mesh.toml" "${config_dir}/"
cp -f "${fixture_dir}/ssh-mesh.yaml" "${ssh_config_dir}/"
(
  export MESH_HOME="${state_root}"
  export MESH_INIT_DIR="${config_dir}"
  export MESH_LOG_FILE=/dev/stderr
  export SSH_BASEDIR="${ssh_base}"
  export SSH_MESH_CONFIG="${ssh_config_dir}"
  exec setsid mesh-init
) &
mesh_init_pid=$!

wait_for "ssh activation listener on 0.0.0.0:${ssh_port}" 30 listens_on_wildcard_v4 "${ssh_port}"
wait_for "http activation listener on 0.0.0.0:${http_port}" 30 listens_on_wildcard_v4 "${http_port}"
wait_for "admin activation listener on 0.0.0.0:${admin_port}" 30 listens_on_wildcard_v4 "${admin_port}"

# The first HTTP request triggers Accept=false activation. ssh-mesh now uses
# the admin console as its root, so verify the redirect instead of the removed
# development static-root fixture.
wait_for "activated ssh-mesh HTTP root redirect" 45 http_redirects_to \
  "http://127.0.0.1:${http_port}/" "/_m/adm/"
wait_for "activated ssh-mesh HTTP vscode proxy redirect" 10 http_redirects_to \
  "http://127.0.0.1:${http_port}/proxy/${http_port}/" "/proxy/${http_port}/_m/adm/"
wait_for "activated ssh-mesh admin API" 45 http_ok \
  "http://127.0.0.1:${admin_port}/_m/api/ssh/clients"
wait_for "activated ssh-mesh admin UI direct path" 10 http_contains \
  "http://127.0.0.1:${admin_port}/_m/adm/" "Mesh Console"
wait_for "activated ssh-mesh admin UI vscode proxy path" 10 http_contains \
  "http://127.0.0.1:${admin_port}/proxy/${admin_port}/" "Mesh Console"
wait_for "activated ssh-mesh prefixed API path" 10 http_ok \
  "http://127.0.0.1:${admin_port}/proxy/${admin_port}/_m/api/ssh/clients"
wait_for "activated ssh-mesh SSH TCP listener" 30 tcp_open "${ssh_port}"
wait_for "ssh listener remains on 0.0.0.0:${ssh_port}" 10 listens_on_wildcard_v4 "${ssh_port}"
wait_for "http listener remains on 0.0.0.0:${http_port}" 10 listens_on_wildcard_v4 "${http_port}"
wait_for "admin listener remains on 0.0.0.0:${admin_port}" 10 listens_on_wildcard_v4 "${admin_port}"

# Exercise mesh-init's service-manager shutdown path and prove it reaps the
# activated child rather than leaving listeners behind.
stop_mesh_init
wait_for "activated listeners close after mesh-init SIGTERM" 15 bash -c \
  "! timeout 1 bash -c ':</dev/tcp/127.0.0.1/${ssh_port}' && ! timeout 1 bash -c ':</dev/tcp/127.0.0.1/${http_port}' && ! timeout 1 bash -c ':</dev/tcp/127.0.0.1/${admin_port}'"

echo "ssh-mesh activation smoke test passed"

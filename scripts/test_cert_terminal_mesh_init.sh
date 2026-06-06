#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
chmod 0777 "$TMPDIR"

dump_logs() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "test failed with status ${status}" >&2
    for log in "$TMPDIR"/*.log; do
      [ -f "$log" ] || continue
      echo "--- ${log##*/} ---" >&2
      tail -200 "$log" >&2
    done
  fi
  rm -rf "$TMPDIR" 2>/dev/null || true
}
trap dump_logs EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 77
  }
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

subid_start() {
  local file="$1"
  local name
  name="$(id -un)"
  awk -F: -v user="$name" '$1 == user { print $2; exit }' "$file"
}

wait_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    if timeout 1 bash -c ":</dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for port ${port}" >&2
  return 1
}

need python3
need ssh
need ssh-keygen
need timeout
need bwrap

cd "$ROOT"
cargo build -p mesh-init -p ssh-mesh

SERVER_BASE="$TMPDIR/server-ssh"
CONFIG_DIR="$TMPDIR/ssh-mesh-config"
CA_KEY="$TMPDIR/ca"
ALICE_KEY="$TMPDIR/alice"
mkdir -p "$SERVER_BASE" "$CONFIG_DIR/users/alice"
ssh-keygen -q -t ecdsa -N "" -f "$CA_KEY"
ssh-keygen -q -t ecdsa -N "" -f "$ALICE_KEY"
ssh-keygen -q -t ecdsa -N "" -f "$SERVER_BASE/id_ecdsa"
ssh-keygen -q -s "$CA_KEY" -I alice-user -n 'alice@test.m' -V -1h:+1h "$ALICE_KEY.pub"
printf '@cert-authority %s\n' "$(cat "$CA_KEY.pub")" > "$SERVER_BASE/authorized_cas"
cp "$ALICE_KEY.pub" "$CONFIG_DIR/users/alice/authorized_keys"
chmod 600 "$SERVER_BASE/id_ecdsa" "$ALICE_KEY"
chmod -R a+rX "$SERVER_BASE" "$CONFIG_DIR"
chmod a+r "$ALICE_KEY" "$ALICE_KEY.pub" "${ALICE_KEY}-cert.pub"

ROOT_INNER="$TMPDIR/root-inside-bwrap.sh"
cat >"$ROOT_INNER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_ssh_uid_check() {
  local login="$1"
  local cert_file="$2"
  local expected_uid="$3"
  local output
  local status

  set +e
  output="$(
    printf 'id -u\nexit\n' | timeout 20 ssh -tt \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o CertificateFile="${cert_file}" \
      -i "${ALICE_KEY}" \
      -p "${SSH_PORT}" \
      -l "${login}" \
      127.0.0.1
  )"
  status=$?
  set -e

  echo "$output"
  echo "$output" | tr -d '\r' | grep -E '^[0-9]+$' | tail -1 | grep -qx "${expected_uid}"
  if [ "$status" -ne 0 ] && [ "$status" -ne 255 ]; then
    exit "$status"
  fi
}

mkdir -p /run /home/alice
RUNTIME=/run/ssh-mesh-test
mkdir -p "$RUNTIME"
cp -r "${SERVER_BASE}" "${RUNTIME}/server-ssh"
cp -r "${CONFIG_DIR}" "${RUNTIME}/ssh-mesh-config"
cp "${ALICE_KEY}" "${RUNTIME}/alice"
cp "${ALICE_KEY}.pub" "${RUNTIME}/alice.pub"
cp "${ALICE_KEY}-cert.pub" "${RUNTIME}/alice-cert.pub"
SERVER_BASE="${RUNTIME}/server-ssh"
CONFIG_DIR="${RUNTIME}/ssh-mesh-config"
ALICE_KEY="${RUNTIME}/alice"
chmod 600 "${SERVER_BASE}/id_ecdsa" "${ALICE_KEY}"

if ! chown "${REQUESTED_USER_UID}:${REQUESTED_USER_UID}" /home/alice 2>/dev/null; then
  ACTUAL_USER_UID="$(stat -c %u /home/alice)"
  echo "root namespace cannot chown /home/alice to ${REQUESTED_USER_UID}; using mapped owner ${ACTUAL_USER_UID}" >&2
else
  ACTUAL_USER_UID="$(stat -c %u /home/alice)"
fi
[ "$ACTUAL_USER_UID" = "$(stat -c %u /home/alice)" ]

MESH_INIT_RUN=/run/mesh-init RUST_LOG=info "${ROOT}/target/debug/mesh-init" \
  >"${TMPDIR}/root-mesh-init.log" 2>&1 &
MESH_INIT_PID=$!

for _ in $(seq 1 100); do
  [ -S /run/mesh-init/control.sock ] && break
  sleep 0.1
done
[ -S /run/mesh-init/control.sock ]

MESH_INIT_SOCK=/run/mesh-init/control.sock \
SSH_BASEDIR="${SERVER_BASE}" \
SSH_MESH_CONFIG="${CONFIG_DIR}" \
SSH_MESH_HOME_ROOT=/home \
SSH_PORT="${SSH_PORT}" \
HTTP_PORT="${HTTP_PORT}" \
RUST_LOG=info \
  "${ROOT}/target/debug/ssh-mesh" >"${TMPDIR}/root-ssh-mesh.log" 2>&1 &
SSH_MESH_PID=$!

cleanup() {
  kill "${SSH_MESH_PID}" "${MESH_INIT_PID}" 2>/dev/null || true
}
trap cleanup EXIT

wait_port "${SSH_PORT}"
run_ssh_uid_check 'alice@test.m' "${ALICE_KEY}-cert.pub" "${ACTUAL_USER_UID}"
run_ssh_uid_check alice none "${ACTUAL_USER_UID}"
SH
chmod a+rx "$ROOT_INNER"

REGULAR_INNER="$TMPDIR/regular-user-bwrap.sh"
cat >"$REGULAR_INNER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_ssh_uid_check() {
  local login="$1"
  local cert_file="$2"
  local expected_uid="$3"
  local output
  local status

  set +e
  output="$(
    printf 'id -u\nexit\n' | timeout 20 ssh -tt \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o CertificateFile="${cert_file}" \
      -i "${ALICE_KEY}" \
      -p "${REGULAR_SSH_PORT}" \
      -l "${login}" \
      127.0.0.1
  )"
  status=$?
  set -e

  echo "$output"
  echo "$output" | tr -d '\r' | grep -E '^[0-9]+$' | tail -1 | grep -qx "${expected_uid}"
  if [ "$status" -ne 0 ] && [ "$status" -ne 255 ]; then
    exit "$status"
  fi
}

export HOME="/run/regular-home"
LOG_DIR="$HOME"
dump_regular_logs() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    for log in "$LOG_DIR"/regular-*.log; do
      [ -f "$log" ] || continue
      echo "--- ${log##*/} ---" >&2
      tail -200 "$log" >&2
    done
  fi
  exit "$status"
}
trap dump_regular_logs EXIT
HOME_ROOT="${HOME}/.local/home"
CONTROL_DIR="${HOME}/.run/mesh-init"
mkdir -p "${HOME_ROOT}/alice" "${CONTROL_DIR}"
if [ "$(id -u)" = 0 ] && [ "${REGULAR_PREPARED:-0}" = 0 ]; then
  RUNTIME=/run/ssh-mesh-regular-test
  mkdir -p "$RUNTIME" "$HOME_ROOT/alice" "$CONTROL_DIR"
  cp -r "${SERVER_BASE}" "${RUNTIME}/server-ssh"
  cp -r "${CONFIG_DIR}" "${RUNTIME}/ssh-mesh-config"
  cp "${ALICE_KEY}" "${RUNTIME}/alice"
  cp "${ALICE_KEY}.pub" "${RUNTIME}/alice.pub"
  cp "${ALICE_KEY}-cert.pub" "${RUNTIME}/alice-cert.pub"
  cp "$0" "${RUNTIME}/regular-user-bwrap.sh"
  cp "${ROOT}/target/debug/mesh-init" "${RUNTIME}/mesh-init"
  cp "${ROOT}/target/debug/ssh-mesh" "${RUNTIME}/ssh-mesh"
  chown -R "${REGULAR_UID}:${REGULAR_GID}" "$HOME" "$RUNTIME"
  chown "${ALICE_HOME_UID}:${ALICE_HOME_GID}" "$HOME_ROOT/alice"
  chmod 600 "${RUNTIME}/server-ssh/id_ecdsa" "${RUNTIME}/alice"
  chmod 755 "${RUNTIME}/regular-user-bwrap.sh" "${RUNTIME}/mesh-init" "${RUNTIME}/ssh-mesh"
  exec setpriv --reuid "${REGULAR_UID}" --regid "${REGULAR_GID}" --clear-groups \
    env REGULAR_PREPARED=1 \
    HOME="$HOME" \
    ROOT="$ROOT" \
    TMPDIR="$TMPDIR" \
    SERVER_BASE="${RUNTIME}/server-ssh" \
    CONFIG_DIR="${RUNTIME}/ssh-mesh-config" \
    ALICE_KEY="${RUNTIME}/alice" \
    REGULAR_SSH_PORT="$REGULAR_SSH_PORT" \
    REGULAR_HTTP_PORT="$REGULAR_HTTP_PORT" \
    ALICE_HOME_UID="$ALICE_HOME_UID" \
    MESH_INIT_BIN="${RUNTIME}/mesh-init" \
    SSH_MESH_BIN="${RUNTIME}/ssh-mesh" \
    /bin/bash "${RUNTIME}/regular-user-bwrap.sh"
fi

[ "$(stat -c %u "${HOME_ROOT}/alice")" = "${ALICE_HOME_UID}" ]

MESH_INIT_RUN="${CONTROL_DIR}" RUST_LOG=info "${MESH_INIT_BIN:-${ROOT}/target/debug/mesh-init}" \
  >"${LOG_DIR}/regular-mesh-init.log" 2>&1 &
MESH_INIT_PID=$!

for _ in $(seq 1 100); do
  [ -S "${CONTROL_DIR}/control.sock" ] && break
  sleep 0.1
done
[ -S "${CONTROL_DIR}/control.sock" ]

EXPECTED_UID="$(id -u)"
MESH_INIT_SOCK="${CONTROL_DIR}/control.sock" \
SSH_BASEDIR="${SERVER_BASE}" \
SSH_MESH_CONFIG="${CONFIG_DIR}" \
SSH_MESH_HOME_ROOT="${HOME_ROOT}" \
SSH_PORT="${REGULAR_SSH_PORT}" \
HTTP_PORT="${REGULAR_HTTP_PORT}" \
RUST_LOG=info \
  "${SSH_MESH_BIN:-${ROOT}/target/debug/ssh-mesh}" >"${LOG_DIR}/regular-ssh-mesh.log" 2>&1 &
SSH_MESH_PID=$!

cleanup() {
  kill "${SSH_MESH_PID}" "${MESH_INIT_PID}" 2>/dev/null || true
}
trap cleanup EXIT

wait_port "${REGULAR_SSH_PORT}"
run_ssh_uid_check 'alice@test.m' "${ALICE_KEY}-cert.pub" "${EXPECTED_UID}"
run_ssh_uid_check alice none "${EXPECTED_UID}"
SH
chmod a+rx "$REGULAR_INNER"

run_root_bwrap() {
  SSH_PORT="$(free_port)"
  HTTP_PORT="$(free_port)"
  REQUESTED_USER_UID=1234
  export ROOT TMPDIR SERVER_BASE CONFIG_DIR ALICE_KEY SSH_PORT HTTP_PORT REQUESTED_USER_UID
  export -f wait_port

  echo "== root mesh-init and ssh-mesh in bwrap =="
  local subuid subgid
  subuid="$(subid_start /etc/subuid || true)"
  subgid="$(subid_start /etc/subgid || true)"
  if [ -n "$subuid" ] && [ -n "$subgid" ] && command -v unshare >/dev/null 2>&1; then
    if unshare --user --map-auto --setuid 0 --setgid 0 --fork --kill-child true; then
      unshare \
      --user \
      --map-auto \
      --setuid 0 \
      --setgid 0 \
      --fork \
      --kill-child \
      -- \
      bwrap \
        --proc /proc \
        --dev /dev \
        --tmpfs /run \
        --tmpfs /home \
        --ro-bind /bin /bin \
        --ro-bind /usr /usr \
        --ro-bind /lib /lib \
        --ro-bind-try /lib64 /lib64 \
        --ro-bind /etc /etc \
        --bind "$ROOT" "$ROOT" \
        --bind "$TMPDIR" "$TMPDIR" \
        --setenv PATH /usr/bin:/bin \
        --setenv ROOT "$ROOT" \
        --setenv TMPDIR "$TMPDIR" \
        --setenv SSH_PORT "$SSH_PORT" \
        --setenv HTTP_PORT "$HTTP_PORT" \
        --setenv SERVER_BASE "$SERVER_BASE" \
        --setenv CONFIG_DIR "$CONFIG_DIR" \
        --setenv REQUESTED_USER_UID "$REQUESTED_USER_UID" \
        --setenv ALICE_KEY "$ALICE_KEY" \
        "$ROOT_INNER"
      return 0
    fi
    echo "subuid root namespace failed; retrying with bwrap's default user namespace" >&2
  fi

  bwrap \
    --unshare-user \
    --uid 0 \
    --gid 0 \
    --proc /proc \
    --dev /dev \
    --tmpfs /run \
    --tmpfs /home \
    --ro-bind /bin /bin \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind /etc /etc \
    --bind "$ROOT" "$ROOT" \
    --bind "$TMPDIR" "$TMPDIR" \
    --setenv PATH /usr/bin:/bin \
    --setenv ROOT "$ROOT" \
    --setenv TMPDIR "$TMPDIR" \
    --setenv SSH_PORT "$SSH_PORT" \
    --setenv HTTP_PORT "$HTTP_PORT" \
    --setenv SERVER_BASE "$SERVER_BASE" \
    --setenv CONFIG_DIR "$CONFIG_DIR" \
    --setenv REQUESTED_USER_UID "$REQUESTED_USER_UID" \
    --setenv ALICE_KEY "$ALICE_KEY" \
    "$ROOT_INNER"
}

run_regular_user_subuid_bwrap() {
  local subuid subgid
  subuid="$(subid_start /etc/subuid || true)"
  subgid="$(subid_start /etc/subgid || true)"
  if [ -z "$subuid" ] || [ -z "$subgid" ] || ! command -v unshare >/dev/null 2>&1; then
    echo "SKIP: no subuid/subgid mapping available for regular-user namespace test" >&2
    return 0
  fi

  REGULAR_SSH_PORT="$(free_port)"
  REGULAR_HTTP_PORT="$(free_port)"
  export ROOT TMPDIR SERVER_BASE CONFIG_DIR ALICE_KEY REGULAR_SSH_PORT REGULAR_HTTP_PORT
  export SUBUID="$subuid" SUBGID="$subgid"
  export -f wait_port

  echo "== regular-user mesh-init and ssh-mesh with ~/.local/home/alice owned by subuid =="
  REGULAR_UID=1000
  REGULAR_GID=1000
  ALICE_HOME_UID=1001
  ALICE_HOME_GID=1001
  export REGULAR_UID REGULAR_GID ALICE_HOME_UID ALICE_HOME_GID
  if ! unshare --user --map-auto --setuid 0 --setgid 0 --fork --kill-child true; then
    echo "SKIP: regular-user subuid namespace could not be created in this environment" >&2
    return 0
  fi

  unshare \
    --user \
    --map-auto \
    --setuid 0 \
    --setgid 0 \
    --fork \
    --kill-child \
    -- \
    bwrap \
      --proc /proc \
      --dev /dev \
      --tmpfs /run \
      --ro-bind /bin /bin \
      --ro-bind /usr /usr \
      --ro-bind /lib /lib \
      --ro-bind-try /lib64 /lib64 \
      --ro-bind /etc /etc \
      --bind "$ROOT" "$ROOT" \
      --bind "$TMPDIR" "$TMPDIR" \
      --setenv PATH /usr/bin:/bin \
      --setenv ROOT "$ROOT" \
      --setenv TMPDIR "$TMPDIR" \
      --setenv SERVER_BASE "$SERVER_BASE" \
      --setenv CONFIG_DIR "$CONFIG_DIR" \
      --setenv ALICE_KEY "$ALICE_KEY" \
      --setenv REGULAR_SSH_PORT "$REGULAR_SSH_PORT" \
      --setenv REGULAR_HTTP_PORT "$REGULAR_HTTP_PORT" \
      --setenv SUBUID "$subuid" \
      --setenv SUBGID "$subgid" \
      --setenv REGULAR_UID "$REGULAR_UID" \
      --setenv REGULAR_GID "$REGULAR_GID" \
      --setenv ALICE_HOME_UID "$ALICE_HOME_UID" \
      --setenv ALICE_HOME_GID "$ALICE_HOME_GID" \
      "$REGULAR_INNER"
}

run_root_bwrap
run_regular_user_subuid_bwrap

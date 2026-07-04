#!/usr/bin/env bash
# Verify mesh-init/ssh-mesh in an independently started NixOS VM.
#
# Expected VM shape:
#   - guest SSH/ssh-mesh port 15022 is forwarded to host port 14022
#   - guest /nix is mounted from host read-only
#   - guest /home is mounted from target/nixos-vm-fs/home
#   - guest /opt is mounted from target/nixos-vm-fs/opt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

HOST="${SSH_MESH_NIXOS_HOST:-127.0.0.1}"
PORT="${SSH_MESH_NIXOS_SSH_PORT:-14022}"
USER="${SSH_MESH_NIXOS_USER:-system}"
KEY="${SSH_MESH_NIXOS_KEY:-crates/ssh-mesh/tests/testdata/alice/id_ecdsa}"
STATE="${SSH_MESH_NIXOS_STATE:-target/nixos-vm-fs}"
FIXTURES="${PROJECT_ROOT}/tests/nixos/mesh-init"

ssh_cmd=(
  ssh
  -i "${KEY}"
  -p "${PORT}"
  -o IdentitiesOnly=yes
  -o IdentityAgent=none
  -o CertificateFile=none
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o BatchMode=yes
  "${USER}@${HOST}"
)

ssh_vm() {
  "${ssh_cmd[@]}" "$@"
}

wait_for_ssh() {
  local i
  for i in $(seq 1 60); do
    if ssh_vm true >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "VM SSH is not reachable at ${HOST}:${PORT}" >&2
  exit 1
}

copy_dir() {
  local src="$1"
  local dst="$2"
  mkdir -p "${dst}"
  cp -a "${src}/." "${dst}/"
}

echo "=== Preparing host-mounted /home and /opt fixtures under ${STATE} ==="
mkdir -p "${STATE}/home" "${STATE}/opt"
rm -rf \
  "${STATE}/home/system/etc/mesh-init" \
  "${STATE}/home/system/tmp" \
  "${STATE}/home/override-app" \
  "${STATE}/home/demo-app" \
  "${STATE}/opt/system/etc/mesh-init" \
  "${STATE}/opt/demo-app" \
  "${STATE}/opt/override-app"

copy_dir "${FIXTURES}/opt" "${STATE}/opt"
copy_dir "${FIXTURES}/home/system" "${STATE}/home/system"
copy_dir "${FIXTURES}/home/override-app" "${STATE}/home/override-app"

mkdir -p "${STATE}/home/ssh-mesh/etc" "${STATE}/home/ssh-mesh/run/ssh-mesh"
install -m 0600 crates/ssh-mesh/tests/testdata/alice/id_ecdsa \
  "${STATE}/home/ssh-mesh/etc/id_ecdsa"
install -m 0644 crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub \
  "${STATE}/home/ssh-mesh/etc/id_ecdsa.pub"
install -m 0644 crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub \
  "${STATE}/home/ssh-mesh/etc/authorized_keys"
mkdir -p "${STATE}/home/system/tmp"
rm -f "${STATE}/home/system/etc/uidmap"

echo "=== Waiting for VM SSH on ${HOST}:${PORT} ==="
wait_for_ssh

echo "=== Checking required guest mounts ==="
ssh_vm 'set -eu
findmnt -n /nix >/dev/null
findmnt -n /home >/dev/null
findmnt -n /opt >/dev/null
test -x /opt/ssh-mesh/bin/mesh-init
test -d /home/system/etc/mesh-init
test -d /opt/system/etc/mesh-init
'

echo "=== Reloading mesh-init and checking mesh endpoints ==="
ssh_vm 'set -eu
/opt/ssh-mesh/bin/mesh-init reload
test -S /run/mesh/mesh-init/mesh.sock
test "$(stat -c %a /run/mesh/mesh-init/mesh.sock)" = 666
/opt/ssh-mesh/bin/mesh-init status ssh-mesh >/dev/null
for i in $(seq 1 60); do
  [ -S /run/mesh/ssh-mesh/mesh.sock ] && break
  sleep 1
done
test -S /run/mesh/ssh-mesh/mesh.sock
test "$(stat -c %a /run/mesh/ssh-mesh/mesh.sock)" = 666
'

echo "=== Checking core config /home overrides /opt ==="
ssh_vm 'set -eu
rm -f /home/system/tmp/override-check
/opt/ssh-mesh/bin/mesh-init start override-check >/dev/null
test "$(cat /home/system/tmp/override-check)" = home
'

echo "=== Checking cgroup resources and hardening fixtures ==="
ssh_vm 'set -eu
/opt/ssh-mesh/bin/mesh-init start memlimit | grep pid
test -d /sys/fs/cgroup/mesh.slice/memlimit.scope
test "$(cat /sys/fs/cgroup/mesh.slice/memlimit.scope/memory.low)" = 67108864
test "$(cat /sys/fs/cgroup/mesh.slice/memlimit.scope/memory.high)" = 268435456
test "$(cat /sys/fs/cgroup/mesh.slice/memlimit.scope/memory.max)" = 536870912
test "$(cat /sys/fs/cgroup/mesh.slice/memlimit.scope/cpu.weight)" = 50
/opt/ssh-mesh/bin/mesh-init start hardening-mounts
/opt/ssh-mesh/bin/mesh-init start hardening-process
/opt/ssh-mesh/bin/mesh-init start hardening-caps-drop
/opt/ssh-mesh/bin/mesh-init start hardening-caps-ambient
for path in \
  /home/system/tmp/results-mounts \
  /home/system/tmp/results-process \
  /home/system/tmp/results-caps-drop \
  /home/system/tmp/results-caps-ambient; do
  for i in $(seq 1 60); do
    [ -s "$path" ] && break
    sleep 1
  done
  test -s "$path"
done
grep "PASS mounts" /home/system/tmp/results-mounts
grep "PASS process" /home/system/tmp/results-process
grep "PASS caps-drop" /home/system/tmp/results-caps-drop
grep "PASS caps-ambient" /home/system/tmp/results-caps-ambient
'

echo "=== Checking on-demand app UID allocation ==="
ssh_vm 'set -eu
rm -rf /home/demo-app
rm -f /home/system/etc/uidmap
/opt/ssh-mesh/bin/mesh-init start demo-app
for path in /home/demo-app/uid /home/demo-app/gid /home/demo-app/source; do
  for i in $(seq 1 60); do
    [ -s "$path" ] && break
    sleep 1
  done
  test -s "$path"
done
test -d /home/demo-app
uid="$(stat -c %u /home/demo-app)"
gid="$(stat -c %g /home/demo-app)"
grep -Eq "^demo-app[[:space:]]+${uid}[[:space:]]+${gid}$" /home/system/etc/uidmap
test -d "/run/user/${uid}"
test "$(stat -c %a "/run/user/${uid}")" = 700
test "$(stat -c %u "/run/user/${uid}")" = "${uid}"
test "$(cat /home/demo-app/uid)" = "${uid}"
test "$(cat /home/demo-app/gid)" = "${gid}"
test "$(cat /home/demo-app/source)" = opt
'

echo "=== Checking on-demand /home app config overrides /opt ==="
ssh_vm 'set -eu
/opt/ssh-mesh/bin/mesh-init start override-app
for i in $(seq 1 60); do
  [ -s /home/override-app/source ] && break
  sleep 1
done
test -s /home/override-app/source
test "$(cat /home/override-app/source)" = home
'

echo "=== Checking SSH command path ==="
ssh_vm 'printf ssh-ok'

echo "=== NixOS mesh-init verification passed ==="

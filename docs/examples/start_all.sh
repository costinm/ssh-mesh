#!/usr/bin/env bash
set -euo pipefail

# Start the full three-node example mesh:
#
#   alice: mesh-init + ssh-mesh on SSH 18222 / HTTP 18280
#   bob:   QEMU VM node on SSH 18322 / HTTP 18380
#   user:  user-mode mesh-init + ssh-mesh on SSH 18422 / HTTP 18480
#
# Alice and user run in bubblewrap. Bob is started with QEMU and requires a
# Nix-built Initos VM artifact:
#
#   SSH_MESH_BOB_VM_DIR=/path/to/share/bob-vm
#
# or:
#
#   SSH_MESH_BOB_KERNEL=/path/to/bzImage
#   SSH_MESH_BOB_INITRD=/path/to/initrd.img
#   SSH_MESH_BOB_ROOTFS=/path/to/initos.erofs
#
# The examples share a private state root. Alice and user share the host network
# namespace. Bob's TCP ports are forwarded from QEMU user networking.
#
#   $SSH_MESH_EXAMPLE_ROOT/shared
#
# Binaries are expected in PATH; package-scoped install locations are prepended
# for host and test layouts.

export PATH="/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${PATH}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need bwrap
need mesh-init
need ssh-mesh
need qemu-system-x86_64

vm_dir="${SSH_MESH_BOB_VM_DIR:-/opt/ssh-mesh/share/bob-vm}"
kernel="${SSH_MESH_BOB_KERNEL:-${vm_dir}/bzImage}"
initrd="${SSH_MESH_BOB_INITRD:-${vm_dir}/initrd.img}"
rootfs="${SSH_MESH_BOB_ROOTFS:-${vm_dir}/initos.erofs}"
bob_host_ssh_port="${SSH_MESH_BOB_HOST_SSH_PORT:-18322}"
bob_host_http_port="${SSH_MESH_BOB_HOST_HTTP_PORT:-18380}"

if [ ! -r "${kernel}" ] || [ ! -r "${initrd}" ] || [ ! -r "${rootfs}" ]; then
  cat >&2 <<EOF
Bob requires a readable Initos kernel, initrd, and rootfs to start all three nodes.

Build it with:
  nix build .#bob-vm

Then set:
  SSH_MESH_BOB_VM_DIR=/path/to/share/bob-vm

Or set:
  SSH_MESH_BOB_KERNEL=/path/to/bzImage
  SSH_MESH_BOB_INITRD=/path/to/initrd.img
  SSH_MESH_BOB_ROOTFS=/path/to/initos.erofs

To run only the bwrap nodes:
  ./alice/start.sh
  ./user/start.sh
EOF
  exit 2
fi

examples_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-${HOME}/.local/share/ssh-mesh/examples}"
log_dir="${root_dir}/logs"
mkdir -p "${log_dir}" "${root_dir}/shared"

pids=""

cleanup() {
  for pid in ${pids}; do
    kill "${pid}" >/dev/null 2>&1 || true
  done
  wait >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

start_node() {
  node="$1"
  log="${log_dir}/${node}.log"
  echo "starting ${node}; log=${log}"
  "${examples_dir}/${node}/start.sh" >"${log}" 2>&1 &
  pids="${pids} $!"
}

start_node alice
start_node bob
start_node user

cat <<EOF

ssh-mesh example mesh is starting.

State root:
  ${root_dir}

Logs:
  ${log_dir}/alice.log
  ${log_dir}/bob.log
  ${log_dir}/user.log

Fixed listeners:
  alice: ssh 127.0.0.1:18222, http 127.0.0.1:18280
  bob:   qemu hostfwd ssh 127.0.0.1:${bob_host_ssh_port}, http 127.0.0.1:${bob_host_http_port}
  user:  ssh 127.0.0.1:18422, http 127.0.0.1:18480

Trusted UDS sockets:
  ${root_dir}/shared/alice/trusted.sock
  ${root_dir}/shared/bob/trusted.sock
  ${root_dir}/shared/user/trusted.sock

Press Ctrl-C to stop all example nodes.
EOF

wait

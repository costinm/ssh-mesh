#!/usr/bin/env bash
set -euo pipefail

# Start the full example mesh:
#
#   bwrap-net: mesh-init + ssh-mesh on SSH 18222 / HTTP 18280
#   vm-net:    QEMU VM node on SSH 18322 / HTTP 18380
#   user:      user-mode mesh-init + ssh-mesh on SSH 18422 / HTTP 18480
#
# The user node also installs mesh-init activation sockets for bwrap-nonet and
# no-network VMs. Bwrap-nonet uses stdin/stdout; no-network VMs use vsock.
#
# Bwrap-net and user run in bubblewrap. VM-Net is started with QEMU.
#
# The examples share a private state root. Bwrap-net and user share the host network
# namespace. VM-Net's TCP ports are forwarded from QEMU user networking.
#
#   $SSH_MESH_EXAMPLE_ROOT/shared
#
# Binaries are expected in PATH; package-scoped install locations are prepended
# for host and test layouts.

examples_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd "${examples_dir}/../.." 2>/dev/null && pwd)"
target_dir="${SSH_MESH_TARGET_DIR:-${workspace_dir}/target}"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-${target_dir}/examples}"
default_nix_profile="${target_dir}/nix/profile"
if [ ! -e "${default_nix_profile}" ] && [ -e "${target_dir}/nix/profiles" ]; then
  default_nix_profile="${target_dir}/nix/profiles"
fi
nix_profile="${NIX_PROFILE:-${default_nix_profile}}"
staged_opt="${SSH_MESH_OPT_DIR:-${root_dir}/opt}"
staged_bin_dir="${staged_opt}/ssh-mesh/bin"
log_dir="${root_dir}/logs"
run_dir="${root_dir}/run"
pid_file="${run_dir}/start_all.pids"

export NIX_PROFILE="${nix_profile}"
export SSH_MESH_EXAMPLE_ROOT="${root_dir}"
export SSH_MESH_OPT_DIR="${staged_opt}"
export SSH_MESH_EXAMPLE_BIN_DIR="${SSH_MESH_EXAMPLE_BIN_DIR:-${staged_bin_dir}}"
export PATH="${SSH_MESH_EXAMPLE_BIN_DIR}:/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${NIX_PROFILE}/bin:${PATH}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need bwrap
need qemu-system-x86_64
need setsid

mkdir -p "${log_dir}" "${run_dir}" "${root_dir}/shared"

example_bin_src=""
if [ -x "${workspace_dir}/target/x86_64-unknown-linux-musl/release/ssh-mesh" ]; then
  example_bin_src="${workspace_dir}/target/x86_64-unknown-linux-musl/release"
elif [ -x "${workspace_dir}/target/debug/ssh-mesh" ]; then
  example_bin_src="${workspace_dir}/target/debug"
fi

if [ -n "${example_bin_src}" ] && [ -x "${workspace_dir}/scripts/build.sh" ]; then
  "${workspace_dir}/scripts/build.sh" stage_examples \
    "${example_bin_src}" \
    "${root_dir}" \
    "${staged_opt}"
fi

need mesh-init
need ssh-mesh

# Try to locate the VM assets
if [ -n "${SSH_MESH_VM_NET_VM_DIR:-}" ]; then
  vm_dir="${SSH_MESH_VM_NET_VM_DIR}"
elif [ -n "${SSH_MESH_BOB_VM_DIR:-}" ]; then
  vm_dir="${SSH_MESH_BOB_VM_DIR}"
elif [ -d "${workspace_dir}/result-default" ]; then
  vm_dir="${workspace_dir}/result-default"
elif [ -d "${examples_dir}/share/bob-vm" ]; then
  vm_dir="${examples_dir}/share/bob-vm"
elif [ -d "${nix_profile}/opt/ssh-mesh/share/bob-vm" ]; then
  vm_dir="${nix_profile}/opt/ssh-mesh/share/bob-vm"
else
  vm_dir="/opt/ssh-mesh/share/bob-vm"
fi

# Locate kernel
if [ -f "${vm_dir}/img/vmlinux-cloud" ]; then
  kernel="${vm_dir}/img/vmlinux-cloud"
elif [ -f "${nix_profile}/img/vmlinux-cloud" ]; then
  kernel="${nix_profile}/img/vmlinux-cloud"
elif [ -f "${vm_dir}/bzImage" ]; then
  kernel="${vm_dir}/bzImage"
else
  kernel="${SSH_MESH_VM_NET_KERNEL:-${SSH_MESH_BOB_KERNEL:-${vm_dir}/bzImage}}"
fi

# Locate rootfs
if [ -f "${vm_dir}/img/ssh-mesh.erofs" ]; then
  rootfs="${vm_dir}/img/ssh-mesh.erofs"
elif [ -f "${vm_dir}/initos.erofs" ]; then
  rootfs="${vm_dir}/initos.erofs"
else
  rootfs="${SSH_MESH_VM_NET_ROOTFS:-${SSH_MESH_BOB_ROOTFS:-${vm_dir}/initos.erofs}}"
fi

vm_artifact_dir="${root_dir}/vm-artifacts"
mkdir -p "${vm_artifact_dir}"
cp -f "${kernel}" "${vm_artifact_dir}/vmlinux-cloud"
cp -f "${rootfs}" "${vm_artifact_dir}/ssh-mesh.erofs"
export SSH_MESH_VM_NONET_KERNEL="${SSH_MESH_VM_NONET_KERNEL:-/tmp/mesh/state/vm-artifacts/vmlinux-cloud}"
export SSH_MESH_VM_NONET_ROOTFS="${SSH_MESH_VM_NONET_ROOTFS:-/tmp/mesh/state/vm-artifacts/ssh-mesh.erofs}"

vm_host_ssh_port="${SSH_MESH_VM_NET_HOST_SSH_PORT:-${SSH_MESH_BOB_HOST_SSH_PORT:-18322}}"
vm_host_http_port="${SSH_MESH_VM_NET_HOST_HTTP_PORT:-${SSH_MESH_BOB_HOST_HTTP_PORT:-18380}}"

if [ ! -r "${kernel}" ] || [ ! -r "${rootfs}" ]; then
  cat >&2 <<EOF
VM-Net requires a readable kernel and rootfs to start the VM example.

Build it with:
  nix build .#default -o result-default

Then set:
  SSH_MESH_VM_NET_VM_DIR=/path/to/result-default

Or set:
  SSH_MESH_VM_NET_KERNEL=/path/to/bzImage
  SSH_MESH_VM_NET_ROOTFS=/path/to/initos.erofs

To run only the bwrap nodes:
  ./bwrap-net/start.sh
  ./user/start.sh
EOF
  exit 2
fi

user_key="${examples_dir}/user/home/user/.ssh/id_ecdsa"
user_cert="${examples_dir}/user/home/user/.ssh/id_ecdsa-user-cert.pub"
bwrap_net_key="${examples_dir}/bwrap-net/home/bwrap-net/.ssh/id_ecdsa"
bwrap_net_cert="${examples_dir}/bwrap-net/home/bwrap-net/.ssh/id_ecdsa-user-cert.pub"
vm_net_key="${examples_dir}/vm-net/home/vm-net/.ssh/id_ecdsa"
vm_net_cert="${examples_dir}/vm-net/home/vm-net/.ssh/id_ecdsa-user-cert.pub"

for key_file in \
  "${user_key}" "${user_cert}" \
  "${bwrap_net_key}" "${bwrap_net_cert}" \
  "${vm_net_key}" "${vm_net_cert}"
do
  if [ ! -r "${key_file}" ]; then
    echo "missing example SSH key/certificate: ${key_file}" >&2
    echo "regenerate with: docs/examples/generate_keys.sh" >&2
    exit 2
  fi
done

node_pids=""
node_pgroups=""
cleanup_done=0

stop_pids() {
  pids="$1"
  [ -n "${pids}" ] || return 0

  for pid in ${pids}; do
    pgid="$(ps -o pgid= -p "${pid}" 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -n "${pgid}" ]; then
      kill -TERM "-${pgid}" >/dev/null 2>&1 || true
    fi
  done
  for pid in ${pids}; do
    kill -TERM "${pid}" >/dev/null 2>&1 || true
  done

  for _ in 1 2 3 4 5; do
    live=0
    for pid in ${pids}; do
      if kill -0 "${pid}" >/dev/null 2>&1; then
        live=1
      fi
    done
    [ "${live}" = "0" ] && return 0
    sleep 1
  done

  for pid in ${pids}; do
    pgid="$(ps -o pgid= -p "${pid}" 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -n "${pgid}" ]; then
      kill -KILL "-${pgid}" >/dev/null 2>&1 || true
    fi
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  done
}

find_existing_example_pids() {
  ps -eo pid=,args= | while read -r pid args; do
    case "${args}" in
      *"${root_dir}"*)
        case "${args}" in
          *" bwrap "*|*" mesh-init"*|*" ssh-mesh"*|*" qemu-system-"*|*" crosvm "*|*" cloud-hypervisor "*|*" virtiofsd "*)
            printf '%s\n' "${pid}"
            ;;
        esac
        ;;
    esac
  done
}

stop_existing_examples() {
  pids=""
  if [ -r "${pid_file}" ]; then
    pids="$(tr '\n' ' ' <"${pid_file}")"
  fi

  found_pids="$(find_existing_example_pids | tr '\n' ' ')"
  if [ -n "${found_pids}" ]; then
    pids="${pids} ${found_pids}"
  fi

  if [ -n "${pids}" ]; then
    echo "stopping existing example processes"
    stop_pids "${pids}"
  fi
  : >"${pid_file}"
}

cleanup() {
  if [ "${cleanup_done}" = "1" ]; then
    return
  fi
  cleanup_done=1

  trap - INT TERM EXIT

  for pgid in ${node_pgroups}; do
    kill -TERM "-${pgid}" >/dev/null 2>&1 || true
  done
  for pid in ${node_pids}; do
    kill -TERM "${pid}" >/dev/null 2>&1 || true
  done

  for _ in 1 2 3 4 5; do
    live=0
    for pid in ${node_pids}; do
      if kill -0 "${pid}" >/dev/null 2>&1; then
        live=1
      fi
    done
    if [ "${live}" = "0" ]; then
      break
    fi
    sleep 1
  done

  for pgid in ${node_pgroups}; do
    kill -KILL "-${pgid}" >/dev/null 2>&1 || true
  done
  for pid in ${node_pids}; do
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  done
  rm -f "${pid_file}"
  wait >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

stop_existing_examples

start_node() {
  node="$1"
  log="${log_dir}/${node}.log"
  echo "starting ${node}; log=${log}"
  setsid "${examples_dir}/${node}/start.sh" >"${log}" 2>&1 &
  pid="$!"
  node_pgroups="${node_pgroups} ${pid}"
  node_pids="${node_pids} ${pid}"
  printf '%s\n' "${pid}" >>"${pid_file}"
}

start_node bwrap-net
start_node vm-net
start_node user

cat <<EOF

ssh-mesh example mesh is starting.

State root:
  ${root_dir}

Logs:
  ${log_dir}/bwrap-net.log
  ${log_dir}/vm-net.log
  ${log_dir}/user.log

Fixed listeners:
  bwrap-net: ssh 127.0.0.1:18222, http 127.0.0.1:18280
  vm-net:    qemu hostfwd ssh 127.0.0.1:${vm_host_ssh_port}, http 127.0.0.1:${vm_host_http_port}
  user:      ssh 127.0.0.1:18422, http 127.0.0.1:18480

Trusted UDS sockets:
  ${root_dir}/shared/bwrap-nonet/trusted.sock  (activated by user mesh-init)
  ${root_dir}/shared/vm-net/trusted.sock
  ${root_dir}/shared/vm-nonet-qemu/trusted.sock (activated by user mesh-init, qemu vsock)
  ${root_dir}/shared/vm-nonet-crosvm/trusted.sock (activated by user mesh-init, crosvm vsock)
  ${root_dir}/shared/vm-nonet-ch/trusted.sock (activated by user mesh-init, cloud-hypervisor vsock)
  ${root_dir}/shared/user/trusted.sock

HTTP URLs from crates/ssh-mesh route mappings:
  bwrap-net admin UI:       http://127.0.0.1:18280/_m/adm
  bwrap-net SSH clients:    http://127.0.0.1:18280/_m/api/ssh/clients
  bwrap-net SSH config API: http://127.0.0.1:18280/_m/api/sshc/config/hosts
  bwrap-net OpenAPI:        http://127.0.0.1:18280/_m/api/openapi.json
  bwrap-net SSH over H2C:   http://127.0.0.1:18280/_m/_ssh
  bwrap-net TCP proxy:      http://127.0.0.1:18280/_m/_tcp/127.0.0.1/22
  bwrap-net UDS proxy:      http://127.0.0.1:18280/_m/_uds/home/bwrap-net/.run/pmond/control.sock

  vm-net admin UI:          http://127.0.0.1:${vm_host_http_port}/_m/adm
  vm-net SSH clients:       http://127.0.0.1:${vm_host_http_port}/_m/api/ssh/clients
  vm-net SSH config API:    http://127.0.0.1:${vm_host_http_port}/_m/api/sshc/config/hosts
  vm-net OpenAPI:           http://127.0.0.1:${vm_host_http_port}/_m/api/openapi.json
  vm-net SSH over H2C:      http://127.0.0.1:${vm_host_http_port}/_m/_ssh
  vm-net TCP proxy:         http://127.0.0.1:${vm_host_http_port}/_m/_tcp/127.0.0.1/22
  vm-net UDS proxy:         http://127.0.0.1:${vm_host_http_port}/_m/_uds/home/vm-net/.run/pmond/control.sock

  user admin UI:            http://127.0.0.1:18480/_m/adm
  user SSH clients:         http://127.0.0.1:18480/_m/api/ssh/clients
  user SSH config API:      http://127.0.0.1:18480/_m/api/sshc/config/hosts
  user OpenAPI:             http://127.0.0.1:18480/_m/api/openapi.json
  user SSH over H2C:        http://127.0.0.1:18480/_m/_ssh
  user TCP proxy:           http://127.0.0.1:18480/_m/_tcp/127.0.0.1/22
  user UDS proxy:           http://127.0.0.1:18480/_m/_uds/home/user/.run/pmond/control.sock

Seeded SSH keys:
  main node key/cert homes are checked in under:
    ${examples_dir}/bwrap-net/home/bwrap-net/.ssh
    ${examples_dir}/user/home/user/.ssh
    ${examples_dir}/vm-net/home/vm-net/.ssh
  regenerate them with:
    ${examples_dir}/generate_keys.sh

Example SSH shells:
  # Keep the SSH username explicit. If omitted, OpenSSH uses the local account name,
  # which is not a principal in the example user certificate.
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 user@127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@bwrap-net.example.m 127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@vm-net.example.m 127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@bwrap-nonet.example.m 127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@vm-nonet-qemu.example.m 127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@vm-nonet-crosvm.example.m 127.0.0.1
  ssh -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@vm-nonet-ch.example.m 127.0.0.1

Example pmond local forwards:
  ssh -N -F /dev/null -i "${bwrap_net_key}" -o IdentitiesOnly=yes -o CertificateFile="${bwrap_net_cert}" -o ControlMaster=no -o ControlPath=none -p 18222 \\
    -L 127.0.0.1:19282:/home/bwrap-net/.run/pmond/control.sock \\
    bwrap-net@127.0.0.1
  curl http://127.0.0.1:19282/_m/pmon/_ps

  ssh -N -F /dev/null -i "${vm_net_key}" -o IdentitiesOnly=yes -o CertificateFile="${vm_net_cert}" -o ControlMaster=no -o ControlPath=none -p ${vm_host_ssh_port} \\
    -L 127.0.0.1:19283:/home/vm-net/.run/pmond/control.sock \\
    vm-net@127.0.0.1
  curl http://127.0.0.1:19283/_m/pmon/_ps

  ssh -N -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -L 127.0.0.1:19284:/home/user/.run/pmond/control.sock \\
    user@127.0.0.1
  curl http://127.0.0.1:19284/_m/pmon/_ps

  ssh -N -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@bwrap-nonet.example.m \\
    -L 127.0.0.1:19285:/home/bwrap-nonet/.run/pmond/control.sock \\
    127.0.0.1
  curl http://127.0.0.1:19285/_m/pmon/_ps

  ssh -N -F /dev/null -i "${user_key}" -o IdentitiesOnly=yes -o CertificateFile="${user_cert}" -o ControlMaster=no -o ControlPath=none -p 18422 \\
    -l system@vm-nonet-qemu.example.m \\
    -L 127.0.0.1:19286:/home/vm-nonet-qemu/.run/pmond/control.sock \\
    127.0.0.1
  curl http://127.0.0.1:19286/_m/pmon/_ps

Press Ctrl-C to stop all example nodes.
EOF

wait

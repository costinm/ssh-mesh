#!/usr/bin/env bash
set -euo pipefail

# Start the full example mesh:
#
#   host1:    gateway host on SSH 18422 / HTTP 18480
#   host2:    remote host on SSH 18222 / HTTP 18280
#   host3-vm: worker VM host on SSH 18322 / HTTP 18380
#
# The host1 node installs mesh-init activation sockets for app1-bwrap.
# Host3-vm installs activation sockets for app2/app3/app4 VM apps.
#
# Host2 and host1 run in bubblewrap. Host3-vm is started with QEMU.
#
# The examples share a private state root. Host2 and host1 share the host network
# namespace. Host3-vm's TCP ports are forwarded from QEMU user networking.
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
if [ -n "${SSH_MESH_HOST3_VM_DIR:-}" ]; then
  vm_dir="${SSH_MESH_HOST3_VM_DIR}"
elif [ -d "${workspace_dir}/result-default" ]; then
  vm_dir="${workspace_dir}/result-default"
elif [ -d "${examples_dir}/share/host3-vm-vm" ]; then
  vm_dir="${examples_dir}/share/host3-vm-vm"
elif [ -d "${nix_profile}/opt/ssh-mesh/share/host3-vm-vm" ]; then
  vm_dir="${nix_profile}/opt/ssh-mesh/share/host3-vm-vm"
else
  vm_dir="/opt/ssh-mesh/share/host3-vm-vm"
fi

# Locate kernel
if [ -f "${vm_dir}/img/vmlinux-cloud" ]; then
  kernel="${vm_dir}/img/vmlinux-cloud"
elif [ -f "${nix_profile}/img/vmlinux-cloud" ]; then
  kernel="${nix_profile}/img/vmlinux-cloud"
elif [ -f "${vm_dir}/bzImage" ]; then
  kernel="${vm_dir}/bzImage"
else
  kernel="${SSH_MESH_HOST3_VM_KERNEL:-${vm_dir}/bzImage}"
fi

# Locate rootfs
if [ -f "${vm_dir}/img/ssh-mesh.erofs" ]; then
  rootfs="${vm_dir}/img/ssh-mesh.erofs"
elif [ -f "${vm_dir}/initos.erofs" ]; then
  rootfs="${vm_dir}/initos.erofs"
else
  rootfs="${SSH_MESH_HOST3_VM_ROOTFS:-${vm_dir}/initos.erofs}"
fi

vm_artifact_dir="${root_dir}/vm-artifacts"
mkdir -p "${vm_artifact_dir}"
cp -f "${kernel}" "${vm_artifact_dir}/vmlinux-cloud"
cp -f "${rootfs}" "${vm_artifact_dir}/ssh-mesh.erofs"
export SSH_MESH_APP_VM_KERNEL="${SSH_MESH_APP_VM_KERNEL:-/tmp/mesh/state/vm-artifacts/vmlinux-cloud}"
export SSH_MESH_APP_VM_ROOTFS="${SSH_MESH_APP_VM_ROOTFS:-/tmp/mesh/state/vm-artifacts/ssh-mesh.erofs}"

vm_host_ssh_port="${SSH_MESH_HOST3_VM_HOST_SSH_PORT:-18322}"
vm_host_http_port="${SSH_MESH_HOST3_VM_HOST_HTTP_PORT:-18380}"

if [ ! -r "${kernel}" ] || [ ! -r "${rootfs}" ]; then
  cat >&2 <<EOF
Host3-vm requires a readable kernel and rootfs to start the VM example.

Build it with:
  nix build .#default -o result-default

Then set:
  SSH_MESH_HOST3_VM_DIR=/path/to/result-default

Or set:
  SSH_MESH_HOST3_VM_KERNEL=/path/to/bzImage
  SSH_MESH_HOST3_VM_ROOTFS=/path/to/initos.erofs

To run only the bwrap nodes:
  ./host2/start.sh
  ./host1/start.sh
EOF
  exit 2
fi

host1_key="${examples_dir}/host1/home/system/.ssh/id_ecdsa"
host1_cert="${examples_dir}/host1/home/system/.ssh/id_ecdsa-user-cert.pub"
host2_key="${examples_dir}/host2/home/system/.ssh/id_ecdsa"
host2_cert="${examples_dir}/host2/home/system/.ssh/id_ecdsa-user-cert.pub"
host3_key="${examples_dir}/host3-vm/home/system/.ssh/id_ecdsa"
host3_cert="${examples_dir}/host3-vm/home/system/.ssh/id_ecdsa-user-cert.pub"
ssh_config="${examples_dir}/ssh_config"

for key_file in \
  "${host1_key}" "${host1_cert}" \
  "${host2_key}" "${host2_cert}" \
  "${host3_key}" "${host3_cert}" \
  "${ssh_config}"
do
  if [ ! -r "${key_file}" ]; then
    echo "missing example SSH key/certificate/config: ${key_file}" >&2
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

start_node host2
start_node host3-vm
start_node host1

cat <<EOF

ssh-mesh example mesh is starting.

State root:
  ${root_dir}

Logs:
  ${log_dir}/host2.log
  ${log_dir}/host3-vm.log
  ${log_dir}/host1.log

Fixed listeners:
  host2: ssh 127.0.0.1:18222, http 127.0.0.1:18280
  host3-vm: qemu hostfwd ssh 127.0.0.1:${vm_host_ssh_port}, http 127.0.0.1:${vm_host_http_port}
  host1: ssh 127.0.0.1:18422, http 127.0.0.1:18480

Trusted UDS sockets:
  ${root_dir}/shared/app1-bwrap/trusted.sock  (activated by host1 mesh-init)
  ${root_dir}/shared/host3-vm/trusted.sock
  ${root_dir}/shared/app2-qemu/trusted.sock (activated by host3-vm mesh-init, qemu vsock)
  ${root_dir}/shared/app3-crosvm/trusted.sock (activated by host3-vm mesh-init, crosvm vsock)
  ${root_dir}/shared/app4-ch/trusted.sock (activated by host3-vm mesh-init, cloud-hypervisor vsock)
  ${root_dir}/shared/host1/trusted.sock

HTTP URLs from crates/ssh-mesh route mappings:
  host2 admin UI:       http://127.0.0.1:18280/_m/adm
  host2 SSH clients:    http://127.0.0.1:18280/_m/api/ssh/clients
  host2 SSH config API: http://127.0.0.1:18280/_m/api/sshc/config/hosts
  host2 OpenAPI:        http://127.0.0.1:18280/_m/api/openapi.json
  host2 SSH over H2C:   http://127.0.0.1:18280/_m/_ssh
  host2 TCP proxy:      http://127.0.0.1:18280/_m/_tcp/127.0.0.1/22
  host2 UDS proxy:      http://127.0.0.1:18280/_m/_uds/home/system/.run/pmond/control.sock

  host3-vm admin UI:          http://127.0.0.1:${vm_host_http_port}/_m/adm
  host3-vm SSH clients:       http://127.0.0.1:${vm_host_http_port}/_m/api/ssh/clients
  host3-vm SSH config API:    http://127.0.0.1:${vm_host_http_port}/_m/api/sshc/config/hosts
  host3-vm OpenAPI:           http://127.0.0.1:${vm_host_http_port}/_m/api/openapi.json
  host3-vm SSH over H2C:      http://127.0.0.1:${vm_host_http_port}/_m/_ssh
  host3-vm TCP proxy:         http://127.0.0.1:${vm_host_http_port}/_m/_tcp/127.0.0.1/22
  host3-vm UDS proxy:         http://127.0.0.1:${vm_host_http_port}/_m/_uds/home/system/.run/pmond/control.sock

  host1 admin UI:            http://127.0.0.1:18480/_m/adm
  host1 SSH clients:         http://127.0.0.1:18480/_m/api/ssh/clients
  host1 SSH config API:      http://127.0.0.1:18480/_m/api/sshc/config/hosts
  host1 OpenAPI:             http://127.0.0.1:18480/_m/api/openapi.json
  host1 SSH over H2C:        http://127.0.0.1:18480/_m/_ssh
  host1 TCP proxy:           http://127.0.0.1:18480/_m/_tcp/127.0.0.1/22
  host1 UDS proxy:           http://127.0.0.1:18480/_m/_uds/home/system/.run/pmond/control.sock

Seeded SSH keys:
  main node key/cert homes are checked in under:
    ${examples_dir}/host2/home/system/.ssh
    ${examples_dir}/host1/home/system/.ssh
    ${examples_dir}/host3-vm/home/system/.ssh
  regenerate them with:
    ${examples_dir}/generate_keys.sh

SSH config:
  cd ${examples_dir}
  ssh -F ssh_config <host-alias>

Example SSH shells:
  ssh -F ssh_config host1
  ssh -F ssh_config host2
  ssh -F ssh_config host3-vm
  ssh -F ssh_config app1-bwrap
  ssh -F ssh_config app2-qemu
  ssh -F ssh_config app3-crosvm
  ssh -F ssh_config app4-ch

Direct SSH shells:
  ssh -F ssh_config host2-direct
  ssh -F ssh_config -p ${vm_host_ssh_port} host3-vm-direct

Example pmond local forwards:
  ssh -N -F ssh_config \\
    -L 127.0.0.1:19282:/home/system/.run/pmond/control.sock \\
    host2-direct
  curl http://127.0.0.1:19282/_m/pmon/_ps

  ssh -N -F ssh_config -p ${vm_host_ssh_port} \\
    -L 127.0.0.1:19283:/home/system/.run/pmond/control.sock \\
    host3-vm-direct
  curl http://127.0.0.1:19283/_m/pmon/_ps

  ssh -N -F ssh_config \\
    -L 127.0.0.1:19284:/home/system/.run/pmond/control.sock \\
    host1
  curl http://127.0.0.1:19284/_m/pmon/_ps

  ssh -N -F ssh_config \\
    -L 127.0.0.1:19285:/home/app1/.run/pmond/control.sock \\
    app1-bwrap
  curl http://127.0.0.1:19285/_m/pmon/_ps

  ssh -N -F ssh_config \\
    -L 127.0.0.1:19286:/home/app2/.run/pmond/control.sock \\
    app2-qemu
  curl http://127.0.0.1:19286/_m/pmon/_ps

Press Ctrl-C to stop all example nodes.
EOF

wait

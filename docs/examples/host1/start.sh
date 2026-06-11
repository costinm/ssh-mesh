#!/usr/bin/env bash
set -euo pipefail

# Start the host1-mode example in bubblewrap using installed binaries.
#
# Unlike host2, this script does not remap to uid 0. mesh-init runs as the
# invoking non-root host1 and uses its ordinary HOME-relative defaults.

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
examples_dir="$(cd "${example_dir}/.." && pwd)"
workspace_dir="$(cd "${examples_dir}/../.." 2>/dev/null && pwd)"
target_dir="${SSH_MESH_TARGET_DIR:-${workspace_dir}/target}"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-${target_dir}/examples}"
default_nix_profile="${target_dir}/nix/profile"
if [ ! -e "${default_nix_profile}" ] && [ -e "${target_dir}/nix/profiles" ]; then
  default_nix_profile="${target_dir}/nix/profiles"
fi
nix_profile="${NIX_PROFILE:-${default_nix_profile}}"
inner_nix_profile="${nix_profile}"
staged_opt="${SSH_MESH_OPT_DIR:-}"
if [ -z "${staged_opt}" ] && [ -d "${nix_profile}/opt" ]; then
  staged_opt="${nix_profile}/opt"
elif [ -z "${staged_opt}" ] && [ -d /opt ]; then
  staged_opt="/opt"
fi
staged_bin_dir="${staged_opt:+${staged_opt}/ssh-mesh/bin}"
export NIX_PROFILE="${nix_profile}"
export SSH_MESH_EXAMPLE_ROOT="${root_dir}"
export SSH_MESH_EXAMPLE_BIN_DIR="${SSH_MESH_EXAMPLE_BIN_DIR:-${staged_bin_dir:-${root_dir}/bin}}"
export PATH="${SSH_MESH_EXAMPLE_BIN_DIR}:/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${NIX_PROFILE}/bin:${PATH}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need bwrap
need mesh-init
need ssh-mesh
need pmond
need lmesh
need h2t

node="host1"
state_dir="${root_dir}/${node}"
home_dir="${state_dir}/home/system"
shared_dir="${root_dir}/shared"
package_bwrap_args=()
device_bwrap_args=()
if [ -d /nix ]; then
  package_bwrap_args+=(--ro-bind /nix /nix)
fi
if [ -e "${nix_profile}" ]; then
  nix_profile_real="$(readlink -f "${nix_profile}")"
  inner_nix_profile="/nix-profile"
  package_bwrap_args+=(
    --ro-bind "${nix_profile_real}" "${inner_nix_profile}"
  )
fi
if [ -d "${SSH_MESH_EXAMPLE_BIN_DIR}" ]; then
  package_bwrap_args=(
    "${package_bwrap_args[@]}"
    --dir /out
    --dir /out/ssh-mesh
    --ro-bind "${SSH_MESH_EXAMPLE_BIN_DIR}" /out/ssh-mesh/bin
  )
elif [ -d /out/ssh-mesh ]; then
  package_bwrap_args+=(
    --dir /out
    --ro-bind /out/ssh-mesh /out/ssh-mesh
  )
fi
if [ -n "${staged_opt}" ] && [ -d "${staged_opt}" ]; then
  package_bwrap_args+=(
    --ro-bind "${staged_opt}" /opt
  )
fi
for host_dir in /bin /usr /lib /lib64; do
  if [ -e "${host_dir}" ]; then
    package_bwrap_args+=(
      --ro-bind "${host_dir}" "${host_dir}"
    )
  fi
done
for host_dev in /dev/kvm /dev/vhost-vsock; do
  if [ -e "${host_dev}" ]; then
    device_bwrap_args+=(
      --dev-bind "${host_dev}" "${host_dev}"
    )
  fi
done
rm -rf "${shared_dir}/app2" "${shared_dir}/app2-vsock"
mkdir -p \
  "${home_dir}/.config/mesh-init" \
  "${home_dir}/.config/ssh-mesh" \
  "${home_dir}/.run/mesh-init" \
  "${home_dir}/.run/ssh-mesh/mux" \
  "${home_dir}/.ssh" \
  "${shared_dir}/${node}" \
  "${shared_dir}/app1-bwrap" \
  "${shared_dir}/app2-qemu" \
  "${shared_dir}/app3-crosvm" \
  "${shared_dir}/app4-ch"

for app_home in "${example_dir}/home/"*; do
  [ -d "${app_home}" ] || continue
  app_name="$(basename "${app_home}")"
  mkdir -p "${state_dir}/home/${app_name}"
  cp -a "${app_home}/." "${state_dir}/home/${app_name}/"
done
chmod 700 "${home_dir}/.ssh"
chmod 600 "${home_dir}/.ssh/config" "${home_dir}/.ssh/id_ecdsa" 2>/dev/null || true
chmod 644 "${home_dir}/.ssh/"*.pub "${home_dir}/.ssh/authorized_cas" 2>/dev/null || true

echo "host1 HOME: ${home_dir}"
echo "host1 shared sockets: ${shared_dir}/${node}"

exec bwrap \
  --tmpfs / \
  "${package_bwrap_args[@]}" \
  --dev /dev \
  "${device_bwrap_args[@]}" \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir /home/system \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  --ro-bind "${examples_dir}" /examples \
  --bind "${root_dir}" /tmp/mesh/state \
  --bind "${home_dir}" /home/system \
  --bind "${shared_dir}" /tmp/mesh/shared \
  --unshare-pid \
  --unshare-uts \
  --share-net \
  --as-pid-1 \
  --hostname ssh-mesh-host1 \
  --chdir /home/system \
  --setenv HOME /home/system \
  --setenv USER system \
  --setenv LOGNAME system \
  --setenv PATH "/out/ssh-mesh/bin:/opt/ssh-mesh/bin:/opt/busybox/bin:${inner_nix_profile}/bin:${PATH}" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  --setenv SSH_MESH_EXAMPLE_ROOT /tmp/mesh/state \
  --setenv SSH_MESH_OPT_DIR /tmp/mesh/state/opt \
  --setenv NIX_PROFILE "${inner_nix_profile}" \
  --setenv SSH_MESH_APP_VM_KERNEL "${SSH_MESH_APP_VM_KERNEL:-}" \
  --setenv SSH_MESH_APP_VM_ROOTFS "${SSH_MESH_APP_VM_ROOTFS:-}" \
  mesh-init "$@"

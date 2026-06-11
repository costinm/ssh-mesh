#!/usr/bin/env bash
set -euo pipefail

# Start host2 in bubblewrap using installed binaries.
#
# This example intentionally uses the default HOME-relative runtime layout:
#
#   $HOME/.config/mesh-init
#   $HOME/.config/ssh-mesh
#   $HOME/.ssh
#   $HOME/.run
#
# The only ssh-mesh-specific override is MESH_INIT_SOCK, because host2 runs as
# uid 0 inside the bwrap host1 namespace while mesh-init is kept in the
# HOME-relative host1 layout for readability.

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

node="host2"
state_dir="${root_dir}/${node}"
home_dir="${state_dir}/home/system"
shared_dir="${root_dir}/shared"
package_bwrap_args=()
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

mkdir -p \
  "${home_dir}/.config/mesh-init" \
  "${home_dir}/.config/ssh-mesh" \
  "${home_dir}/.run/mesh-init" \
  "${home_dir}/.run/ssh-mesh/mux" \
  "${home_dir}/.ssh" \
  "${shared_dir}/${node}"

if [ -d "${example_dir}/home/system" ]; then
  cp -a "${example_dir}/home/system/." "${home_dir}/"
fi
chmod 700 "${home_dir}/.ssh"
chmod 600 "${home_dir}/.ssh/config" "${home_dir}/.ssh/id_ecdsa" 2>/dev/null || true
chmod 644 "${home_dir}/.ssh/"*.pub "${home_dir}/.ssh/authorized_cas" 2>/dev/null || true

echo "host2 HOME: ${home_dir}"
echo "host2 shared sockets: ${shared_dir}/${node}"

exec bwrap \
  --tmpfs / \
  "${package_bwrap_args[@]}" \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir /home/system \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  --bind "${home_dir}" /home/system \
  --bind "${shared_dir}" /tmp/mesh/shared \
  --unshare-user \
  --uid 0 \
  --gid 0 \
  --unshare-pid \
  --unshare-uts \
  --share-net \
  --hostname ssh-mesh-host2 \
  --chdir /home/system \
  --setenv HOME /home/system \
  --setenv USER system \
  --setenv LOGNAME system \
  --setenv PATH "/out/ssh-mesh/bin:/opt/ssh-mesh/bin:/opt/busybox/bin:${inner_nix_profile}/bin:${PATH}" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  --setenv NIX_PROFILE "${inner_nix_profile}" \
  --setenv MESH_INIT_SOCK /home/system/.run/mesh-init/control.sock \
  mesh-init

#!/usr/bin/env bash
set -euo pipefail

# Start app1-bwrap in bubblewrap using installed binaries.
#
# Default mode starts mesh-init in a private network namespace. The --stdio mode
# is intended for mesh-init socket activation: the parent mesh-init accepts a
# trusted UDS connection and this script runs ssh-mesh over that inherited
# stdin/stdout stream.
#
# This example intentionally uses the default HOME-relative runtime layout:
#
#   $HOME/.config/mesh-init
#   $HOME/.config/ssh-mesh
#   $HOME/.ssh
#   $HOME/.run
#
# The only ssh-mesh-specific override is MESH_INIT_SOCK, because app1-bwrap runs as
# uid 0 inside the bwrap host1 namespace while mesh-init is kept in the
# HOME-relative host1 layout for readability.

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
examples_dir="$(cd "${example_dir}/../../.." && pwd)"
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
need ssh-mesh

mode="${1:-}"
case "${mode}" in
  daemon|--daemon) mode="daemon" ;;
  stdio|--stdio) mode="stdio" ;;
  *)
    echo "usage: $0 [--daemon|--stdio]" >&2
    exit 2
    ;;
esac
shift

if [ "${mode}" = "daemon" ]; then
  need mesh-init
  need pmond
  need lmesh
  need h2t
fi

mode_bwrap_env=()
mode_command=(mesh-init)
if [ "${mode}" = "stdio" ]; then
  mode_bwrap_env=(
    --setenv SSH_MESH_TRUSTED_STDIO 1
    --setenv SSH_PORT 0
    --setenv HTTP_PORT 0
    --setenv RUST_LOG off
  )
  mode_command=(
    /opt/busybox/bin/sh
    -c
    'mkdir -p "$HOME/.run/pmond"; MESH_LOG_FILE="$HOME/.run/pmond/pmond.log" pmond --uds control.sock >/dev/null 2>&1 & exec ssh-mesh'
  )
fi

node="app1-bwrap"
app_home="app1"
state_dir="${root_dir}/${node}"
home_dir="${state_dir}/home/${app_home}"
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

cp -a "${example_dir}/." "${home_dir}/"
if [ -e "${nix_profile}" ]; then
  ln -sfn "${inner_nix_profile}" "${home_dir}/nix-profile"
fi
chmod 700 "${home_dir}/.ssh"
chmod 600 "${home_dir}/.ssh/config"

if [ "${mode}" != "stdio" ]; then
  echo "app1-bwrap HOME: ${home_dir}"
  echo "app1-bwrap shared sockets: ${shared_dir}/${node}"
fi

exec bwrap \
  --tmpfs / \
  "${package_bwrap_args[@]}" \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir /home/app1 \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  --bind "${home_dir}" /home/app1 \
  --bind "${shared_dir}" /tmp/mesh/shared \
  --unshare-user \
  --uid 0 \
  --gid 0 \
  --as-pid-1 \
  --unshare-pid \
  --unshare-uts \
  --unshare-net \
  --hostname ssh-mesh-app1-bwrap \
  --chdir /home/app1 \
  --setenv HOME /home/app1 \
  --setenv USER app1 \
  --setenv LOGNAME app1 \
  --setenv PATH "/out/ssh-mesh/bin:/opt/ssh-mesh/bin:/opt/busybox/bin:${inner_nix_profile}/bin:${PATH}" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  --setenv NIX_PROFILE "${inner_nix_profile}" \
  --setenv MESH_INIT_SOCK /home/app1/.run/mesh-init/control.sock \
  "${mode_bwrap_env[@]}" \
  "${mode_command[@]}" "$@"

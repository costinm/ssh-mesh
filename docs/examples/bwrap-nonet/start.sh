#!/usr/bin/env bash
set -euo pipefail

# Start bwrap-nonet in bubblewrap using installed binaries.
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
# The only ssh-mesh-specific override is MESH_INIT_SOCK, because bwrap-nonet runs as
# uid 0 inside the bwrap user namespace while mesh-init is kept in the
# HOME-relative user layout for readability.

export PATH="/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${PATH}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need bwrap
need ssh-mesh

mode="${1:-daemon}"
case "${mode}" in
  daemon|--daemon) mode="daemon" ;;
  stdio|--stdio) mode="stdio" ;;
  *)
    echo "usage: $0 [--daemon|--stdio]" >&2
    exit 2
    ;;
esac

if [ "${mode}" = "daemon" ]; then
  need mesh-init
  need pmond
  need lmesh
  need mcp-pmond
  need h2t
fi

mode_bwrap_env=()
mode_command=(mesh-init)
if [ "${mode}" = "stdio" ]; then
  mode_bwrap_env=(
    --setenv SSH_MESH_TRUSTED_STDIO 1
    --setenv SSH_PORT 0
    --setenv HTTP_PORT 0
  )
  mode_command=(ssh-mesh)
fi

node="bwrap-nonet"
example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-${HOME}/.local/share/ssh-mesh/examples}"
state_dir="${root_dir}/${node}"
home_dir="${state_dir}/home/${node}"
shared_dir="${root_dir}/shared"
package_bwrap_args=()
if [ -d /nix ]; then
  package_bwrap_args+=(--ro-bind /nix /nix)
fi
if [ -d /out/ssh-mesh ]; then
  package_bwrap_args+=(
    --dir /out
    --ro-bind /out/ssh-mesh /out/ssh-mesh
  )
fi
if [ -e /opt/ssh-mesh ]; then
  package_bwrap_args+=(
    --dir /opt
    --ro-bind /opt/ssh-mesh /opt/ssh-mesh
  )
fi
if [ -n "${SSH_MESH_EXAMPLE_BIN_DIR:-}" ]; then
  package_bwrap_args=(
    "${package_bwrap_args[@]}"
    --dir /out
    --dir /out/ssh-mesh
    --ro-bind "${SSH_MESH_EXAMPLE_BIN_DIR}" /out/ssh-mesh/bin
  )
fi

mkdir -p \
  "${home_dir}/.config/mesh-init" \
  "${home_dir}/.config/ssh-mesh" \
  "${home_dir}/.run/mesh-init" \
  "${home_dir}/.run/ssh-mesh/mux" \
  "${home_dir}/.ssh" \
  "${shared_dir}/${node}"

cp "${example_dir}/config/mesh-init/"*.toml "${home_dir}/.config/mesh-init/"
cp "${example_dir}/config/ssh-mesh/mesh.yaml" "${home_dir}/.config/ssh-mesh/mesh.yaml"
cp "${example_dir}/config/ssh/config" "${home_dir}/.ssh/config"
chmod 700 "${home_dir}/.ssh"
chmod 600 "${home_dir}/.ssh/config"

echo "bwrap-nonet HOME: ${home_dir}"
echo "bwrap-nonet shared sockets: ${shared_dir}/${node}"

exec bwrap \
  --tmpfs / \
  "${package_bwrap_args[@]}" \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir /home/bwrap-nonet \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  --bind "${home_dir}" /home/bwrap-nonet \
  --bind "${shared_dir}" /tmp/mesh/shared \
  --unshare-user \
  --uid 0 \
  --gid 0 \
  --unshare-pid \
  --unshare-uts \
  --unshare-net \
  --hostname ssh-mesh-bwrap-nonet \
  --chdir /home/bwrap-nonet \
  --setenv HOME /home/bwrap-nonet \
  --setenv USER bwrap-nonet \
  --setenv LOGNAME bwrap-nonet \
  --setenv PATH "/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${PATH}" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  --setenv MESH_INIT_SOCK /home/bwrap-nonet/.run/mesh-init/control.sock \
  "${mode_bwrap_env[@]}" \
  "${mode_command[@]}"

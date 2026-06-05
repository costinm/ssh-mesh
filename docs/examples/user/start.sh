#!/usr/bin/env bash
set -euo pipefail

# Start the user-mode example in bubblewrap using installed binaries.
#
# Unlike alice, this script does not remap to uid 0. mesh-init runs as the
# invoking non-root user and uses its ordinary HOME-relative defaults.

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
need pmond
need lmesh
need mcp-pmond
need h2t

node="user"
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

echo "user HOME: ${home_dir}"
echo "user shared sockets: ${shared_dir}/${node}"

exec bwrap \
  --tmpfs / \
  "${package_bwrap_args[@]}" \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir /home/user \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  --bind "${home_dir}" /home/user \
  --bind "${shared_dir}" /tmp/mesh/shared \
  --unshare-pid \
  --unshare-uts \
  --share-net \
  --hostname ssh-mesh-user \
  --chdir /home/user \
  --setenv HOME /home/user \
  --setenv USER user \
  --setenv LOGNAME user \
  --setenv PATH "/out/ssh-mesh/bin:/opt/ssh-mesh/bin:${PATH}" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  mesh-init

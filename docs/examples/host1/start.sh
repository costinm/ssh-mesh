#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
examples_dir="$(cd "${example_dir}/.." && pwd)"
workspace_dir="$(cd "${examples_dir}/../.." 2>/dev/null && pwd)"
target_dir="${SSH_MESH_TARGET_DIR:-${workspace_dir}/target}"
root_dir="${1:-${target_dir}/examples}"
if [ "$#" -gt 0 ]; then
  shift
fi

default_nix_profile="${target_dir}/nix/profile"
if [ ! -e "${default_nix_profile}" ] && [ -e "${target_dir}/nix/profiles" ]; then
  default_nix_profile="${target_dir}/nix/profiles"
fi
staged_opt="${target_dir}/dist/opt"

mkdir -p \
  "${root_dir}/shared/host1" \
  "${root_dir}/shared/app1-bwrap" \
  "${root_dir}/shared/app2-qemu" \
  "${root_dir}/shared/app3-crosvm" \
  "${root_dir}/shared/app4-ch" \
  "${root_dir}/shared/app5-vm" \
  "${root_dir}/vm-artifacts"

rm -rf "${root_dir}/shared/app2" "${root_dir}/shared/app2-vsock"

for artifact in vmlinux-cloud ssh-mesh.erofs modules-cloud.erofs; do
  if [ -r "${target_dir}/dist/img/${artifact}" ]; then
    cp -f "${target_dir}/dist/img/${artifact}" "${root_dir}/vm-artifacts/${artifact}"
  fi
done

export NIX_PROFILE="${NIX_PROFILE:-${default_nix_profile}}"
export SSH_MESH_OPT_DIR="${staged_opt}"
export SSH_MESH_STATE_ROOT="${root_dir}"
export SSH_MESH_APP_NAME=host1
export SSH_MESH_APP_HOME=system
export SSH_MESH_APP_TEMPLATE_DIR="${example_dir}"
export SSH_MESH_APP_STATE_DIR="${root_dir}/host1"
export SSH_MESH_APP_HOME_DIR="${root_dir}/host1/home/system"
export SSH_MESH_SHARED_DIR="${root_dir}/shared"
export SSH_MESH_BWRAP_COPY_HOME_SET=1
export SSH_MESH_BWRAP_BIND_STATE=1
export SSH_MESH_BWRAP_ROOT=0
export SSH_MESH_BWRAP_NET=share
export SSH_MESH_BWRAP_DEVICES=1

exec "${staged_opt}/ssh-mesh/bin/run_bwrap.sh" "$@"

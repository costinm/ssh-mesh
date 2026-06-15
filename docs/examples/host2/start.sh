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

mkdir -p "${root_dir}/shared/host2"

export NIX_PROFILE="${NIX_PROFILE:-${default_nix_profile}}"
export SSH_MESH_OPT_DIR="${staged_opt}"
export SSH_MESH_STATE_ROOT="${root_dir}"
export SSH_MESH_APP_NAME=host2
export SSH_MESH_APP_HOME=system
export SSH_MESH_APP_TEMPLATE_DIR="${example_dir}/home/system"
export SSH_MESH_APP_STATE_DIR="${root_dir}/host2"
export SSH_MESH_APP_HOME_DIR="${root_dir}/host2/home/system"
export SSH_MESH_SHARED_DIR="${root_dir}/shared"
export SSH_MESH_BWRAP_ROOT=1
export SSH_MESH_BWRAP_NET=share

exec "${staged_opt}/ssh-mesh/bin/run_bwrap.sh" "$@"

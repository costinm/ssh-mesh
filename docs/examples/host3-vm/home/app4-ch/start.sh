#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SSH_MESH_VM_NODE="${SSH_MESH_VM_NODE:-$(basename "${script_dir}")}"
exec "${script_dir}/run-app" "$@"

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run_bwrap.sh [--daemon|--stdio]

Environment:
  SSH_MESH_APP_NAME          instance name, for example host1 or app1-bwrap
  SSH_MESH_APP_HOME          home basename inside the sandbox, for example system
  SSH_MESH_APP_TEMPLATE_DIR  source home template, or a host dir with home/*
  SSH_MESH_EXAMPLE_ROOT      mutable state root mounted by the parent host
  SSH_MESH_OPT_DIR           staged package tree mounted as /opt
EOF
}

mode="${1:---daemon}"
case "${mode}" in
  daemon|--daemon) mode="daemon" ;;
  stdio|--stdio) mode="stdio" ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac
if [ "$#" -gt 0 ]; then
  shift
fi

app="${SSH_MESH_APP_NAME:-${SSH_MESH_BWRAP_APP:-app1-bwrap}}"
app_home="${SSH_MESH_APP_HOME:-app1}"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-/tmp/mesh/state}"
template_dir="${SSH_MESH_APP_TEMPLATE_DIR:-${root_dir}/host1/home/${app}}"
state_dir="${SSH_MESH_APP_STATE_DIR:-${root_dir}/${app}}"
home_dir="${SSH_MESH_APP_HOME_DIR:-${state_dir}/home/${app_home}}"
shared_dir="${SSH_MESH_SHARED_DIR:-${root_dir}/shared}"
nix_profile="${NIX_PROFILE:-/nix-profile}"
inner_nix_profile="${nix_profile}"
opt_dir="${SSH_MESH_OPT_DIR:-}"

mkdir -p \
  "${home_dir}/.config/mesh-init" \
  "${home_dir}/.config/ssh-mesh" \
  "${home_dir}/.run/mesh-init" \
  "${home_dir}/.run/ssh-mesh/mux" \
  "${home_dir}/.ssh" \
  "${shared_dir}" \
  "${state_dir}/run"

if [ "${SSH_MESH_BWRAP_COPY_HOME_SET:-0}" != "0" ] && [ -d "${template_dir}/home" ]; then
  for template_home in "${template_dir}/home/"*; do
    [ -d "${template_home}" ] || continue
    name="$(basename "${template_home}")"
    mkdir -p "${state_dir}/home/${name}"
    cp -R "${template_home}/." "${state_dir}/home/${name}/"
  done
elif [ -d "${template_dir}" ]; then
  cp -R "${template_dir}/." "${home_dir}/"
fi

if [ -n "${SSH_MESH_HOST3_VM_HOST_SSH_PORT:-}" ] && [ -f "${home_dir}/.config/ssh-mesh/mesh.yaml" ]; then
  sed -i \
    "s/port: 18322/port: ${SSH_MESH_HOST3_VM_HOST_SSH_PORT}/g" \
    "${home_dir}/.config/ssh-mesh/mesh.yaml"
fi

if [ -e "${nix_profile}" ]; then
  inner_nix_profile="/nix-profile"
  ln -sfn "${inner_nix_profile}" "${home_dir}/nix-profile"
fi
chmod 700 "${home_dir}/.ssh" 2>/dev/null || true
chmod 600 "${home_dir}/.ssh/config" "${home_dir}/.ssh/id_ecdsa" 2>/dev/null || true
chmod 644 "${home_dir}/.ssh/"*.pub "${home_dir}/.ssh/authorized_cas" 2>/dev/null || true

package_args=()
if [ -z "${opt_dir}" ]; then
  if [ -d /opt/ssh-mesh ] && [ -d /opt/busybox ]; then
    opt_dir=/opt
  else
    echo "run_bwrap.sh requires SSH_MESH_OPT_DIR or host /opt/ssh-mesh and /opt/busybox" >&2
    exit 2
  fi
fi
package_args+=(--ro-bind "${opt_dir}" /opt)
if [ -d /nix ]; then
  package_args+=(--ro-bind /nix /nix)
fi
if [ -e "${nix_profile}" ]; then
  package_args+=(--ro-bind "$(readlink -f "${nix_profile}")" "${inner_nix_profile}")
fi

state_args=(--dir /tmp/mesh/state)
if [ "${SSH_MESH_BWRAP_BIND_STATE:-0}" != "0" ]; then
  state_args=(--bind "${root_dir}" /tmp/mesh/state)
fi

user_args=()
if [ "${SSH_MESH_BWRAP_ROOT:-1}" != "0" ]; then
  user_args=(--unshare-user --uid 0 --gid 0)
elif [ "${SSH_MESH_BWRAP_USERNS:-0}" != "0" ]; then
  user_args=(--unshare-user)
fi

net_args=(--unshare-net)
if [ "${SSH_MESH_BWRAP_NET:-none}" = "share" ]; then
  net_args=(--share-net)
fi

device_args=()
if [ "${SSH_MESH_BWRAP_DEVICES:-0}" != "0" ]; then
  for host_dev in /dev/kvm /dev/vhost-vsock; do
    if [ -e "${host_dev}" ]; then
      device_args+=(--dev-bind "${host_dev}" "${host_dev}")
    fi
  done
fi

mode_env=()
mode_command=(mesh-init)
if [ "${mode}" = "stdio" ]; then
  mode_env=(
    --setenv SSH_MESH_TRUSTED_STDIO 1
    --setenv SSH_PORT 0
    --setenv HTTP_PORT 0
    --setenv RUST_LOG off
  )
  mode_command=(
    /opt/busybox/bin/sh
    -c
    'mkdir -p "$HOME/.run/mesh-init" "$HOME/.run/pmond" "$HOME/.config/mesh-init-stdio"; MESH_INIT_DIR="$HOME/.config/mesh-init-stdio" MESH_INIT_RUN="$HOME/.run/mesh-init" MESH_LOG_FILE="$HOME/.run/mesh-init/mesh-init.log" mesh-init >/dev/null 2>&1 & for i in $(seq 1 50); do [ -S "$HOME/.run/mesh-init/control.sock" ] && break; sleep 0.1; done; MESH_LOG_FILE="$HOME/.run/pmond/pmond.log" pmond --uds control.sock >/dev/null 2>&1 & exec ssh-mesh'
  )
else
  echo "${app} HOME: ${home_dir}"
  echo "${app} shared sockets: ${shared_dir}"
fi

exec bwrap \
  --tmpfs / \
  "${package_args[@]}" \
  --dev /dev \
  "${device_args[@]}" \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /home \
  --dir "/home/${app_home}" \
  --dir /tmp/mesh \
  --dir /tmp/mesh/shared \
  "${state_args[@]}" \
  --bind "${home_dir}" "/home/${app_home}" \
  --bind "${shared_dir}" /tmp/mesh/shared \
  "${user_args[@]}" \
  --as-pid-1 \
  --unshare-pid \
  --unshare-uts \
  "${net_args[@]}" \
  --hostname "ssh-mesh-${app}" \
  --chdir "/home/${app_home}" \
  --setenv HOME "/home/${app_home}" \
  --setenv USER "${app_home}" \
  --setenv LOGNAME "${app_home}" \
  --setenv PATH "/opt/ssh-mesh/bin:/opt/busybox/bin:${inner_nix_profile}/bin" \
  --setenv RUST_LOG "${RUST_LOG:-info}" \
  --setenv NIX_PROFILE "${inner_nix_profile}" \
  --setenv SSH_MESH_EXAMPLE_ROOT /tmp/mesh/state \
  --setenv MESH_INIT_SOCK "/home/${app_home}/.run/mesh-init/control.sock" \
  --setenv SSH_MESH_HOME_ROOT /home \
  "${mode_env[@]}" \
  "${mode_command[@]}" "$@"

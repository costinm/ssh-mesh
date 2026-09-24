#!/usr/bin/env bash
# start_bwrap.sh - start mesh-init inside a read-mostly bwrap sandbox, then
# run a command in the same namespace once the mesh-init control socket is up.
#
# Production- and test-oriented: components run from a staged package tree
# (target/dist/opt after scripts/build.sh, or `result-sshm` from a nix
# build); /run, /home and /tmp are fresh tmpfs. When the mesh-init control
# socket appears, the requested command runs and the sandbox exits.
#
# Usage:
#   scripts/start_bwrap.sh --bin DIR [--exec CMD [ARG...]] [options]
#
# Options:
#   --bin DIR              required. Directory with the release binaries
#                          (ssh-mesh, mesh-init, mesh), mounted read-only at
#                          /opt/ssh-mesh/bin. With scripts/build.sh this is
#                          target/dist/opt/ssh-mesh/bin; with a nix build
#                          pass result-sshm/bin.
#   --opt-dir DIR          staged opt tree mounted read-only at /opt (adds
#                          /opt/busybox); optional.
#   --mount SRC:DST[:ro]   extra bind mount, repeatable, for per-app assets
#                          and state paths.
#   --mesh-init-config DIR directory of mesh-init service toml files, bind
#                          mounted at /run/mesh-init-etc with
#                          MESH_INIT_DIR set there. Without it mesh-init
#                          starts with default (seeded) config.
#   --user UID[:GID]       run the payload as UID:GID; needs util-linux
#                          /usr/bin/unshare --map-auto (subuid namespace).
#                          Without it the sandbox runs as mapped root
#                          (bwrap --unshare-user).
#   --no-wait              do not wait for the mesh-init control socket.
#   --exec CMD [ARG...]    required. Command run after the sandbox is ready.
#
# Environment: RUST_LOG, MESH_INIT_SOCK (default
# /run/mesh/mesh-init/mesh.sock), SSH_PORT, HTTP_PORT, plus whatever the
# command needs. All are propagated into the sandbox.
set -euo pipefail

bin_dir=""
opt_dir=""
mesh_init_config=""
user_spec=""
do_wait="yes"
extra_mount_args=()

MESH_INIT_SOCK="${MESH_INIT_SOCK:-/run/mesh/mesh-init/mesh.sock}"
MESH_INIT_CONFIG_DIR_IN_NS="${MESH_INIT_CONFIG_DIR_IN_NS:-/run/mesh-init-etc}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin) bin_dir="$2"; shift 2 ;;
    --opt-dir) opt_dir="$2"; shift 2 ;;
    --mesh-init-config) mesh_init_config="$2"; shift 2 ;;
    --user) user_spec="$2"; shift 2 ;;
    --no-wait) do_wait="no"; shift ;;
    --mount) extra_mount_args+=("$2"); shift 2 ;;
    --exec) shift; break ;;
    -h|--help|help)
      awk '
        /^# / { sub(/^# /, ""); print }
      ' "$0"
      exit 0
      ;;
    *)
      printf 'start_bwrap.sh: unknown argument %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [ "$#" -eq 0 ]; then
  printf 'start_bwrap.sh: nothing to --exec\n' >&2
  exit 2
fi
exec_args=("$@")

if [ ! -d "${bin_dir}" ]; then
  printf 'start_bwrap.sh: --bin directory %s missing\n' "${bin_dir}" >&2
  exit 1
fi

if [ -n "${user_spec}" ] && [ ! -x /usr/bin/unshare ]; then
  printf 'start_bwrap.sh: --user requires /usr/bin/unshare --map-auto\n' >&2
  exit 1
fi

bin_dir="$(readlink -f "${bin_dir}")"
[ -n "${opt_dir}" ] && opt_dir="$(readlink -f "${opt_dir}")"
[ -n "${mesh_init_config}" ] && mesh_init_config="$(readlink -f "${mesh_init_config}")"

# Host-side staging of the inner shell: a scratch dir bind-mounted at
# /run/start-bwrap inside the namespace.
scratch_dir="$(mktemp -d -t ssh-mesh-start-bwrap.XXXXXX)"
trap 'rm -rf "${scratch_dir:-}"' EXIT

cat > "${scratch_dir}/entry.sh" <<'ENTRY'
#!/usr/bin/env bash
# Inner PID 1: start mesh-init, wait for the control socket, exec CMD.
set -euo pipefail

export PATH="/opt/ssh-mesh/bin:/usr/bin:/bin"

mesh-init &
mesh_init_pid=$!
trap 'kill "${mesh_init_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 200); do
  [ -S "${MESH_INIT_SOCK}" ] && break
  kill -0 "${mesh_init_pid}" 2>/dev/null || {
    printf 'start_bwrap.sh: mesh-init exited before %s appeared\n' "${MESH_INIT_SOCK}" >&2
    exit 1
  }
  sleep 0.25
done

[ -S "${MESH_INIT_SOCK}" ] || {
  printf 'start_bwrap.sh: mesh-init control socket never appeared: %s\n' "${MESH_INIT_SOCK}" >&2
  exit 1
}

if [ "${START_BWRAP_DO_WAIT:-yes}" != "no" ]; then
  exec "$@"
else
  # Run the command in the same namespace and keep mesh-init alive for it.
  "$@" &
  payload_pid=$!
  wait "${payload_pid}"
fi
ENTRY

chmod 755 "${scratch_dir}/entry.sh"

# 1. Base mounts: bin dirs, device/proc, fresh tmpfs. The base is identical
#    every run.
bwrap_args=(
  --ro-bind /bin /bin
  --ro-bind /usr /usr
  --ro-bind /lib /lib
  --ro-bind-try /lib64 /lib64
  --ro-bind /etc /etc
  --ro-bind "${bin_dir}" /opt/ssh-mesh/bin
  --dev /dev
  --proc /proc
  --tmpfs /tmp
  --tmpfs /home
  --tmpfs /run
  --dir /run/mesh
  --bind "${scratch_dir}" /run/start-bwrap
)

# 2. Staged opt tree (build.sh outcome), if the caller mounted one.
if [ -n "${opt_dir}" ]; then
  if [ -d "${opt_dir}" ]; then
    bwrap_args+=(--ro-bind "${opt_dir}" /opt)
  else
    printf 'start_bwrap.sh: --opt-dir %s missing\n' "${opt_dir}" >&2
    exit 1
  fi
fi

# 3. Additional per-component mounts; DST defaults to rw.
for mount_arg in "${extra_mount_args[@]:-}"; do
  [ -n "${mount_arg}" ] || continue
  mount_src="${mount_arg%%:*}"
  mount_rest="${mount_arg#*:}"
  case "${mount_rest}" in
    *:ro)
      bwrap_args+=(--ro-bind "${mount_src}" "${mount_rest%:*}")
      ;;
    *)
      bwrap_args+=(--bind "${mount_src}" "${mount_rest}")
      ;;
  esac
done

# 4. Environment passed into the sandbox.
env_args=(
  --setenv PATH "/opt/ssh-mesh/bin:/usr/bin:/bin"
  --setenv RUST_LOG "${RUST_LOG:-info}"
  --setenv MESH_INIT_SOCK "${MESH_INIT_SOCK}"
  --setenv START_BWRAP_DO_WAIT "${do_wait}"
)
if [ -n "${SSH_PORT:-}" ]; then
  env_args+=(--setenv SSH_PORT "${SSH_PORT}")
fi
if [ -n "${HTTP_PORT:-}" ]; then
  env_args+=(--setenv HTTP_PORT "${HTTP_PORT}")
fi

# 5. mesh-init config dir: mount the caller's staging directory read-only and
#    point MESH_INIT_DIR there.
if [ -n "${mesh_init_config}" ]; then
  if [ -d "${mesh_init_config}" ]; then
    bwrap_args+=(--ro-bind "${mesh_init_config}" "${MESH_INIT_CONFIG_DIR_IN_NS}")
    env_args+=(--setenv MESH_INIT_DIR "${MESH_INIT_CONFIG_DIR_IN_NS}")
  else
    printf 'start_bwrap.sh: --mesh-init-config %s is not a directory\n' "${mesh_init_config}" >&2
    exit 1
  fi
fi

# 6. Payload identity: default is mapped root (bwrap --unshare-user);
#    --user UID[:GID] switches to an outer util-linux subuid namespace.
if [ -n "${user_spec}" ]; then
  user_uid="${user_spec%%:*}"
  user_gid="${user_spec##*:}"
  [ -n "${user_gid}" ] || user_gid="${user_uid}"
else
  user_uid=""
  user_gid=""
  user_uid="0"
  user_gid="0"
  bwrap_args+=(--unshare-user --uid 0 --gid 0)
fi

# Launch. Root runs the entry directly; sub-uid namespaces run through the
# util-linux unshare wrapper.
if [ "${user_spec:-}" != "" ]; then
  /usr/bin/unshare \
    --user \
    --map-auto \
    --fork \
    -- \
    bwrap "${bwrap_args[@]}" \
      "${env_args[@]}" \
      --setenv START_BWRAP_UID "${user_uid}" \
      /bin/bash /run/start-bwrap/entry.sh \
      setpriv --reuid "${user_uid}" --regid "${user_gid}" --clear-groups \
      -- \
      "${exec_args[@]}"
else
  bwrap "${bwrap_args[@]}" \
    "${env_args[@]}" \
    /bin/bash /run/start-bwrap/entry.sh \
    "${exec_args[@]}"
fi

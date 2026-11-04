# Source from the repository root before starting Codex or running repo scripts.
# Runtime state uses the normal home/shared service layout. Build toolchains
# and their caches stay under target/.

if [ -n "${BASH_SOURCE:-}" ]; then
    _env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _env_dir="$(pwd)"
fi

# This checkout owns its build/cache roots. Do not inherit another project's
# REPO_ROOT when env.sh is sourced from a parent shell.
export REPO_ROOT="${_env_dir}"
export REAL_HOME="${REAL_HOME:-${HOME:-}}"

if [ "${HOME:-}" = "${REPO_ROOT}/target/home" ]; then
    export HOME="${REAL_HOME}"
fi
if [ -n "${SSH_MESH_LOCAL_HOME:-}" ]; then
    export HOME="${SSH_MESH_LOCAL_HOME}"
fi
export CODEX_HOME="${CODEX_HOME:-${REAL_HOME}/.codex}"

for _xdg_pair in XDG_CACHE_HOME:cache XDG_CONFIG_HOME:config XDG_DATA_HOME:share XDG_STATE_HOME:state; do
    _xdg_name="${_xdg_pair%%:*}"
    _xdg_old="${_xdg_pair#*:}"
    if [ "${!_xdg_name:-}" = "${REPO_ROOT}/target/${_xdg_old}" ]; then
        unset "${_xdg_name}"
    fi
done
export XDG_CACHE_HOME="${SSH_MESH_XDG_CACHE_HOME:-${XDG_CACHE_HOME:-${HOME}/.cache}}"
export XDG_CONFIG_HOME="${SSH_MESH_XDG_CONFIG_HOME:-${XDG_CONFIG_HOME:-${HOME}/.config}}"
export XDG_DATA_HOME="${SSH_MESH_XDG_DATA_HOME:-${XDG_DATA_HOME:-${HOME}/.local/share}}"
export XDG_STATE_HOME="${SSH_MESH_XDG_STATE_HOME:-${XDG_STATE_HOME:-${HOME}/.local/state}}"

export NIX_PROFILE="${SSH_MESH_NIX_PROFILE:-${REPO_ROOT}/target/nix/profile}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"

if [ "${MESH_HOME:-}" = "${REPO_ROOT}/target/mesh" ]; then unset MESH_HOME; fi
if [ -n "${SSH_MESH_MESH_HOME:-}" ]; then export MESH_HOME="${SSH_MESH_MESH_HOME}"; fi
if [ "${SSH_MESH_STATE_ROOT:-}" = "${REPO_ROOT}/target/ssh-mesh-state" ]; then unset SSH_MESH_STATE_ROOT; fi
export SSH_MESH_STATE_ROOT="${SSH_MESH_STATE_ROOT:-${HOME}/.local/share/ssh-mesh/state}"
if [ "${TMPDIR:-}" = "${REPO_ROOT}/target/tmp" ]; then unset TMPDIR; fi
export TMPDIR="${SSH_MESH_TMPDIR:-${TMPDIR:-/tmp}}"

export CARGO_HOME="${SSH_MESH_CARGO_HOME:-${REPO_ROOT}/target/cargo}"
export RUSTUP_HOME="${SSH_MESH_RUSTUP_HOME:-${REPO_ROOT}/target/rustup}"

mkdir -p \
    "${HOME}" \
    "${XDG_CACHE_HOME}" \
    "${XDG_CONFIG_HOME}" \
    "${XDG_DATA_HOME}" \
    "${XDG_STATE_HOME}" \
    "${TMPDIR}" \
    "${SSH_MESH_STATE_ROOT}" \
    "$(dirname "${NIX_PROFILE}")" \
    "${CARGO_HOME}" \
    "${RUSTUP_HOME}"

_path_prepend() {
    if [ -d "$1" ]; then
        case ":${PATH:-}:" in
            *":$1:"*) ;;
            *) PATH="$1:${PATH:-}" ;;
        esac
    fi
}

_path_force_prepend() {
    if [ -d "$1" ]; then
        PATH="$1:${PATH:-}"
    fi
}

_path_prepend "/nix/var/nix/profiles/default/bin"
_path_prepend "${NIX_PROFILE}/bin"
_path_prepend "${CARGO_HOME}/bin"
_path_prepend "${REPO_ROOT}/target/x86_64-unknown-linux-musl/release"
export PATH

_path_force_prepend "/nix/var/nix/profiles/default/bin"
_path_force_prepend "${NIX_PROFILE}/bin"
_path_force_prepend "${CARGO_HOME}/bin"
_path_force_prepend "${REPO_ROOT}/target/x86_64-unknown-linux-musl/release"
export PATH

unset _env_dir
unset _xdg_pair _xdg_name _xdg_old
unset -f _path_prepend
unset -f _path_force_prepend

# Source from the repository root before starting Codex or running repo scripts.
# It keeps Codex auth/config in the real home while moving general tool state
# into repo-local target/ paths.

if [ -n "${BASH_SOURCE:-}" ]; then
    _env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _env_dir="$(pwd)"
fi

export REPO_ROOT="${REPO_ROOT:-${_env_dir}}"
export REAL_HOME="${REAL_HOME:-${HOME:-}}"

export HOME="${SSH_MESH_LOCAL_HOME:-${REPO_ROOT}/target/home}"
export CODEX_HOME="${CODEX_HOME:-${REAL_HOME}/.codex}"

export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${REPO_ROOT}/target/cache}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${REPO_ROOT}/target/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-${REPO_ROOT}/target/share}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-${REPO_ROOT}/target/state}"

export NIX_PROFILE="${NIX_PROFILE:-${REPO_ROOT}/target/nix/profile}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"

export MESH_HOME="${MESH_HOME:-${REPO_ROOT}/target/mesh}"
export SSH_MESH_STATE_ROOT="${SSH_MESH_STATE_ROOT:-${REPO_ROOT}/target/ssh-mesh-state}"
export TMPDIR="${TMPDIR:-${REPO_ROOT}/target/tmp}"

export CARGO_HOME="${SSH_MESH_CARGO_HOME:-${REPO_ROOT}/target/cargo}"
export RUSTUP_HOME="${SSH_MESH_RUSTUP_HOME:-${REPO_ROOT}/target/rustup}"

mkdir -p \
    "${HOME}" \
    "${XDG_CACHE_HOME}" \
    "${XDG_CONFIG_HOME}" \
    "${XDG_DATA_HOME}" \
    "${XDG_STATE_HOME}" \
    "${TMPDIR}" \
    "${MESH_HOME}" \
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
export PATH

_path_force_prepend "/nix/var/nix/profiles/default/bin"
_path_force_prepend "${NIX_PROFILE}/bin"
_path_force_prepend "${CARGO_HOME}/bin"
export PATH

unset _env_dir
unset -f _path_prepend
unset -f _path_force_prepend

# Source this file from the repo root or fw/esp32 after running scripts/esp32-deps.sh.
if [ -n "${BASH_SOURCE:-}" ]; then
    _fw_esp32_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _fw_esp32_env_dir="$(pwd)"
fi

export REPO_ROOT="${REPO_ROOT:-$(cd "${_fw_esp32_env_dir}/../.." && pwd)}"

if [ -f "${REPO_ROOT}/target/esp32-5.5/env.sh" ]; then
    . "${REPO_ROOT}/target/esp32-5.5/env.sh"
else
    export ESP_ROOT="${REPO_ROOT}/target/esp32-5.5"
    export IDF_PATH="${ESP_ROOT}/esp-idf"
    export IDF_TOOLS_PATH="${ESP_ROOT}/espressif"
    export CARGO_HOME="${ESP_ROOT}/cargo"
    export RUSTUP_HOME="${ESP_ROOT}/rustup"
    export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${REPO_ROOT}/target/cache}"
    export NIX_PROFILE="${NIX_PROFILE:-${REPO_ROOT}/target/nix/profile}"
    export RUST_ESP_TOOLCHAIN_BIN="${RUSTUP_HOME}/toolchains/esp/bin"
    unset IDF_PYTHON_ENV_PATH

    _fw_esp32_path_prepend() {
        if [ -d "$1" ]; then
            case ":${PATH:-}:" in
                *":$1:"*) ;;
                *) PATH="$1:${PATH:-}" ;;
            esac
        fi
    }

    _fw_esp32_path_prepend "/nix/var/nix/profiles/default/bin"
    _fw_esp32_path_prepend "${NIX_PROFILE}/bin"
    _fw_esp32_path_prepend "${CARGO_HOME}/bin"
    _fw_esp32_path_prepend "${IDF_TOOLS_PATH}/python_env/idf5.5_py3.13_env/bin"
    _fw_esp32_path_prepend "${RUST_ESP_TOOLCHAIN_BIN}"
    export PATH
    unset -f _fw_esp32_path_prepend
fi

unset _fw_esp32_env_dir

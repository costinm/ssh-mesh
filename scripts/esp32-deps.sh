#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="${1:-${NIX_PROFILE:-${REPO_ROOT}/target/nix/profile}}"
ESP_ROOT="${ESP_ROOT:-${REPO_ROOT}/target/esp32-5.5}"
ESP_IDF_VERSION="${ESP_IDF_VERSION:-v5.5.4}"

export XDG_CACHE_HOME="${REPO_ROOT}/target/nix/cache"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"
export IDF_TOOLS_PATH="${ESP_ROOT}/espressif"
export CARGO_HOME="${ESP_ROOT}/cargo"
export RUSTUP_HOME="${ESP_ROOT}/rustup"
RUST_ESP_TOOLCHAIN_BIN="${RUSTUP_HOME}/toolchains/esp/bin"
ESP_HOME="${ESP_ROOT}/home"

mkdir -p "${ESP_ROOT}" "${IDF_TOOLS_PATH}" "${CARGO_HOME}" "${RUSTUP_HOME}" "${ESP_HOME}" "${XDG_CACHE_HOME}"

if [ -d "${PROFILE}" ] && [ ! -d "${PROFILE}/bin" ] && [ -e "${PROFILE}/profile" ]; then
    PROFILE="${PROFILE}/profile"
fi

echo "Installing ESP32 host tools into Nix profile: ${PROFILE}"
if [ -d "${PROFILE}" ] && [ ! -L "${PROFILE}" ]; then
    echo "Removing non-symlink directory at ${PROFILE} so Nix can manage the profile..."
    rm -rf "${PROFILE}"
fi
if nix profile list --profile "${PROFILE}" 2>/dev/null | grep -q "esp32-deps"; then
    echo "  esp32-deps: already present"
else
    nix profile add "path:${REPO_ROOT}/fw/esp32#esp32-deps" --profile "${PROFILE}"
fi

export PATH="${PROFILE}/bin:${CARGO_HOME}/bin:${PATH}"

if [ ! -d "${ESP_ROOT}/esp-idf/.git" ]; then
    echo "Cloning ESP-IDF ${ESP_IDF_VERSION} into ${ESP_ROOT}/esp-idf"
    git clone --branch "${ESP_IDF_VERSION}" --depth 1 --recursive \
        https://github.com/espressif/esp-idf.git "${ESP_ROOT}/esp-idf"
else
    echo "ESP-IDF checkout already exists: ${ESP_ROOT}/esp-idf"
    if [ "${ESP32_DEPS_REFRESH:-0}" = "1" ]; then
        git -C "${ESP_ROOT}/esp-idf" fetch --depth 1 origin "refs/tags/${ESP_IDF_VERSION}:refs/tags/${ESP_IDF_VERSION}"
        git -C "${ESP_ROOT}/esp-idf" checkout "${ESP_IDF_VERSION}"
        git -C "${ESP_ROOT}/esp-idf" submodule update --init --recursive --depth 1
    else
        echo "  skipping SDK refresh; set ESP32_DEPS_REFRESH=1 to update submodules"
    fi
fi

echo "Installing ESP-IDF tools under: ${IDF_TOOLS_PATH}"
IDF_TOOLS_PATH="${IDF_TOOLS_PATH}" "${ESP_ROOT}/esp-idf/install.sh" esp32,esp32s3

echo "Installing Rust ESP toolchain under: ${RUSTUP_HOME}"
HOME="${ESP_HOME}" espup install \
    --targets esp32,esp32s3 \
    --export-file "${ESP_ROOT}/export-esp.sh"

cat >"${ESP_ROOT}/env.sh" <<'EOF'
if [ -n "${BASH_SOURCE:-}" ]; then
    _esp_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _esp_env_dir="$(pwd)"
fi

export REPO_ROOT="${REPO_ROOT:-$(cd "${_esp_env_dir}/../.." && pwd)}"
export ESP_ROOT="${ESP_ROOT:-${REPO_ROOT}/target/esp32-5.5}"
export IDF_PATH="${IDF_PATH:-${ESP_ROOT}/esp-idf}"
export IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-${ESP_ROOT}/espressif}"
export CARGO_HOME="${CARGO_HOME:-${ESP_ROOT}/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${ESP_ROOT}/rustup}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${REPO_ROOT}/target/cache}"
export NIX_PROFILE="${NIX_PROFILE:-${REPO_ROOT}/target/nix/profile}"
export RUST_ESP_TOOLCHAIN_BIN="${RUST_ESP_TOOLCHAIN_BIN:-${RUSTUP_HOME}/toolchains/esp/bin}"

_esp_path_prepend() {
    if [ -d "$1" ]; then
        case ":${PATH:-}:" in
            *":$1:"*) ;;
            *) PATH="$1:${PATH:-}" ;;
        esac
    fi
}

_esp_path_force_prepend() {
    if [ -d "$1" ]; then
        PATH="$1:${PATH:-}"
    fi
}

_esp_path_prepend "/nix/var/nix/profiles/default/bin"
_esp_path_prepend "${NIX_PROFILE}/bin"
_esp_path_prepend "${CARGO_HOME}/bin"

if [ -f "${ESP_ROOT}/export-esp.sh" ]; then
    . "${ESP_ROOT}/export-esp.sh"
fi
if [ -f "${IDF_PATH}/export.sh" ]; then
    . "${IDF_PATH}/export.sh"
fi

_esp_path_force_prepend "/nix/var/nix/profiles/default/bin"
_esp_path_force_prepend "${NIX_PROFILE}/bin"
_esp_path_force_prepend "${CARGO_HOME}/bin"
_esp_path_force_prepend "${RUST_ESP_TOOLCHAIN_BIN}"
export PATH

unset _esp_env_dir
unset -f _esp_path_prepend
unset -f _esp_path_force_prepend
EOF

cat >"${REPO_ROOT}/fw/esp32/env.sh" <<'EOF'
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
    export ESP_ROOT="${ESP_ROOT:-${REPO_ROOT}/target/esp32-5.5}"
    export IDF_PATH="${IDF_PATH:-${ESP_ROOT}/esp-idf}"
    export IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-${ESP_ROOT}/espressif}"
    export CARGO_HOME="${CARGO_HOME:-${ESP_ROOT}/cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-${ESP_ROOT}/rustup}"
    export RUST_ESP_TOOLCHAIN_BIN="${RUST_ESP_TOOLCHAIN_BIN:-${RUSTUP_HOME}/toolchains/esp/bin}"
fi

unset _fw_esp32_env_dir
EOF

echo
echo "ESP32 dependencies are ready."
echo "Load them with: . fw/esp32/env.sh"
echo "Build with:     (cd fw/esp32 && idf.py build)"

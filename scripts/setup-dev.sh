#!/usr/bin/env bash
# Populate the environment-specific writable dev workspace under $SSH_MESH_DEV
# (default: $HOME/opt/ssh-mesh-dev) and keep generic SDKs ($HOME/opt/rust and
# $HOME/opt/esp-idf) clean and versionless.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_MESH_DIR="${SSH_MESH_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

find_sibling_repo() {
    local var_val="$1"
    shift
    if [ -n "$var_val" ] && [ -d "$var_val" ]; then
        cd "$var_val" && pwd -P
        return 0
    fi
    for candidate in "$@"; do
        if [ -d "$candidate" ]; then
            cd "$candidate" && pwd -P
            return 0
        fi
    done
    return 1
}

DMESH_DIR="$(find_sibling_repo "${DMESH_DIR:-${DMESH_REPO:-}}" \
    "$SSH_MESH_DIR/../dmesh" \
    "$SSH_MESH_DIR/../../dmesh" \
    /ws/dmesh || true)"
ESP_XIP_DIR="$(find_sibling_repo "${ESP_XIP_DIR:-${XIP_REPO:-}}" \
    "$SSH_MESH_DIR/../esp-xip-modules" \
    "$SSH_MESH_DIR/../../esp-xip-modules" \
    /ws/esp-xip-modules || true)"

RUST_ROOT="${RUST_SDK_ROOT:-$HOME/opt/rust}"
SSH_MESH_DEV="${SSH_MESH_DEV:-$HOME/opt/ssh-mesh-dev}"

mkdir -p \
    "$SSH_MESH_DEV/bin" \
    "$SSH_MESH_DEV/etc/schemas" \
    "$SSH_MESH_DEV/cargo" \
    "$SSH_MESH_DEV/nix"

# Keep $HOME/opt/android-sdk linked if materialized via dmesh flake/dev-env.
if [ ! -e "$HOME/opt/android-sdk" ] && [ -e "$HOME/opt/dmesh-dev/android-sdk" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/dmesh-dev/android-sdk")" "$HOME/opt/android-sdk"
fi

# Keep $HOME/opt/esp-idf -> $HOME/opt/esp-idf-6.0 aligned without referencing target/.
if [ ! -e "$HOME/opt/esp-idf" ] && [ -d "$HOME/opt/esp-idf-6.0" ]; then
    idf_target="$(readlink -f "$HOME/opt/esp-idf-6.0")"
    ln -sfn "$idf_target" "$HOME/opt/esp-idf"
fi

if [ -d "$HOME/opt/esp-idf/rustup/toolchains/esp" ] && [ -d "$RUST_ROOT/rustup/toolchains" ]; then
    ln -sfn "$HOME/opt/esp-idf/rustup/toolchains/esp" "$RUST_ROOT/rustup/toolchains/esp"
fi

# Migrate project-specific binary/schemas/config out of generic $HOME/opt/rust.
if [ -f "$SSH_MESH_DIR/target/x86_64-unknown-linux-musl/release/mesh-api-gen" ]; then
    cp -f "$SSH_MESH_DIR/target/x86_64-unknown-linux-musl/release/mesh-api-gen" "$SSH_MESH_DEV/bin/mesh-api-gen"
    chmod +x "$SSH_MESH_DEV/bin/mesh-api-gen"
elif [ -f "$RUST_ROOT/cargo/bin/mesh-api-gen" ]; then
    mv -f "$RUST_ROOT/cargo/bin/mesh-api-gen" "$SSH_MESH_DEV/bin/mesh-api-gen"
    chmod +x "$SSH_MESH_DEV/bin/mesh-api-gen"
fi
rm -f "$RUST_ROOT/cargo/bin/mesh-api-gen"
rmdir "$RUST_ROOT/cargo/bin" 2>/dev/null || true

if [ -d "$RUST_ROOT/etc/schemas" ]; then
    mkdir -p "$SSH_MESH_DEV/etc/schemas"
    cp -a "$RUST_ROOT/etc/schemas/." "$SSH_MESH_DEV/etc/schemas/"
    rm -rf "$RUST_ROOT/etc"
fi

# Refresh schemas from sibling repos if present.
if [ -n "$ESP_XIP_DIR" ] && [ -d "$ESP_XIP_DIR/target/nix/dmesh-cli/etc/schemas" ]; then
    cp -a "$ESP_XIP_DIR/target/nix/dmesh-cli/etc/schemas/." "$SSH_MESH_DEV/etc/schemas/"
fi
if [ -n "$DMESH_DIR" ] && [ -f "$DMESH_DIR/crates/lmesh/resources/tools.json" ]; then
    mkdir -p "$SSH_MESH_DEV/etc/schemas/lmesh"
    cp -f "$DMESH_DIR/crates/lmesh/resources/tools.json" "$SSH_MESH_DEV/etc/schemas/lmesh/tools.json"
fi

# Move mutable Cargo caches out of $HOME/opt/rust/cargo so $HOME/opt/rust stays generic.
for item in registry git .global-cache .package-cache .package-cache-mutate; do
    if [ -e "$RUST_ROOT/cargo/$item" ]; then
        if [ ! -e "$SSH_MESH_DEV/cargo/$item" ]; then
            mv "$RUST_ROOT/cargo/$item" "$SSH_MESH_DEV/cargo/$item"
        else
            rm -rf "$RUST_ROOT/cargo/$item"
        fi
    fi
done
rm -f "$RUST_ROOT/cargo/config.toml"

# The shared CARGO_HOME config used to carry cross-repo Cargo [patch] blocks.
# They polluted this workspace's Cargo.lock with [[patch.unused]] markers.
# Per-repo patching now lives with the consumers: /ws/dmesh writes its own
# .cargo/config.toml (scripts/build.sh) and /ws/esp-xip-modules keeps [patch]
# tables in its workspace Cargo.toml files.
rm -f "$SSH_MESH_DEV/cargo/config.toml"

# Collect existing nix flake out-links under $SSH_MESH_DEV/nix/.
if [ -e "$HOME/opt/android-sdk" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/android-sdk")" "$SSH_MESH_DEV/nix/android-sdk"
fi
if [ -e "$HOME/opt/esp-idf" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/esp-idf")" "$SSH_MESH_DEV/nix/esp-idf"
fi
if [ -e "$HOME/opt/esp-dev" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/esp-dev")" "$SSH_MESH_DEV/nix/esp-dev"
fi
if [ -e "$HOME/opt/wasm-dev" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/wasm-dev")" "$SSH_MESH_DEV/nix/wasm-dev"
fi
if [ -e "$HOME/opt/dmesh-dev" ]; then
    ln -sfn "$(readlink -f "$HOME/opt/dmesh-dev")" "$SSH_MESH_DEV/nix/dmesh-dev"
fi
if [ -n "$DMESH_DIR" ] && [ -e "$DMESH_DIR/target/nix/profile" ]; then
    ln -sfn "$(readlink -f "$DMESH_DIR/target/nix/profile")" "$SSH_MESH_DEV/nix/dmesh-deps"
fi

echo "SSH_MESH_DEV ready at $SSH_MESH_DEV (RUST_SDK=$RUST_ROOT, ESP_IDF=$HOME/opt/esp-idf)"

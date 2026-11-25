#!/usr/bin/env bash
# Explicit online setup. Normal builds never install dependencies.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -gt 1 || ${1:-} == --help || ${1:-} == -h ]]; then
    echo "Usage: setup-dev.sh [DIR] (default: ~/opt)"
    [[ $# -le 1 ]] && exit 0 || exit 2
fi
mkdir -p "${1:-${DEV_ROOT:-$HOME/opt}}"
export DEV_ROOT="$(cd "${1:-${DEV_ROOT:-$HOME/opt}}" && pwd)"
export SSH_MESH_DEV="${SSH_MESH_DEV:-$DEV_ROOT/ssh-mesh-dev}"
export RUST_SDK_ROOT="${RUST_SDK_ROOT:-$DEV_ROOT/rust}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"
flake="${SSH_MESH_FLAKE:-github:costinm/ssh-mesh}"
mkdir -p "$SSH_MESH_DEV"/{bin,cargo,etc/schemas,nix} "$RUST_SDK_ROOT/rustup/toolchains" "$REPO/target"
# rust-sdk is a plain Rust distribution (bin/, lib/), NOT a rustup home.
# Keep the SDK root writable for the optional ESP toolchain link.
nix build "$flake#rust-sdk" --out-link "$SSH_MESH_DEV/nix/rust-sdk"
stable="$RUST_SDK_ROOT/rustup/toolchains/stable-x86_64-unknown-linux-gnu"
if [[ -e "$stable" && ! -L "$stable" ]]; then
    echo "Keeping existing Rust toolchain directory: $stable"
else
    ln -sfn "$SSH_MESH_DEV/nix/rust-sdk" "$stable"
fi
nix build "$flake#build-deps" --out-link "$SSH_MESH_DEV/nix/build-deps"
nix build "$flake#runtime-deps" --out-link "$SSH_MESH_DEV/nix/runtime-deps"
nix build "$flake#mesh-api-gen" --out-link "$SSH_MESH_DEV/nix/mesh-api-gen"
ln -sfn "$SSH_MESH_DEV/nix/mesh-api-gen/bin/mesh-api-gen" "$SSH_MESH_DEV/bin/mesh-api-gen"
esp="${XIP_ESP_ROOT:-$DEV_ROOT/esp-idf}/rustup/toolchains/esp"
if [[ -d "$esp" && ! -e "$RUST_SDK_ROOT/rustup/toolchains/esp" ]]; then
    ln -s "$esp" "$RUST_SDK_ROOT/rustup/toolchains/esp"
fi
# Copy old schemas/caches only when absent; never delete user config or caches.
if [[ -d "$RUST_SDK_ROOT/etc/schemas" ]]; then
    cp -an "$RUST_SDK_ROOT/etc/schemas/." "$SSH_MESH_DEV/etc/schemas/"
fi
for item in registry git .global-cache .package-cache .package-cache-mutate; do
    if [[ -e "$RUST_SDK_ROOT/cargo/$item" && ! -e "$SSH_MESH_DEV/cargo/$item" ]]; then
        cp -a "$RUST_SDK_ROOT/cargo/$item" "$SSH_MESH_DEV/cargo/$item"
    fi
done
dmesh="${DMESH_DIR:-${DMESH_REPO:-$REPO/../../dmesh}}"
if [[ ! -d "$dmesh" ]]; then dmesh="$REPO/../dmesh"; fi
if [[ -f "$dmesh/crates/lmesh/resources/tools.json" ]]; then
    mkdir -p "$SSH_MESH_DEV/etc/schemas/lmesh"
    cp "$dmesh/crates/lmesh/resources/tools.json" "$SSH_MESH_DEV/etc/schemas/lmesh/tools.json"
fi
xip="${ESP_XIP_DIR:-${XIP_REPO:-$REPO/../../esp-xip-modules}}"
if [[ ! -d "$xip" ]]; then xip="$REPO/../esp-xip-modules"; fi
if [[ -d "$xip/target/nix/dmesh-cli/etc/schemas" ]]; then
    cp -a "$xip/target/nix/dmesh-cli/etc/schemas/." "$SSH_MESH_DEV/etc/schemas/"
fi
{
    printf 'export DEV_ROOT=${DEV_ROOT:-%q}\n' "$DEV_ROOT"
    printf 'export SSH_MESH_DEV=${SSH_MESH_DEV:-%q}\n' "$SSH_MESH_DEV"
    printf 'export RUST_SDK_ROOT=${RUST_SDK_ROOT:-%q}\n' "$RUST_SDK_ROOT"
    printf 'export SSH_MESH_NIX_PROFILE=${SSH_MESH_NIX_PROFILE:-%q}\n' "$SSH_MESH_DEV/nix/build-deps"
    printf 'export SSH_MESH_BUSYBOX=${SSH_MESH_BUSYBOX:-%q}\n' "$SSH_MESH_DEV/nix/runtime-deps/opt/busybox/bin/busybox"
} > "$REPO/target/setup-env.sh"
(
    cd "$REPO"
    unset CARGO_TARGET_DIR
    . ./env.sh
    CARGO_NET_OFFLINE=false cargo fetch --target x86_64-unknown-linux-musl
)
echo "Ready. Run ./scripts/build.sh (SDKs: $DEV_ROOT)."

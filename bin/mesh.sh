#!/bin/sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Script to perform different mesh operations and tests.
PATH=${SCRIPT_DIR}/target/debug:$PATH

set -euo pipefail

# Start mesh 
tun() {
    : "${MESH_TUN_BIN:=mesh-tun}"
    : "${MESH_TUN_CONTROL_SOCKET:=/tmp/mesh-tun-control.sock}"
    : "${MESH_TUN_BWRAP_SOCKET:=/tmp/mesh-tun-bwrap.sock}"
    : "${MESH_TUN_SOCKET:=/tmp/mesh-tun-qemu.sock}"
    : "${MESH_TUN_BWRAP_POOL:=10.5.0.0/24}"
    : "${MESH_TUN_BWRAP_GW:=10.5.0.1}"

    export RUST_LOG=info
    exec env \
    MESH_TUN_MODE=uds \
    MESH_TUN_TCP_REWRITE=false \
    MESH_TUN_CONTROL_SOCKET="$MESH_TUN_CONTROL_SOCKET" \
    MESH_TUN_BWRAP_SOCKET="$MESH_TUN_BWRAP_SOCKET" \
    MESH_TUN_BWRAP_POOL="$MESH_TUN_BWRAP_POOL" \
    MESH_TUN_BWRAP_GW="$MESH_TUN_BWRAP_GW" \
    MESH_TUN_SOCKET="$MESH_TUN_SOCKET" \
    "$MESH_TUN_BIN"
}

# Run bwrap with a TAP using mesh-tun.
# Requires tun to be running.
bwrap_tap() {
    for arg in "$@"; do
    if [ "$arg" = "--" ]; then
        exec "$MESH_TUN_BIN" bwrap "$@"
    fi
    done

    bwrap_args=(
    --unshare-user
    --unshare-net
    --uid 0
    --gid 0
    )

    for dir in /usr /bin /sbin /lib /lib64 /etc /nix; do
    if [ -e "$dir" ]; then
        bwrap_args+=(--ro-bind "$dir" "$dir")
    fi
    done

    bwrap_args+=(
    --dev /dev
    --proc /proc
    --tmpfs /tmp
    )

    exec "$MESH_TUN_BIN" bwrap "${bwrap_args[@]}" -- "$@"
}


"$@"
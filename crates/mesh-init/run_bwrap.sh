#!/bin/bash
set -e

# run_bwrap.sh: Runs mesh-init inside bubblewrap

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target/debug"

echo "Building workspace binaries..."
# Build mesh-init and the test dependency binaries so they can be spawned
cargo build -p mesh-init
cargo build -p ssh-mesh
cargo build -p pmond

echo "Copying test configs..."
bash "${WORKSPACE_DIR}/crates/mesh-init/copy_testdata.sh"

RUN_DIR="/tmp/mesh-init-run"
mkdir -p "$RUN_DIR"
SOCKET="$RUN_DIR/control.sock"

# Bubblewrap command
# We map the root filesystem as read-only, but /tmp and /run as writeable tempfs
# mesh-init will be run from the target directory so it can easily `spawn` sibling binaries
echo "Starting mesh-init via bwrap..."
echo "UDS Control Socket at: ${SOCKET}"
echo "(Press Ctrl+C to stop)"

bwrap \
  --ro-bind / / \
  --dev /dev \
  --proc /proc \
  --bind /sys /sys \
  --tmpfs /tmp \
  --tmpfs /run \
  --bind "${TARGET_DIR}" /tmp/mesh-init \
  --chdir "/tmp/mesh-init" \
  --unshare-pid \
  --share-net \
  --setenv MESH_INIT_DIR /tmp/mesh-init/testdata \
  --setenv MESH_INIT_RUN "$RUN_DIR" \
  /tmp/mesh-init/mesh-init

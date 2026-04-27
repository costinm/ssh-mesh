#!/bin/bash
set -e

# run_podman.sh: Runs mesh-init inside podman using the host rootfs

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target/debug"

echo "Building workspace binaries..."
cargo build -p mesh-init
cargo build -p ssh-mesh
cargo build -p pmond

echo "Copying test configs..."
bash "${WORKSPACE_DIR}/crates/mesh-init/copy_testdata.sh"

RUN_DIR="/tmp/mesh-init-run"
mkdir -p "$RUN_DIR"
SOCKET="$RUN_DIR/control.sock"

# We run podman as a privileged container with host rootfs (for testing the init daemon locally).
# Since it wants --rootfs, we'll map the host's root /.
echo "Starting mesh-init via podman..."
echo "UDS Control Socket at: ${SOCKET}"
echo "(Press Ctrl+C to stop)"

# Ensure we don't accidentally get an permission denied on /tmp for the socket if we don't bind it right.
# --rootfs doesn't take volume arguments mapping the same way, but podman run options can be a bit strict.
# Actually, --rootfs / runs with the host OS as the image so we don't need a container image download.
# We add --privileged since mesh-init needs to mount cgroups or manipulate them.
sudo podman run --rm -it \
  --rootfs / \
  --privileged \
  --network host \
  --workdir "/tmp/mesh-init" \
  -v "${TARGET_DIR}:/tmp/mesh-init" \
  -v /tmp:/tmp \
  -v /run:/run \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -e MESH_INIT_DIR=/tmp/mesh-init/testdata \
  -e MESH_INIT_RUN="$RUN_DIR" \
  /tmp/mesh-init/mesh-init

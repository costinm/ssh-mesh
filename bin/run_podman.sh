#!/bin/bash
set -e

# run_podman.sh: Runs mesh-init inside podman using the host rootfs
# This is opinionated - only app is configurable.

APP=$1
shift

TARGET_DIR="${HOME}/.local/${APP}"
uid="$(id -u)"
mkdir -p "/tmp/${uid}/${APP}" "/run/users/${uid}/${APP}" "$TARGET_DIR"

run1() {
podman unshare bash -c '
  ROOTFS="/tmp/myrootfs_${1}"
  mkdir -p "$ROOTFS"
  mount --bind /mnt/ROOTA "$ROOTFS"
  mount -t tmpfs tmpfs "$ROOTFS/run"
  mount -t tmpfs tmpfs "$ROOTFS/tmp"

  podman run --rm -it \
    --network host \
    --workdir "/z" \
    -v /opt:/opt \
    -v /sys:/sys \
    -v "/run/users/'"${uid}"'/${1}:/run" \
    -v "'"${TARGET_DIR}"':/z" \
    -v /sys/fs/cgroup/mesh.slice:/sys/fs/cgroup \
    --hostname "${1}" \
    -e HOME="'"${HOME}"'" \
    -e RUST_LOG=info \
    --rootfs "$ROOTFS" \
    /opt/ssh-mesh/bin/mesh-init "${@:2}"
' -- "$APP" "$@"
}

# Must prepae $ROOTFS/run and $ROOTFS/tmp as tmpfs volumes
# podman doesn't work otherwise without the extra complexity
# (found by gemini)

podman run --rm -it \
    --network host \
    --workdir "/z" \
    -v /opt:/opt \
    -v /sys:/sys \
    -v "/run/users/"${uid}"/${1}:/run" \
    -v ${TARGET_DIR}:/z \
    -v /sys/fs/cgroup/mesh.slice:/sys/fs/cgroup \
    --hostname "${1}" \
    -e HOME="${HOME}" \
    -e RUST_LOG=info \
    --rootfs /mnt/ROOTA \
    /opt/ssh-mesh/bin/mesh-init "$@"

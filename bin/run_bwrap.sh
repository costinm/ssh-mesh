#!/bin/bash
set -e

# run_bwrap.sh: Runs mesh-init inside bubblewrap with a user app
# This is opinionated - only app is configurable.

APP=$1
shift

# Bubblewrap command
# We map the root filesystem as read-only, but /tmp and /run as writeable tempfs
# mesh-init will be run from the target directory so it can easily `spawn` sibling binaries

TARGET_DIR="${HOME}/.local/${APP}"
uid="$(id -u)"
mkdir -p "/tmp/${uid}/${APP}" "/run/users/${uid}/${APP}" "$TARGET_DIR"

  # --ro-bind /usr /usr \
  # --symlink usr/lib /lib \
  # --symlink usr/bin /bin \


bwrap \
  --unshare-cgroup \
  --dir /sys/fs/cgroup \
  --ro-bind /mnt/ROOTA / \
  --bind /opt /opt \
  --dev /dev \
  --proc /proc \
  --bind /sys /sys \
  --tmpfs /tmp \
  --bind /run/users/${uid}/${APP} /run \
  --bind "${TARGET_DIR}" /z \
  --chdir "/z" \
  --unshare-pid \
  --unshare-user \
  --unshare-uts \
  --share-net \
  --hostname $APP \
  --uid 0 \
  --as-pid-1 \
  --bind /sys/fs/cgroup/mesh.slice /sys/fs/cgroup \
  --setenv HOME ${HOME} \
  --setenv RUST_LOG info \
  /opt/ssh-mesh/bin/mesh-init "$@"

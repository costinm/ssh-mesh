#!/usr/bin/env bash
set -euo pipefail

: "${OUT:?OUT is required}"
: "${KERNEL_CLOUD:?KERNEL_CLOUD is required}"
: "${BOB_ROOTFS:?BOB_ROOTFS is required}"
: "${BOB_CONFIG:?BOB_CONFIG is required}"
: "${BOB_INITOS_POD:?BOB_INITOS_POD is required}"
: "${BOB_RUNNER:?BOB_RUNNER is required}"
: "${SSH_MESH_FULL:?SSH_MESH_FULL is required}"

mkdir -p \
  "${OUT}/share/bob-vm" \
  "${OUT}/share/bob-vm/bin" \
  "${OUT}/share/bob-vm/config" \
  "${OUT}/bin"

cp "${KERNEL_CLOUD}/img/bzImage" "${OUT}/share/bob-vm/bzImage"
cp "${KERNEL_CLOUD}/img/vmlinux" "${OUT}/share/bob-vm/vmlinux"
cp "${KERNEL_CLOUD}/img/config" "${OUT}/share/bob-vm/kernel.config"
cp "${BOB_ROOTFS}/img/bob-rootfs.erofs" "${OUT}/share/bob-vm/bob-rootfs.erofs"
ln -s bob-rootfs.erofs "${OUT}/share/bob-vm/initos.erofs"

for module_image in "${KERNEL_CLOUD}"/img/modules-*.erofs; do
  [ -f "${module_image}" ] && cp "${module_image}" "${OUT}/share/bob-vm/modules-cloud.erofs"
done

cp -R "${BOB_CONFIG}/." "${OUT}/share/bob-vm/config/"
cp "${BOB_INITOS_POD}" "${OUT}/share/bob-vm/initos-pod"
cp "${BOB_RUNNER}" "${OUT}/bin/run-bob-vm"
cp "${SSH_MESH_FULL}"/bin/* "${OUT}/share/bob-vm/bin/"
chmod 0755 "${OUT}/bin/run-bob-vm" "${OUT}/share/bob-vm/initos-pod" "${OUT}"/share/bob-vm/bin/*

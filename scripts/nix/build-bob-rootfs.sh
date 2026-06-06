#!/usr/bin/env bash
set -euo pipefail

: "${OUT:?OUT is required}"
: "${BUSYBOX:?BUSYBOX is required}"
: "${INITOS_INIT_VM:?INITOS_INIT_VM is required}"

root="${TMPDIR:-/tmp}/bob-rootfs"
rm -rf "${root}"

mkdir -p \
  "${root}"/{dev,dev/shm,etc,home/bob,initos,lib,lib/firmware,lib/modules,out/ssh-mesh/bin,proc,run,src,sys,sysroot,tmp/mesh/shared/bob,usr/bin,usr/sbin,var/cache,var/log,x,z} \
  "${root}"/opt/busybox/bin \
  "${root}"/opt/initos/bin \
  "${OUT}"/img

cp "${BUSYBOX}" "${root}/opt/busybox/bin/busybox"
chmod 0755 "${root}/opt/busybox/bin/busybox"

(
  cd "${root}/opt/busybox/bin"
  for applet in $(./busybox --list); do
    case "${applet}" in
      busybox) ;;
      *) ln -s busybox "${applet}" ;;
    esac
  done
)

cp "${INITOS_INIT_VM}" "${root}/opt/initos/bin/initos-init-vm"
chmod 0755 "${root}/opt/initos/bin/initos-init-vm"

ln -s opt/busybox/bin "${root}/bin"
ln -s opt/busybox/bin "${root}/sbin"

mkfs.erofs --all-root --force-uid=0 -T0 -zlz4 "${OUT}/img/bob-rootfs.erofs" "${root}"

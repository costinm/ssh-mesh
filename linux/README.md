# VM support

There are many ways to run a VM - from 'full disk image with GPT and EFI' to micro-VMs.

This fits the 'minimal' category: it does build a kernel, primarily because it is important to have the ability to make changes and include what you want, and to avoid the complex 'initrd' and loading modules for the core functions.

The upstream NixOS kernel is not a good no-initrd VM kernel for this tree. In
the current nixpkgs kernel, the useful early filesystems and VM block/transport
drivers are modules: `erofs`, `ext4`, `squashfs`, `9p`, `virtiofs`, `virtio`,
`virtio-pci`, `virtio-blk`, `virtio-net`, `tun`, and vsock. Putting those
modules in `modules-cloud.erofs` does not solve first boot, because the guest
would need the EROFS module before it can mount the EROFS modules image. The
upstream kernel is suitable if paired with a real initrd; this flake keeps a
custom kernel for the no-initrd path.

Along with the kernel, a small script and Nix flake to 
create an environment and use few common hypervisors - qemu, cloud-hypervisor, crosvm (more can be added): no reason to 
pick one when you can test and use what work better in a specific use case or for testing.

The `vrun` launcher is shipped by the main `ssh-mesh` package, not by this
flake. The default package is a standalone kernel artifact under
`/opt/ssh-mesh-kernel`: it copies the kernel image, config, modules EROFS, and
static BusyBox into one tree so it can be copied to another machine without
bringing hypervisor closures along. Hypervisors are intentionally separate:
`../vm-tools#default` installs qemu, cloud-hypervisor, crosvm, crun, and
virtiofsd for hosts that want a complete local VM test profile. `vrun` detects
the kernel profile and uses hypervisors from `PATH` or explicit `VIRT_*`
overrides.

## Opinionated choices

- custom kernel with enough build-in features to not require initrd and modules for most use cases.
- rootfs is an erofs image with minimal userspace (based on busybox) and including ssh-mesh - since this is what I'm testing and believe should handle the communication.
- virtiofs exposing a shared directory, including startup scripts.
- console used either as a terminal - or as the main ssh connection. If used as a terminal, a vsock is used for ssh.

Network is optional - the expectation is that the mesh will
apply policies and handle communication without having to 
intercept traffic, but with application code using UDS or 
localhost connections.

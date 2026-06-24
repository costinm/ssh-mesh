# VM support

There are many ways to run a VM - from 'full disk image with GPT and EFI' to micro-VMs.

This fits the 'minimal' category: it does build a kernel, primarily because it is important to have the ability to make changes and include what you want, and to avoid the complex 'initrd' and loading modules for the core functions.

Along with the kernel, a small script and Nix flake to 
create an environment and use few common hypervisors - qemu, cloud-hypervisor, crosvm (more can be added): no reason to 
pick one when you can test and use what work better in a specific use case or for testing.

## Opinionated choices

- custom kernel with enough build-in features to not require initrd and modules for most use cases.
- rootfs is an erofs image with minimal userspace (based on busybox) and including ssh-mesh - since this is what I'm testing and believe should handle the communication.
- virtiofs exposing a shared directory, including startup scripts.
- console used either as a terminal - or as the main ssh connection. If used as a terminal, a vsock is used for ssh.

Network is optional - the expectation is that the mesh will
apply policies and handle communication without having to 
intercept traffic, but with application code using UDS or 
localhost connections.


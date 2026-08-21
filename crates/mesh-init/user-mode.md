# User mode mesh-init

The primary mode for ssh-mesh is as a sidecar, with mesh-init running as root and managing
the resources, and ssh-mesh, tun, and other components as separated users - each app running
as a different user with additional isolation (light build-tin like systemd but also bwrap, podman, VM).

It is also possible to run mesh-init as a regular user. In this case it is not possible to
run ssh-mesh and other components as separate users, and some of the isolation options
are also off. Starting a VM or bwrap remains available (if /dev/kvm permissions allow), and some of the systemd-like build-in isolations methods remain.

The main use is for testing - the tests for an app using activation and mesh services is likely to run in a restricted container or as regular user. I don't think production
or real-use should use 'user mode' since it's more restricted, less secure and network is likely slower.

As user:
- all services run as the same user.
- no access control based on UID
- will not attempt directly using subuids, but may use mount namespaces.
- no cgroups or pressure checking

## Layout

mesh-init current dir is used as a base, with ./etc/mesh-init used for configs.
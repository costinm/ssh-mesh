# Mesh Init

The primary function is to manage the isolation and lifecycle of applications based on resource usage and availability. 

Isolation is based on using different user IDs and namespaces. User namespaces are already covered by Bubblewrap, Podman, etc - but they can't use separate UIDs,
just sub-uids and the main user ID is shared. 

Docker, podman, CRI, systemd and many init systems run as root - but they are very large and too powerful - if something can be done in a jail and possibly not run at all time,
it should be.

This is a middle ground - small daemon, running as root, but with very limited power:

- can launch, stop or freeze processes running in namespaces and with cgroups. May delegate to bubblewrap, podman - after changing the user ID and dropping privileges.

- can watch a set of FDs for accept or read events, and start or unfreeze processes based on these events. It can also receive FDs from processes it launched before freezing them.

- each app has a config file that defines the jail, resources, command to launch, etc - managed by a control plane or user. 

- exposed as a MCP/LSP-like json protocol over a UDS socket, no HTTP/2 or other large dependencies. SSH and HTTP/2 handled by separate app (can be ssh-mesh, ztunnel, etc).

- The protocol allow start with args/env/FD, stop and watching FD operations.

- Mesh-init will watch PSI and memory usage and freeze or stop
applications - based on priority/importance. OOM score will also be adjusted - with a set of apps like 'system_ui' having a hook to adjust importance based on visibility/usage/etc. This is part of the init because it needs root and cross-app visibility.

Why daemon: needs to listen and manage lifecycle of workloads
and listen. It is not required to run as UID 1, but recommended - and if it is PID1 will also take care of zombies.

The caller is not allowed to configure arbitrary options - the jail is defined in the config for the app, but only few things are configurable.

The actual execution can be handled directly for simple cases or delegated. If mesh-init is not running as PID1 - it may check if systemd-run, podman, bublewrap are available and use them - a script or separate program runnign as user will handle the selection to keep the root portion small.

## API 

- 'start' request receives the name of the app ("google-chrome"). If a config file exists ('google-chrome.toml'), it is loaded and used to configure the jail, including
 resources, command to launch, etc. Additional parameters are env, args and a set of FDs. The user ID is in the config.

- stop / freeze / unfreeze

- listen/watch - receive FDs to listen. 

The config will include the executable path, UID/GID, limits, etc. 

It will have 2 config dirs: "system" and "user". The system
configs will be loaded at startup and executed at startup,
user apps are on demand only and config loaded only when start
is called.

System configs can also include FDs to listen on. 


## Resources

If memory is low, it will freeze/stop process based on importance - similar to Android LMK. 

It will keep alive and restart processes - but only if 
resources (memory) is available. If not - it will first freeze or stop other processes of lower priority. A process will not be started until the memory.low can be satisfied.

## Termination

Lower priority apps will be terminated if the resources are low. 

Mesh apps - using UDS or TCP trough the mesh server or providing signals trough the 
socket - will be kept alive for x seconds after the last request or session is terminated. 

## Implementation

- scripts or separate programs can be used to launch - main init should fork as user and exec, with all logic post-fork 
separated to keep 'as root' code isolated and minimal.

- a separate app can be used to handle termination and freezing, does not need to run as root. For example the pmond crate can handle this.

- cgroups should be created, with group write - and owned by
a dedicated 

Android init syntax should be used, and the protocol and behavior should be consistent. While Android init does not 
auto-terminates (it is using framework and LMK), the start and
watching part should be very similar. See https://android.googlesource.com/platform/system/core/+/master/init/README.md only a subset is supported.

The system init files will be located under /etc/mesh-init/, and /system/etc/mesh-init.

User init files will be under `/data/data/[APP_ID]/[NAME]-init.rc` - and only a subset of features will work, UID 
will be assigned automatically based on ownership of parent
directory and all UDS sockets will be under the same dir.

## Running as non-root

If UID is not 0, it will still work, but without ability to change UIDs and may not be able to use cgroups. This is useful for testing or when running in a pod started as regular user.

Testing can also be done with bubblewrap and user namespaces.

## Similar projects

Bubblewrap - focused on user namespace isolation - no resource
management.

ujail, nsjail - similar to bubblewrap, no daemon required.
Podman can be used with '--rootfs' and doesn't require a daemon, can handle resource limits.

With systemd - `systemd-run` supports namespaces and cgroups and can set limits, using per-user systemd instance. The root
systemd is a security risk, avoid. Systemd, inetd support listening to sockets.

Kubelet is managing resources and evicts low priority workloads.

Android does almost everyting, but not usable on desktop
or server linux. LMK is handling low memory. Broadcasts, Jobs
provide a way to start/unfreeze apps, Android init can listen
to sockets.

## TODO

- 'app configs' are on-demand only, not read on boot and are
not restarted automatically.
- env variable to set system and app config dir.
- check peer identity - allow 0, 1000 and current user if not 
running as root.

Useful crates:
- unshare https://github.com/tailhook/unshare
- https://harrystern.net/extrasafe-user-namespaces.html
- https://crates.io/crates/unshare_petbox

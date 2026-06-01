# Using native ssh for mesh

SSH has been used for secure communication for a very long time, including tunnels and remote file access. OpenSSH and Dropbear are good enough for small servers - including OpenWRT routers or small containers using SSH mainly for control and management.

Agents are starting to support SSH as a mechanism for remote execution and to operate
on target VMs/hosts. SSH is not a replacement for HTTPS/HBONE - but an additional transport, not changing the semantics of the mesh. 

This document starts to document how to use dropbear/openssh servers as part of 
a mesh - without additional servers required on the target device.

## File access

- create user - $USER
- create a dir, owned by root - $FILE_ROOT
- create the home dir - owned by user, with authorized keys


```
UsePAM no


Match User $USER
  ChrootDirectory $FILE_ROOT
  ForceCommand internal-sftp
  # Yes to allow the user to use the device as jump or forwarder.
  AllowTcpForwarding no
  X11Forwarding no
  PermitTTY no
  PermitTunnel no
  
  
```

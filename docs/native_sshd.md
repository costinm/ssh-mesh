# Using native ssh for mesh

SSH has been used for secure communication for a very long time, including tunnels and remote file access. OpenSSH and Dropbear are
good enough for small servers - including OpenWRT routers or small 
containers using SSH mainly for control and management.

## File access

- create user - $USER
- create a dir, owned by root - $FILE_ROOT
- create the home dir - owned by user, with authorized keys


```
UsePAM no


Match User $USER
  ChrootDirectory $FILE_ROOT
  ForceCommand internal-sftp
  AllowTcpForwarding no
  X11Forwarding no
  PermitTTY no
  PermitTunnel no
  
  
  
```

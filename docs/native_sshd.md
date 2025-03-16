# Using native ssh for mesh

SSH has been used for secure communication for a very long time, including 
tunnels and remote file access.

## File access

- create users like 'restic'
- create a dir, owned by root - /z/backup
- create the home dir - owned by user, with authorized keys


```
UsePAM no


Match User restic
  ChrootDirectory /z/backup
  ForceCommand internal-sftp
  AllowTcpForwarding no
  X11Forwarding no
  PermitTTY no
  PermitTunnel no
  
  
  
```

# SFTP

Using the new go os.Root doesn't seem to work - it requires the paths to 
be relative.

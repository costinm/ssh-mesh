# sftp

This is russh-sftp wrapped as a standalone binary that can be run in an isolated
namespace, mainly for use with ssh based tools. For file sharing between hosts - 9p and NFS are likely better options if root is available to mount them, or with fuse for 9p - but sshfs provides several convenient integrations so is worth supporting
as well.
package sshpty

/*

This is intended for debug, running as user and without
the additional openssh-sftp-server, on containers.

Eventually realized it's not worth it - isolation is poor, and
sshfs is not the best remote filesystem. With port forwarding
rsync or 9P work better for most cases, even NFS over TCP.

On a host or VM - better option is to just install
dropbear or openssh binaries for servers - or use 9p or
nfs over a tunnel.

Fork of sftp package: add base dir for minimal 'chroot'
Uses low level interface: os.Stat, os.File, etc

The package has an equivalent of http.Handler as well, but
seems far too complex compared to just http.

Client side: https://github.com/kubernetes/kops/blob/master/util/pkg/vfs/sshfs.go
https://github.com/kubernetes/kops/blob/master/util/pkg/vfs/vfs.go - as a VFS interface for k8s

6-year old https://github.com/nxsre/sshfs-go - FUSE client

On WRT or linux - can use openssh-sftp-server ( no dropbear equivalent )
opkg install openssh-sftp-server

Note: openssh client for scp uses sftp, needs "-O" for old scp.

SCP is based on BSD RCP.
It is based on 'exec scp'. No dir listing.

A 'remote filesystem' can be useful - but it is never as good
or as fast as a local filesystem, and doesn't have all
the features (in particular btrfs/zfs FS). A remote block
device can be a better option, but lacks multiple writers.

In practice, FUSE and rclone or similar are good enough to
expose a file-like interface without the expectation
of a 'real root FS', only for interop with unix tools.

*/


//func SFTPHandler(sess io.ReadWriteCloser) {
//	debugStream := ioutil.Discard
//	serverOptions := []sftp.ServerOption{
//		sftp.WithDebug(debugStream),
//	}
//	server, err := sftp.NewServer(
//		sess,
//		serverOptions...,
//	)
//	if err != nil {
//		log.Printf("sftp server init error: %s\n", err)
//		return
//	}
//	if err := server.Serve(); err == io.EOF {
//		server.Close()
//		log.Println("sftp client exited session.")
//	} else if err != nil {
//		log.Println("sftp server completed with error:", err)
//	}
//}
//

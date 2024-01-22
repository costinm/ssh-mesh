package sshdebug

import (
	"io"
	"io/ioutil"
	"log"

	"github.com/costinm/sftp"
	"golang.org/x/crypto/ssh"
)

/*
The 'sftp' package is a great client - but the server is quite limited. No good way to chroot or use a specific
base dir, generate dynamic files, control access, UIDs, etc.
Better option is to just install dropbear or openssh binaries for servers - or use 9p or nfs over a tunnel.

Fork: add base dir

Low level interface: os.Stat, os.File, etc
Alternatives: io/fs/Fs() -

Client side: https://github.com/kubernetes/kops/blob/master/util/pkg/vfs/sshfs.go
https://github.com/kubernetes/kops/blob/master/util/pkg/vfs/vfs.go - as a VFS interface for k8s

6-year old https://github.com/nxsre/sshfs-go - FUSE client

On WRT or linux - can use openssh-sftp-server ( no dropbear equivalent )
opkg install openssh-sftp-server

Note: openssh client for scp uses sftp, needs "-O" for old scp.

SCP is based on BSD RCP. It is based on 'exec scp'. No dir listing.

*/

// TODO: remove

func subsystemHandler(req *ssh.Request, conn *ssh.ServerConn, ch ssh.Channel) {
	// Instead of 'exec'/'shell' - this is mainly 'sftp'
	var payload = struct{ Value string }{}
	ssh.Unmarshal(req.Payload, &payload)

	if conn.Permissions.Extensions["sub"] != "admin" {
		req.Reply(false, nil)
		return
	}

	if "sftp" == payload.Value {
		req.Reply(true, nil)
		go func() {
			sftpHandler(ch)
			exit(ch, 0)
		}()
	} else {
		req.Reply(false, nil)
	}
}

func sftpHandler(sess io.ReadWriteCloser) {
	debugStream := ioutil.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		log.Println("sftp client exited session.")
	} else if err != nil {
		log.Println("sftp server completed with error:", err)
	}
}

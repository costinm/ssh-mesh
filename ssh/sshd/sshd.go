package main

import (
	"log"
	"os"

	ssh "github.com/costinm/cert-ssh/ssh"
	"github.com/costinm/cert-ssh/sshca"
)

func main() {
	caAddr := sshca.GetConf("SSH_CA", "sshca.ssh-ca.svc.cluster.local:8080")
	ns := sshca.GetConf("POD_NAMESPACE", "")
	if ns == "" {
		// not in k8s - localhost dev, or a port forward
		ns = "default"
		//caAddr = "127.0.0.1:14023"
	}
	log.Println("Starting sshd", os.Environ())

	// run-k8s helper can't start a debug ssh server if running ssh_signer -
	// no signer. Start one in-process, for debugging.
	err := ssh.StartSSHDWithCA(ns, caAddr)
	if err != nil {
		panic(err)
	}

	select {}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"os"

	ssh "github.com/costinm/cert-ssh/ssh"
	"github.com/costinm/cert-ssh/sshca"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	caAddr := sshca.GetConf("SSH_CA", "sshca.ssh-ca.svc.cluster.local:8080")
	ns := sshca.GetConf("POD_NAMESPACE", "")
	if ns == "" {
		// not in k8s - localhost dev, or a port forward
		ns = "default"
		//caAddr = "127.0.0.1:14023"
	}

		var err2 error
		var signer gossh.Signer
		var r string
		if caAddr != "" {
			r, signer, err2 = sshca.GetCertHostSigner(caAddr)
		}
		if err2 != nil {
			privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			signer, _ = gossh.NewSignerFromKey(privk1)
			log.Println("SSH cert signer not found, use ephemeral private key", err2)
		}

	log.Println("Starting sshd", os.Environ())

	// run-k8s helper can't start a debug ssh server if running ssh_signer -
	// no signer. Start one in-process, for debugging.
	err := ssh.InitFromSecret(map[string][]byte{}, ns, signer, r)
	if err != nil {
		panic(err)
	}

	select {}
}

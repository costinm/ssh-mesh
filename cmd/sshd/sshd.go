package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"os"

	"github.com/costinm/ssh-mesh/ssh"
	gossh "golang.org/x/crypto/ssh"
)


// sshd is a minimal binary providing a ssh server using optional mesh SSH certificates provided by a ssh mesh gateway.
// It also includes a client that maintains connection and port forwarding with the gate.
//
// Should be added to docker containers as /usr/sbin/sshd, or linked in.
// Can also be added as a sidecar container to K8S.
func main() {
	caAddr := ssh.Conf("SSH_CA", "sshgate.istio-system.svc.cluster.local:8080")
	sshGate := ssh.Conf("SSH_GATE", "sshgate.istio-system.svc.cluster.local:14022")
	ns := ssh.Conf("WORKLOAD_NAMESPACE", "default")

	//sshc := &ssh.Client{
	//	SSHCa: Conf("SSH_CA", "127.0.0.1:14023"),
	//	SSHD: Conf("SSH_GATE", "127.0.0.1:14022"),
	//	Namespace: Conf("WORKLOAD_NAMESPACE", "default"),
	//	CertProvider: ssh.InitSigner,
	//}
	sshc := &ssh.Client{
		SSHCa: caAddr,
		SSHD: sshGate,
		Namespace: ns,
		CertProvider: ssh.InitSigner,
	}
	sshc.CertProvider = func(ctx context.Context, sshCA string) (gossh.Signer, error) {
		ephemeralPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ephemeralSigner, _ := gossh.NewSignerFromKey(ephemeralPrivate)
		return ephemeralSigner, nil
	}
	// run-k8s helper can't start a debug ssh server if running ssh_signer -
	// no signer. Start one in-process, for debugging.
	err := sshc.Start()
	if err != nil {
		panic(err)
	}

	log.Println("Starting sshd", os.Environ())

	// run-k8s helper can't start a debug ssh server if running ssh_signer -
	// no signer. Start one in-process, for debugging.
	err = ssh.InitFromSecret(map[string][]byte{}, ns)
	if err != nil {
		panic(err)
	}

	select {}
}

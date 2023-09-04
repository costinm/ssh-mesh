package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net"
	"testing"

	"github.com/costinm/ssh-mesh/sshc"
	"github.com/costinm/ssh-mesh/sshca"
	"golang.org/x/crypto/ssh"
)

func TestE2E(t *testing.T) {
	ca := &sshca.SSHCA{}
	ca.InitRoot()

	bob, err := initTransport(ca, "bob", 11002)
	if err != nil {
		t.Fatal(err)
	}
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := ssh.NewSignerFromKey(privk1)
	_, hcc, err := ca.Sign(casigner1.PublicKey(), ssh.UserCert, []string{"alice" + "@" + domain})
	aliceSignerC, err := ssh.NewCertSigner(hcc, casigner1)

	//ctx := context.Background()

	// TODO: P2: load/save root
	// TODO: P2: http interface for CA
	abc, err := net.Dial("tcp", "localhost:11002")
	if err != nil {
		t.Fatal(err)
	}

	acc, err := sshc.NewSSHC(&sshc.SSHClientConf{
		Signer: aliceSignerC,
	})
	err = acc.DialConn(abc, "bob.test.svc.cluster.local:11002")
	//ac := acc.SSHConn
	//ac, asshC, err := alice.DialConn(ctx, "bob.test.svc.cluster.local:11002", abc)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(acc.RemoteKey, bob.SignerHost.PublicKey())
	// RoundTripStart from bob...
	//asshC.RoundTripStart()

	// TODO: extend with custom message handlers, both ends.
	//ok, res, err := asshC.SendRequest("test", true, []byte{1})
	//log.Println(asshC)

	//abs, err := ac.OpenStream("direct-tcpip", ssh.Marshal(
	//	&forwardTCPIPChannelRequest{}))
	//log.Println(abs, err)
}

var domain = "test.svc.cluster.local"

func initTransport(ca *sshca.SSHCA, s string, i int) (*Transport, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := ssh.NewSignerFromKey(privk1)
	_, hch, err := ca.Sign(casigner1.PublicKey(), ssh.HostCert, []string{s + "." + domain})
	if err != nil {
		return nil, err
	}
	aliceSigner, err := ssh.NewCertSigner(hch, casigner1)
	if err != nil {
		return nil, err
	}

	alice, err := NewSSHTransport(&TransportConfig{
		SignerHost:   aliceSigner,
		User:         s + "@" + domain,
		Port:         i,
		AuthorizedCA: []ssh.PublicKey{ca.Signer.PublicKey()},
	})
	if err != nil {
		return nil, err
	}

	go alice.Start()

	return alice, nil
}

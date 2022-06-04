package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestE2E(t *testing.T) {
	ca := &SSHCA{}

	ca.InitRoot()

	alice, err := initTransport(ca, "alice", 11001)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := initTransport(ca, "bob", 11002)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// TODO: P2: load/save root
	// TODO: P2: http interface for CA
	abc, err := net.Dial("tcp", "localhost:11002")
	ac, asshC, err := alice.DialConn(ctx, "bob", abc)

	log.Println(ac.RemoteKey, bob.SignerHost.PublicKey())
	// Dial from bob...
	//asshC.Dial()

	// TODO: extend with custom message handlers, both ends.
	ok, res, err := asshC.SendRequest("test", true, []byte{1})
	log.Println(ok, res)

	abs, err := ac.OpenStream("direct-tcpip", ssh.Marshal(&forwardTCPIPChannelRequest{}))
	log.Println(abs)
}

func initTransport(ca *SSHCA, s string, i int) (*Transport, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := ssh.NewSignerFromKey(privk1)
	_, hch, err := ca.Sign(casigner1.PublicKey(), ssh.HostCert, []string{s + ".test.svc.cluster.local"})
	if err != nil {
		return nil, err
	}
	_, hcc, err := ca.Sign(casigner1.PublicKey(), ssh.UserCert, []string{s + "@test.svc.cluster.local"})
	if err != nil {
		return nil, err
	}
	aliceSigner, err := ssh.NewCertSigner(hch, casigner1)
	if err != nil {
		return nil, err
	}
	aliceSignerC, err := ssh.NewCertSigner(hcc, casigner1)
	if err != nil {
		return nil, err
	}
	alice, err := NewSSHTransport(&TransportConfig{
		SignerHost:   aliceSigner,
		SignerClient: aliceSignerC,
		Port:         i,
	})
	if err != nil {
		return nil, err
	}

	go alice.Start()

	return alice, nil
}

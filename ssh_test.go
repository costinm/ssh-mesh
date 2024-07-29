package ssh_mesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"testing"

	"github.com/costinm/meshauth"
	"golang.org/x/crypto/ssh"
)


func TestE2E(t *testing.T) {
	ctx := context.Background()

	ca, err := NewNode("testdata/test.mesh.local/ca/sshm.json")
	if err != nil {
		t.Fatal(err)
	}

	bob, err := NewNode("testdata/test.mesh.local/bob/sshm.json")
	if err != nil {
		t.Fatal(err)
	}
	bob.Address = ":11122"
	l, err := bob.ListenAndStart()
	if err != nil {
		t.Fatal(err)
	}

	alice, err := InitMeshNode(ca, "alice", domain)
	if err != nil {
		t.Fatal(err)
	}

	acc, err := alice.Client(ctx, "bob.test.mesh.local")
	if err != nil {
		t.Fatal(err)
	}
	err = acc.Dial(ctx, l.Addr().String()) // "127.0.0.1:11122")
	if err != nil {
		t.Fatal(err)
	}

	log.Println(acc.RemoteKey, bob.Signer.PublicKey())

	// RoundTripStart from bob...
	//asshC.RoundTripStart()

	// TODO: extend with custom message handlers, both ends.
	//ok, res, err := asshC.SendRequest("test", true, []byte{1})
	//log.Println(asshC)

	//abs, err := ac.OpenStream("direct-tcpip", ssh.Marshal(
	//	&forwardTCPIPChannelRequest{}))
	//log.Println(abs, err)
}

var domain = "test.mesh.local"

// InitMeshNode provisions an ephemeral mesh node for testing.
// Should do the same as the ssh-keygen script.
func InitMeshNode(ca *SSHMesh, name string, domain string) (*SSHMesh, error) {
	ma := meshauth.New(nil)
	ma.InitSelfSignedFromPEMKey("")

	// ssh-keygen
	nodePrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	encodedKey, _ := x509.MarshalECPrivateKey(nodePrivate)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey})

	ma.Priv = string(privatePEM)

	nodeSSHSigner, _ := ssh.NewSignerFromKey(nodePrivate)

	// Sign the 2 certs
	_, hch, err := ca.Sign(nodeSSHSigner.PublicKey(), ssh.HostCert,
		[]string{name + "." + domain, name, name + "@" + domain})
	if err != nil {
		return nil, err
	}

	_, hcc, err := ca.Sign(nodeSSHSigner.PublicKey(), ssh.UserCert,
		[]string{name + "@" + domain})

	node, err := NewSSHMesh(ma)
	if err != nil {
		return nil, err
	}

	node.SetKeys(ma.Priv, base64.StdEncoding.EncodeToString(hch.Marshal()),
		base64.StdEncoding.EncodeToString(hcc.Marshal()))


	return node, nil
}

// NewNode creates a new SSH mesh node, based on a config location.
//
// For testing and apps using multiple nodes.
//
// TODO: support URLs (with JWT auth) and dirs
func NewNode(loc string) (*SSHMesh, error) {

	ma := meshauth.New(nil)

	sshmf := loc
	if loc[len(loc)-1] == '/' {
		sshmf = loc + "sshm.json"
		// TODO: dir, load dest from files.
	}
	cfgdata, err := os.ReadFile(sshmf)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(cfgdata, ma.MeshCfg)

	return NewSSHMesh(ma)
}

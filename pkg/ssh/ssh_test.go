package ssh

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)


func TestE2E(t *testing.T) {
	ctx := context.Background()

	ca, err := NewNode("../../testdata/test.mesh.local/ca/sshm.json")
	if err != nil {
		t.Fatal(err)
	}

	bob, err := NewNode("../../testdata/test.mesh.local/b.bob/sshm.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := bob.ListenAndStart()
	if err != nil {
		t.Fatal(err)
	}

	alice := InitMeshNode(ca, "alice", domain)
	if err != nil {
		t.Fatal(err)
	}

	//acc := &SSHCMux{Address: "bob.test.mesh.local"}
	//acc.SSHMesh = alice
	//
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
func InitMeshNode(ca *SSHMesh, name string, domain string) (*SSHMesh) {
	node := New()

	node.Address = ":0"

	node.Provision(context.Background())

	// Sign the 2 certs
	hch, _, _ := ca.Sign(node.Signer.PublicKey(), ssh.HostCert,
		[]string{name + "." + domain, name, name + "@" + domain})

	hcc, _, _ := ca.Sign(node.Signer.PublicKey(), ssh.UserCert,
		[]string{name + "@" + domain})


	node.SetCertHost(string(hch))
	node.SetCertClient(string(hcc))

	return node
}

// NewNode creates a new SSH mesh node, based on a config location.
//
// For testing and apps using multiple nodes.
//
// TODO: support URLs (with JWT auth) and dirs
func NewNode(loc string) (*SSHMesh, error) {

	m := New()
	sshmf := loc
	if loc[len(loc)-1] == '/' {
		sshmf = loc + "sshm.json"
		// TODO: dir, load dest from files.
	}
	cfgdata, err := os.ReadFile(sshmf)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(cfgdata, m)

	return m, m.Provision(context.Background())
}

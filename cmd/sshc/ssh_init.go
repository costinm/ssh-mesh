package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/util"
	gossh "golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
)

// Load or generate a SSH node config.
// To simplify the code and testing, the SSH node will only interact with a config - which
// can be loaded from JSON file or an MDS server, to bootstrap.

// Load the standard SSH files - from:
// - env
// - config dir
// - current working dir
// - $HOME/.ssh
func EnvSSH(config *sshd.SSHConfig) {
	// Also SSH_AUTHORIZED_KEYS for compat
	ac1 := os.Getenv("SSH_AUTHORIZED_KEYS")
	if config.AuthorizedKeys == "" && ac1 != "" {
		config.AuthorizedKeys = ac1
	}

	ac := util.FindConfig("authorized_keys", "")
	if config.AuthorizedKeys == "" && ac != nil {
		config.AuthorizedKeys = string(ac)
	}

	key := util.FindConfig("id_ecdsa", "")
	if key != nil {
		config.Private = string(key)
	}

	cert_host := util.FindConfig("id_ecdsa_host.pub", "")
	if cert_host != nil {
		config.CertHost = string(cert_host)
	}

	cert_c := util.FindConfig("id_ecdsa_cert.pub", "")
	if cert_c != nil {
		config.CertClient = string(cert_c)
	}

	// TODO: load the cert from file !
	// TODO: is a CA is defined, get certs
}

func SaveKeyPair(name string) (*ecdsa.PrivateKey, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ecb, _ := x509.MarshalECPrivateKey(privk1)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	err := ioutil.WriteFile(name, keyPEM, 0700)
	if err != nil {
		return nil, err
	}

	casigner1, _ := gossh.NewSignerFromKey(privk1)
	pubString := string(gossh.MarshalAuthorizedKey(casigner1.PublicKey()))
	err = ioutil.WriteFile(name+".pub", []byte(pubString), 0700)
	if err != nil {
		return nil, err
	}

	return privk1, nil
}

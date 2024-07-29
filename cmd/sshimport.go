package cmd

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/costinm/meshauth"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
)

func FromSSHConfig(ma *meshauth.Mesh) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	sshd := home + "/.ssh/"

	if ma.Cert == nil {
		// Also look in the .ssh directory - this is mainly for secrets.
		key, err := os.ReadFile(sshd + "id_ecdsa")
		if err == nil {
			k, err := ssh.ParseRawPrivateKey([]byte(key))
			if err == nil {
				if privk1, ok := k.(*ecdsa.PrivateKey); ok {
					ecb, _ := x509.MarshalECPrivateKey(privk1)
					keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})
					ma.Priv = string(keyPEM)
					ma.InitSelfSignedFromPEMKey(string(keyPEM))
				}
			}
			log.Print("Init from ~/.ssh")
		}
	}

	auth, err := os.ReadFile(sshd + "id_ecdsa")
	if err == nil {
		ma.MeshCfg.Env["SSH_AUTHORIZED_KEYS"] = string(auth) + "\n" +
			os.Getenv("SSH_AUTHORIZED_KEYS")
	}

}
package ssh

import (
	"os"
)

// FromEnv is called to load private key and configs from file or env variables.
// Not useful for a library - only as a main app.
//
// It will use the same key for clients and servers.
// Existing $HOME/.ssh is used unless SSHM_CFGDIR is set.
//
// Configs:
// - id_ecdsa and id_ecdsa_{host,cert}.pub (optional)
// - authorzied_keys
func (sshMesh *SSHMesh) FromEnv() {
	sshMesh.Address = ":15022"
	home := os.Getenv("SSHM_CFGDIR")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		home = "."
	}
	sshd := home + "/.ssh/"

	ac1 := os.Getenv("SSH_AUTHORIZED_KEYS")
	if sshMesh.AuthorizedKeys == "" && ac1 != "" {
		sshMesh.AuthorizedKeys = ac1
	}
	if sshMesh.AuthorizedKeys == "" {
		ak, _ := os.ReadFile(sshd + "authorized_keys")
		if ak != nil {
			sshMesh.AuthorizedKeys = string(ak)
		}
	}

	cert_host, _ := os.ReadFile(sshd + "id_ecdsa_host.pub")
	if cert_host != nil {
		sshMesh.CertHost = string(cert_host)
	}

	cert_c, _ := os.ReadFile(sshd + "id_ecdsa_cert.pub")
	if cert_c != nil {
		sshMesh.CertClient = string(cert_c)
	}

	// Also look in the .ssh directory - this is mainly for secrets.
	key, err := os.ReadFile(sshd + "id_ecdsa")
	if err == nil {
		sshMesh.SetKeySSH(string(key))

	}

	if os.Getenv("SSH_UPSTREAM") != "" {
		sshcm := &SSHCMux{
			Address: os.Getenv("SSH_UPSTREAM"),
		}
		sshcm.StayConnected()
	}

}

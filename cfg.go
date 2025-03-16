package ssh_mesh

import (
	"os"
)

// FromEnv is called to load private key and configs from file or env variables.
func (ss *SSHMesh) FromEnv() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	sshd := home + "/.ssh/"


	ac1 := os.Getenv("SSH_AUTHORIZED_KEYS")
	if ss.AuthorizedKeys == "" && ac1 != "" {
		ss.AuthorizedKeys = ac1
	}
	if ss.AuthorizedKeys == "" {
		ak, _ := os.ReadFile(sshd + "authorized_keys")
		if ak != nil {
			ss.AuthorizedKeys = string(ak)
		}
	}
	// TODO: conver authorized_keys to json, save.

	cert_host, _ := os.ReadFile(sshd + "id_ecdsa_host.pub")
	if cert_host != nil {
		ss.CertHost = string(cert_host)
	}

	cert_c, _ := os.ReadFile(sshd + "id_ecdsa_cert.pub")
	if cert_c != nil {
		ss.CertClient = string(cert_c)
	}

	// Also look in the .ssh directory - this is mainly for secrets.
	key, err := os.ReadFile(sshd + "id_ecdsa")
	if err == nil {
		ss.SetKeySSH(string(key))

	}
}

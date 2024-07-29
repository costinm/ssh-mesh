package ssh_mesh

import (
	"context"
	"os"
)

func (ss *SSHMesh) FromEnv(ctx context.Context, base string) {
	ma := ss.Mesh

	ac1 := os.Getenv("SSH_AUTHORIZED_KEYS")
	if ss.AuthorizedKeys == "" && ac1 != "" {
		ss.AuthorizedKeys = ac1
	}

	cert_host := ma.GetRaw("id_ecdsa_host.pub", "")
	if cert_host != nil {
		ss.CertHost = string(cert_host)
	}

	cert_c := ma.GetRaw("id_ecdsa_cert.pub", "")
	if cert_c != nil {
		ss.CertClient = string(cert_c)
	}
}

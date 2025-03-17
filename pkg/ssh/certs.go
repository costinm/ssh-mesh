package ssh

import (
	"crypto/rand"

	"golang.org/x/crypto/ssh"
)

// SSH CA is different from TLS CA - any host can sign certificates (no restrictions),
// and only 'flat' model is used.
// That doesn't mean you can't have independent methods to establish hieararchical
// trust - DNS records, JWTs, TLS certs or chains of SSH certs are possible.
// But the protocol level is much simpler and flat.


// Sign will sign a client or server certificate.
//
// Each host can sign - the resulting cert should be under the host
// trust.
func (s *SSHMesh) Sign(pub ssh.PublicKey, certType uint32, names []string) ([]byte, *ssh.Certificate, error) {
	//pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(in.Public))

	cert := &ssh.Certificate{
		ValidPrincipals: names,
		Key:             pub,
		ValidBefore:     ssh.CertTimeInfinity,
		CertType:        certType,
	}
	err := cert.SignCert(rand.Reader, s.Signer)

	if err != nil {
		return nil, nil, err
	}

	// This is a public key
	return ssh.MarshalAuthorizedKey(cert), cert, nil
}

// SignCert signs an arbitrary certificate.
func (s *SSHMesh) SignCert(cert *ssh.Certificate) ([]byte, error) {
	err := cert.SignCert(rand.Reader, s.Signer)
	if err != nil {
		return nil, err
	}
	// This is a public key
	return ssh.MarshalAuthorizedKey(cert), nil
}


//	return "cert-authority " + string(ssh.MarshalAuthorizedKey(s.Signer.PublicKey()))



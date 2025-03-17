package ssh

import (
	"crypto/rand"

	"golang.org/x/crypto/ssh"
)

// SSH CA is different from TLS CA - any host can sign certificates
// (no restrictions), and only a 'flat' model is used.
//
// That doesn't mean you can't have independent methods to establish hierarchical
// trust - DNS records, JWTs, TLS certs or chains of SSH certs are possible.
// But the protocol level is much simpler and flat.


func (ssht *SSHMesh) SetCertHost(key string) error {
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	//cert, err := ssh.ParsePublicKey([]byte(s.CertHost))
	if err != nil {
		return  err
	}
	ssht.SignerHost, err = ssh.NewCertSigner(cert.(*ssh.Certificate), ssht.Signer)
	return nil
}

func (ssht *SSHMesh) SetCertClient(key string) error {
	// Client and host certificates are in the authorized key format ( like the .pub files)
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	//cert, err := ssh.ParsePublicKey([]byte(s.CertHost))
	if err != nil {
		return  err
	}
	ssht.SignerClient, err = ssh.NewCertSigner(cert.(*ssh.Certificate), ssht.Signer)
	crt := cert.(*ssh.Certificate)

	// Make sure the user we sent is matching the one in the cert
	// It is verified.
	ssht.User = crt.ValidPrincipals[0]

	return nil
}

func (s *SSHMesh) isUserAuthority(auth ssh.PublicKey) bool {
	if s.AuthorizedCA == nil {
		return false
	}
	for _, pubk := range s.AuthorizedCA {
		if KeysEqual(auth, pubk) {
			return true
		}
	}
	return false
}

// isHostAuthority is used by client to check if a FQDN can be signed by a CA.
// Currently using the default mesh root.
//
// In future it may use DNS or control plane to fetch the cert.
func (s *SSHMesh) isHostAuthority(auth ssh.PublicKey, host string) bool {
	if s.AuthorizedCA == nil {
		return false
	}
	for _, pubk := range s.AuthorizedCA {
		if KeysEqual(auth, pubk) {
			return true
		}
	}
	return false
}

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

// SignCert signs an arbitrary certificate. The cert is expected to include
// Key, Valid*, CertType, ValidPrincipals.
//
// Optional: Serial, KeyId, Permissions ( a map of claims and the critical
// like "force-command", "source-address" )
//
// The cert signing will initialize Nonce, Signature.
//
// The result is in 'authorized keys' format.
func (s *SSHMesh) SignCert(cert *ssh.Certificate) ([]byte, error) {
	err := cert.SignCert(rand.Reader, s.Signer)
	if err != nil {
		return nil, err
	}
	// This is a public key
	return ssh.MarshalAuthorizedKey(cert), nil
}

func (s *SSHMesh) CertAuthority() string {
	crt := s.SignerHost.PublicKey().(*ssh.Certificate)
	return "cert-authority " + string(ssh.MarshalAuthorizedKey(crt.SignatureKey))
}

func (s *SSHMesh) NodeCertAuthority() string {
	return "cert-authority " + string(ssh.MarshalAuthorizedKey(s.Signer.PublicKey()))
}


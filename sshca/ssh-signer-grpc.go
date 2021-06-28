//go:generate  protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative --go_out=. ssh-signer.proto

package sshca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"
)

var GetConf func(string, string) string = func(k string, d string) string {
	v := os.Getenv(k)
	if v != "" {
		return v
	}
	return d
}

type SSHSigner struct {
	UnimplementedSSHCertificateServiceServer
	Root string
	Signer gossh.Signer
}

// InitPrivate will load the private key
// By default will use ./var/run/secrets/ssh-ca
// This can be overridden using SSH_CA_DIR env.
func (s *SSHSigner) InitPrivate() error {
	// Alternative would be ${HOME}/.ssh/ssh-ca/id_ecdsa file.
	var rootca_dir = "./var/run/secrets/ssh-ca"
	var rootca_file = rootca_dir + "/id_ecdsa"

	var privk *ecdsa.PrivateKey
	var casigner gossh.Signer

	keyB, err := ioutil.ReadFile(rootca_file)
	if err == nil {
		casigner, err = gossh.ParsePrivateKey(keyB)
	}

	if err != nil || casigner == nil {
		pwd, _ :=os.Getwd()
		log.Println("Failed to read key, generating", err, pwd, os.Environ())
		privk, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		casigner, _ = gossh.NewSignerFromKey(privk)
		ecb, _ := x509.MarshalECPrivateKey(privk)
		keyB := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})
		os.MkdirAll(rootca_dir, 0700)
		err = ioutil.WriteFile(rootca_file, keyB, 0700)
		if err != nil {
			log.Println("Failed to save private, using in-memory ", err)
		}
	}

	s.Root = "cert-authority " + string(gossh.MarshalAuthorizedKey(casigner.PublicKey()))
	s.Signer = casigner
	return nil
}

func (s *SSHSigner) CreateCertificate(ctx context.Context, in *SSHCertificateRequest) (*SSHCertificateResponse, error) {
	// TODO: get identity from JWT or cert or metadata
	md, _ := metadata.FromIncomingContext(ctx)

	log.Println("Request ", md, ctx, in)

	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(in.Public))
	if err != nil {
		return nil, err
	}
	log.Println("Creating certificate for ", in.Public)
	return &SSHCertificateResponse{
		Host: string(s.SignHost(pub, "localhost")),
		User: string(s.SignUser(pub, "costin")),
		Root: s.Root,
	}, nil
}

func (s *SSHSigner) SignHost(pub gossh.PublicKey, name string) []byte {

	cert := &gossh.Certificate{
		ValidPrincipals: []string{name},
		Key:             pub,
		ValidBefore:     gossh.CertTimeInfinity,
		CertType:        gossh.HostCert,
	}
	cert.SignCert(rand.Reader, s.Signer)

	return gossh.MarshalAuthorizedKey(cert)
}

func (s *SSHSigner) SignUser(pub gossh.PublicKey, name string) []byte {

	cert := &gossh.Certificate{
		ValidPrincipals: []string{name},
		Key:             pub,
		ValidBefore:     gossh.CertTimeInfinity,
		CertType:        gossh.UserCert,
	}
	cert.SignCert(rand.Reader, s.Signer)

	return gossh.MarshalAuthorizedKey(cert)
}


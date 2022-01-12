package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	gossh "golang.org/x/crypto/ssh"
)

type SSHCA struct {
	Root   string
	Signer gossh.Signer
	Domain string
}

// Init will load the private key
// By default will use ./var/run/secrets/ssh-ca
// This can be overridden using SSH_CA_DIR env.
func (s *SSHCA) Init() error {
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

func (s *SSHCA) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	r := &CertificateRequest{}
	err = json.Unmarshal(data, r)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	res, err := s.CreateCertificate(request.Context(), r, request)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	resData, err := json.Marshal(res)
	w.Write(resData)
}


func (s *SSHCA) CreateCertificate(ctx context.Context, in *CertificateRequest, request *http.Request) (*CertificateResponse, error) {
	// TODO: get identity from JWT or cert or metadata
	//md, _ := metadata.FromIncomingContext(ctx)

	log.Println("Request ", request.Header, ctx, in)

	// Debug/local dev
	domain := []string{"localhost"}
	user := "unauthenticated" // k8s convention

	xfcc := request.Header.Get("x-forwarded-client-cert")
	if xfcc != "" {
		remoteID := RemoteIDmTLS(xfcc)
		sd := remoteID.TrustDomain
		if s.Domain != "" {
			sd = s.Domain
		}
		suffix := remoteID.Namespace + "." + sd
		user = remoteID.ServiceAccount + "@" + suffix
		d := remoteID.ServiceAccount + "." + suffix
		domain = []string{d}
		for _, n := range in.Hostname {
			domain = append(domain, n + "." + suffix)
		}
	}

	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(in.Public))
	if err != nil {
		return nil, err
	}
	log.Println("Creating certificate for ", domain, user, in.Public)
	return &CertificateResponse{
		Host: string(s.SignHost(pub, domain)),
		User: string(s.SignUser(pub, user)),
		Root: s.Root,
	}, nil
}

func (s *SSHCA) SignHost(pub gossh.PublicKey, names []string) []byte {

	cert := &gossh.Certificate{
		ValidPrincipals: names,
		Key:             pub,
		ValidBefore:     gossh.CertTimeInfinity,
		CertType:        gossh.HostCert,
	}
	cert.SignCert(rand.Reader, s.Signer)

	return gossh.MarshalAuthorizedKey(cert)
}

func (s *SSHCA) SignUser(pub gossh.PublicKey, name string) []byte {

	cert := &gossh.Certificate{
		ValidPrincipals: []string{name},
		Key:             pub,
		ValidBefore:     gossh.CertTimeInfinity,
		CertType:        gossh.UserCert,
	}
	cert.SignCert(rand.Reader, s.Signer)

	return gossh.MarshalAuthorizedKey(cert)
}


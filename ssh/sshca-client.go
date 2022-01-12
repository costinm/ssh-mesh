package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// Certificate request message.
// In SSH, the user certificate includes:
//  - public key and nonce
//  - CertType = 1
//  - KeyId - optional
//  - ValidPrincipals[] - matched against user
type CertificateRequest struct {

	// Public key to sign
	Public string `protobuf:"bytes,1,opt,name=public,proto3" json:"public,omitempty"`

	// hostname to sign. Namespace and domain will be added
	Hostname []string `protobuf:"bytes,2,rep,name=hostname,proto3" json:"hostname,omitempty"`

	User     string   `protobuf:"bytes,3,opt,name=user,proto3" json:"user,omitempty"`
	KeyId    string   `protobuf:"bytes,5,opt,name=keyId,proto3" json:"keyId,omitempty"`

	// Optional: requested certificate validity period, in seconds.
	ValidityDuration int64             `protobuf:"varint,4,opt,name=validity_duration,json=validityDuration,proto3" json:"validity_duration,omitempty"`
	CriticalOptions  map[string]string `protobuf:"bytes,6,rep,name=critical_options,json=criticalOptions,proto3" json:"critical_options,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`

	Extensions       map[string]string `protobuf:"bytes,7,rep,name=extensions,proto3" json:"extensions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

// Certificate response message.
type CertificateResponse struct {

	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	User string `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Root string `protobuf:"bytes,3,opt,name=root,proto3" json:"root,omitempty"`
}

type SSHCAClient struct {
	httpClient *http.Client
}

func InitSigner(ctx context.Context, sshCA string) (ssh.Signer, error) {
	ephemeralPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ephemeralSigner, _ := ssh.NewSignerFromKey(ephemeralPrivate)
	req := &CertificateRequest{
		Public: string(ssh.MarshalAuthorizedKey(ephemeralSigner.PublicKey())),
	}

	certResponse, err := CreateCertificate(ctx, req)
	if err != nil {
		log.Println("Error creating cert ", err)
		return nil, err
	}

	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(certResponse.User))
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("unexpected cert")
	}
	signer, _ := ssh.NewCertSigner(cert, ephemeralSigner)

	return signer, nil
}

func CreateCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	return nil, nil
}

func GetCertHostSigner(sshCA string) (string, ssh.Signer, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := ssh.NewSignerFromKey(privk1)
	req := &CertificateRequest{
		Public: string(ssh.MarshalAuthorizedKey(casigner1.PublicKey())),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, err := CreateCertificate(ctx, req)
	if err != nil {
		log.Println("Error creating cert ", err)
		return "", nil, err
	}

	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(r.Host))
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return "", nil, errors.New("unexpected cert")
	}
	signer, _ := ssh.NewCertSigner(cert, casigner1)
	return r.Root, signer, nil
}



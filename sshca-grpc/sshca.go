package sshca_grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
)

func InitSigner(ctx context.Context, sshCA string) (ssh.Signer, error) {
	ssc, con, err := GetSSHSignclient(sshCA)
	if err != nil {
		return nil, err
	}
	defer con.Close()

	ephemeralPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ephemeralSigner, _ := ssh.NewSignerFromKey(ephemeralPrivate)
	req := &SSHCertificateRequest{
		Public: string(ssh.MarshalAuthorizedKey(ephemeralSigner.PublicKey())),
	}

	certResponse, err := ssc.CreateCertificate(ctx, req)
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

func GetCertHostSigner(sshCA string) (string, ssh.Signer, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, con, err := GetSSHSignclient(sshCA)
	if err != nil {
		return "", nil, err
	}
	defer con.Close()
	casigner1, _ := ssh.NewSignerFromKey(privk1)
	req := &SSHCertificateRequest{
		Public: string(ssh.MarshalAuthorizedKey(casigner1.PublicKey())),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.CreateCertificate(ctx, req)
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

func GetSSHSignclient(sshCA string) (SSHCertificateServiceClient, *grpc.ClientConn,  error) {
	creds := insecure.NewCredentials()

	xdsBootstrap := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if xdsBootstrap != "" {
		log.Println("Using xDS credentials...")
		var err error
		if creds, err = xdscreds.NewClientCredentials(xdscreds.ClientOptions{
			FallbackCreds: insecure.NewCredentials(),
		}); err != nil {
			return nil, nil, err
		}
	}

	conn, err := grpc.Dial(sshCA, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	c := NewSSHCertificateServiceClient(conn)
	return c, conn, nil
}


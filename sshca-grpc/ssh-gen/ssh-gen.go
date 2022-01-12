package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	ssh "github.com/costinm/ssh-mesh/sshca"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
)


func init() {
       if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
       if err := view.Register(ocgrpc.DefaultClientViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
}

func main() {
	user := os.Getenv("USER")
	if user == "" {
		user = "default"
	}
	creds := insecure.NewCredentials()

	xdsBootstrap := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if xdsBootstrap != "" {
		log.Println("Using xDS credentials...")
		var err error
		if creds, err = xdscreds.NewClientCredentials(xdscreds.ClientOptions{FallbackCreds: insecure.NewCredentials()}); err != nil {
			log.Fatalf("failed to create client-side xDS credentials: %v", err)
		}
	}

	conn, err := grpc.Dial("[::1]:8080", grpc.WithTransportCredentials(creds))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := ssh.NewSSHCertificateServiceClient(conn)

	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := gossh.NewSignerFromKey(privk1)
	pubString := string(gossh.MarshalAuthorizedKey(casigner1.PublicKey()))
	req := &ssh.SSHCertificateRequest{
		Public: pubString,
		User: user,
	}
	r, err := c.CreateCertificate(ctx, req)
	if err != nil {
		log.Println("Error creating cert ", err)
		panic(err)
	}


	ecb, _ := x509.MarshalECPrivateKey(privk1)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	err = ioutil.WriteFile("id_ecdsa", keyPEM, 0700)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("id_ecdsa.pub", []byte(pubString), 0700)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("id_ecdsa-cert.pub", []byte(r.User), 0700)
	if err != nil {
		panic(err)
	}

	pubk, _,_, _, err := gossh.ParseAuthorizedKey([]byte(r.Root))

	ak := "cert-authority " + string(gossh.MarshalAuthorizedKey(pubk))

	err = ioutil.WriteFile("authorized-keys", []byte(ak), 0700)
	if err != nil {
		panic(err)
	}

	kh := "@cert-authority * " + string(gossh.MarshalAuthorizedKey(pubk))
	err = ioutil.WriteFile("known-hosts", []byte(kh), 0700)
	if err != nil {
		panic(err)
	}

	fmt.Println("SSHD: ...")
	fmt.Println("SSHC: ...")
}


package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"

	"github.com/costinm/ssh-mesh/sshca-grpc"

	gossh "golang.org/x/crypto/ssh"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// Used to configure mTLS certs in client
	xdscreds "google.golang.org/grpc/credentials/xds"

	// Register XDS server, bootstrap
	_ "google.golang.org/grpc/xds"
)


func init() {
       if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
       if err := view.Register(ocgrpc.DefaultClientViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
}

func cfg(key, def string) string {
	res := os.Getenv(key)
	if res == "" {
		return def
	}
	return res
}

func NewClient(ctx context.Context, sshURL string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	xdsBootstrap := os.Getenv("GRPC_XDS_BOOTSTRAP")

	if xdsBootstrap != "" {
		// Proxyless grpc - will configure the 'secure naming' (identity of the server) and client certs.
		log.Println("Using xDS credentials...")
		var err error
		if creds, err = xdscreds.NewClientCredentials(xdscreds.ClientOptions{FallbackCreds: insecure.NewCredentials()}); err != nil {
			return nil, err
		}

		sshURL = "xds:///sshca.istio-system.svc.cluster.local:15043"

	} else {
		// Use certs provisioned by agent (zatar, citadel) - not proxyless gRPC.


	}


	conn, err := grpc.DialContext(ctx, sshURL, grpc.WithTransportCredentials(creds))
	return conn, err
}

func SignCert(ctx context.Context, c sshca_grpc.SSHCertificateServiceClient, privk1 *ecdsa.PrivateKey) (*sshca_grpc.SSHCertificateResponse, string, error) {
	// Extract SSH-style public key associated with private
	casigner1, _ := gossh.NewSignerFromKey(privk1)
	pubString := string(gossh.MarshalAuthorizedKey(casigner1.PublicKey()))
	user := cfg("USER", "default")

	req := &sshca_grpc.SSHCertificateRequest{
		Public: pubString,
		User: user,
	}
	r, err := c.CreateCertificate(ctx, req)

	return r, pubString, err
}

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sshURL := cfg("ssh_ca", "[::1]:8080")
	conn, err := NewClient(ctx, sshURL)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer conn.Close()

	c := sshca_grpc.NewSSHCertificateServiceClient(conn)

	// TODO: Read it from file, if it exists.
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	r, _, err := SignCert(ctx, c, privk1)
	if err != nil {
		log.Println("Error creating cert ", err)
		panic(err)
	}


	if false {
		pubk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(r.Root))
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
	} else {
		// Print user certificate - can be redirected to a file.
		fmt.Println(r.User)
	}
}


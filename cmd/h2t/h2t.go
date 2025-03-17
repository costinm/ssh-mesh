package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/costinm/ssh-mesh/pkg/h2"
	"github.com/costinm/ssh-mesh/pkg/tokens"
)

var (
	token = flag.String("token", "", "token to use")

)

// h2t is a minimal TCP tunnel over h2 (like Istio Ambient),
// forwarding stdin/stdout
//
// Expects proper certificates ( TODO: document how to add a custom
// CA to the VM roots or use option to specify )
//
// Unfortunately curl doesn't support streaming - if it did, this could
// be done with a curl command.
//
// Mainly intended for SSH and debugging ambient-like tunnels.
//
// The host certificate validation is handled by h2t - so no need to save
// or check host cert at SSH level (unless you don't trust the http gateway).
// This is convenient for serverless or K8S Pods - no need for
// additional secret storage.
//
// Example:
//
// ssh -o ProxyCommand="h2t %h" -o StrictHostKeyChecking=no	-o UserKnownHostsFile=/dev/null ${SSH_HOSTNAME}
//
// Or an equivalent .ssh/config can be used.
func main() {
	flag.Parse()

	ctx := context.Background()

	if len(flag.Args()) == 0 {
		log.Fatal("Args: url")
	}

	// URL or hostname
	url := flag.Args()[0]

	// TokenSource
	// Will use MDS, k8s, cloud or other sources to get
	// JWTs.
	ma := &tokens.TokenExec{}

	// This works great for https. No support for plain h2 - but h2 would be
	// used in a mesh, where you don't need the H2 tunneling of SSH in the first
	// place - since the purpose is to deal with H2 Gateways where normal TCP is
	// blocked
	client := http.DefaultClient

	// The URL can be explicit
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}

	port := os.Getenv("H2T_PORT")
	if port != "" {
		l, err := net.Listen("tcp", port)
		if err != nil {
			panic(err)
			for {
				conn, err := l.Accept()
				if err != nil {
					panic(err)
				}
				go func() {
					sc, err := h2.NewStreamH2(ctx, client, url, "localhost:15022", ma)
					if err != nil {
						log.Fatal(err)
					}
					go func() {
						io.Copy(sc, conn)
					}()

					io.Copy(conn, sc)
				}()
			}
		}
	}

	sc, err := h2.NewStreamH2(ctx, client, url, "localhost:15022", ma)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		io.Copy(sc, os.Stdin)
	}()

	io.Copy(os.Stdout, sc)
}

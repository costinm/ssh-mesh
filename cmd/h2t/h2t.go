package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/costinm/meshauth"
	"github.com/costinm/ssh-mesh/nio"
	"golang.org/x/net/http2"
)

var (
	//h2c_addr = flag.String("h2c", "", "H2C address")

	h2c = flag.Bool("h2c", false, "Use H2C")
)

// h2t is a minimal TCP tunnel over h2 (like Istio Ambient), forwarding stdin.
//
// Expects proper certificates ( TODO: document how to add a custom
// CA to the VM roots or use option to specify )
//
// Unfortunately curl doesn't support streaming - if it did, this could
// be done with a curl command.
//
// Mainly intended for SSH and debugging.
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

	ma, err := meshauth.FromEnv(ctx, nil, "")

	client := http.DefaultClient
	if *h2c {
		// Can't do h2c using the std client - need custom code.
		client = &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			},
		}
	}

	// The URL can be explicit
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}

	sc, err := nio.NewStreamH2(ctx, client, url, "localhost:15022",  ma)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		io.Copy(sc, os.Stdin)
	}()


	io.Copy(os.Stdout, sc)
}

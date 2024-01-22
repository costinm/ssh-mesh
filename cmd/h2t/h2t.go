package main

import (
	"context"
	"io"
	"log"
	"os"
	"strings"

	"github.com/costinm/ssh-mesh/util"
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
// ssh -o ProxyCommand="h2t %h" \
//     -o StrictHostKeyChecking=no	-o UserKnownHostsFile=/dev/null \
//     ${SSH_HOSTNAME}
//
// Or an equivalent .ssh/config can be used.
func main() {
	ctx := context.Background()
	if len(os.Args) == 0 {
		log.Fatal("Args: url")
	}
	url := os.Args[1]
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}

	mds := util.NewMDSClient("")

	sc, err := util.NewStreamH2(ctx, url, "localhost:15022",  mds)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		io.Copy(sc, os.Stdin)
	}()


	io.Copy(os.Stdout, sc)
}

package main

import (
	"context"
	"net/http"

	"github.com/costinm/ssh-mesh/ssh"
)

// SSH gateway and CA, minimal.
//
// - use standard ssh config files - can be mounted from a Secret or local files
// - 'admin' can create certificates, using ssh command
// - all authorized users can forward
func main() {
	_, cf := context.WithCancel(context.Background())
	defer cf()

	sshs := &ssh.SSHCA{}

	err := sshs.Init()
	if err != nil {
		panic(err)
	}

	mux := &http.ServeMux{}

	//mux.Handle("/sshca/CreateCertificate", sshs)

	http.ListenAndServe(":8080", mux)
}

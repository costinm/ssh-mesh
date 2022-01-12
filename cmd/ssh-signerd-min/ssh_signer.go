package main

import (
	"net/http"

	"github.com/costinm/ssh-mesh/ssh"
)

// Only the signer, using HTTP REST.
// Should be used with an Envoy proxy
//
// Used mainly to identify binary size impact
func main() {

	sshs := &ssh.SSHCA{
	}

	err := sshs.Init()
	if err != nil {
		panic(err)
	}

	// Status
	mux := &http.ServeMux{}
	mux.Handle("/ca/Certificate", sshs)

	http.ListenAndServe(":8080", mux)
}


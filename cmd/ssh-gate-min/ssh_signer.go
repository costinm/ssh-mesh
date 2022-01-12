package main

import (
	"net/http"

	"github.com/costinm/ssh-mesh/ssh"
)

// SSH gate with minimal deps.
//
// Used mainly to identify binary size impact
func main() {
	//caAddr :=ssh.Conf("SSH_CA", "sshgate.istio-system.svc.cluster.local:8080")

	sshs := &ssh.SSHCA{
	}

	err := sshs.Init()
	if err != nil {
		panic(err)
	}

	// Status
	mux := &http.ServeMux{}

	http.ListenAndServe(":8080", mux)
}


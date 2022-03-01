package main

import (
	"context"
	"net/http"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	urest "github.com/costinm/krun/pkg/urest"
	"github.com/costinm/ssh-mesh/ssh"
)

// SSH CA, proxyless:
// - uses hbone for transport (mTLS)
// - metrics
func main() {
	ctx, cf := context.WithCancel(context.Background())
	defer cf()

	// Init the mesh object, using env variables.
	kr := mesh.New()

	// Init K8S - discovering using GCP API and env.
	// Init K8S client, using official API server.
	// Will attempt to use GCP API to load metadata and populate the fields
	_, err := urest.K8SClient(ctx, &urest.MeshSettings{ProjectId: kr.ProjectId})
	if err != nil {
		panic(err)
	}

	sshs := &ssh.SSHCA{}

	err = sshs.Init()
	if err != nil {
		panic(err)
	}

	mux := &http.ServeMux{}

	mux.Handle("/sshca/CreateCertificate", sshs)

	http.ListenAndServe(":8080", mux)
}

package main

import (
	"context"
	"github.com/costinm/meshauth"
	"github.com/costinm/ssh-mesh/cmd"
	"github.com/costinm/ssh-mesh/pkg/socks"
	"log"
)

// Minimal SSH mesh node.
//
// Currently very little config to keep it simple:
//
// - ssh port 15022
// - SOCKS on 15002
// - H2 on 15082
// - if running as root, TPROXY on 15001 (and expects a CNI to setup)
//
// Will look for a ".ssh" dir under HOME, otherwise a sshm.json file in the
// working directory.
//
// For easy run in K8S, env variables are also used:
//   - SSH_AUTHORIZED_KEYS: enable shell access and SSHFS, for the 'owner'.
//   - SSHD: connect to an upstream SSH mesh node (server) and keeps the
//     connection alive while remote-forwarding the SSH port.
//
// The server will attempt to find a GCP-style metadata server, to authenticate in
// addition to SSH certificates.
//
// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://$HOST
// ssh $HOST -R ... -L ...
//
func main() {
	ctx := context.Background()

	meshauth.Register("sshd", cmd.NewSSHMesh)
	meshauth.Register("sshc", cmd.NewSSHC)
	meshauth.Register("socks",  socks.RegisterFn)
	meshauth.Register("h2c", cmd.InitH2C)

	ma, err := meshauth.FromEnv(ctx, nil, "sshm")
	if err != nil {
		panic(err)
	}

	if ma.Cert == nil {
		cmd.FromSSHConfig(ma)
	}
	if ma.Cert == nil {
		ma.InitSelfSigned("")
		log.Print("Using self-signed key")
	}

	ma.Start(ctx)


	// Server providing reverse tunneling and chained jump host.
	// shouldn't be needed with sshd servers - only useful for tor-style chaining or as part of meshauth
	// TODO: support mesh.internal style and nip.io style.
	//st.StayConnected(ctx)

	ma.MainEnd()
}


//  - sshc 9.8M->6.6M
//  - sshd + h2c: 10.3/6.9

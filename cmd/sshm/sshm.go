package main

import (
	"context"
	"fmt"
	"os"

	ssh_mesh "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/cmd"
)

/*

TODO:
- create control socket
- client to use control socket for MCP (like h2t)

*/

// Minimal SSH mesh node.
//
// Currently very little config to keep it simple:
//
// - ssh port 15022
// - SOCKS on 15002
// - H2 on 15082
// - if running as root, TPROXY on 15001 (and expects a CNI to set capture)
//
// Will look for a sshm.json file in the working directory for config. Default keys in $HOME/.ssh
//
// For easy run in K8S, env variables are also used:
//   - SSH_AUTHORIZED_KEYS: enable shell access and SSHFS, for the 'owner'.
//   - SSHD: connect to an upstream SSH mesh node (server) and keeps the
//     connection alive while remote-forwarding the SSH port.
//
// Accepts connections using SSH_AUTHORIZED_KEYS, certs or a GCP-style metadata server.
//

// export Module
func Module(ctx context.Context) any {
	return ssh_mesh.NewSSHM()
}

// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://$HOST
// ssh $HOST -R ... -L ...
func main() {
	ctx := context.Background()

	s := ssh_mesh.NewSSHM()
	s.SSH.FromEnv()

	err := s.Provision(ctx)
	if err != nil {
		fmt.Printf("SSHMesh error %v", err)
		os.Exit(1)
	}

	s.Start(ctx)

	cmd.WaitEnd()
}

//  - sshc 9.8M->6.6M
//  - sshd + h2c: 10.3/6.9

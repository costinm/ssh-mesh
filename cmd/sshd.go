package cmd

import (
	"context"
	"io"
	"log"
	"net"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/tokens"
	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/nio"
	"github.com/costinm/ssh-mesh/sshdebug"
)

func NewSSHMesh(mod *meshauth.Module) error {
	if mod.Address == "" {
		mod.Address = ":15022"
	}

	ctx := context.Background()

	st, err := sshd.NewSSHMesh(mod.Mesh)
	if err != nil {
		return err
	}

	st.FromEnv(ctx, "sshm")

	st.Address = mod.Address

	// Configure JWT authenticators - will be used to verify incoming tokens
	authn := tokens.NewAuthn(&mod.Mesh.MeshCfg.AuthnConfig)
	if len(mod.Mesh.AuthnConfig.Issuers) > 0 {
		err := authn.FetchAllKeys(ctx, mod.Mesh.AuthnConfig.Issuers)
		if err != nil {
			log.Println("Issuers", err)
		}
		st.TokenChecker = authn.CheckJwtMap
	}

	// Checks "SSH_AUTHORIZED_KEYS" or the host ~/.ssh/authorized_keys
	if len(st.AuthorizedKeys) == 0 {
		// If no authorized keys set - sessions will be used for proxy and control, no shell.
		st.ChannelHandlers["session"] = sshd.SessionHandler
	} else {
		// Start internal SSHD/SFTP, only admin can connect.
		// Better option is to install dropbear and start real sshd.
		// Will probably remove this - useful for static binary
		st.ChannelHandlers["session"] = sshdebug.SessionHandler
	}

	st.InitMux(mod.Mesh.Mux)

	st.Forward = func(ctx context.Context, host string, closer io.ReadWriteCloser) {
		str := nio.GetStream(closer, closer)
		//defer ug.OnStreamDone(str)
		//ug.OnStream(str)

		str.Dest = host
		nc, err := mod.Mesh.DialContext(ctx, "tcp", str.Dest)
		if err != nil {
			return
		}

		nio.Proxy(nc, str, str, str.Dest)
	}

	mod.Module = st

	mod.NetListener, err = net.Listen("tcp", mod.Address)
	if err != nil {
		return err
	}

	st.Listener = mod.NetListener
	return nil
}

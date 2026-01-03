package ssh_mesh

import (
	"context"
	"net"

	"github.com/costinm/ssh-mesh/nio"
	"github.com/costinm/ssh-mesh/pkg/h2"
	"github.com/costinm/ssh-mesh/pkg/socks"
	ssh_mesh "github.com/costinm/ssh-mesh/pkg/ssh"
)

// SSHM can be used to embed the components of a ssh mesh - H2 and
// SSH transports, tprox/socks for capture - into another app.
type SSHM struct {
	// SSH wraps the ssh library with additional helpers for client and server modes.
	SSH *ssh_mesh.SSHMesh

	// H2C transports - delegating TLS to ambient or secure L2/3 layers.
	// It is possible to add a TLS handler as well - but main use case is to deal with
	// HTTP gateways, if TCP connectivity to the app is available - SSH is simpler.
	H2 *h2.H2

	// Explicit egress - will open SSH tunnels (over SSH or H2).
	Socks *nio.Listener // socks.Socks

	// Captured egress - same as Socks, but using the IP of the remote.
	//
	//TProxy *tproxy.TProxy
}

func NewSSHM() *SSHM {
	return &SSHM{
		SSH: ssh_mesh.New(),
		H2:  h2.New(),
		Socks: &nio.Listener{
			ConnServer: &socks.Socks{OnConn: OnConn},
		},
		// special listener
		//TProxy: &tproxy.TProxy{OnConn: OnConn},
	}
}

// OnConn is called when a new SSH connection is established.
func OnConn(remoteConn net.Conn, dst string, la *net.TCPAddr, postDial func(net.Addr, error)) {
	d := &net.Dialer{}
	nc, err := d.DialContext(context.Background(), "tcp",
		dst)
	if err != nil {
		remoteConn.Close()
		if postDial != nil {
			postDial(nil, err)
		}
		return
	}
	if postDial != nil {
		postDial(nc.LocalAddr(), nil)
	}

	nio.Proxy(nc, remoteConn, remoteConn, dst)

}

func (s *SSHM) Provision(ctx context.Context) error {

	err := s.SSH.Provision(ctx)
	if err != nil {
		return err
	}

	s.H2.DialMeta = s.SSH.DialHTTP
	s.H2.SSHStreamHandler = s.SSH.HandleAccepted

	s.SSH.H2Dialer = s.H2

	s.H2.InitMux(s.H2.Mux)

	// s.TProxy.Addr = ":15024"
	// err = s.TProxy.Provision(ctx)
	// if err != nil {
	// 	return err
	// }
	err = s.H2.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *SSHM) Start(ctx context.Context) {
	s.SSH.Start(ctx)
	s.H2.Start()
	//s.TProxy.Start(ctx)
	s.Socks.Start(ctx)
}

package ssh_mesh

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/costinm/ssh-mesh/nio"
	"github.com/costinm/ssh-mesh/pkg/h2"
	"github.com/costinm/ssh-mesh/pkg/socks"
	ssh_mesh "github.com/costinm/ssh-mesh/pkg/ssh"
	"github.com/costinm/ssh-mesh/pkg/tproxy"
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
	TProxy *tproxy.TProxy
}

func NewSSHM() *SSHM {
	return &SSHM{
		SSH: ssh_mesh.New(),
		H2:  h2.New(),
		Socks: &nio.Listener{
			ConnServer: &socks.Socks{OnConn: OnConn},
		},
		// special listener
		TProxy: &tproxy.TProxy{OnConn: OnConn},
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

	s.TProxy.Addr = ":15024"
	err = s.TProxy.Provision(ctx)
	if err != nil {
		return err
	}
	err = s.H2.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *SSHM) Start(ctx context.Context) {
	s.SSH.Start(ctx)
	s.H2.Start()
	s.Socks.Start(ctx)
	s.TProxy.Start(ctx)
}

var startupTime = time.Now()

// WaitEnd should be the last thing in a main() app - will block, waiting for SIGTERM and handle draining.
//
// This will also handle any extra args - interpreting them as a CLI and running the command, allowing
// chaining in docker. Init is using a yaml for config and no CLI.
func WaitEnd() {

	if len(os.Args) == 1 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		//for {
		//sig := <-sigCh

		// d := os.Getenv("DRAIN_TIMEOUT")
		// if d == "" {
		// 	d = "1000"
		// }
		// di, _ := strconv.Atoi(d)

		// slog.Info("Exit", "sig", sig, "running", time.Since(startupTime),
		// 	"drain", di)

		// time.AfterFunc(time.Millisecond*time.Duration(di), func() {
		// 	os.Exit(0)
		// })
		//}
		<-sigCh
		os.Exit(0)
	}

	cmd := os.Args[1]
	var argv []string

	// If it has extra args, exec the command
	if len(os.Args) > 2 {
		argv = os.Args[2:]
	}
	c := exec.Command(cmd, argv...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Env = os.Environ()

	if err := c.Start(); err != nil {
		slog.Error("failed to start subprocess", "cmd", cmd, "args", argv, "err", err)
		os.Exit(c.ProcessState.ExitCode())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		if err := c.Process.Signal(sig); err != nil {
			slog.Error("failed to signal process", "err", err)
		}
	}()

	if err := c.Wait(); err != nil {
		if v, ok := err.(*exec.ExitError); ok {
			ec := v.ExitCode()
			os.Exit(ec)
		}
	}
}

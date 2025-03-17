package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/costinm/ssh-mesh/pkg/h2"
	"github.com/costinm/ssh-mesh/pkg/socks"
	ssh_mesh "github.com/costinm/ssh-mesh/pkg/ssh"
	"github.com/costinm/ssh-mesh/pkg/tproxy"
)

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
// This includes the meshauth packages and config.
//
// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://$HOST
// ssh $HOST -R ... -L ...
func main() {
	ctx := context.Background()

	ssht := ssh_mesh.New()
	ssht.Address = ":12022"
	ssht.FromEnv()

	mux := http.NewServeMux()
	h2s := http.Server{
		Protocols: &http.Protocols{},
		Handler:   mux,
	}
	h2s.Protocols.SetUnencryptedHTTP2(true)
	h2s.Protocols.SetHTTP1(true)

	h2srv := &h2.H2{
		DialMeta: ssht.DialMeta,
		SSHStreamHandler: ssht.HandleAccepted,
	}

	ssht.H2Dialer = h2srv
	// TODO: add a forward to a local app
	h2srv.InitMux(mux)

	//authn, err := appinit.Get[nio.TokenChecker](ctx, cs, "authn")
	//if authn != nil {
	//	ssht.TokenChecker = *authn
	//}

	// Start all modules in the config
	err := ssht.Start(ctx)
	if err != nil {
		panic(err)
	}
	l, err := net.Listen("tcp", ":12028")
	if err != nil {
		panic(err)
	}

	//go h2s.ListenAndServe()
	go h2s.Serve(l)

	ls, err := net.Listen("tcp", ":12023")
	if err != nil {
		panic(err)
	}
	s := &socks.Socks{NetListener: ls}
	s.Start(ctx)

	tproxy.IptablesCapture(ctx,  ":12024", func(nc net.Conn, dest, la *net.TCPAddr) {

	})

	if os.Getenv("SSH_UPSTREAM") != "" {
		sshcm := &ssh_mesh.SSHCMux{}
		sshcm.StayConnected()
	}

	WaitEnd()
}

//  - sshc 9.8M->6.6M
//  - sshd + h2c: 10.3/6.9

var startupTime = time.Now()

// WaitEnd should be the last thing in a main() app - will block, waiting for SIGTERM and handle draining.
//
// This will also handle any extra args - interpreting them as a CLI and running the command, allowing
// chaining in docker. Init is using a yaml for config and no CLI.
func WaitEnd() {

	if len(os.Args) == 1 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		for {
			// An alternative is to handle the stdin, as
			// a communication channel with parent for server apps.
			// Perhaps with a flag.
			sig := <-sigCh

			d := os.Getenv("DRAIN_TIMEOUT")
			if d == "" {
				d = "1000"
			}
			di, _ := strconv.Atoi(d)

			slog.Info("Exit", "sig", sig, "running", time.Since(startupTime),
				"drain", di)

			time.AfterFunc(time.Millisecond*time.Duration(di), func() {
				os.Exit(0)
			})
		}
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

package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"os"
	"time"

	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/sshdebug"
	"github.com/costinm/ssh-mesh/util"
)

// Connect to a SSH server and keeps the connection alive.
//
// Works with regular sshd - but only one client can do a remote forward for port
// 22/80/443.
//
// The ssh-mesh (and sish, others) servers will multiplex 22, 80 and 443, allowing
// a remote to open a connection to the client workload.
//
// Can optionally start a local sshd server, with sshfs included, allowing debug
// access for a specific admin identity.
//
// Can optionally start a local jump host/server, for accessing other local ports,
// for networking or debug.
//
// # The ssh-mesh server also accepts JWTs instead of passwords, Equivalent with
//
// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://$HOST
// ssh $HOST -R ... -L ...
func main() {
	cfg := &sshd.SSHConfig{}
	util.MainStart("sshmc", cfg)

	if cfg.SocksAddr == "" {
		cfg.SocksAddr = "127.0.0.1:14080"
	}
	if cfg.TProxyAddr == "" {
		cfg.TProxyAddr = ":14001"
	}
	if cfg.Address == "" {
		cfg.Address = ":14022"
	}
	if cfg.SSHD == "" {
		cfg.SSHD = os.Getenv("SSHD")
	}
	EnvSSH(cfg)

	// TODO: if key and certs are missing in config but a URL is specified, fetch the private key and certs
	// ( a 'metadata' bootstrap/launcher should be run first to get all secret and config bits )

	// Transport handles both server and client.
	// Will auto generate key if not set.
	st, err := sshd.NewSSHMesh(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// Server providing reverse tunneling and jump host.
	if cfg.SSHD != "" {
		// TODO: list of ssh servers for redundancy
		sshc, err := st.Client(ctx, cfg.SSHD)
		if err != nil {
			log.Fatal(err)
		}

		go sshc.StayConnected(cfg.SSHD)
	}

	// Start internal SSHD/SFTP, only admin can connect.
	// Better option is to install dropbear and start real sshd.
	// Will probably remove this - useful for static binary
	st.ChannelHandlers["session"] = sshdebug.SessionHandler

	// Start a SSH mesh node. This allows other authorized local nodes to jump and a debug
	// interface.
	_, err = st.Start()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: based on config, forward few local ports.

	// Client connections forwarded - similar to -D

	util.Sock5Capture(cfg.SocksAddr, func(s *util.Socks, c net.Conn) {
		t0 := time.Now()
		dest := s.Dest
		if dest == "" {
			dest = s.DestAddr.String()
		}
		pp, err := st.Proxy(ctx, dest, c)
		if err != nil {
			slog.Info("SocksDialError", "err", err, "dest", dest)
		}

		go func() {
			pp.ProxyTo(c)
			slog.Info("socks",
				"to", dest,
				"dur", time.Since(t0),
				//"dial", pp.sch.RemoteAddr(),
				"in", pp.InBytes,
				"out", pp.OutBytes,
				"ierr", pp.InErr,
				"oerr", pp.OutErr)
		}()

	})

	// Same for TProxy
	util.IptablesCapture(cfg.TProxyAddr, func(c net.Conn, destA, la *net.TCPAddr) {
		ctx := context.Background()
		t0 := time.Now()
		dest := destA.String()
		pp, err := st.Proxy(ctx, dest, c)
		if err != nil {
			slog.Info("TProxyDialError", "err", err, "dest", dest)
		}

		go func() {
			pp.ProxyTo(c)
			slog.Info("socks",
				"to", dest,
				"dur", time.Since(t0),
				//"dial", pp.sch.RemoteAddr(),
				"in", pp.InBytes,
				"out", pp.OutBytes,
				"ierr", pp.InErr,
				"oerr", pp.OutErr)
		}()
	})

	// TODO: debug trace
	util.MainEnd()
}

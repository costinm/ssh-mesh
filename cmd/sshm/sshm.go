package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/costinm/meshauth"

	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/sshdebug"
	"github.com/costinm/ssh-mesh/util"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)


// SSH mesh node.
//
// Currently very little config to keep it simple:
//
// - ssh port 15022
// - SOCKS on 15002
// - H2 on 15082
// - if running as root, TPROXY on 15001 (and expects a CNI to setup)
//
// Will look for a ".ssh" dir under HOME if set, otherwise a sshm.json file in the
// working directory.
//
// For easy run in K8S, env variables are also used:
// - SSH_AUTHORIZED_KEYS: enable shell access and SSHFS, for the 'owner'.
// - SSHD: connect to an upstream SSH mesh node (server) and keeps the
//  connection alive while remote-forwarding the SSH port.
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

	cfg := &sshd.SSHConfig{
		MeshAuthCfg: meshauth.MeshAuthCfg {
			Dst: map[string]*meshauth.Dest{},
			Listeners: map[string]*meshauth.PortListener{},
		},
	}
	err := util.MainStart("sshm", cfg)
	if err != nil {
		panic(err)
	}

	initDefaults(cfg)

	// Issuers are trusted to sign both JWTs and ssh certs.
	//
	authn := meshauth.NewAuthn(&cfg.MeshAuthCfg.AuthConfig)
	if len(cfg.AuthConfig.Issuers) > 0 {
		err := authn.FetchAllKeys(ctx, cfg.AuthConfig.Issuers)
		if err != nil {
			log.Println("Issuers", err)
		}
		cfg.TokenChecker = authn.CheckJwtMap
	}

	cfg.AuthConfig.Issuers = append(cfg.AuthConfig.Issuers,
		&meshauth.TrustConfig{
			Issuer: "https://accounts.google.com",
	})

	log.Println("Starting with ", cfg)
	// Start the SSH main object.
	st, err := sshd.NewSSHMesh(cfg)
	if err != nil {
		log.Fatal(err)
	}


	if len(cfg.AuthorizedKeys) == 0 {
		st.ChannelHandlers["session"] = sshd.SessionHandler
	} else {
		// Start internal SSHD/SFTP, only admin can connect.
		// Better option is to install dropbear and start real sshd.
		// Will probably remove this - useful for static binary
		st.ChannelHandlers["session"] = sshdebug.SessionHandler
	}

	// Start listening.
	_, err = st.Start()
	if err != nil {
		log.Fatal(err)
	}

	// Server providing reverse tunneling and chained jump host.
	// shouldn't be needed with sshd servers - only useful for tor-style chaining or as part of meshauth
	// This provides reflective keys.
	// TODO: support mesh.internal style and nip.io style.
	st.StayConnected(ctx)

	// Also start a H2 server - it increases the size from 6.1 to 6.8M, but it seems
	// worth it at this point. May optimize later...
	initH2(st, cfg)

	// Client connections forwarded - similar to -D
	initSocks(cfg, st, ctx)

	// Same for TProxy
	initTProxy(cfg, st)


	// TODO: debug trace
	util.MainEnd()
}

func initTProxy(cfg *sshd.SSHConfig, st *sshd.SSHMesh) (*net.TCPListener, error) {
	return util.IptablesCapture(cfg.TProxyAddr, func(c net.Conn, destA, la *net.TCPAddr) {
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
}

func initSocks(cfg *sshd.SSHConfig, st *sshd.SSHMesh, ctx context.Context) (net.Listener, error) {
	return util.Sock5Capture(cfg.SocksAddr, func(s *util.Socks, c net.Conn) {
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
}

func initH2(st *sshd.SSHMesh, cfg *sshd.SSHConfig) {
	// Load Http/h2 handlers (tunnel, etc)
	mux := http.NewServeMux()

	st.InitMux(mux)

	if cfg.H2CAddr != "" {
		go func() {
			// Adds about 400k to binary size - but allows the server to run behind an Istio/K8S
			// gateawy or in cloudrun.
			h2ch := h2c.NewHandler(mux, &http2.Server{})

			http.ListenAndServe(cfg.H2CAddr, h2ch)
		}()
	}
}

func initDefaults(cfg *sshd.SSHConfig) {
	// TODO: use same defaults as ztunnel
	if cfg.Listeners["socks"] == nil {
		cfg.Listeners["socks"] = &meshauth.PortListener{
			Address: "127.0.0.1:15002",
			Protocol: "socks",
		}
	}

	if cfg.SocksAddr == "" {
		cfg.SocksAddr = "127.0.0.1:15002"
	}
	if cfg.TProxyAddr == "" {
		cfg.TProxyAddr = ":15001"
	}
	if cfg.Address == "" {
		cfg.Address = ":15022"
	}
	if cfg.H2CAddr == "" {
		cfg.H2CAddr = ":15082"
	}
	sshdEnv := os.Getenv("SSHD")
	if sshdEnv != "" {
		cfg.Dst[sshdEnv] = &meshauth.Dest{
			Addr: sshdEnv,
			Proto: "ssh-upstream",
		}
	}

	// Load additional config from .ssh directory (running on a VM)
	sshd.EnvSSH(cfg)
}

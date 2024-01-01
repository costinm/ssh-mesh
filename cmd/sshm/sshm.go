package main

import (
	"context"
	"log"
	"net/http"

	"log/slog"

	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/ssh-mesh/util"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// SSHM is an extended version of the mesh ssh service, intended for
// jump hosts/gateway/waypoints.
//
// It also includes a H2C server for tunneling and routing.
// This has its separate go.mod - since it links k8s client libraries and
// other integrations.
func main() {
	// Basic init and load the config json (env, etc)
	cfg := &sshd.SSHConfig{}
	util.MainStart("sshm", cfg)

	if cfg.H2CAddr == "" {
		cfg.H2CAddr = ":15082"
	}
	if cfg.Address == "" {
		cfg.Address = ":15022"
	}

	if len(cfg.Issuers) > 0 {
		go InitJWT(cfg.Issuers)
		cfg.TokenChecker = CheckJwt
	}

	ctx := context.Background()
	// Start the SSH main object.
	st, err := sshd.NewSSHMesh(cfg)
	if err != nil {
		log.Fatal(err)
	}
	st.ChannelHandlers["session"] = sshd.SessionHandler

	// Server providing reverse tunneling and chained jump host.
	// shouldn't be needed with sshd servers - only useful for tor-style chaining or as part of meshauth
	// This provides reflective keys.
	// TODO: support mesh.internal style and nip.io style.
	if cfg.SSHD != "" {
		sshc, err := st.Client(ctx, cfg.SSHD)
		if err != nil {
			log.Fatal(err)
		}

		go sshc.StayConnected(cfg.SSHD)
	}

	// Start listening.
	_, err = st.Start()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Load Http/h2 handlers (tunnel, etc)
	st.InitMux(mux)

	if cfg.H2CAddr != "" {
		go func() {
			// Adds about 400k to binary size - but allows the server to run behind an Istio/K8S
			// gateawy or in cloudrun.
			h2ch := h2c.NewHandler(mux, &http2.Server{})

			http.ListenAndServe(cfg.H2CAddr, h2ch)
		}()
	}

	slog.Info("Started", "cfg", cfg)

	// wait for signals, etc.
	util.MainEnd()
}

package cmd

import (
	"github.com/costinm/meshauth"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
)

func InitH2C(module *meshauth.Module) error {
	if module.Address == "" {
		module.Address = ":15008"
	}
	// Also start a H2 server - it increases the size from 6.1 to 6.8M, but it seems
	// worth it at this point. May optimize later...
	// It allows the server to run behind an Istio/K8S gateawy or in cloudrun.
	h2ch := h2c.NewHandler(module.Mesh.Mux, &http2.Server{})
	go http.ListenAndServe(module.Address, h2ch)
	return nil
}

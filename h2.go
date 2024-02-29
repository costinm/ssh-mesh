package ssh_mesh

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/costinm/ssh-mesh/nio"
	"golang.org/x/crypto/ssh"
)

// InitMux add the H2 functions
//
func (st *SSHMesh) InitMux(mux *http.ServeMux) {
	mux.HandleFunc("/_debug/", func(writer http.ResponseWriter, request *http.Request) {
		// TODO
	})

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		// Override - when running in serverless or a gateway with fixed hostname
		hosts := request.Header.Get("x-host")

		host := request.Host

		if len(hosts) >0 {
			host = hosts
		}

		// HBONE-style connect - default is to accept a SSH tunnel.
		if host != "" {
			if host == "localhost:15022" {
				// Process as an in-process SSH connection.
				writer.WriteHeader(200)
				st.HandleServerConn(nio.NewStreamServerRequest(request, writer))
				return
			}


			cc, _ := st.connectedClientNodes.Load(host)

			if cc != nil {
				payload := ssh.Marshal(&remoteForwardChannelData{
					DestAddr:   "",
					DestPort:   uint32(80),
					OriginAddr: request.RemoteAddr,
					OriginPort: uint32(1234),
				})
				ch, reqs, err := cc.(*SSHSMux).ServerConn.OpenChannel("forwarded-tcpip", payload)
				if err != nil {
					writer.WriteHeader(500)
					return
				}
				go ssh.DiscardRequests(reqs)

				// TODO: create a H2C or HTTP connection to the host.
				//

				ch.Close()
				return
			}

			slog.Info("Req", "connect", host, "req", request)
			writer.WriteHeader(404)
			return
		}

		// WIP: forward to localhost or other destinations
		rt := http.DefaultClient

		preq := nio.CreateUpstreamRequest(writer, request)
		preq.URL, _ = url.Parse("http://localhost:8080")
		pres, err := rt.Do(preq)

		nio.SendBackResponse(writer, preq, pres, err)

		slog.Info("Req", "req", request)
		// TODO: apply any authz from the mesh config

	})
}



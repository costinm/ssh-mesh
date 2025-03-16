package ssh_mesh

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/costinm/ssh-mesh/nio"

	"golang.org/x/crypto/ssh"
)

// InitMux add the H2 functions on a mux.
func (st *SSHMesh) InitMux(mux *http.ServeMux) {
	u, _ := url.Parse("http://127.0.0.1:8080")
	localReverseProxyH1 := httputil.NewSingleHostReverseProxy(u)

	// TODO: option for h2 proxy

	mux.HandleFunc("/tun/", func(writer http.ResponseWriter, request *http.Request) {
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
				st.HandleServerConn(&SSHSMux{
					NetConn: nio.NewStreamServerRequest(request, writer),
					// TODO: use a different serverConfig that lets HTTP handle all authn, get authn from the http request
				})
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
		//rt := http.DefaultClient
		//preq := nio.CreateUpstreamRequest(writer, request)
		//preq.URL, _ = url.Parse("http://127.0.0.1:8080")
		//pres, err := rt.Do(preq)
		//
		//nio.SendBackResponse(writer, preq, pres, err)

		localReverseProxyH1.ServeHTTP(writer, request)

		slog.Info("Req", "req", request)
		// TODO: apply any authz from the mesh config

	})
}



package h2

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/costinm/ssh-mesh/nio"
)

// H2 is the HTTP/2 transport. It handles incoming http requests as mux
// and may be used as a http server as well.
//
// As a transport it can accept and dial connections, with proxy support.
//
// curl localhost:9080/debug/vars --http2-prior-knowledge
type H2 struct {
	//MaxHandlers:                  0,
	//MaxConcurrentStreams:         0,
	//MaxDecoderHeaderTableSize:    0,
	//MaxEncoderHeaderTableSize:    0,
	//MaxReadFrameSize:             0,
	//PermitProhibitedCipherSuites: false,
	//IdleTimeout:                  0,
	//MaxUploadBufferPerConnection: 0,
	//MaxUploadBufferPerStream:     0,
	//NewWriteScheduler:            nil,
	//CountError:                   nil,
	// Addr - included
	http.Server

	NetListener net.Listener

	// The key is a route as defined by go ServerMux.
	// The value can be:
	// - a URL - in which case it's a reverse proxy
	// - a string that is a resource name - in which case it's a Handler
	// Other values like TCP proxy can be defined later.
	Routes map[string]string

	// The actual mux that is configured. Will be mapped to a H2C/H1 server by
	// default, assuming ambient or secure network.
	Mux *http.ServeMux `json:-`

	SSHStreamHandler func(net.Conn) error

	// Client side
	DialMeta func(context.Context, string, string) (io.ReadWriteCloser, error)
	TokenSource TokenSource
	// ResourceStore is used to resolve resources, is a registry of types and
	// objects. We're looking for handlers.
	ResourceStore ResourceStore `json:-`
}

type ResourceStore interface {
	Resource(ctx context.Context, name string) (any, error)
}


// The x/net dependency can add h2c support (pre 1.24)
// The x/net also includes websocket, webdav, quic

// Can't do h2c using the std client - need custom code.
type H2C struct {
	http.Transport
}

func (h *H2C) Provision(ctx context.Context) error {
	//h.AllowHTTP = true
	//h.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	//	var d net.Dialer
	//	return d.DialContext(ctx, network, addr)
	//}

	//h.ReadIdleTimeout = 10000 * time.Second
	//h.StrictMaxConcurrentStreams = false
	h.Protocols = new(http.Protocols)
	h.Protocols.SetUnencryptedHTTP2(true)
	h.Protocols.SetHTTP1(true)

	return nil
}


func (r *H2) Provision(ctx context.Context) error {
	if r.Addr == "" {
		r.Addr = ":15082"
	}
	if r.Mux == nil {
		r.Mux = http.NewServeMux()
	}
	// TODO: add a middleware
	r.Handler = r.Mux
	r.Protocols = new(http.Protocols)
	r.Protocols.SetUnencryptedHTTP2(true)
	r.Protocols.SetHTTP1(true)

	if r.NetListener == nil {
		l, err := net.Listen("tcp", r.Addr)
		if err != nil {
			return err
		}

		r.NetListener = l
	}

	for k, v := range r.Routes {
		r.Mux.HandleFunc(k, func(writer http.ResponseWriter, request *http.Request) {
			h, err := r.ResourceStore.Resource(ctx, v)
			if err != nil {
				writer.WriteHeader(500)
				return
			}
			// TODO: if v is http or https - plug in a proxy
			// same for tcp/ssh/etc
			if hh, ok := h.(http.Handler); ok {
				hh.ServeHTTP(writer, request)
			} else {
				writer.WriteHeader(500)
				return
			}
		})
	}

	return nil
}

func (r *H2) Start() error {

	// Also start a H2 server - it increases the size from 6.1 to 6.8M, but it seems
	// worth it at this point. May optimize later...
	// It allows the server to run behind an Istio/K8S gateawy or in cloudrun.

	// implements the H2CD protocol - detects requests with PRI and proto HTTP/2.0 and Upgrade - and calls
	// ServeConn.

	// TODO: add 	if hb.TCPUserTimeout != 0 {
	//		// only for TCPConn - if this is used for tls no effect
	//		syscall.SetTCPUserTimeout(conn, hb.TCPUserTimeout)
	//	}

	go r.Serve(r.NetListener)
	return nil
}

func (r *H2) WithResourceStore(rs ResourceStore) {
	r.ResourceStore = rs
}


// InitMux add the H2 functions on a mux.
func (st *H2) InitMux(mux *http.ServeMux) {
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
				st.SSHStreamHandler(NewStreamServerRequest(request, writer))
				return
			}

			rwc, err := st.DialMeta(request.Context(), host, request.RemoteAddr)
			if err != nil {
				writer.WriteHeader(500)
				return
			}
			if rwc != nil {
				err := nio.Proxy(rwc, request.Body, writer, host)
				if err != nil {
					slog.Info("Error forwarding", "err", err)
				}
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



package h2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime/debug"
	"time"

	"github.com/costinm/ssh-mesh/nio"
)

// H2 is the HTTP/2 transport. It handles incoming http requests as mux
// and may be used as a http server as well.
//
// As a transport it can accept and dial connections, with proxy support.
//
// Test with:
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

	NetListener net.Listener `json:"-"`

	// The key is a route as defined by go ServerMux.
	// The value can be:
	// - a URL - in which case it's a reverse proxy
	// - a string that is a resource name - in which case it's a Handler
	// Other values like TCP proxy can be defined later.
	Routes map[string]string

	// The actual mux that is configured. Will be mapped to a H2C/H1 server by
	// default, assuming ambient or secure network.
	Mux *http.ServeMux `json:"-"`

	SSHStreamHandler func(net.Conn) error `json:"-"`

	// DialMeta opens a TCP connection to a client using -R on 80
	// or 443, using the FQDN. This and next 2 functions integrate
	// with the 'mesh' layer, discovering or using connections.
	DialMeta func(context.Context, string, string) (io.ReadWriteCloser, error) `json:"-"`

	FindRoundTripper func(ctx context.Context, urlOrHost string) (http.RoundTripper, error)

	// RegisterReverse handles a mapping of '-R' remote accept connections.
	// HTTP, SSH are treated specially.
	RegisterReverse func(ctx context.Context, host string, rt http.RoundTripper)

	TokenSource TokenSource `json:"-"`

	// ResourceStore is used to resolve resources, is a registry of types and
	// objects. We're looking for handlers.
	ResourceStore ResourceStore `json:"-"`

	Logger *slog.Logger

	clients map[string]*H2C `json:"-"`
	fs      http.Handler
}

func New() *H2 {
	h2 := &H2{
		Mux:    http.NewServeMux(),
		Routes: map[string]string{},
		Server: http.Server{
			Protocols: &http.Protocols{},
		},
		Logger: slog.Default(),
	}
	h2.Server.Handler = h2.Mux
	h2.Protocols.SetUnencryptedHTTP2(true)
	h2.Protocols.SetHTTP1(true)

	return h2
}

type ResourceStore interface {
	Resource(ctx context.Context, name string) (any, error)
}

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

// The x/net dependency can add h2c support (pre 1.24)
// The x/net also includes websocket, webdav, quic

func (r *H2) Provision(ctx context.Context) error {
	if r.Addr == "" {
		r.Addr = ":15082"
	}
	r.clients = map[string]*H2C{}
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

	r.Logger = r.Logger.With("addr", r.NetListener.Addr().String())

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
	if _, err := os.Stat("./www"); err == nil {
		r.fs = http.FileServer(http.Dir("./www"))
		r.Mux.Handle("/", r.fs)
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

	r.Logger.Info("h2/start")
	go r.Serve(r.NetListener)
	return nil
}

func (r *H2) WithResourceStore(rs ResourceStore) {
	r.ResourceStore = rs
}

func (st *H2) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	actx := &nio.RequestContext{
		Context: request.Context(),

		Start: time.Now(),
	}
	if st.Logger != nil {
		actx.Logger = st.Logger.With("url", request.URL)
	}

	defer func() {
		// TODO: add it to an event buffer
		if st.Logger != nil {
			st.Logger.InfoContext(request.Context(), "REQUEST",
				//"remoteID", RemoteID,
				//"SAN", SAN,
				"request", request.URL, "time", time.Since(actx.Start))
		}
		if r := recover(); r != nil {
			// TODO: this should go to utel tracing (via slog interface)
			if st.Logger != nil {
				st.Logger.Info("Recover", "err", r)
			}
			debug.PrintStack()

			// find out exactly what the error was and set err
			var err error

			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			if err != nil {
				fmt.Println("ERRROR: ", err)
			}
		}
	}()

	//if h.Auth != nil {
	//	err := h.Auth.Auth(actx, request)
	//	if err != nil {
	//		log.Println("Failed auth", err, request.Header)
	//		writer.WriteHeader(403)
	//		return
	//	}
	//}

	// other keys in a normal request context:
	// - http-server (*http.Server)
	// - local-addr - *net.TCPAddr
	st.Mux.ServeHTTP(writer, request.WithContext(actx))

}

func (st *H2) ProxyHTTP(writer http.ResponseWriter, request *http.Request) {
	host := request.Host
	hosts := request.Header.Get("x-host")
	if len(hosts) > 0 {
		host = hosts
	}
	if host == "" {
		u, _ := url.Parse("http://127.0.0.1:8080")
		localReverseProxyH1 := httputil.NewSingleHostReverseProxy(u)
		localReverseProxyH1.ServeHTTP(writer, request)
		return
	}
}

// HandleTun handles a request for '-L' style tunneling - the remote
// is asking to proxy a TCP connection.
//
// # In-process services (SSH and HTTP) are handled directly
//
// Local ports and remote destinations can be forwarded only with authz,
// for 'owner' and allowed users.
func (st *H2) HandleTunReq(writer http.ResponseWriter, request *http.Request) {

	// Override - when running in serverless or a gateway with
	// fixed hostname. Otherwise use the Host header.
	host := request.Host
	hosts := request.Header.Get("x-host")
	if len(hosts) > 0 {
		host = hosts
	}

	// HBONE-style connect - default is to accept a SSH tunnel.
	if host != "" {
		if host == "localhost:15022" || host == "ssh" {
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
}

// InitMux add the H2 functions on a mux.
func (st *H2) InitMux(mux *http.ServeMux) {

	mux.HandleFunc("/tun/", st.HandleTunReq)

	// Default route
	u, _ := url.Parse("http://127.0.0.1:8080")
	localReverseProxyH1 := httputil.NewSingleHostReverseProxy(u)

	// My custom proxy is obsoleted by the upstream proxy, which has
	// better features. Only thing missing seems to be stats on copy.
	// If I need it, will just start with a fork of the new
	// upstream code.

	// TODO: option for h2 proxy
	mux.Handle("/", localReverseProxyH1)
}

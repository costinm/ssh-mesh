package nio

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const ConnectOverrideHeader = "x-host"

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

type H2Dialer struct {
	MDS TokenSource
	H2TunURL string
	HttpClient *http.Client
}

func NewH2Dialer(tunURL string) (*H2Dialer) {
	return &H2Dialer{
		H2TunURL: tunURL,
		HttpClient:  http.DefaultClient,
	}
}

func (h2d *H2Dialer) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {
	r, w := io.Pipe()
	req, _ := http.NewRequest("POST", h2d.H2TunURL, r)

	// TODO: JWT from MDS
	if h2d.MDS != nil {
		t, err := h2d.MDS.GetToken(ctx, addr)
		if err != nil {
			return nil, err
		}
		if t != "" {
			req.Header["authorization"] = []string{"Bearer " + t}
		}
	}
	req.Header[ConnectOverrideHeader] = []string{addr}

	// HBone uses CONNECT IP:port - we need to use POST and can't use the header. For now use x-host

	res, err := h2d.HttpClient.Do(req)
	if err != nil {
		if res == nil {
			log.Println("H2T error", err)
		} else {
			log.Println("H2T error", err, res.StatusCode, res.Header)
		}
		return nil, err
	}

	log.Println("H2T", res.StatusCode, res.Header)

	return newStreamHttpRequest(w, req, res), nil
}

// NewStreamH2 creates a H2 stream using POST.
//
// Will use the token provider if not nil.
func NewStreamH2(ctx context.Context, hc *http.Client, addr string, tcpaddr string, mds TokenSource) (*StreamHttpClient, error) {
	hd := &H2Dialer{
		HttpClient: hc,
		MDS: mds,
		H2TunURL: addr,
	}
	nc, err := hd.DialContext(ctx, "tcp", tcpaddr)
	if err != nil {
		return nil, err
	}

	return nc.(*StreamHttpClient), err
}

type StreamHttpClient struct {
	StreamState

	Request        *http.Request
	Response   *http.Response
	ReadCloser func()

	// Writer side of the request pipe
	TLS           *tls.ConnectionState
	RequestInPipe io.WriteCloser
}

func (s *StreamHttpClient) Context() context.Context {
	return s.Request.Context()
}

// Create a new stream from a HTTP request/response.
//
// For accepted requests, http2/server.go newWriterAndRequests populates the request based on the headers.
// Server validates method, path and scheme=http|https. Req.Body is a pipe - similar with what we use for egress.
// Request context is based on stream context, which is a 'with cancel' based on the serverConn baseCtx.
func newStreamHttpRequest(rw io.WriteCloser,  r *http.Request, w *http.Response) *StreamHttpClient { // *StreamHttpClient {
	slog.Info("H2C-client", "res", w.Header,"rs", w.Status, "sc", w.StatusCode)
	return &StreamHttpClient{
		//StreamId: int(atomic.AddUint32(&nio.StreamId, 1)),
		StreamState: StreamState{Stats: Stats{Open: time.Now()}},

		Request:       r,
		Response:      w,
		RequestInPipe: rw,
		// TODO: extract from JWT, reconstruct
		TLS: r.TLS,
		//Dest:    r.Host,
	}
}

// NewStreamRequest creates a Stream based on the result of a RoundTrip.
// out is typically the pipe used by request to send bytes.
// TODO: abstract the pipe and the roundtrip call.
func NewStreamRequest(r *http.Request, out io.WriteCloser, w *http.Response) Stream { // *StreamHttpClient {
	return &StreamHttpClient{
		StreamState: StreamState{Stats: Stats{Open: time.Now()}},
		//OutHeader:   w.Header,
		Request: r,
		//In:          w.Body, // Input from remote http
		RequestInPipe: out, //
		//TLS:         r.TLS,
		Response: w,
		//Dest:        r.Host,
	}
}



func (s *StreamHttpClient) Read(b []byte) (n int, err error) {
	// TODO: update stats
	return s.Response.Body.Read(b)
}

func (s *StreamHttpClient) Write(b []byte) (n int, err error) {
	n, err = s.RequestInPipe.Write(b)
	if err != nil {
		s.WriteErr = err
		return n, err
	}
	//if f, ok := s.ResponseWriter.(http.Flusher); ok {
	//	f.Flush()
	//}
	s.SentBytes += n
	s.SentPackets++
	s.LastWrite = time.Now()

	return
}

func (s *StreamHttpClient) Close() error {
	if s.ReadCloser != nil {
		s.ReadCloser()
	}
	return s.CloseWrite()
}

func (s *StreamHttpClient) CloseWrite() error {
	// There is no real close - returning from the handler will be the close.
	// This is a problem for flushing and proper termination, if we terminate
	// the connection we also stop the reading side.
	// Server side HTTP stream. For client side, FIN can be sent by closing the pipe (or
	// request body). For server, the FIN will be sent when the handler returns - but
	// this only happen after request is completed and body has been read. If server wants
	// to send FIN first - while still reading the body - we are in trouble.

	// That means HTTP2 TCP servers provide no way to send a FIN from server, without
	// having the request fully read.
	// This works for H2 with the current library - but very tricky, if not set as trailer.
	s.RequestInPipe.Close()
	return nil
}

func (s *StreamHttpClient) LocalAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (s *StreamHttpClient) RemoteAddr() net.Addr {
	if s.Request != nil && s.Request.RemoteAddr != "" {
		r, err := net.ResolveTCPAddr("tcp", s.Request.RemoteAddr)
		if err == nil {
			return r
		}
	}
	return nil
}

func (s *StreamHttpClient) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *StreamHttpClient) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *StreamHttpClient) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *StreamHttpClient) State() *StreamState {
	return &s.StreamState
}

func (s *StreamHttpClient) Header() http.Header {
	return s.Response.Header
}

func (s *StreamHttpClient) RequestHeader() http.Header {
	return s.Request.Header
}

func (s *StreamHttpClient) TLSConnectionState() *tls.ConnectionState {
	return s.TLS
}

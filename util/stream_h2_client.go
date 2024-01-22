package util

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)


type StreamHttpClient struct {
	StreamState

	Request        *http.Request
	TLS        *tls.ConnectionState
	Response   *http.Response
	ReadCloser func()

	// Writer side of the request pipe
	RequestWriter  io.WriteCloser
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
		RequestWriter: rw,
		// TODO: extract from JWT, reconstruct
		TLS: r.TLS,
		//Dest:    r.Host,
	}
}

const ConnectOverrideHeader = "x-host"

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

// NewStreamH2 creates a H2 stream using POST.
//
// Will use the token provider if not nil.
func NewStreamH2(ctx context.Context, addr string, tcpaddr string, mds TokenSource) (*StreamHttpClient, error) {

	r, w := io.Pipe()
	req, _ := http.NewRequest("POST", addr, r)
	// TODO: JWT from MDS
	if mds != nil {
		t, err := mds.GetToken(ctx, addr)
		if err != nil {
			return nil, err
		}
		req.Header["authorization"] = []string{"Bearer " + t}
	}
	req.Header[ConnectOverrideHeader] = []string{tcpaddr}

	// HBone uses CONNECT IP:port - we need to use POST and can't use the header. For now use x-host

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return newStreamHttpRequest(w, req, res), nil
}

func (s *StreamHttpClient) Read(b []byte) (n int, err error) {
	// TODO: update stats
	return s.Response.Body.Read(b)
}

func (s *StreamHttpClient) Write(b []byte) (n int, err error) {
	n, err = s.RequestWriter.Write(b)
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
	s.RequestWriter.Close()
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
	return nil // s.Response.Header()
}

func (s *StreamHttpClient) RequestHeader() http.Header {
	return s.Request.Header
}

func (s *StreamHttpClient) TLSConnectionState() *tls.ConnectionState {
	return s.TLS
}

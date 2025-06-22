package h2

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// NewStreamH2 creates a H2 stream using POST.
//
// Will use the token provider if not nil.
func NewStreamH2(ctx context.Context, hc http.RoundTripper, addr string, tcpaddr string, mds TokenSource) (*StreamHttpClient, error) {

	r, w := io.Pipe()

	req, _ := http.NewRequest("POST", addr, r)

	// TODO: JWT from MDS
	if mds != nil {
		t, err := mds.GetToken(ctx, addr)
		if err != nil {
			return nil, err
		}
		if t != "" {
			req.Header["authorization"] = []string{"Bearer " + t}
		}
	}
	req.Header[ConnectOverrideHeader] = []string{addr}

	// HBone uses CONNECT IP:port - we need to use POST and can't use the header. For now use x-host

	res, err := hc.RoundTrip(req)
	if err != nil {
		if res == nil {
			log.Println("H2T error", err)
		} else {
			log.Println("H2T error", err, res.StatusCode, res.Header)
		}
		return nil, err
	}

	// log.Println("H2T", res.StatusCode, res.Header)

	return &StreamHttpClient{
		Request:       req,
		Response:      res,
		RequestInPipe: w,
	}, err
}

type StreamHttpClient struct {
	StreamState

	Request  *http.Request
	Response *http.Response

	RequestInPipe io.WriteCloser
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

package nio

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

)

/*
The mesh is lazy - which is the most scalable design, trading off latency
on the first request for a given peer with 'internet scale', low startup
cost, low config size.

This is very different from Istio v1 - where ALL config for the mesh is sent
 to ALL nodes, trading huge config and high startup cost for ~100 ms for
each initial connection.

Browsers and most internet apps are lazy too - they don't know about a peer
DNS and other properties until they are needed.

On the listener side, mesh capturing egress can also be lazy - SOCKS or captured outbond connections can be configured on-demand, and same for
accepted inbound connections.

The mesh still need to listens on a couple of ports:
- inbound tproxy capture
- egress tproxy capture
- SOCKS for non-capture egress
- HTTP/2 H2C for 'sandwitched' mesh with L4 secure
- H2 and SSH for native security.
- http for local admin and control

The mesh model is also 'peer to peer' - each node can request or serve
'resources' or streams, and may use established peering (SSH for example,
or already estabilished trust and metadata, address).

*/


// Listener is a wrapper around net.Listener.
//
// Few things to note:
// - in many cases the real listener will be remote (ssh -R) or provided by some
//   plugin or integration (caddy reloading listener, etc)
// - the core idea for ssh-mesh is on-demand - the handler may also be a separate
//   child process, wasm module etc that is not loaded.

type Listener struct {
	// NetListener and Dialer can be set by the user.
	NetListener net.Listener  `json:"-"`

	Address string `json:"address,omitempty"`

	ForwardTo string
	Dialer      ContextDialer `json:"-"`

	// Once the listener is created, it will be passed to an object using
	// http.Serve pattern. In all other cases it will start listening and
	// accepting connections.
	TCPServer TCPServer `json:"-"`

	// ConnServer is equivalent to http.Handler, will handle an accepted
	// connection.
	ConnServer ConnServer `json:"-"`

}

var NewListener func(ctx context.Context, addr string) net.Listener

type ContextDialer interface {
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}

type TCPServer interface {
  // Serve is a blocking call - returns when the server is closed, usually
	// because listener is shutting down.
	Serve(net.Listener) error
}

type ConnServer interface {
	// Serve is a blocking call - returns when the server is closed, usually
	// because listener is shutting down.
	ServeTCP(context.Context, net.Conn) error
}

type ConnServerBuilder interface {
	// Serve is a blocking call - returns when the server is closed, usually
	// because listener is shutting down.
	NewTCPServer() func(context.Context, net.Conn)
}

type StreamHandler interface {
	HandleStream(ctx context.Context, w io.Writer, r io.Reader)
}

type TCPProxy struct {
	Dialer ContextDialer

	// ForwardTo is the address to forward to.
	ForwardTo string

	PostDial func(ctx context.Context, dialedConn net.Conn, addr string) error
}

func (tl *TCPProxy) ProxyTCP(ctx context.Context, listenerConn net.Conn,
	addr string) error {
	return nil
}


func (tl *Listener) ServeTCP(ctx context.Context, a net.Conn) error {

	nc, err := tl.Dialer.DialContext(ctx, "", tl.ForwardTo)
	if err != nil {
		log.Println("RoundTripStart error", tl.ForwardTo, err)
		a.Close()
		return nil
	}
	err = Proxy(nc, a, a, tl.ForwardTo)
	if err != nil {
		log.Println("FWD", tl.Address, a.RemoteAddr(), err)
	} else {
		log.Println("FWD", tl.Address, a.RemoteAddr())
	}

	return err
}

func (tl *Listener) Serve(l net.Listener) error {
	tl.NetListener = l
	for {
		a, err := l.Accept()
		if ne, ok := err.(interface {
			Temporary() bool
		}); ok && ne.Temporary() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
		go tl.ServeTCP(context.Background(), a)
	}
}


func (tl *Listener) Start(ctx context.Context) error {
	if tl.Address == "" {
		return nil
	}

	if tl.NetListener == nil {
		var err error
		if NewListener != nil {
			tl.NetListener = NewListener(context.Background(), tl.Address)
			// May be nil or a virtual listener (reverse)
		} else {
			tl.NetListener, err = Listen(tl.Address)
		}

		ls, err := net.Listen("tcp", tl.Address)
		if err != nil {
			return err
		}
		tl.NetListener = ls
	}

	go func() {
		err := tl.Serve(tl.NetListener)
		if err != nil {
			log.Println("Serve error", err)
		}
	}()
	return nil
}

func Listen(addr string) (net.Listener, error) {
	if os.Getenv("NO_FIXED_PORTS") != "" {
		addr = ":0"
	}
	if strings.HasPrefix(addr, "/") ||
			strings.HasPrefix(addr, "@") {
		if strings.HasPrefix(addr, "/") {
			if _, err := os.Stat(addr); err == nil {
				os.Remove(addr)
			}
		}
		us, err := net.ListenUnix("unix",
			&net.UnixAddr{
				Name: addr,
				Net:  "unix",
			})
		if err != nil {
			return nil, err
		}

		return us, err
	}

	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return listener, err
}

type VListener struct {
	closed   chan struct{}
	incoming chan net.Conn
	netAddr  net.Addr
	NetListener net.Listener
}


func (l *VListener) OnConnection(c net.Conn) error {
	l.incoming <- c
	return nil
}

func (l *VListener) Close() error {
	l.closed <- struct{}{}
	return nil
}

func (l *VListener) Addr() net.Addr {
	if l.netAddr != nil {
		return l.netAddr
	}
	if l.NetListener != nil {
		return l.NetListener.Addr()
	}
	return l.netAddr
}

func (l *VListener) Accept() (net.Conn, error) {
	if l.NetListener != nil {
		return l.NetListener.Accept()
	}
	for {
		select {
		case c, ok := <-l.incoming:
			if !ok {
				return nil, fmt.Errorf("listener is closed")
			}
			return c, nil
		case <-l.closed:
			return nil, fmt.Errorf("listener is closed")
		}
	}
}

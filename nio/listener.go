package nio

import (
	"expvar"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

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

func ListenAndServe(addr string, f func(conn net.Conn)) (net.Listener, error) {
	listener, err := Listen(addr)
	if err != nil {
		return nil, err
	}
	go ServeListener(listener, f)
	return listener, nil
}

func ServeListener(l net.Listener, f func(conn net.Conn)) error {
	varzAccepted := expvar.NewInt(fmt.Sprintf("io_accept_total{addr=%q}", l.Addr().String()))
	varzAcceptErr := expvar.NewInt(fmt.Sprintf("io_accept_err_total{addr=%q}", l.Addr().String()))
	for {
		remoteConn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(interface {
				Temporary() bool
			}); ok && ne.Temporary() {
				varzAcceptErr.Add(1)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// TODO: callback to notify. This may happen if interface restarts, etc.
			log.Println("Accepted done ", l)
			return err
		}

		varzAccepted.Add(1)

		// TODO: set read/write deadlines

		go f(remoteConn)
	}
}

// ChannelListener implements Listener interface over a chan
// It allows apps expecting a net.Listener to accept virtual streams
// tunneled and multiplexed.
type ChannelListener struct {
	closed   chan struct{}
	incoming chan net.Conn
	Address  net.Addr
}

func NewChannelListener() *ChannelListener {
	return &ChannelListener{
		incoming: make(chan net.Conn),
		closed:   make(chan struct{}),
	}
}

func (l *ChannelListener) OnConnection(c net.Conn) error {
	l.incoming <- c
	return nil
}

func (l *ChannelListener) Close() error {
	l.closed <- struct{}{}
	return nil
}

func (l *ChannelListener) Addr() net.Addr {
	return l.Address
}

func (l *ChannelListener) Accept() (net.Conn, error) {
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

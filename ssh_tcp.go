package ssh_mesh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	ssh "golang.org/x/crypto/ssh"
	"golang.org/x/exp/slog"
)

// TCP forwarding - server side.
// sshc includes client side TCP handling.

type localForwardChannelData struct {
	// DestAddr can be a string (hostname) or IP.
	// For mesh destinations, hostname will be used.
	DestAddr string

	// DestPort is the frontend service port.
	// Special ports: 22, 15022, 80, 443, 8080, 8443 may be handled
	// directly.
	DestPort uint32

	// OriginAddr and port should be the initial client.
	OriginAddr string
	OriginPort uint32
}

// DirectTCPIPHandler is for 'direct-tcpip' channel type, to support client-originated reverseForwards. It runs on the
// server side.
//
// # See RFC 4254 7.2
//
// - When client starts with a -L CPORT:host:port, and connects to CPORT
// - Also when client uses socks for dynamic reverseForwards (-D)
// - jump (-J)
//
// If the destination port is 22/15022 - existing connections can be used to
// avoid an extra TCP connection.
//
// Laddr is typically 127.0.0.1 (unless ssh has an open socks, and other machines use it)
func DirectTCPIPHandler(ctx context.Context, srv *SSHMesh, newChan ssh.NewChannel) {
	d := localForwardChannelData{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)

	// We now have a destination host and port, and the channel to forward.

	t0 := time.Now()

	if d.DestPort == 22 || d.DestPort == 15022 {
		if rc, ok := srv.connectedClientNodes.Load(d.DestAddr); ok {
			conn, _ := rc.(*SSHSMux)
			payload := ssh.Marshal(&remoteForwardChannelData{
				DestAddr:   d.DestAddr,
				DestPort:   22,
				OriginAddr: d.OriginAddr,
				OriginPort: d.OriginPort,
			})
			sch, reqs, err := conn.ServerConn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				// TODO: log failure to open channel
				log.Println(err)
				ch.Close()
				return
			}
			go ssh.DiscardRequests(reqs)

			proxy(ch, sch, func(ein error, eout error, nin int64, nout int64) {
				slog.Info("direct-tcpip jump", "to", dest, "from", fmt.Sprintf("%s:%d", d.OriginAddr, d.OriginPort),
					"dur", time.Since(t0),
					"in", nin, "out", nout, "ierr", ein, "oerr", eout)
			})
			return
		}
	}

	// Generic handler for all reverseForwards. If not set, use Dial()
	if srv.Forward != nil {
		srv.Forward(ctx, dest, ch)
		return
	}

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	proxy(ch, dconn, func(ein error, eout error, nin int64, nout int64) {
		slog.Info("direct-tcpip", "to", dest, "from", fmt.Sprintf("%s:%d", d.OriginAddr, d.OriginPort),
			"dur", time.Since(t0), "dial", dconn.RemoteAddr(),
			"in", nin, "out", nout, "ierr", ein, "oerr", eout)
	})
}

type Proxy struct {
	sch io.ReadWriteCloser

	OutBytes, InBytes int64
	OutErr, InErr     error
}

func (p *Proxy) ProxyTo(ch io.ReadWriteCloser) {
	c := make(chan error, 1)
	go func() {
		p.OutBytes, p.OutErr = io.Copy(p.sch, ch)
		c <- p.OutErr
	}()
	defer ch.Close()
	defer p.sch.Close()

	p.InBytes, p.InErr = io.Copy(ch, p.sch)
}

func (srv *SSHMesh) Proxy(ctx context.Context, dest string, ch io.ReadWriteCloser) (*Proxy, error) {
	var dialer net.Dialer
	// TODO: never dial port 80 ( or the list of HTTP ports) from a local capturing service.
	// Must go to SSH or HTTPS port.
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}

	return &Proxy{sch: dconn}, nil
}

func proxy(ch io.ReadWriteCloser, sch io.ReadWriteCloser, onDone func(error, error, int64, int64)) {
	var nin, nout int64
	c := make(chan error, 1)
	go func() {
		defer ch.Close()
		defer sch.Close()
		n, err := io.Copy(ch, sch)
		nin = n
		err2 := <-c
		onDone(err, err2, nin, nout)
	}()
	go func() {
		n, err := io.Copy(sch, ch)
		nout = n
		c <- err
	}()
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// "tcpip-forward" is used by clients to request servers accept and use forwarded-tcpip.
//
// This has few special ports:
//   - 22 - any client asking for SSH forwarding will be multiplexed as a jump host.
//     Hostname based on credentials.
func tcpipForwardHandler(ctx context.Context, srv *SSHMesh, conn *SSHSMux, req *ssh.Request) (bool, []byte) {
	var reqPayload remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}
	if reqPayload.BindPort == 0 || reqPayload.BindPort == 15022 {
		// Treat port 0 as port 15022 (i.e. jump MUX). A SSH node doesn't support
		// arbitrary ports.
		//if reqPayload.BindAddr != "" {
		//	// TODO: cert must allow it
		//	srv.connectedClientNodes.Store(reqPayload.BindAddr, conn)
		//}
		// TODO: if the node is on H2C - return 443 to indicate mux over H2.
		return true, ssh.Marshal(&remoteForwardSuccess{15022})
	}
	if reqPayload.BindPort == 22 {
		//srv.connectedClientNodes.Store(reqPayload.BindAddr, conn)
		return true, ssh.Marshal(&remoteForwardSuccess{reqPayload.BindPort})
	}
	if reqPayload.BindPort == 80 {
		return true, ssh.Marshal(&remoteForwardSuccess{reqPayload.BindPort})
	}

	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))

	ln, err := net.Listen("tcp", addr)

	if err != nil {
		// TODO: log listen failure
		return false, []byte{}
	}
	_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
	destPort, _ := strconv.Atoi(destPortStr)
	srv.Lock()
	srv.reverseForwards[addr] = ln
	srv.Unlock()

	go func() {
		<-ctx.Done()
		srv.Lock()
		ln, ok := srv.reverseForwards[addr]
		srv.Unlock()
		if ok {
			ln.Close()
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				// TODO: log accept failure
				break
			}
			originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			originPort, _ := strconv.Atoi(orignPortStr)
			payload := ssh.Marshal(&remoteForwardChannelData{
				DestAddr:   reqPayload.BindAddr,
				DestPort:   uint32(destPort),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})
			go func() {
				ch, reqs, err := conn.ServerConn.OpenChannel("forwarded-tcpip", payload)
				if err != nil {
					// TODO: log failure to open channel
					log.Println(err)
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				proxy(c, ch, func(err error, err2 error, i int64, i2 int64) {

				})
			}()
		}

		srv.Lock()
		delete(srv.reverseForwards, addr)
		srv.Unlock()
	}()

	return true, ssh.Marshal(&remoteForwardSuccess{uint32(destPort)})
}

func cancelTcpipForwardHandler(ctx context.Context, srv *SSHMesh, conn *SSHSMux, req *ssh.Request) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}

	//p := reqPayload.BindPort
	//if p == 22 || p == 15022 {
	//	srv.connectedClientNodes.Delete(reqPayload.BindAddr)
	//	return true, nil
	//}

	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	srv.Lock()
	ln, ok := srv.reverseForwards[addr]
	srv.Unlock()
	if ok {
		ln.Close()
	}
	return true, nil
}

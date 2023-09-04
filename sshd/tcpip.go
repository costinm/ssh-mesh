package sshd

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	ssh "golang.org/x/crypto/ssh"
	"golang.org/x/exp/slog"
)

// Handle TCP forward.
//
// based on gliderlabs, sish - will probably be replaced with the more
// efficient impl from wpgate.

// - When client starts with a -L CPORT:host:port, and connects to CPORT
// - Also when client uses socks for dynamic forwards.
// - jump (-J)
func directTcpipHandler(ctx context.Context, ssht *Transport, conn ssh.Conn,
	newChannel ssh.NewChannel) {

	// TODO: allow connections to mesh VIPs
	//if role == ROLE_GUEST &&
	//		req.Rport != SSH_MESH_PORT && req.Rport != H2_MESH_PORT {
	//	newChannel.Reject(ssh.Prohibited,
	//		"only authorized users can proxy " +
	//				scon.VIP6.String())
	//	continue
	//}
	//log.Println("-L: forward request", req.Laddr, req.Lport, req.Raddr, req.Rport, role)

	go DirectTCPIPHandler(ctx, ssht, conn, newChannel)
	//scon.handleDirectTcpip(newChannel, req.Raddr, req.Rport, req.Laddr, req.Lport)
	//conId++
}

// RFC 4254 7.2 - direct-tcpip
// -L or -D, or egress. Client using VPN as an egress gateway.
// Raddr can be a string (hostname) or IP.
// Laddr is typically 127.0.0.1 (unless ssh has an open socks, and other machines use it)
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// Handles direct-tcpip channel type. This is typically running on the server, to support
// client-originated forwards.
//
// Clients handle forwarded-tcpip requests from server (accepted connections).
//
// Will extract the destination IP:port and forward the request.
// TODO: plugin the mesh transport and RBAC
func DirectTCPIPHandler(ctx context.Context, srv *Transport, conn ssh.Conn, newChan ssh.NewChannel) {
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
	t0 := time.Now()

	if d.DestPort == 22 {
		if rc, ok := srv.jumpHosts.Load(d.DestAddr); ok {
			conn, _ := rc.(*ssh.ServerConn)
			payload := ssh.Marshal(&remoteForwardChannelData{
				DestAddr:   d.DestAddr,
				DestPort:   22,
				OriginAddr: d.OriginAddr,
				OriginPort: d.OriginPort,
			})
			sch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				// TODO: log failure to open channel
				log.Println(err)
				ch.Close()
				return
			}
			go ssh.DiscardRequests(reqs)

			go proxy(ch, sch, func() {
				slog.Info("direct-tcpip jump", "to", d.DestAddr, "from", "",
					"dur", time.Since(t0))
			})
			return
		}
	}

	// Generic handler for all forwards. If not set, use Dial()
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

	go proxy(ch, dconn, func() {
		slog.Info("direct-tcpip", "to", d.DestAddr, "from", "",
			"dur", time.Since(t0))
	})

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}

func proxy(ch io.ReadWriteCloser, sch io.ReadWriteCloser, onDone func()) {
	go func() {
		defer ch.Close()
		defer sch.Close()
		io.Copy(ch, sch)
	}()
	go func() {
		defer ch.Close()
		defer sch.Close()
		io.Copy(sch, ch)
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

// tcpip-forward is used by clients to request servers accept and use forwarded-tcpip.
//
// This has few special ports:
//   - 22 - any client asking for SSH forwarding will be multiplexed as a jump host.
//     Hostname based on credentials.
//   - 80/443 - TODO, based on SISH - similar multiplexing
func tcpipForwardHandler(ctx context.Context, srv *Transport,
	conn *ssh.ServerConn, req *ssh.Request) (bool, []byte) {
	srv.Lock()
	if srv.forwards == nil {
		srv.forwards = make(map[string]net.Listener)
	}
	srv.Unlock()

	var reqPayload remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}
	if reqPayload.BindPort == 22 {
		srv.jumpHosts.Store(reqPayload.BindAddr, conn)
		return true, ssh.Marshal(&remoteForwardSuccess{reqPayload.BindPort})
	}
	if reqPayload.BindPort == 80 {
		srv.httpHosts.Store(reqPayload.BindAddr, conn)
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
	srv.forwards[addr] = ln
	srv.Unlock()
	go func() {
		<-ctx.Done()
		srv.Lock()
		ln, ok := srv.forwards[addr]
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
				ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
				if err != nil {
					// TODO: log failure to open channel
					log.Println(err)
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					defer ch.Close()
					defer c.Close()
					io.Copy(ch, c)
				}()
				go func() {
					defer ch.Close()
					defer c.Close()
					io.Copy(c, ch)
				}()
			}()
		}
		srv.Lock()
		delete(srv.forwards, addr)
		srv.Unlock()
	}()

	return true, ssh.Marshal(&remoteForwardSuccess{uint32(destPort)})
}

func cancelTcpipForwardHandler(ctx context.Context, srv *Transport, conn *ssh.ServerConn, req *ssh.Request) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}

	if reqPayload.BindPort == 22 {
		srv.jumpHosts.Delete(reqPayload.BindAddr)
		return true, nil
	}

	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	srv.Lock()
	ln, ok := srv.forwards[addr]
	srv.Unlock()
	if ok {
		ln.Close()
	}
	return true, nil
}

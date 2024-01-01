package ssh_mesh

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/costinm/ssh-mesh/util"
	"golang.org/x/crypto/ssh"
)

// Client side of SSH mesh.
//

// SSHCMux is a multiplexed client connection to a single destination.
type SSHCMux struct {
	Mux
	*SSHConfig

	*Dest

	LastConnected time.Time

	// The SSH Conn object
	SSHConn ssh.Conn

	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request

	// TODO: limit by domain ?
	AuthorizedCA []ssh.PublicKey

	// Same as the transport
	CertChecker *ssh.CertChecker

	SSHClient *ssh.Client

	// Last received remote key (should be a Certificate)
	RemoteKey ssh.PublicKey
}

// Dial opens one SSH connection to addr.
// It blocks until the handshake is done.
func (sc *SSHCMux) Dial(ctx context.Context, addr string) error {
	tcon, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return sc.DialConn(ctx, tcon, addr)
}

func (sc *SSHCMux) DialConn(ctx context.Context, tcon net.Conn, addr string) error {
	sc.NetConn = tcon

	if sc.Id == "" {
		sc.Id = "jwt"
	}

	mdsBase := os.Getenv("GCE_METADATA_HOST")
	if mdsBase == "" {
		mdsBase = "169.254.169.254"
	}
	if !strings.Contains(mdsBase, "/") {
		mdsBase = "http://" + mdsBase + "/computeMetadata/v1/"
	}
	mds := &util.MDS{
		MDSBase: mdsBase,
		Client:  http.DefaultClient,
	}

	clientCfg := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (secret string, err error) {
				t, err := mds.GetTokenAud("ssh://" + addr)
				if err != nil {
					return "", err
				}
				return t, nil
			}),
			ssh.PublicKeys(sc.SignerClient),
		},
		Config: ssh.Config{},
		//ClientVersion: version,
		Timeout: 3 * time.Second,
		User:    sc.Id, // first principal in the certificate

		// hostname is passed back from addr, empty string
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if sc.CertChecker != nil {
				err := sc.CertChecker.CheckHostKey(hostname, remote, key)
				if err == nil {
					return err
				}
			}
			// Not in mesh mode - allow any hosts, they're only used for jumping, not trusted.
			if len(sc.AuthorizedCA) == 0 {
				slog.Info("Permissive/test host, no CA", "host", hostname, "addr", remote, "key", key)
				return nil
			}
			slog.Info("SSHC rejected host", "host", hostname, "addr", remote, "key", key)
			return errors.New("Server not authenticated")
		},
	}

	cc, chans, reqs, err := ssh.NewClientConn(tcon, addr, clientCfg)
	if err != nil {
		return err
	}

	sc.SSHConn = cc

	sc.chans = chans
	sc.reqs = reqs

	sc.LastConnected = time.Now()

	// NewClient will handle requests (reply false) and channel opens (via channelHandlers created by c.HandleChannelOpen),
	// keep track of reverseForwards (close all on done)
	//
	// It is the only way to use the Session implementation in the core library - which is equivalent to OpenChannel("session")
	c := ssh.NewClient(cc, chans, reqs)
	sc.SSHClient = c

	// The client adds "forwarded-tcpip" and "forwarded-streamlocal" when ListenTCP is called.
	// This in turns sends "tcpip-forward" command, with IP:port
	// The method returns a Listener, with port set.
	// Instead, we don't call ListenTCP, and handle the channels directly (
	// no listener )
	fch := c.HandleChannelOpen("forwarded-tcpip")
	go sc.handleReverseForwardAccept(fch)

	// TODO: allow registration of arbitrary handlers for channels
	// TODO: allow registration of HTTP handlers (channels)

	return nil
}

// RFC 4254 7.1
type channelForwardMsg struct {
	addr  string
	rport uint32
}

// ListenTCP requests the remote peer open a listening socket on port.
//
// Regular SSH servers don't multiplex on port.
// RFC4254:
// "" means that connections are to be accepted on all protocol
//
//	   families supported by the SSH implementation.
//
//	o  "0.0.0.0" means to listen on all IPv4 addresses.
//
//	o  "::" means to listen on all IPv6 addresses.
//
//	o  "localhost" means to listen on all protocol families supported by
//	   the SSH implementation on loopback addresses only ([RFC3330] and
//	   [RFC3513]).
//
//	o  "127.0.0.1" and "::1" indicate listening on the loopback
//	   interfaces for IPv4 and IPv6, respectively.
//
// Port 0 is usually supported.
func (c *SSHCMux) ListenTCP(domain string, port uint32) (uint32, error) {

	m := channelForwardMsg{
		domain,
		port,
	}
	// send message
	ok, resp, err := c.SSHConn.SendRequest("tcpip-forward", true, ssh.Marshal(&m))
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("ssh: tcpip-forward request denied by peer")
	}

	var p struct {
		Port uint32
	}
	if err := ssh.Unmarshal(resp, &p); err != nil {
		return 0, err
	}

	return p.Port, nil
}

// See RFC 4254, section 7.2
type forwardedTCPPayload struct {
	Addr string
	Port uint32
	// Note that sish doesn't preserve it by default
	OriginAddr string
	OriginPort uint32
}

func (sc *SSHCMux) handleReverseForwardAccept(fch <-chan ssh.NewChannel) {
	// This would needed to kick handleForwardsOnce
	// c.ListenTCP(&net.TCPAddr{}) // any port, ignored
	for ch := range fch {
		switch channelType := ch.ChannelType(); channelType {
		case "forwarded-tcpip":
			var payload forwardedTCPPayload
			if err := ssh.Unmarshal(ch.ExtraData(), &payload); err != nil {
				ch.Reject(ssh.ConnectionFailed, "could not parse forwarded-tcpip payload: "+err.Error())
				continue
			}

			// RFC 4254 section 7.2 specifies that incoming
			// addresses should list the address, in string
			// format. It is implied that this should be an IP
			// address, as it would be impossible to connect to it
			// otherwise.
			//laddr, err := parseTCPAddr(payload.Addr, payload.Port)
			//if err != nil {
			//	ch.Reject(ConnectionFailed, err.Error())
			//	continue
			//}
			//raddr, err = parseTCPAddr(payload.OriginAddr, payload.OriginPort)
			//if err != nil {
			//	ch.Reject(ConnectionFailed, err.Error())
			//	continue
			//}
			c, cr, err := ch.Accept()
			if err != nil {
				ch.Reject(ssh.ConnectionFailed, "could not accept: "+err.Error())
				continue
			}
			go ssh.DiscardRequests(cr)
			go sc.handleReverseAcceptedStream(c, payload)
		}
	}
}

// handleReverseAcceptedStream handles streams accepted from the remote server (-R).
// This is an extension to the regular SSH client, waypoints can use any port.
//
// For a regular ssh client, all service ports must be forwarded.
func (sc *SSHCMux) handleReverseAcceptedStream(ch io.ReadWriteCloser,
	fwto forwardedTCPPayload) {

	if fwto.Port == 22 || fwto.Port == 15022 {
		sc.Proxy(ch, "localhost:15022", "")
		return
	}

	// fwto.Addr will be this hostname. We need the port.
	dstp := sc.ReverseForwards[strconv.Itoa(int(fwto.Port))]
	if dstp == "" {
		if sc.Waypoint {
			dstp = net.JoinHostPort(fwto.Addr, strconv.Itoa(int(fwto.Port)))
		} else {
			slog.Warn("Unknown port", "port", fwto.Port, "addr", fwto.Addr,
				"origPort", fwto.OriginPort, "oAddr", fwto.OriginAddr)
			ch.Close()
			return
		}
	}

	sc.Proxy(ch, dstp, "")
}

// Proxy an incoming stream to a destination, for remotely accepted steams (-R)
// TODO: optimize.
func (sc *SSHCMux) Proxy(ch io.ReadWriteCloser, dstp string, s string) {
	c, err := net.Dial("tcp", dstp)
	if err != nil {
		slog.Error("ssh failed to connect", "addr", dstp)
		return
	}
	proxy(ch, c, func(err error, err2 error, i int64, i2 int64) {
		if err == nil && err2 == nil {
			slog.Info("Proxy", "dst", dstp, "in", i, "out", i2)
		} else {
			slog.Info("Proxy", "dst", dstp, "in", i, "out", i2, "errin", err, "errout", err2)
		}
	})
}

// StayConnected will maintain an active connection, typically with an egress or ingress gateway.
// 'addr' is the IP:port to connect to - not the 'canonical' service.
// TODO: create or use UDS for multiplex.
func (sshc *SSHCMux) StayConnected(addr string) {
	sshDomain, _, _ := net.SplitHostPort(addr)

	hn := os.Getenv("SSH_HOSTNAME")
	if hn == "" {
		hn, _ = os.Hostname()
	}
	if hn == "localhost" {
		hn = os.Getenv("K_SERVICE")
	}

	ctx := context.Background()

	for {
		t0 := time.Now()
		err := sshc.Dial(ctx, addr)
		if err != nil {
			slog.Info("Dial_error", "err", err, "addr", addr)
			time.Sleep(3 * time.Second)
			continue
		}
		t1 := time.Now()
		c := sshc.SSHClient

		// Open a session - for example sish sends logs and info (without waiting for shell!)
		//go sshc.ClientSession()

		port, err := sshc.ListenTCP("", 0)

		// This is used for openssh/dropbear - which don't multiplex 22
		// (no automatic jump-host / waypoint feature ).
		slog.Info("JumpHost", "port", port, "addr", addr)

		crv := os.Getenv("K_REVISION")
		if crv != "" {
			_, err = sshc.ListenTCP(crv+"."+sshDomain, 22)
			if err != nil {
				log.Println("Failed to forward", err)
			}
		}

		for k, _ := range sshc.ReverseForwards {
			kp, _ := strconv.Atoi(k)
			_, err = sshc.ListenTCP(hn+"."+sshDomain, uint32(kp))
			if err != nil {
				log.Println("Failed to forward", err)
			}
		}

		slog.Info("SSH_CONNECTED", "hostname", hn, "domain", sshDomain,
			"dial_time", t1.Sub(t0),
			"con_time", time.Since(t0))

		c.Wait()
		slog.Info("SSH_DISCONNECTED", "hostname", hn, "domain", sshDomain, "dur", time.Since(t0))
	}

}

// OpenStream creates a new stream.
// This uses the same channel in both directions.
func (c *SSHCMux) OpenStream(n string, data []byte) (*Stream, error) {
	s, r, err := c.SSHConn.OpenChannel(n, data)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(r)
	return &Stream{Channel: s, clientMux: c}, nil
}

// Exec opens a client session channel for a command.
func (ssht *SSHCMux) Exec(cmd string, env map[string]string) (*RemoteExec, error) {
	if ssht.SSHConn == nil {
		return nil, errors.New("Only for client connections")
	}
	sessionCh, sessionServerReq, err := ssht.SSHConn.OpenChannel("session", nil)
	if err != nil {
		log.Println("Error opening session", err)
		ssht.SSHConn.Close()
		return nil, err
	}

	re := &RemoteExec{
		Channel:          sessionCh,
		sessionServerReq: sessionServerReq,
	}

	// serverReq will be used only to notity that the session is over, may receive keepalives
	go func() {
		for msg := range sessionServerReq {
			// TODO: exit-status, exit-signal messages
			log.Println("SSHCMux: /ssh/srvmsg session message from server ", msg.Type, msg)
			if msg.WantReply {
				msg.Reply(false, nil)
			}
		}
	}()

	req := execMsg{
		Command: cmd,
	}

	// TODO: send env first

	ok, err := sessionCh.SendRequest("exec", true, ssh.Marshal(&req))
	if err == nil && !ok {
		log.Println("SSHCMux: Message channel failed", err)
		return nil, err
	}

	return re, nil
}

// RemoteExec is a "session" channel.
type RemoteExec struct {
	ssh.Channel
	sessionServerReq <-chan *ssh.Request
}

// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}

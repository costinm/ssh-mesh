package sshc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"log/slog"

	"github.com/costinm/ssh-mesh/util"
	"golang.org/x/crypto/ssh"
)

type SSHClientConf struct {
	// Last time connected
	User   string
	Signer ssh.Signer

	// Hostname to use when binding. If not set, will use os.Hostname or guess from service/instance
	Hostname string
}

type SSHC struct {
	*SSHClientConf

	LastConnected time.Time

	Forwards map[string]string

	SSHConn ssh.Conn
	chans   <-chan ssh.NewChannel
	reqs    <-chan *ssh.Request

	con net.Conn

	// TODO: limit by domain ?
	AuthorizedCA []ssh.PublicKey
	CertChecker  *ssh.CertChecker

	ServerKey ssh.PublicKey
	SSHClient *ssh.Client

	// Last received remote key
	RemoteKey ssh.PublicKey
}

func (sc *SSHC) Dial(addr string) error {
	tcon, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return sc.DialConn(tcon, addr)
}

func (sc *SSHC) DialConn(tcon net.Conn, addr string) error {
	sc.con = tcon
	if sc.User == "" {
		sc.User = "jwt"
	}

	sc.CertChecker = &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, user string) bool {
			if sc.AuthorizedCA == nil {
				return false
			}
			for _, pubk := range sc.AuthorizedCA {
				if KeysEqual(auth, pubk) {
					return true
				}
			}
			return false
		},
	}

	clientCfg := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (secret string, err error) {
				t, err := util.GetTokenAud("ssh://" + addr)
				if err != nil {
					return "", err
				}
				return t, nil
			}),
			ssh.PublicKeys(sc.Signer)},
		Config: ssh.Config{},
		//ClientVersion: version,
		Timeout: 3 * time.Second,
		User:    sc.User,

		// hostname is passed back from addr, empty string
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			slog.Info("Host", "host", hostname, "addr", remote, "key", key)
			sc.RemoteKey = key
			if sc.ServerKey != nil {
				if KeysEqual(key, sc.ServerKey) {
					return nil
				}
			}
			if sc.AuthorizedCA != nil {
				err := sc.CertChecker.CheckHostKey(hostname, remote, key)
				if err == nil {
					return err
				}
			}
			if sc.AuthorizedCA == nil && sc.ServerKey == nil {
				return nil
			}
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
	// keep track of forwards (close all on done)
	//
	// It is the only way to use the Session implementation in the core library - which is equivalent to OpenChannel("session")
	c := ssh.NewClient(cc, chans, reqs)
	sc.SSHClient = c
	// The client adds "forwarded-tcpip" and "forwarded-streamlocal" when ListenTCP is called.
	// This in turns sends "tcpip-forward" command, with IP:port
	// The method returns a Listener, with port set.
	// Instead we don't call ListenTCP, and handle the channels directly (
	//  no listener )
	fch := c.HandleChannelOpen("forwarded-tcpip")
	go sc.handleForwards(fch)

	// TODO: allow registration of arbitrary handlers for channels
	// TODO: allow registration of HTTP handlers (channels)

	//// Deprecated extension: clients also forward streams from servers.
	//go func() {
	//	dtcp := client.HandleChannelOpen("direct-tcpip")
	//	for newChannel := range dtcp {
	//		directTcpipHandler(ctx, ssht, cc, newChannel)
	//	}
	//}()

	return nil
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk ssh.PublicKey) bool {

	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}

// RFC 4254 7.1
type channelForwardMsg struct {
	addr  string
	rport uint32
}

// ListenTCP requests the remote peer open a listening socket
// on laddr. Incoming connections will be available by calling
// Accept on the returned net.Listener.
func (c *SSHC) ListenTCP(domain string, port uint32) error {

	m := channelForwardMsg{
		domain,
		port,
	}
	// send message
	ok, resp, err := c.SSHConn.SendRequest("tcpip-forward", true, ssh.Marshal(&m))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("ssh: tcpip-forward request denied by peer")
	}

	var p struct {
		Port uint32
	}
	if err := ssh.Unmarshal(resp, &p); err != nil {
		return err
	}

	return nil
}

// See RFC 4254, section 7.2
type forwardedTCPPayload struct {
	Addr string
	Port uint32
	// Note that sish doesn't preserve it by default
	OriginAddr string
	OriginPort uint32
}

func (sc *SSHC) handleForwards(fch <-chan ssh.NewChannel) {
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
			go sc.HandleStream(c, payload)
		}
	}
}

func (sc *SSHC) HandleStream(ch io.ReadWriteCloser, fwto forwardedTCPPayload) {
	// fwto.Addr will be this hostname. We need the port.

	dstp := sc.Forwards[strconv.Itoa(int(fwto.Port))]
	if dstp == "" {
		slog.Warn("Unknown port", "port", fwto.Port)
		ch.Close()
		return
	}
	c, err := net.Dial("tcp", dstp)
	if err != nil {
		slog.Error("ssh failed to connect", "addr", fwto)
		return
	}
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

}

func NewSSHC(cf *SSHClientConf) (*SSHC, error) {
	if cf == nil {
		cf = &SSHClientConf{}
	}
	sshc := &SSHC{
		SSHClientConf: cf,
		Forwards:      map[string]string{},
	}

	if cf.Signer == nil {
		privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cf.Signer, _ = ssh.NewSignerFromKey(privk1)
	}

	return sshc, nil
}

func (sshc *SSHC) StayConnected(addr string) {
	sshDomain, _, _ := net.SplitHostPort(addr)

	hn := os.Getenv("SSH_HOSTNAME")
	if hn == "" {
		hn, _ = os.Hostname()
	}
	if hn == "localhost" {
		hn = os.Getenv("K_SERVICE")
	}

	for {
		t0 := time.Now()
		err := sshc.Dial(addr)
		if err != nil {
			slog.Info("Dial_error", "err", err, "addr", addr)
			time.Sleep(3 * time.Second)
			continue
		}
		t1 := time.Now()
		c := sshc.SSHClient

		// Open a session - sish sends logs and info
		go func() {
			sc, r, err := c.OpenChannel("session", nil)
			if err != nil {
				log.Println("Failed to open session", err)
				return
			}
			go ssh.DiscardRequests(r)
			data := make([]byte, 1024)
			for {
				n, err := sc.Read(data)
				if err != nil {
					log.Println("Failed to read", err)
					return
				}
				log.Println("IN:", string(data[0:n]))
			}

		}()

		sshc.Forwards["80"] = "localhost:8080"
		sshc.Forwards["22"] = "localhost:15022"
		err = sshc.ListenTCP(hn+"."+sshDomain, 80)
		if err != nil {
			log.Println("Failed to forward", err)
		}
		err = sshc.ListenTCP(hn+"."+sshDomain, 22)
		if err != nil {
			log.Println("Failed to forward", err)
		}
		crv := os.Getenv("K_REVISION")
		if crv != "" {
			err = sshc.ListenTCP(crv+"."+sshDomain, 22)
			if err != nil {
				log.Println("Failed to forward", err)
			}
		}

		for k, _ := range sshc.Forwards {
			kp, _ := strconv.Atoi(k)
			err = sshc.ListenTCP(hn+"."+sshDomain, uint32(kp))
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

package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const version = "SSH-2.0-cert-ssh"

type TransportConfig struct {
	Address string
	Port    int

	Shell          string
	AuthorizedKeys []ssh.PublicKey

	SignerHost   ssh.Signer
	SignerClient ssh.Signer

	Listener net.Listener

	Namespace   string
	User        string
	TrustDomain string

	CertProvider func(ctx context.Context, sshCA string) (ssh.Signer, error)

	// Public keys of all trusted roots
	RootCA []string
}

type Transport struct {
	*TransportConfig

	serverConfig *ssh.ServerConfig

	forwards map[string]net.Listener
	sync.Mutex

	// HandleConn can be used to overlay a SSH conn.

	CertChecker *ssh.CertChecker

	// Client is a SSH client, using Istio-like certificates.
	// By default will get a client cert, using the Istio identity,
	// and connect to the specified SSHD.
	//
	// Will also forward the HBONE ports.
	SSHCa string
	SSHD  string

	client *ssh.Client
	config *ssh.ClientConfig

	ClientCertChecker *ssh.CertChecker
git 	authorizedCA      []ssh.PublicKey

	//
	// Ports map[string]string
}

var (
	ServerChannelHandlers = map[string]func(ctx context.Context, ssht *Transport, conn ssh.Conn, newChannel ssh.NewChannel){}
	ServerRequestHandlers = map[string]func(ctx context.Context, ssht *Transport, conn *ssh.ServerConn, r *ssh.Request) (bool, []byte){}
	ClientChannelHandlers = map[string]func(ctx context.Context, ssht *Transport, conn *ssh.ServerConn, newChannel ssh.NewChannel){}
	ClientRequestHandlers = map[string]func(ctx context.Context, ssht *Transport, conn *ssh.ServerConn, r *ssh.Request){}
)

//func (srv *Server) getServer(signer ssh.Signer) *ssh.Server {
//	forwardHandler := &ssh.ForwardedTCPHandler{}
//
//	server := &ssh.Server{
//		ChannelHandlers: map[string]ssh.ChannelHandler{
//			"direct-tcpip": ssh.DirectTCPIPHandler,
//			"session":      ssh.DefaultSessionHandler,
//		},
//		RequestHandlers: map[string]ssh.RequestHandler{
//			"tcpip-forward":        forwardHandler.HandleSSHRequest,
//			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
//		},
//	}
//}

// InitFromSecret is a helper method to init the sshd using a secret or CA address
func InitFromSecret(sshCM map[string][]byte, ns string) error {
	tc := &TransportConfig{
	}

	sshCA := sshCM["SSHCA_ADDR"]

	var authKeys []ssh.PublicKey
	for k, v := range sshCM {
		if strings.HasPrefix(k, "authorized_key_") {
			pubk1, _, _, _, err := ssh.ParseAuthorizedKey(v)
			if err != nil {
				log.Println("SSH_DEBUG: invalid ", k, err)
			} else {
				authKeys = append(authKeys, pubk1)
				log.Println("Adding authorized key", k, string(v))
			}
		}
	}

	extra := os.Getenv("SSH_AUTH")
	if extra != "" {
		pubk1, _, _, _, err := ssh.ParseAuthorizedKey([]byte(extra))
		if err != nil {
			log.Println("SSH_DEBUG: invalid SSH_AUTH", err)
		} else {
			authKeys = append(authKeys, pubk1)
		}
	}

	if len(authKeys) == 0 && sshCA == nil {
		// No debug config, skip creating SSHD
		return nil
	}

	if sshCA != nil {
		sc := &SSHCAClient{
			Addr: string(sshCA),
		}
		r, signer, _, err := sc.GetCertHostSigner()
		if err == nil {
			tc.SignerHost = signer
			tc.RootCA = append(tc.RootCA, r)
		}
	}

	// load private key and cert from secret, if present
	ek := sshCM["id_ecdsa"]
	if ek != nil {
		pk, err := ssh.ParsePrivateKey(ek)
		if err != nil {
			log.Println("Failed to parse key ", err)
		} else {
			tc.SignerHost = pk
		}
	}
	if tc.SignerHost == nil {
		privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, _ := ssh.NewSignerFromKey(privk1)
		tc.SignerHost = signer
	}

	ssht, err := NewSSHTransport(tc)
	if err != nil {
		log.Println("SSH debug init failed", err)
		return err
	}
	if len(authKeys) != 0 {
		ssht.AddAuthorizedKeys(authKeys)
	}

	go ssht.Start()
	return nil
}

func New() *Transport {
	t := &Transport{}
	return t
}

func NewSSHTransport(tc *TransportConfig) (*Transport, error) {
	var err error


	if tc.Port == 0 {
		tc.Port = 15022
	}
	if tc.Shell == "" {
		// TODO: detect
		tc.Shell = "/bin/bash"
	}

	s := &Transport{
		TransportConfig: tc,

		serverConfig: &ssh.ServerConfig{},
		//Port:         15022,
		//Shell:        "/bin/bash",
		// Server cert checker
	}

	s.CertChecker = &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				if s.authorizedCA == nil {
					return false
				}
				for _, pubk := range s.authorizedCA {
					if KeysEqual(auth, pubk) {
						return true
					}
				}
				return false
			},
		}

	for _, v := range tc.RootCA {
		pubk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
		if err != nil {
			log.Println("No root CA key")
			continue
		}
		s.authorizedCA = append(s.authorizedCA, pubk)
	}

	authorizedKeysBytes, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/authorized_keys")
	if err == nil {
		s.AddAuthorizedFile(authorizedKeysBytes)
	}

	if s.Address == "" {
		s.Address = ":15022"
	}

	s.serverConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if s.authorizedCA != nil {
			p, err := s.CertChecker.Authenticate(conn, key)
			if err == nil {
				return p, nil
			}
		}
		if s.AuthorizedKeys != nil {
			for _, k := range s.AuthorizedKeys {
				if KeysEqual(key, k) {
					return &ssh.Permissions{}, nil
				}
			}
		}
		//log.Println("SSH auth failure", key, s.AuthorizedKeys)
		return nil, errors.New("SSH connection: no key found")
	}
	s.serverConfig.AddHostKey(tc.SignerHost)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	s.Listener, err = net.Listen("tcp", s.Address)
	if err != nil {
		log.Println("Failed to listend on ", s.Address, err)
		return nil, err
	}
	log.Println("SSHD listening on ", s.Address)

	return s, nil
}

func (ssht *Transport) AddAuthorized(extra string) {
	pubk1, _, _, _, err := ssh.ParseAuthorizedKey([]byte(extra))
	if err == nil {
		ssht.AuthorizedKeys = append(ssht.AuthorizedKeys, pubk1)
	}
}

func (ssht *Transport) AddAuthorizedFile(auth []byte) {
	for len(auth) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(auth)
		if err != nil {
			return
		}

		ssht.AuthorizedKeys = append(ssht.AuthorizedKeys, pubKey)
		auth = rest
	}
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

func (ssht *Transport) Start() {
	go func() {
		for {
			nConn, err := ssht.Listener.Accept()
			if err != nil {
				log.Println("failed to accept incoming connection ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			go ssht.HandleServerConn(nConn)
		}
	}()
}

// SSHConn can be a Client or server ssh connection.
type SSHConn struct {
	// ServerConn - also has Permission
	sc *ssh.ServerConn
	// SSH Client - only when acting as Dial
	// few internal fields in addition to ssh.Conn:
	// - forwards
	// - channelHandlers
	scl *ssh.Client

	closed chan struct{}

	// Original con, with remote/local addr
	wsCon net.Conn

	inChans <-chan ssh.NewChannel
	req     <-chan *ssh.Request

	LastSeen    time.Time
	ConnectTime time.Time

	// Includes the private key of this node
	t *Transport // transport.Transport

	RemoteKey      ssh.PublicKey
	RemoteHostname string
	RemoteAddr     net.Addr
}

// Also implements gossh.Channel - add SendRequest and Stderr, as well as CloseWrite
type sshstream struct {
	ssh.Channel
	con *SSHConn
}

// OpenStream creates a new stream.
// This uses the same channel in both directions.
func (c *SSHConn) OpenStream() (*sshstream, error) {
	if c.sc != nil {
		// Doesn't work with regular ssh clients - this is an extension
		s, r, err := c.sc.OpenChannel("direct-tcpip", []byte{})
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(r)
		return &sshstream{Channel: s, con: c}, nil
	} else {
		s, r, err := c.scl.OpenChannel("direct-tcpip", []byte{})
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(r)
		return &sshstream{Channel: s, con: c}, nil
	}
}

// DialConn wrapps a netConn with a SSH client connections.
func (ssht *Transport) DialConn(ctx context.Context, host string, nc net.Conn) (*SSHConn, *ssh.Client, error) {
	c := &SSHConn{
		closed: make(chan struct{}),
		t:      ssht,
		wsCon:  nc,
	}
	c.ConnectTime = time.Now()

	cc, chans, reqs, err := ssh.NewClientConn(nc, host,
		&ssh.ClientConfig{
			Auth:          ssht.config.Auth,
			Config:        ssht.config.Config,
			ClientVersion: version,
			Timeout:       3 * time.Second,
			User:          ssht.User,
			// hostname is passed back from addr, empty string
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				err := ssht.CertChecker.CheckHostKey(hostname, remote, key)
				if err != nil {
					return err
				}
				c.RemoteKey = key
				c.RemoteAddr = remote
				c.RemoteHostname = hostname

				return nil
			},
		})
	if err != nil {
		return nil, nil, err
	}

	// Using a ssh.Client is possible - but may complicate things. The client
	// is handling reqs, chans for the connection directly.
	// It is the only way to use the Session implementation in the core library.
	// client extends ssh.Conn - but it should not be used directly for session or accept requests.
	client := ssh.NewClient(cc, chans, reqs)
	c.scl = client

	// The client adds "forwarded-tcpip" and "forwarded-streamlocal" when ListenTCP is called.
	// This in turns sends "tcpip-forward" command, with IP:port
	// The method returns a Listener, with port set.

	// Extension: clients also forward streams from servers.
	go func() {
		dtcp := client.HandleChannelOpen("direct-tcpip")
		for newChannel := range dtcp {
			directTcpipHandler(ctx, ssht, cc, newChannel)
		}
	}()

	return c, client, nil
}

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (ssht *Transport) HandleServerConn(nConn net.Conn) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := ssh.NewServerConn(nConn, ssht.serverConfig)
	if err != nil {
		nConn.Close()
		log.Println("SSHD: handshake error ", err, nConn.RemoteAddr())
		//sshGate.metrics.Errors.Add(1)
		return
	}
	log.Println("SSH connection from ", nConn.RemoteAddr())
	// TODO: track the session, for direct use

	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		conn.Close()
		cancel()
	}()

	go ssht.handleServerConnRequests(ctx, globalSrvReqs, nConn, conn)

	// Service the incoming channels (stream in H2).
	// Each channel is a stream - shell, exec, sftp, local TCP forward.
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			directTcpipHandler(ctx, ssht, conn, newChannel)

		case "session":
			sessionHandler(ctx, ssht, conn, newChannel)

		default:
			fmt.Println("SSHD: unknown channel Rejected", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}

}

// Handle global requests on a server connection.
func (ssht *Transport) handleServerConnRequests(ctx context.Context, reqs <-chan *ssh.Request, nConn net.Conn,
		conn *ssh.ServerConn) {
	for r := range reqs {
		// Global types.
		switch r.Type {
		// "-R": we expect at least one R with 0.0.0.0 and port 5222, corresponding to the main mux dispatcher.
		// SSHClientConn clients will only accept back connections with this particular host:port, and srcIP:srcPort.
		// Other reverse accept ports can be opened as well.
		case "tcpip-forward":
			ok, pl := tcpipForwardHandler(ctx, ssht, conn, r)
			r.Reply(ok, pl)
			continue
		case "cancel-tcpip-forward":
			ok, pl := cancelTcpipForwardHandler(ctx, ssht, conn, r)
			r.Reply(ok, pl)
			continue
		case "keepalive@openssh.com":
			//n.LastSeen = time.Now()
			r.Reply(true, nil)

		default:
			log.Println("SSHD: unknown global REQUEST ", r.Type)
			if r.WantReply {
				log.Println(r.Type)
				r.Reply(false, nil)
			}
		}
	}
}

func (ssht *Transport) AddAuthorizedKeys(keys []ssh.PublicKey) {
	for _, k := range keys {
		ssht.AuthorizedKeys = append(ssht.AuthorizedKeys, k)
	}
}

// "forwarded-tcp" or "-R" - reverse, ssh-server-accepted connections sent to client.
// VPN or public device will expose a port, or a dmesh client will use a local port as Gateway
// ForwardIP/ForwardPort are used as keys - to match the listener.
type forwardTCPIPChannelRequest struct {
	ForwardIP   string
	ForwardPort uint32
	OriginIP    string
	OriginPort  uint32
}

// RFC 4254 7.2 - direct-tcpip
// -L or -D, or egress. Client using VPN as an egress gateway.
// Raddr can be a string (hostname) or IP.
// Laddr is typically 127.0.0.1 (unless ssh has an open socks, and other machines use it)
//
type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32

	Laddr string
	Lport uint32
}

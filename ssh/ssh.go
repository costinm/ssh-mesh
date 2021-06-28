package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/costinm/cert-ssh/sshca"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
)

func GetSSHSignclient(sshCA string) (sshca.SSHCertificateServiceClient, *grpc.ClientConn,  error){
	creds := insecure.NewCredentials()

	xdsBootstrap := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if xdsBootstrap != "" {
		log.Println("Using xDS credentials...")
		var err error
		if creds, err = xdscreds.NewClientCredentials(xdscreds.ClientOptions{
			FallbackCreds: insecure.NewCredentials(),
		}); err != nil {
			return nil, nil, err
		}
	}

	conn, err := grpc.Dial(sshCA, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	c := sshca.NewSSHCertificateServiceClient(conn)
	return c, conn, nil
}

func StartSSHDWithCA(ns string, sshCA string) error {
	c, con, err := GetSSHSignclient(sshCA)
	if err != nil {
		return err
	}
	defer con.Close()
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	casigner1, _ := gossh.NewSignerFromKey(privk1)
	//pk := privk1.Public().(*ecdsa.PublicKey)
	//pkb := elliptic.Marshal(elliptic.P256(), pk.X, pk.Y)
	//pubk := base64.StdEncoding.EncodeToString(pkb)
	req := &sshca.SSHCertificateRequest{
		Public: string(gossh.MarshalAuthorizedKey(casigner1.PublicKey())),
	}
	log.Println(req)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.CreateCertificate(ctx, req)
	if err != nil {
		log.Println("Error creating cert ", err)
		return err
	}

	key, _, _, _, _ := gossh.ParseAuthorizedKey([]byte(r.Host))
	cert, ok := key.(*gossh.Certificate)

	fmt.Println(r.User)

	if !ok {
		return errors.New("unexpected cert")
	}
	signer, _ := gossh.NewCertSigner(cert, casigner1)

	ssht, err := NewSSHTransport(signer, "", ns, r.Root)
	if err != nil {
		return err
	}
	go ssht.Start()
	return nil
}


type Server struct {
	Port           int
	Shell          string
	AuthorizedKeys []gossh.PublicKey

	clientConfig *gossh.ClientConfig
	serverConfig *gossh.ServerConfig

	signer gossh.Signer

	// HandleConn can be used to overlay a SSH conn.

	CertChecker    *gossh.CertChecker
	Address        string
	Listener       net.Listener
	forwardHandler *ForwardedTCPHandler
}

func NewSSHTransport(signer gossh.Signer, name, domain, root string) (*Server, error) {
	pubk, _,_, _, err := gossh.ParseAuthorizedKey([]byte(root))
	if err != nil {
		return nil, err
	}

	s := &Server{
		signer: signer,
		clientConfig: &gossh.ClientConfig{
			Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
			HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
				return nil
			},
			//Config: gossh.Config{
			//	MACs: []string{
			//		"hmac-sha2-256-etm@opengossh.com",
			//		"hmac-sha2-256",
			//		"hmac-sha1",
			//		"hmac-sha1-96",
			//	},
			//	Ciphers: []string{
			//		"aes128-gcm@opengossh.com",
			//		"chacha20-poly1305@opengossh.com",
			//		"aes128-ctr", "none",
			//	},
			//},
		},
		serverConfig: &gossh.ServerConfig{

		},
		Port: 15022,
		Shell: "/bin/bash",
		// Server cert checker
		CertChecker: &gossh.CertChecker{
			IsUserAuthority: func(auth gossh.PublicKey) bool {
				return KeysEqual(auth, pubk)
			},
		},
	}
	//pk, err := LoadAuthorizedKeys(os.Getenv("HOME") + "/.ssh/authorized_keys")
	//if err == nil {
	//	s.AuthorizedKeys = pk
	//}
	extra := os.Getenv("AUTHORIZED")
	if extra != "" {
		pubk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(extra))
		if err == nil {
			s.AuthorizedKeys = append(s.AuthorizedKeys, pubk)
		}
	}

	if s.Address == "" {
		s.Address = ":15022"
	}

	s.forwardHandler = &ForwardedTCPHandler{}

	s.serverConfig.PublicKeyCallback = s.CertChecker.Authenticate
	s.serverConfig.AddHostKey(signer)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	s.Listener, err = net.Listen("tcp", s.Address)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk gossh.PublicKey) bool {

	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}

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

func (t *Server) Start() {
	go func() {
		for {
			nConn, err := t.Listener.Accept()
			if err != nil {
				log.Println("failed to accept incoming connection ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			go t.HandleServerConn(nConn)
		}
	}()
}

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (sshGate *Server) HandleServerConn(nConn net.Conn) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := gossh.NewServerConn(nConn, sshGate.serverConfig)
	if err != nil {
		nConn.Close()
		log.Println("SSHD: handshake error ", err, nConn.RemoteAddr())
		//sshGate.metrics.Errors.Add(1)
		return
	}

	// TODO: track the session, for direct use

	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		conn.Close()
		cancel()
	}()

	go sshGate.handleServerConnRequests(ctx, globalSrvReqs, nConn, conn)

	// Service the incoming Channel channel.
	// Each channel is a stream - shell, exec, local TCP forward.
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			// When remote starts with a -L PORT:host:port, and connects to port
			var req channelOpenDirectMsg
			//scon.gate.localFwdS.Total.Add(1)
			err := gossh.Unmarshal(newChannel.ExtraData(), &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				newChannel.Reject(gossh.UnknownChannelType, "invalid data")
				continue
			}

			// TODO: allow connections to mesh VIPs
			//if role == ROLE_GUEST &&
			//		req.Rport != SSH_MESH_PORT && req.Rport != H2_MESH_PORT {
			//	newChannel.Reject(ssh.Prohibited,
			//		"only authorized users can proxy " +
			//				scon.VIP6.String())
			//	continue
			//}
			//log.Println("-L: forward request", req.Laddr, req.Lport, req.Raddr, req.Rport, role)

			go DirectTCPIPHandler(ctx, sshGate, conn, newChannel)
			//scon.handleDirectTcpip(newChannel, req.Raddr, req.Rport, req.Laddr, req.Lport)
			//conId++

		case "session":
			// session channel - the main interface for shell, exec
			ch, reqs, _ := newChannel.Accept()
			// Used for messages.
			s := &session{
				Channel: ch,
				conn: conn,
				srv: sshGate,
			}
			go s.handleRequests(reqs)

		default:
			fmt.Println("SSHD: unknown channel Rejected", newChannel.ChannelType())
			newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
		}
	}


}


// Global requests
func (scon *Server) handleServerConnRequests(ctx context.Context, reqs <-chan *gossh.Request, nConn net.Conn, conn *gossh.ServerConn) {
	for r := range reqs {
		// Global types.
		switch r.Type {
		// "-R": we expect at least one R with 0.0.0.0 and port 5222, corresponding to the main mux dispatcher.
		// SSHClientConn clients will only accept back connections with this particular host:port, and srcIP:srcPort.
		// Other reverse accept ports can be opened as well.
		case "tcpip-forward":
			var req tcpipForwardRequest
			err := gossh.Unmarshal(r.Payload, &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				r.Reply(false, nil)
				continue
			}

			go scon.forwardHandler.HandleSSHRequest(ctx, scon, r, conn)

			continue

		case "keepalive@openssh.com":
			//n.LastSeen = time.Now()
			//log.Println("SSHD: client keepalive", n.VIP)
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


type execRequest struct {
	Command string
}

type tcpipForwardRequest struct {
	BindIP   string
	BindPort uint32
}

type tcpipForwardResponse struct {
	BoundPort uint32
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



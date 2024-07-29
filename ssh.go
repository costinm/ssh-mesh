package ssh_mesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/oidc"
	"golang.org/x/crypto/ssh"
)

// TODO: fetch github and alike keys from URL !
// For a user costinm@github.com, using github JWT or a public key we can
// verify the key by fetching it from github.com/keys/USER.key
// Further with SSH we can treat the key as a signer for derived keys (CA).



type Command struct {
	Run func(env map[string]string, args []string, in io.Reader, out io.WriteCloser, err io.WriteCloser)
}

// SSHMesh is a minimal L4S (ambient) mesh implementation based on SSH,
// and compatible with standard SSH clients and servers.
type SSHMesh struct {
	Mesh *meshauth.Mesh

	// Address to listen on as SSH. Will default to 14022 for regular nodes and
	// 15022 for gateways.
	Address string `json:"sshd_addr,omitempty"`
	Listener    net.Listener     `json:"-"`
	CertChecker *ssh.CertChecker `json:"-"`

	// Generated config for the ssh server.
	serverConfig *ssh.ServerConfig

	// connected clients. For SSH Mesh, all clients are assumed to be
	// mesh clients capable of accepting jump connections. Regular ssh clients
	// should explicitly request -R on 80 and 15022 - or on port 0.
	connectedClientNodes sync.Map //[string,*SSHSMux]

	// TODO: list of clients by FQDN (with the pod IP as key)

	// TCP reverseForwards (active listeners on ports) - except 22/80/443/etc
	// Created by trusted clients using 'tcpip-forward' command.
	// The certificate must explicitly allow it.
	reverseForwards map[string]net.Listener

	// Multiplexed clients to upstream hosts, by destination.
	// May disconnect - the same client is reused.
	Clients sync.Map // [string,*SSHCMux]

	ConnectErrors atomic.Int64


	// Map of public key to user ID.
	// Key is the marshalled public key (from authorized_keys), value is the user ID (comment)
	UsersKeys map[string]string `json:"-"`

	// Signer is the 'workload identity' signer. It is using the main workload
	// private key (workload key), but with a host certificate.
	Signer       ssh.Signer `json:"-"`

	// SignerClient is a client workload identity - using the SA cert when
	// a CA is used. Otherwise, same as Signer.
	SignerClient ssh.Signer `json:"-"`

	// Forward is a function that will proxy a stream to a destination.
	// If missing, it will be dialed.
	// Used on a server for all client forwarding - except locally connected clients.
	Forward func(context.Context, string, io.ReadWriteCloser) `json:"-"`

	// WIP: Internally defined commands.
	InternalCommands map[string]*Command `json:"-"`


	// Root CA keys - will be authorized to connect and create tunnels, not get shell.
	AuthorizedCA []ssh.PublicKey `json:"-"`

	// WIP: Custom channel handlers.
	ChannelHandlers map[string]func(ctx context.Context, sconn *SSHSMux, newChannel ssh.NewChannel) `json:"-"`

	// TokenChecker will verify the password field - as a JWT or other forms.
	TokenChecker func(password string) (claims map[string]string, e error) `json:"-"`

	// Deprecated - Credentials
	CertHost   string `json:"ssh.crt,omitempty"`
	// Deprecated - Credentials
	CertClient string `json:"ssh-client.crt,omitempty"`


	// AuthorizedKeys is the same as authorized_keys file.
	// The keys are used as 'trusted sources' for authentication. Any user key can be used for shell/debug access.
	// The CA keys are allowed to connect - but can get a shell only if 'role=admin' is present in the cert.
	//
	// If empty, the SSH_AUTHORIZED_KESY env is used, falling back to authorized_keys in current dir and $HOME/.ssh
	AuthorizedKeys string `json:"authorized_keys,omitempty"`

	sync.Mutex
}

// StayConnected will keep the SSH node connected with any 'ssh-upstream'
// destination in the config.
// Does not support reloading yet.
//func (ss *SSHMesh) StayConnected(ctx context.Context) {
//	for addr, d:=range ss.Mesh.Dst {
//		a := d.Addr
//		if a == "" {
//			a = addr
//		}
//		if d.Proto == "ssh-upstream" {
//			// TODO: list of ssh servers for redundancy
//			sshc, err := ss.Client(ctx, a)
//			if err != nil {
//				log.Fatal(err)
//			}
//
//			go sshc.StayConnected(a)
//		}
//	}
//}

// Client returns a SSH client for a destination.
// It may be disconnected - first call is always disconnected.
func (ss *SSHMesh) Client(ctx context.Context, dst string) (*SSHCMux, error) {
	cp, _ := ss.Clients.Load(dst)
	if cp == nil {
		c := &SSHCMux{
			SSHMesh: ss,
				ReverseForwards: map[string]string{},
			AuthorizedCA: ss.AuthorizedCA,
		}
		c.CertChecker = ss.CertChecker

		// Will be used with tunnels
		c.mds = ss.Mesh
		ss.Clients.Store(dst, c)
		cp = c

		// TODO: ping, detect terminations.
	}


	c := cp.(*SSHCMux)
	return c, nil
}


func (s *SSHMesh) SetKeys(priv string, hostc string, clientc string) (*SSHMesh, error) {
	ma := s.Mesh
	if ma.Priv != "" {
		k, err := ssh.ParseRawPrivateKey([]byte(ma.Priv))
		if err != nil {
			return nil, err
		}
		s.Signer, _ = ssh.NewSignerFromKey(k)
		s.SignerClient = s.Signer

		if s.CertClient != "" {
			cert, err := ssh.ParsePublicKey([]byte(s.CertClient))
			if err != nil {
				return nil, err
			}
			s.SignerClient, err = ssh.NewCertSigner(cert.(*ssh.Certificate), s.SignerClient)
			crt := cert.(*ssh.Certificate)
			s.Mesh.Name = crt.ValidPrincipals[0]
		}
		if s.CertHost != "" {
			cert, err := ssh.ParsePublicKey([]byte(s.CertHost))
			if err != nil {
				return nil, err
			}
			s.Signer, err = ssh.NewCertSigner(cert.(*ssh.Certificate), s.Signer)
		}

	} else {
		privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		s.Signer, _ = ssh.NewSignerFromKey(privk1)
		s.SignerClient = s.Signer
	}
	return s, nil
}

// NewSSHMesh creates the SSHMesh object.
// Must call SetKeys() or FromEnv() before using it.
//
// If the key is missing, a self-signed key is generated.
//
// Extensions compared to regular sshd:
// - can use JWT tokens as password - based on Issuer config.
// - multiplex forwarded ports 22, 80, 443
// - optimized for the use of a CA for both client and server.
//
// TODO: As a server, it can also prove its workload ID with a JWT and jumpstart known_hosts !
func NewSSHMesh(ma *meshauth.Mesh) (*SSHMesh, error) {
	s := &SSHMesh{
		Mesh:             ma,
		serverConfig:     &ssh.ServerConfig{},
		reverseForwards:  map[string]net.Listener{},
		InternalCommands: map[string]*Command{},
		UsersKeys:        map[string]string{},
		ChannelHandlers:  map[string]func(ctx context.Context, ssht *SSHSMux, newChannel ssh.NewChannel){},
	}

	// TODO: if key and certs are missing in config but a URL is specified, fetch the
	//  private key and certs
	// ( a 'metadata' bootstrap/launcher should be run first to get all secret and config bits )

	pk := meshauth.SignerFromKey(ma.Cert.PrivateKey)
	s.Signer, _ = ssh.NewSignerFromSigner(pk)
	s.SignerClient = s.Signer

	if s.AuthorizedKeys != "" {
		s.AddAuthorizedFile([]byte(s.AuthorizedKeys))
	}
	if len(s.Mesh.AuthnConfig.Issuers) > 0 {
		authn := oidc.NewAuthn(&s.Mesh.MeshCfg.AuthnConfig)
		err := authn.FetchAllKeys(context.Background(), s.Mesh.AuthnConfig.Issuers)
		if err != nil {
			log.Println("Issuers", err)
		}
		s.TokenChecker = authn.CheckJwtMap
	}

	if s.TokenChecker != nil {
		// Extension: allow JWT authentication. Normally client certs are used for SSH.
		s.serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			tok, e := s.TokenChecker(string(password))
			if e == nil {
				return &ssh.Permissions{Extensions: tok}, nil
			}
			return nil, errors.New("Invalid password")
		}
	}

	s.CertChecker = &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			if s.AuthorizedCA == nil {
				return false
			}
			for _, pubk := range s.AuthorizedCA {
				if KeysEqual(auth, pubk) {
					return true
				}
			}
			return false
		},
		// Used by clients authenticating the host.
		IsHostAuthority: func(auth ssh.PublicKey, user string) bool {
			if s.AuthorizedCA == nil {
				return false
			}
			for _, pubk := range s.AuthorizedCA {
				if KeysEqual(auth, pubk) {
					return true
				}
			}
			return false
		},
		HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// If the server has one of the authorized keys - allow it.
			keys := string(key.Marshal())
			user := s.UsersKeys[keys]
			if user != "" {
				return nil
			}
			fp := ssh.FingerprintSHA256(key)
			slog.Info("Host auth", "fp", fp, "id", user, "auth",
				string(ssh.MarshalAuthorizedKey(key)), "host", hostname, "remote", remote)
			return nil
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// The authorized keys are associated with the owner/admin
			//	if s.authorizedKeys != nil {
			keys := string(key.Marshal())
			user := s.UsersKeys[keys]
			fp := ssh.FingerprintSHA256(key)
			if user != "" {
				// TODO: add public key
				return &ssh.Permissions{Extensions: map[string]string{"sub": user,
					"role": "admin", "fp": fp}}, nil
			}
			return nil, errors.New("SSHD: no key found")
		},
	}
	s.serverConfig.AddHostKey(s.Signer)
	s.serverConfig.PublicKeyCallback = s.CertChecker.Authenticate

	return s, nil
}

func (ssht *SSHMesh) PubString() {
	casigner1 := ssht.Signer
	pubString := string(ssh.MarshalAuthorizedKey(casigner1.PublicKey()))

	fmt.Println(pubString)
}

// AddAuthorizedFile will load the ssh "authorized_files" content.
//
// All CAs are added separately, and will also be used for host authorization.
// The 'comment' field is saved - and will be used as 'user' when public key auth is using that key.
func (ssht *SSHMesh) AddAuthorizedFile(auth []byte) {
	for len(auth) > 0 {
		pubKey, comm, options, rest, err := ssh.ParseAuthorizedKey(auth)
		if err != nil {
			return
		}
		//if strings.Contains(pubk1.Type(), "cert") {
		if slices.Contains(options, "cert-authority") {
			ssht.AuthorizedCA = append(ssht.AuthorizedCA, pubKey)
		} else {
			ssht.UsersKeys[string(pubKey.Marshal())] = comm
		}
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
func (ssht *SSHMesh) Start(ctx context.Context) ( error) {
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
	return nil
}

func (ssht *SSHMesh) ListenAndStart() (net.Listener, error) {

	var err error
	// Once a ServerConfig has been configured, connections can be
	// accepted.
	if ssht.Listener == nil {
		ssht.Listener, err = net.Listen("tcp", ssht.Address)
		if err != nil {
			log.Println("Failed to listend on ", ssht.Address, err)
			return nil, err
		}
		if strings.HasSuffix(ssht.Address, ":0") {
			ssht.Address = ssht.Listener.Addr().String()
		}
	}

	err  = ssht.Start(context.Background())
	return ssht.Listener, err
}

// OpenStream creates a new stream.
// This uses the same channel in both directions.
func (c *SSHSMux) OpenStream(n string, data []byte) (*Stream, error) {
	// Doesn't work with regular ssh clients - this is an extension
	s, r, err := c.ServerConn.OpenChannel(n, data)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(r)
	return &Stream{Channel: s, serverMux: c}, nil
}

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (ssht *SSHMesh) HandleServerConn(nConn net.Conn) {
	acceptedSSHMux := &SSHSMux{
		Mux: Mux{
			ConnectTime: time.Now(),
			NetConn:     nConn,
		},
		SSHServer: ssht,


	}

	// Before use, a handshake must be performed on the incoming
	// net.Stream. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := ssh.NewServerConn(nConn, ssht.serverConfig)
	if err != nil {
		nConn.Close()
		//log.Println("SSHD: handshake error ", err, nConn.RemoteAddr(),
		//	nConn.LocalAddr())
		ssht.ConnectErrors.Add(1)
		return
	}

	// Only difference from a client conn is the Permissions field, as result
	// of authentication.
	acceptedSSHMux.ServerConn = conn

	ctx, cancel := context.WithCancel(context.Background())

	sub := conn.Permissions.Extensions["sub"]
	// convert email to DNS
	sub = strings.Replace(sub, "@", ".", 1)
	if strings.HasSuffix(sub, "-compute.developer.gserviceaccount.com") {
		// Project number replacement
		// This domain is shared by all workloads using the default service account.
		sub = strings.Replace(sub, "-compute.developer.gserviceaccount.com", ".pn.mesh.internal", 1)
	}
	if strings.HasSuffix(sub, ".iam.gserviceaccount.com") {
		// Project number replacement
		// Shared by all workloads using the custom GSA
		sub = strings.Replace(sub, ".iam.gserviceaccount.com", ".p.mesh.internal", 1)
	}

	acceptedSSHMux.FQDN = conn.User() + "." + sub

	ssht.connectedClientNodes.Store(acceptedSSHMux.FQDN, acceptedSSHMux)


	defer func() {
		// remote addr is from nConn
		// User is the authenticated user - from the client cert.
		//
		ssht.connectedClientNodes.Delete(acceptedSSHMux.FQDN)
		slog.Info("SSHD_CONN",
			"remote", nConn.RemoteAddr(),
			"user", conn.User(),
			"perm", conn.Permissions, "d", time.Since(acceptedSSHMux.ConnectTime))
		conn.Close()
		cancel()
	}()

	go ssht.handleServerConnRequests(ctx, globalSrvReqs, nConn, acceptedSSHMux)

	slog.Info("SSHD_CONN_START",
		"remote", nConn.RemoteAddr(),
		"user", conn.User(),
		"fqdn", acceptedSSHMux.FQDN,
		"perm", conn.Permissions, "d", time.Since(acceptedSSHMux.ConnectTime))

	// Service the incoming channels (stream in H2).
	// Each channel is a stream - shell, exec, sftp, local TCP forward.
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			go DirectTCPIPHandler(ctx, acceptedSSHMux, ssht, newChannel)

		default:
			chandler := ssht.ChannelHandlers[newChannel.ChannelType()]
			if chandler != nil {
				go chandler(ctx, acceptedSSHMux, newChannel)
			} else {
				// TODO: custom channel handlers
				//
				fmt.Println("SSHD: unknown channel Rejected", newChannel.ChannelType())
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			}
		}
	}
}

// Handle global requests on a server connection.
func (ssht *SSHMesh) handleServerConnRequests(ctx context.Context, reqs <-chan *ssh.Request, nConn net.Conn, conn *SSHSMux) {
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
			// TODO: global request handler !
			//
			log.Println("SSHD: unknown global REQUEST ", r.Type)
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}


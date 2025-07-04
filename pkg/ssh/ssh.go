package ssh

import (
	"context"
	"crypto"
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
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/costinm/ssh-mesh/nio"
	"github.com/costinm/ssh-mesh/pkg/h2"
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
	// Address to listen on as SSH. Will default to 14022 for regular nodes and
	// 15022 for gateways.
	Address string `json:"addr,omitempty"`

	KeepAlive map[string]*SSHCMux `json:"connect,omitempty"`

	CertClient string `json:"id_ecdsa_cert.pub,omitempty"`
	CertHost   string `json:"cert_host.pub,omitempty"`

	// Primary key - in PEM format (also used for mTLS)
	Key string `json:"tls.key,omitempty"`

	// AuthorizedKeys is the same as authorized_keys file.
	// The keys are used as 'trusted sources' for authentication. Any user key can be used for shell/debug access.
	// The CA keys are allowed to connect - but can get a shell only if 'role=admin' is present in the cert.
	//
	// If empty, the SSH_AUTHORIZED_KEYS env is used, falling back to authorized_keys in $HOME/.ssh (if FromEnv is called)
	AuthorizedKeys string `json:"authorized_keys,omitempty"`

	// User is in email format, as expected by the SSH client certificates.
	//
	User   string `json:"id,omitempty"`
	Domain string `json:"namespace,omitempty"`

	// Can be set to a custom dialer, for example for mesh protocol tunneling.
	Dialer ContextDialer `json:"-"`

	// Can be set to a custom dialer, for example for mesh protocol tunneling.
	H2Dialer ContextDialer `json:"-"`

	Listener net.Listener `json:"-"`

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

	ConnectErrors atomic.Int64 `json:"-"`

	// Map of public key to user ID.
	// Key is the marshalled public key (from authorized_keys), value is the user ID (comment)
	UsersKeys map[string]string `json:"-"`

	// Signer is the 'workload identity' signer. It is using the main workload
	// private key (workload key), but with a host certificate.
	Signer ssh.Signer `json:"-"`

	// SignerClient is a client workload identity - using the SA cert when
	// a CA is used. Otherwise, same as Signer.
	SignerClient ssh.Signer `json:"-"`
	SignerHost   ssh.Signer `json:"-"`

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
	TokenChecker TokenChecker `json:"-"`
	// TokenSource will provide passwords or tokens.
	// Normally SSH is cert based - but in some cases all we get is a token. For example K8S, Cloudrun, etc.
	TokenSource TokenSource `json:"-"`

	sync.Mutex `json:"-"`
	private    *ecdsa.PrivateKey

	Logger *slog.Logger
}

type ContextDialer interface {
	// Dial with a context based on tls package - 'once successfully
	// connected, any expiration of the context will not affect the
	// connection'.
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}

type TokenChecker interface {
	Check(token string) (claims map[string]string, e error)
}

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
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

func (sshMesh *SSHMesh) SetKeySSH(sshk string) error {
	k, err := ssh.ParseRawPrivateKey([]byte(sshk))
	if err != nil {
		return err
	}
	// Currently only ecdsa keys are used
	sshMesh.private = k.(*ecdsa.PrivateKey)

	sshMesh.Signer, _ = ssh.NewSignerFromKey(k)
	sshMesh.SignerClient = sshMesh.Signer
	return nil
}

// Cert.PrivateKey can be used as a source, if one is loaded.
func (sshMesh *SSHMesh) SetKeyCrypto(cpk crypto.PrivateKey) {
	// Currently only using ECDSA keys
	sshMesh.private = cpk.(*ecdsa.PrivateKey)
	sshMesh.Signer, _ = ssh.NewSignerFromSigner(sshMesh.private)
	sshMesh.SignerClient = sshMesh.Signer
}

func New() *SSHMesh {
	s := &SSHMesh{
		Address: ":15022",

		serverConfig:     &ssh.ServerConfig{},
		reverseForwards:  map[string]net.Listener{},
		InternalCommands: map[string]*Command{},
		UsersKeys:        map[string]string{},
		ChannelHandlers:  map[string]func(ctx context.Context, ssht *SSHSMux, newChannel ssh.NewChannel){},
		Logger:           slog.Default(),
	}

	return s
}

func (sshMesh *SSHMesh) Provision(ctx context.Context) error {
	if sshMesh.AuthorizedKeys != "" {
		sshMesh.AddAuthorizedFile([]byte(sshMesh.AuthorizedKeys))
	}
	s := sshMesh
	if sshMesh.Dialer == nil {
		sshMesh.Dialer = &net.Dialer{}
	}

	var err error

	if sshMesh.Key != "" {
		//encodedKey, _ := x509.MarshalECPrivateKey(nodePrivate)
		//privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey})
		err = sshMesh.SetKeySSH(sshMesh.Key)
		if err != nil {
			return err
		}
	}

	if sshMesh.private == nil {
		privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		s.private = privk1
		s.Signer, _ = ssh.NewSignerFromKey(privk1)
		s.SignerClient = s.Signer
	}
	if s.CertClient != "" {
		s.SetCertClient(s.CertClient)
	}
	if s.CertHost != "" {
		sshMesh.SetCertHost(s.CertHost)
	}

	if sshMesh.Listener == nil {
		sshMesh.Listener, err = net.Listen("tcp", sshMesh.Address)
		if err != nil {
			return err
		}
	}

	sshMesh.Forward = func(ctx context.Context, host string, closer io.ReadWriteCloser) {
		//str := nio.GetStream(closer, closer)
		//defer ug.OnStreamDone(str)
		//ug.OnStream(str)

		//str.Dest = host

		nc, err := sshMesh.Dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return
		}

		nio.Proxy(nc, closer, closer, host)
	}

	if s.TokenChecker != nil {
		// Extension: allow JWT authentication. Normally client certs are used for SSH.
		s.serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			tok, e := s.TokenChecker.Check(string(password))
			if e == nil {
				return &ssh.Permissions{Extensions: tok}, nil
			}
			return nil, errors.New("Invalid token")
		}
	}

	// Authenticate using certificates or public keys present in the 'authorized_keys'.
	// The 'mesh' implementation also allows arbitrary keys - with only mesh forwarding ability.
	s.CertChecker = &ssh.CertChecker{
		// Check 'signed certificate' - server side. The certificate should contain user, extensions like a JWT.
		IsUserAuthority: s.isUserAuthority,

		// Authorized keys or unknown users. The claims are in the authorized file.
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

		// Used by clients authenticating the host.
		IsHostAuthority: sshMesh.isHostAuthority,

		// Host verification by client
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
	}
	if s.SignerHost != nil {
		s.serverConfig.AddHostKey(s.SignerHost)
	}
	s.serverConfig.AddHostKey(s.Signer)

	s.serverConfig.PublicKeyCallback = s.CertChecker.Authenticate

	return nil
}

func (sshMesh *SSHMesh) Start(ctx context.Context) error {
	if sshMesh.Listener == nil {
		err := sshMesh.Provision(ctx)
		if err != nil {
			return err
		}
	}

	go func() {
		for {
			nConn, err := sshMesh.Listener.Accept()
			if err != nil {
				log.Println("failed to accept incoming connection ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			go sshMesh.HandleServerConn(&SSHSMux{NetConn: nConn})
		}
	}()
	sshMesh.Logger.Info("start_ssh", "addr", sshMesh.Listener.Addr().String())

	for k, sshc := range sshMesh.KeepAlive {
		sshc.SSHMesh = sshMesh
		sshc.Address = k
		sshMesh.Logger.Info("start_ssh", "addr", sshMesh.Listener.Addr().String())

		go sshc.StayConnected()
	}

	return nil
}

// Client returns a SSH client for a destination.
// It may be disconnected - first call is always disconnected.
func (sshMesh *SSHMesh) Client(ctx context.Context, dst string) (*SSHCMux, error) {

	c := &SSHCMux{
		SSHMesh: sshMesh,
		Address: dst,
		User:    sshMesh.User,
	}

	return c, nil
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

func (sshMesh *SSHMesh) PubString() {
	casigner1 := sshMesh.Signer
	pubString := string(ssh.MarshalAuthorizedKey(casigner1.PublicKey()))

	fmt.Println(pubString)
}

// AddAuthorizedFile will load the ssh "authorized_files" content.
//
// All CAs are added separately, and will also be used for host authorization.
// The 'comment' field is saved - and will be used as 'user' when public key auth is using that key.
func (sshMesh *SSHMesh) AddAuthorizedFile(auth []byte) {
	for len(auth) > 0 {
		pubKey, comm, options, rest, err := ssh.ParseAuthorizedKey(auth)
		if err != nil {
			return
		}
		//if strings.Contains(pubk1.Type(), "cert") {
		if slices.Contains(options, "cert-authority") {
			sshMesh.AuthorizedCA = append(sshMesh.AuthorizedCA, pubKey)
		} else {
			sshMesh.UsersKeys[string(pubKey.Marshal())] = comm
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

func (sshMesh *SSHMesh) ListenAndStart() (net.Listener, error) {

	var err error
	// Once a ServerConfig has been configured, connections can be
	// accepted.
	if sshMesh.Listener == nil {
		sshMesh.Listener, err = net.Listen("tcp", sshMesh.Address)
		if err != nil {
			log.Println("Failed to listend on ", sshMesh.Address, err)
			return nil, err
		}
		if strings.HasSuffix(sshMesh.Address, ":0") {
			sshMesh.Address = sshMesh.Listener.Addr().String()
		}
	}

	err = sshMesh.Start(context.Background())
	return sshMesh.Listener, err
}

// Stream is a client or server stream - 'Channel' in SSH terms.
//
// Also implements gossh.Channel - add SendRequest and Stderr, as well as CloseWrite
type Stream struct {
	ssh.Channel

	// One of the 2 will be set.
	serverMux *SSHSMux
	clientMux *SSHCMux
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

// SSHSMux is a server ssh connection - a long lived, accepted connection.
type SSHSMux struct {
	// Includes the private key of this node
	SSHServer *SSHMesh `json:"-"`

	// LastSeen    time.Time
	ConnectTime time.Time

	// network stream
	// May be an original con with net.Conn with remote/local addr
	NetConn net.Conn `json:"-"`

	// ServerConn - also has Permission
	ServerConn *ssh.ServerConn `json:"-"`

	RemoteKey ssh.PublicKey `json:"-"`
	//RemoteHostname string
	//RemoteAddr     net.Addr
	FQDN string
}

func (sshMesh *SSHMesh) HandleAccepted(nc net.Conn) error {
	sshMesh.HandleServerConn(&SSHSMux{NetConn: nc})
	return nil
}

// ServeHTTP is the main function implemented by SSH for HTTP purpose.
// It will take the H2 request and treat it as a TCP connection.
// HandleAccepted is handling accepted TCP connections.
func (sshMesh *SSHMesh) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	nc := h2.NewStreamServerRequest(request, writer)
	sshMesh.HandleServerConn(&SSHSMux{NetConn: nc})
}

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (sshMesh *SSHMesh) HandleServerConn(acceptedSSHMux *SSHSMux) {
	acceptedSSHMux.ConnectTime = time.Now()
	acceptedSSHMux.SSHServer = sshMesh

	nConn := acceptedSSHMux.NetConn

	// Before use, a handshake must be performed on the incoming
	// net.Stream. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := ssh.NewServerConn(nConn, sshMesh.serverConfig)
	if err != nil {
		nConn.Close()
		//log.Println("SSHD: handshake error ", err, nConn.RemoteAddr(),
		//	nConn.LocalAddr())
		sshMesh.ConnectErrors.Add(1)
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

	sshMesh.connectedClientNodes.Store(acceptedSSHMux.FQDN, acceptedSSHMux)

	defer func() {
		// remote addr is from nConn
		// User is the authenticated user - from the client cert.
		//
		sshMesh.connectedClientNodes.Delete(acceptedSSHMux.FQDN)
		slog.Info("SSHD_CONN",
			"remote", nConn.RemoteAddr(),
			"user", conn.User(),
			"perm", conn.Permissions, "d", time.Since(acceptedSSHMux.ConnectTime))
		conn.Close()
		cancel()
	}()

	go sshMesh.handleServerConnRequests(ctx, globalSrvReqs, nConn, acceptedSSHMux)

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
			go DirectTCPIPHandler(ctx, acceptedSSHMux, sshMesh, newChannel)
		case "session":
			s := &SSHSession{
				ssht:   sshMesh,
				sshMux: acceptedSSHMux,
			}
			s.Handle(ctx, newChannel)
		default:
			chandler := sshMesh.ChannelHandlers[newChannel.ChannelType()]
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
func (sshMesh *SSHMesh) handleServerConnRequests(ctx context.Context, reqs <-chan *ssh.Request, nConn net.Conn, conn *SSHSMux) {
	for r := range reqs {
		// Global types.
		switch r.Type {
		// "-R": we expect at least one R with 0.0.0.0 and port 5222, corresponding to the main mux dispatcher.
		// SSHClientConn clients will only accept back connections with this particular host:port, and srcIP:srcPort.
		// Other reverse accept ports can be opened as well.
		case "tcpip-forward":
			ok, pl := tcpipForwardHandler(ctx, sshMesh, conn, r)
			r.Reply(ok, pl)
			continue
		case "cancel-tcpip-forward":
			ok, pl := cancelTcpipForwardHandler(ctx, sshMesh, conn, r)
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

// DialHTTP will forward an HTTP connection to a client that opened a -R connection.
// The host must match the 'canonical' hostname of the client.
func (sshMesh *SSHMesh) DialHTTP(ctx context.Context, host string, orig string) (io.ReadWriteCloser, error) {

	cc, _ := sshMesh.connectedClientNodes.Load(host)

	if cc != nil {
		payload := ssh.Marshal(&remoteForwardChannelData{
			DestAddr:   "",
			DestPort:   uint32(80),
			OriginAddr: orig,
			OriginPort: uint32(1234),
		})
		ch, reqs, err := cc.(*SSHSMux).ServerConn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)

		return ch, nil
	}

	return nil, nil
}

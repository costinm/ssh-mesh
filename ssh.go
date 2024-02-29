package ssh_mesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/costinm/meshauth"
	meshauth_util "github.com/costinm/meshauth/util"
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
	*SSHConfig

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

	sync.Mutex
}

func (ss *SSHMesh) StayConnected(ctx context.Context) {
	for addr, d:=range ss.Dst {
		a := d.Addr
		if a == "" {
			a = addr
		}
		if d.Proto == "ssh-upstream" {
			// TODO: list of ssh servers for redundancy
			sshc, err := ss.Client(ctx, a)
			if err != nil {
				log.Fatal(err)
			}

			go sshc.StayConnected(a)
		}
	}
}

// Client returns a SSH client for a destination.
// It may be disconnected - first call is always disconnected.
func (ss *SSHMesh) Client(ctx context.Context, dst string) (*SSHCMux, error) {
	cp, _ := ss.Clients.Load(dst)
	if cp == nil {
		c := &SSHCMux{
			SSHConfig: ss.SSHConfig,
				ReverseForwards: map[string]string{},
			AuthorizedCA: ss.AuthorizedCA,
		}
		c.CertChecker = ss.CertChecker

		c.mds = meshauth_util.NewMDSClient(ss.SSHConfig.TokenProvider)
		ss.Clients.Store(dst, c)
		cp = c

		// TODO: ping, detect terminations.
	}


	c := cp.(*SSHCMux)
	return c, nil
}

// NewNode creates a new SSH mesh node, based on a config location.
//
// TODO: support URLs (with JWT auth) and dirs
func NewNode(loc string) (*SSHMesh, error) {
	sshmf := loc
	if loc[len(loc)-1] == '/' {
		sshmf = loc + "sshm.json"
		// TODO: dir, load dest from files.
	}
	cfgdata, err := os.ReadFile(sshmf)
	if err != nil {
		return nil, err
	}
	sshcfg := &SSHConfig{}
	json.Unmarshal(cfgdata, sshcfg)

	return NewSSHMesh(sshcfg)
}

// NewSSHMesh initializes a node using the ssh configuration.
// The config may include a private key (it should be loaded from a secret).
//
// If the key is missing, a self-signed key is generated.
//
// Extensions compared to regular sshd:
// - can use JWT tokens as password - based on Issuer config.
// - multiplex forwarded ports 22, 80, 443
// - optimized for the use of a CA for both client and server.
//
// TODO: As a server, it can also prove its workload ID with a JWT and jumpstart known_hosts !
func NewSSHMesh(tc *SSHConfig) (*SSHMesh, error) {
	if tc.InternalCommands == nil {
		tc.InternalCommands = map[string]*Command{}
	}
	if tc.UsersKeys == nil {
		tc.UsersKeys = map[string]string{}
	}
	if tc.ChannelHandlers == nil {
		tc.ChannelHandlers = map[string]func(ctx context.Context, ssht *SSHSMux, newChannel ssh.NewChannel){}
	}

	s := &SSHMesh{
		SSHConfig:       tc,
		serverConfig:    &ssh.ServerConfig{},
		reverseForwards: map[string]net.Listener{},
	}

	// TODO: if key and certs are missing in config but a URL is specified, fetch the
	//  private key and certs
	// ( a 'metadata' bootstrap/launcher should be run first to get all secret and config bits )


	if tc.SignerHost == nil {
		if tc.Private != "" {
			k, err := ssh.ParseRawPrivateKey([]byte(tc.Private))
			if err != nil {
				return nil, err
			}
			if privk1, ok := k.(*ecdsa.PrivateKey); ok {
				tc.KeyHost = privk1
			}
			tc.SignerHost, _ = ssh.NewSignerFromKey(k)
			tc.SignerClient = tc.SignerHost

			if tc.CertClient != "" {
				cert, err := ssh.ParsePublicKey([]byte(tc.CertClient))
				if err != nil {
					return nil, err
				}
				tc.SignerClient, err = ssh.NewCertSigner(cert.(*ssh.Certificate), tc.SignerClient)
				crt := cert.(*ssh.Certificate)
				tc.Name = crt.ValidPrincipals[0]
			}
			if tc.CertHost != "" {
				cert, err := ssh.ParsePublicKey([]byte(tc.CertHost))
				if err != nil {
					return nil, err
				}
				tc.SignerHost, err = ssh.NewCertSigner(cert.(*ssh.Certificate), tc.SignerHost)
			}

		} else {
			privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tc.SignerHost, _ = ssh.NewSignerFromKey(privk1)
			tc.SignerClient = tc.SignerHost
			tc.KeyHost = privk1
		}
	}

	if tc.AuthorizedKeys != "" {
		s.AddAuthorizedFile([]byte(tc.AuthorizedKeys))
	}
	if len(tc.AuthnConfig.Issuers) > 0 {
		authn := meshauth.NewAuthn(&tc.MeshCfg.AuthnConfig)
		err := authn.FetchAllKeys(context.Background(), tc.AuthnConfig.Issuers)
		if err != nil {
			log.Println("Issuers", err)
		}
		tc.TokenChecker = authn.CheckJwtMap
	}

	if tc.TokenChecker != nil {
		// Extension: allow JWT authentication. Normally client certs are used for SSH.
		s.serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			tok, e := tc.TokenChecker(string(password))
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
	s.serverConfig.AddHostKey(s.SignerHost)


	s.serverConfig.PublicKeyCallback = s.CertChecker.Authenticate

	return s, nil
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

func (ssht *SSHMesh) Start() (net.Listener, error) {

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
	return ssht.Listener, nil
}

type Mux struct {
	// LastSeen    time.Time
	ConnectTime time.Time
	// network stream
	// May be an original con with net.Conn with remote/local addr
	NetConn io.ReadWriteCloser
}

// SSHSMux is a server ssh connection.
type SSHSMux struct {
	Mux
	// ServerConn - also has Permission
	ServerConn *ssh.ServerConn

	//inChans <-chan ssh.NewChannel
	//req     <-chan *ssh.Request

	// Includes the private key of this node
	SSHServer *SSHMesh // transport.SSHMesh

	RemoteKey ssh.PublicKey
	//RemoteHostname string
	//RemoteAddr     net.Addr

	// For server-side sessions, this is the last active session.
	// With multiplexing, multiple sessions may be in effect.
	SessionStream ssh.Channel
	FQDN          string
}

// Stream is a client or server stream - 'Channel' in SSH terms.
//
// Also implements gossh.Channel - add SendRequest and Stderr, as well as CloseWrite
type Stream struct {
	ssh.Channel

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

// Sign will sign a certificate
// Each host can sign - the resulting cert should be under the host
// trust.
func (s *SSHMesh) Sign(pub ssh.PublicKey, certType uint32,
	names []string) ([]byte, *ssh.Certificate, error) {
	cert := &ssh.Certificate{
		ValidPrincipals: names,
		Key:             pub,
		ValidBefore:     ssh.CertTimeInfinity,
		CertType:        certType,
	}
	err := cert.SignCert(rand.Reader, s.SignerHost)
	if err != nil {
		return nil, nil, err
	}
	// This is a public key
	return ssh.MarshalAuthorizedKey(cert), cert, nil
}

// SignCert signs an arbitrary certificate.
func (s *SSHMesh) SignCert(cert *ssh.Certificate) ([]byte, error) {
	err := cert.SignCert(rand.Reader, s.SignerHost)
	if err != nil {
		return nil, err
	}
	// This is a public key
	return ssh.MarshalAuthorizedKey(cert), nil
}

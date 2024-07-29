package ssh_mesh

import (
	"io"
	"time"

	"github.com/costinm/meshauth"
	"golang.org/x/crypto/ssh"
)

// sshVip is used when tunneling SSH connections over H2, to allow the
// server to determine it's a SSH connection to the built-in SSH server.
// H2 tunnels can forward to any port, including 22 - this allows skipping
// the TCP part and using in-process.
const sshVip = "localhost:15022"

// Mux represents a TCP (or other protocol) connection with multiplexed
// streams on top. It can be used for SSH client, server, H2 and many
// protocols multiplexing streams.
type Mux struct {
	// LastSeen    time.Time
	ConnectTime time.Time

	// network stream
	// May be an original con with net.Conn with remote/local addr
	NetConn io.ReadWriteCloser
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

// SSHSMux is a server ssh connection.
type SSHSMux struct {
	Mux

	// ServerConn - also has Permission
	ServerConn *ssh.ServerConn

	// Includes the private key of this node
	SSHServer *SSHMesh

	RemoteKey ssh.PublicKey
	//RemoteHostname string
	//RemoteAddr     net.Addr

	// For server-side sessions, this is the last active session.
	// With multiplexing, multiple sessions may be in effect.
	SessionStream ssh.Channel

	FQDN          string
}


// SSHCMux is a multiplexed client connection to a single destination.
// That corresponds to a H2 connection - it is possible to have multiple
// SSHCMux connections to the same destination at the same time.
type SSHCMux struct {
	Mux
	*SSHMesh

	// If set, a persistent connection will be maintained and
	// - mux reverseForwards registered for 22, 80, 443
	// - accept streams and trust auth
	Waypoint bool

	// TODO: CIDR/Networks
	ReverseForwards map[string]string

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
	mds       meshauth.TokenSource
}



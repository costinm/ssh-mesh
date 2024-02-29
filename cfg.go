package ssh_mesh

import (
	"context"
	"crypto/ecdsa"
	"io"
	"os"
	"strings"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/util"
	"golang.org/x/crypto/ssh"
)

// SSHConfig is the configuration for the SSH mesh node.
//
// Regular ssh has configs scattered in multiple places and in
// special formats. This combines all configs in a struct that is
// easier to handle in a k8s Secret or env variable passed to a container.
type SSHConfig struct {
	// AuthnConfig defines trust sources for the server, to support JWT auth.
	// The JWT tokens are sent as passwords - this works with regular ssh
	// clients.
	// Audience should be ssh://FQDN, but can be configured.
	// Name should be the hostname or unique - will be used as user ID too.
	meshauth.MeshCfg

	// Address to listen on as SSH. Will default to 14022 for regular nodes and
	// 15022 for gateways.
	Address string `json:"sshd_addr,omitempty"`

	// H2CAddr is the address a server will listen as H2C.
	// This is used with K8S and other H2 gateways.
	// The tunnel is created on "/" with POST method.
	//
	// Currently only on 'gateways' by default, adds to binary size.
	H2CAddr string `json:"h2c_addr,omitempty"`

	//
	// For client nodes, open a socks server (similar to -D).
	// Normal port is 1080
	SocksAddr string `json:"socks_addr,omitempty"`

	TProxyAddr string `json:"tproxy_addr,omitempty"`

	// AuthorizedKeys is the same as authorized_keys file.
	// The keys are used as 'trusted sources' for authentication. Any user key can be used for shell/debug access.
	// The CA keys are allowed to connect - but can get a shell only if 'role=admin' is present in the cert.
	//
	// If empty, the SSH_AUTHORIZED_KESY env is used, falling back to authorized_keys in current dir and $HOME/.ssh
	AuthorizedKeys string `json:"authorized_keys,omitempty"`

	// Private is the private key, in PEM format.
	// For mesh we use one workload identity (verified by this private key) for all protocols.
	// We use tls.key for compatibility with K8S/CertManager secrets.
	Private    string `json:"tls.key,omitempty"`

	// Deprecated - Credentials
	CertHost   string `json:"ssh.crt,omitempty"`
	// Deprecated - Credentials
	CertClient string `json:"ssh-client.crt,omitempty"`

	// Map of public key to user ID.
	// Key is the marshalled public key (from authorized_keys), value is the user ID (comment)
	UsersKeys map[string]string `json:"user_keys,omitempty"`

	SignerHost   ssh.Signer `json:"-"`
	SignerClient ssh.Signer `json:"-"`

	// Forward is a function that will proxy a stream to a destination.
	// If missing, it will be dialed.
	// Used on a server for all client forwarding - except locally connected clients.
	Forward func(context.Context, string, io.ReadWriteCloser) `json:"-"`

	// WIP: Internally defined commands.
	InternalCommands map[string]*Command `json:"-"`

	KeyHost *ecdsa.PrivateKey `json:"-"`

	// Root CA keys - will be authorized to connect and create tunnels, not get shell.
	AuthorizedCA []ssh.PublicKey `json:"-"`

	// WIP: Custom channel handlers.
	ChannelHandlers map[string]func(ctx context.Context, sconn *SSHSMux, newChannel ssh.NewChannel) `json:"-"`

	// TokenChecker will verify the password field - as a JWT or other forms.
	TokenChecker func(password string) (claims map[string]string, e error) `json:"-"`
}



// SetCert the standard SSH files - from:
// - env
// - config dir
// - current working dir
// - $HOME/.ssh
func EnvSSH(config *SSHConfig) {
	ac1 := os.Getenv("SSH_AUTHORIZED_KEYS")
	if config.AuthorizedKeys == "" && ac1 != "" {
		config.AuthorizedKeys = ac1
	}

	ac := util.FindConfig("authorized_keys", "")
	if config.AuthorizedKeys == "" && ac != nil {
		config.AuthorizedKeys = string(ac)
	}

	key := util.FindConfig("id_ecdsa", "")
	if key != nil {
		config.Private = string(key)
	}

	cert_host := util.FindConfig("id_ecdsa_host.pub", "")
	if cert_host != nil {
		config.CertHost = string(cert_host)
	}

	cert_c := util.FindConfig("id_ecdsa_cert.pub", "")
	if cert_c != nil {
		config.CertClient = string(cert_c)
	}

	tc := config
	ks := os.Getenv("K_SERVICE")
	if ks != "" {
		sn := ks
		verNsName := strings.SplitN(ks, "--", 2)
		if len(verNsName) > 1 {
			sn = verNsName[1]
		}
		tc.Name = sn
	}

	if config.Name == "" {
		config.Name, _ = os.Hostname()
		if strings.Contains(config.Name, ".") {
			parts := strings.SplitN(tc.Name, ".", 2)
			config.Name = parts[0]
			if tc.Domain == "" {
				tc.Domain = parts[1]
			}
		}
	}
	if tc.Domain == "" {
		tc.Domain = "mesh.internal"
	}

	// TODO: load the cert from file !
	// TODO: is a CA is defined, get certs
}

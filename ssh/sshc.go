package ssh

import (
	"context"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Quick workaround for 'feature' negotiation. Will be replaced
// with proper variant.
const version = "SSH-2.0-cert-ssh"

// Client is a SSH client, using Istio-like certificates.
// By default will get a client cert, using the Istio identity,
// and connect to the specified SSHD.
//
// Will also forward the HBONE ports.
type Client struct {
	SSHCa     string
	SSHD      string
	Namespace string
	User      string

	client         *ssh.Client
	Signer         ssh.Signer
	RemoteKey      ssh.PublicKey
	RemoteHostname string
	RemoteAddr     net.Addr
	config         *ssh.ClientConfig

	CAKey        ssh.PublicKey
	CertChecker  *ssh.CertChecker
	CertProvider func(ctx context.Context, sshCA string) (ssh.Signer, error)

	//
	// Ports map[string]string
}

func (c *Client) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if c.Signer == nil {
		signer, err :=  c.CertProvider(ctx, c.SSHCa)
		if err != nil {
			return err
		}
		c.Signer = signer
	}
	c.CertChecker = &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, addr string) bool {
			return KeysEqual(auth, c.CAKey)
		},
	}
	authm := []ssh.AuthMethod{}
	authm = append(authm, ssh.PublicKeys(c.Signer))

	// An SSHClientConn client is represented with a ClientConn.
	// TODO: save and verify public key of server
	c.config = &ssh.ClientConfig{
		User:          c.User,
		Auth:          authm,
		Timeout:       3 * time.Second,
		ClientVersion: version,
		//Config: ssh.Config {
		//	MACs: []string{},
		//},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := c.CertChecker.CheckHostKey(hostname, remote, key)
			if err != nil {
				return err
			}
			c.RemoteAddr = remote
			c.RemoteHostname = hostname
			c.RemoteKey = key
			return nil
		},
	}

	return nil
}


type RemoteExec struct {
	ssh.Channel
	sessionServerReq <-chan *ssh.Request
}


// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}

func (c *Client) Exec(cmd string, env map[string]string) (*RemoteExec, error) {
	sessionCh, sessionServerReq, err := c.client.OpenChannel("session", nil)
	if err != nil {
		log.Println("Error opening session", err)
		c.client.Close()
		return nil, err
	}

	re := &RemoteExec{
		Channel: sessionCh,
		sessionServerReq: sessionServerReq,
	}

	// serverReq will be used only to notity that the session is over, may receive keepalives
	go func() {
		for msg := range sessionServerReq {
			// TODO: exit-status, exit-signal messages
			log.Println("SSHC: /ssh/srvmsg session message from server ", msg.Type, msg)
			if msg.WantReply {
				msg.Reply(false, nil)
			}
		}
	}()

	req := execMsg{
		Command: cmd,
	}

	ok, err := sessionCh.SendRequest("exec", true, ssh.Marshal(&req))
	if err == nil && !ok {
		log.Println("SSHC: Message channel failed", err)
		return nil, err
	}

	return re, nil
}

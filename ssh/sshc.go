package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"time"

	"github.com/costinm/cert-ssh/sshca"
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

	CAKey ssh.PublicKey
	CertChecker   *ssh.CertChecker

	//
	// Ports map[string]string
}

func (c *Client) Start() error {
	if c.Signer == nil {
		err := c.InitSigner(c.SSHCa)
		if err != nil {
			return err
		}
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

func (c *Client) InitSigner(sshCA string) error {
	ssc, con, err := GetSSHSignclient(sshCA)
	if err != nil {
		return err
	}
	defer con.Close()

	ephemeralPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ephemeralSigner, _ := ssh.NewSignerFromKey(ephemeralPrivate)
	req := &sshca.SSHCertificateRequest{
		Public: string(ssh.MarshalAuthorizedKey(ephemeralSigner.PublicKey())),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	certResponse, err := ssc.CreateCertificate(ctx, req)
	if err != nil {
		log.Println("Error creating cert ", err)
		return err
	}

	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(certResponse.User))
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return errors.New("unexpected cert")
	}
	signer, _ := ssh.NewCertSigner(cert, ephemeralSigner)

	c.Signer = signer
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

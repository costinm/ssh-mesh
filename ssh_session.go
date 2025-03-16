package ssh_mesh

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"sync/atomic"

	"github.com/costinm/ssh-mesh/pkg/sshpty"
	"golang.org/x/crypto/ssh"
)




// Represents a user properties. User name will be in the ssh login, basic auth,sub of JWT tokens, cert.
// Can also be loaded on demand from storage.
type User struct {

}

var id uint32


// Based on okteto code: https://raw.githubusercontent.com/okteto/remote/main/pkg/ssh/ssh.go
// Removed deps on logger, integrated with ugate.

// Handles PTY/noPTY shell sessions and sftp.

// gliderlabs: current version doesn't work with certs. config() method requires a PublicKeyHandler, which
// doesn't have a reference to the conn ( because gliderlabs decided to invent it's 'better' interface ).
// In general the interface and abstractions are too complex and not needed.


// WIP: The SSH 'gateway' will not have a real shell / sftp session (except for debug). Instead, the session is used as a
// general purpose communication.
//
// Notes on sessions:
// -N - do not start a session at all
// -T - do not get a pty
// If ssh is piped, a terminal will not be allocated - but no flushing seems to happen.
//
// Inside a session - ~. close, ~B break, ~C CLI, ~# connections, ~? help

// Basic untrusted session handler.
func SessionHandler(ctx context.Context, sconn *SSHSMux, newChannel ssh.NewChannel) {

	conn := sconn.ServerConn
	isOwner := conn.Permissions.Extensions["role"] == "admin"

	ch, reqs, _ := newChannel.Accept()

	env := []*KV{}

	ssht := sconn.SSHServer

	sess := &sshpty.PTY{
		Channel: ch,
		Conn:    conn,
	}

	for req := range reqs {
		// "shell", "exec", "env", "subsystem"
		// For pty: signal, break, pty-req, window-change
		//slog.Info("ssh-session", "type", req.Type)

		switch req.Type {
		case "shell", "exec":
			// This is normally the last command in a channel.
			// Env and pty are called first.
			// Depending on user and settings, only specific commands are allowed.
			// For shell - a generic event stream will be used for untrusted users (default)
			//
			// exec may be a command (/..) or may need to be evaluated.
			// as a shell.

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			if isOwner {
				go execHandler(ssht, conn, sess, env, payload.Value)
			} else {
				sid := atomic.AddUint32(&id, 1)
				e := &Exec{In: ch, Out: ch, id: sid,
					sconn: sconn,
					kv: env,
					cmd: payload.Value,
				}
				sconn.m.Lock()
				sconn.SessionStream[sid] = e
				sconn.m.Unlock()

				go e.execHandlerInternal(ch, env, payload.Value)
			}

		case "subsystem":
			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if "sftp" != payload.Value {
				req.Reply(false, nil)
			} else {
				go SFTPHandler(req, sconn, ch)
			}
		case "env":
			var kv KV
			// Typical: LANG
			ssh.Unmarshal(req.Payload, &kv)
			env = append(env, &kv)
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			// Typical pty-req, only for shell ( no params)
			sess.HandleSSHRequest(req)
		}
	}
}

var ftpHandler func(closer io.ReadWriteCloser)

func SFTPHandler(req *ssh.Request, sconn *SSHSMux, ch ssh.Channel) {
	path := "/usr/lib/openssh/sftp-server"
	// Run the SFTP server as a command, with in and out redirected
	// to the channel

	// -e = stderr instead of syslog
	// -d PATH - chroot
	// -R - read only
	//
	cmd := exec.Command(path, "-e", "-d", "/tmp")
	cmd.Env = []string{}
	cmd.Stdin = ch
	cmd.Stdout = ch
	cmd.Stderr = os.Stderr
	cmd.Start()

	cmd.Wait()
	// TODO: run sftp
}



type KV struct {
	Key, Value string
}

func (sshc *SSHCMux) ClientSession() {
	c := sshc.SSHClient

	// Open a session )
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

}

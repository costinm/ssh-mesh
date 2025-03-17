package ssh

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

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

// SSHSession is a multiplexed connection, like TCP forwarding, but with extra packets for executing commands.
//
type SSHSession struct {
	ssht   *SSHMesh
	sshMux *SSHSMux

	Channel ssh.Channel

	sigCh chan<- string

	sync.RWMutex

	sigBuf  []string
	breakCh chan<- bool

	PTY *Pty
	tty *os.File
}

func (sess *SSHSession) Close() error {
	return nil
}

// WIP: The SSH 'gateway' will not have a real shell / sftp session (except for debug). Instead, the session is used as a
// general purpose communication.
//
// Notes on sessions:
// -N - do not start a session at all
// -T - do not get a pty
// If ssh is piped, a terminal will not be allocated - but no flushing seems to happen.
//
// Inside a session - ~. close, ~B break, ~C CLI, ~# connections, ~? help
func (sess *SSHSession) Handle(ctx context.Context, newChannel ssh.NewChannel) {
	sconn := sess.sshMux

	conn := sconn.ServerConn
	isOwner := conn.Permissions.Extensions["role"] == "admin"

	ch, reqs, _ := newChannel.Accept()
  sess.Channel = ch

	env := []*KV{}

	ssht := sconn.SSHServer


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
				go execHandler(ch, ssht, conn, sess, env, payload.Value)
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

			// All other messages are optional and sent before shell/exec
		case "env":
			var kv KV
			// Typical: LANG
			ssh.Unmarshal(req.Payload, &kv)
			env = append(env, &kv)
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "signal":
			var payload struct{ Signal string }
			ssh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- payload.Signal
			} else {
				if len(sess.sigBuf) < 32 {
					sess.sigBuf = append(sess.sigBuf, payload.Signal)
				}
			}
			sess.Unlock()
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			req.Reply(ok, nil)
			sess.Unlock()
		case "pty-req":
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				return
			}
			sess.PTY = &ptyReq
			req.Reply(ok, nil)
		case "window-change":
			if sess.PTY == nil {
				req.Reply(false, nil)
				return
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.PTY.Window = win
				if sess.tty != nil {
					setWinsize(sess.tty, win.Width, win.Height)
				}
			}
			req.Reply(ok, nil)

		default:
			slog.Info("unknown session req", "type", req.Type)
			req.Reply(false, nil)
		}
	}
}

// Window represents the size of a PTY window.
type Window struct {
	Width  int
	Height int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	Term   string
	Window Window
	// HELP WANTED: terminal modes!
}

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = Pty{
		Term: term,
		Window: Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
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

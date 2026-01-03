package ssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

// SSHSession is a net connection (H2 stream equivalent), but with
// extra packets for executing commands including SFTP and an extra
// stderr stream.
//
// This is closer to a WebSocket in binary mode: packets, can multiplex
// sub-channels and commands - flow control is like H2, both on stream and
// mux.
//
// The actual execution is in the exec.go -
type SSHSession struct {
	ssht *SSHMesh

	// This is the parent multiplexed connection.
	sshMux *SSHSMux

	Channel ssh.Channel

	// Window keeps getting update during execution.
	PTY *Pty

	tty *os.File

	Env []*KV

	Cmd *exec.Cmd
}

// Based on okteto code: https://raw.githubusercontent.com/okteto/remote/main/pkg/ssh/ssh.go
// Removed deps on logger, integrated with ugate.
// Handles PTY/noPTY shell sessions and sftp.

// gliderlabs: current version doesn't work with certs. config() method requires a PublicKeyHandler, which
// doesn't have a reference to the conn ( because gliderlabs decided to invent it's 'better' interface ).
// In general the interface and abstractions are too complex and not needed.

var signals = map[ssh.Signal]int{
	ssh.SIGABRT: 6,
	ssh.SIGALRM: 14,
	ssh.SIGFPE:  8,
	ssh.SIGHUP:  1,
	ssh.SIGILL:  4,
	ssh.SIGINT:  2,
	ssh.SIGKILL: 9,
	ssh.SIGPIPE: 13,
	ssh.SIGQUIT: 3,
	ssh.SIGSEGV: 11,
	ssh.SIGTERM: 15,
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
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		slog.Warn("SSHErrorAccept", "err", err)
		return
	}
	sess.Channel = ch

	// Typical order:
	// - env, [ pty-req, window-change]
	// - shell/exec
	// - signal, break
	for req := range reqs {
		// "shell", "exec", "env", "subsystem"
		// For pty: signal, break, pty-req, window-change
		switch req.Type {
		case "shell", "exec":
			// Depending on user and settings, only specific commands are allowed.
			// For shell - a generic event stream will be used for untrusted users (default)
			//
			// exec may be a command (/..) or may need to be evaluated.
			// as a shell.

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			go sess.execHandler(ch, payload.Value)

		case "subsystem":
			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if payload.Value != "sftp" {
				// TODO: we could add a custom subsystem handler, but
				// using regular sessions is cleaner and more consistent
				// with H2. I think subsystem could be deprecated and should
				// only be used for SFTP.
				req.Reply(false, nil)
			} else {
				go sess.SFTPHandler(ctx, req)
			}

			// All other messages are optional and sent before shell/exec
		case "env":
			var kv KV
			// Typical: LANG
			ssh.Unmarshal(req.Payload, &kv)
			sess.Env = append(sess.Env, &kv)
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "signal":
			// This is sent after shell/exec
			var payload struct{ Signal string }
			ssh.Unmarshal(req.Payload, &payload)
			if sess.Cmd != nil && sess.Cmd.Process != nil {
				sv := signals[ssh.Signal(payload.Signal)]
				if sv != 0 {
					sess.Cmd.Process.Signal(syscall.Signal(sv))
				}
			}
		case "break":
			if sess.Cmd != nil && sess.Cmd.Process != nil {
				sess.Cmd.Process.Signal(syscall.SIGINT)
			}
			req.Reply(true, nil)
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

func exit(sess ssh.Channel, code int) error {
	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, ssh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

// Handle exec and shell commands.
// "raw" is the string command - like a URL, but with space separators.
//
// "admin" ( owner key or user ID in a client cert) can run shell session
// or run any command.
//
// Regular users have access to a restricted set of internal commands
// When the server is a real dropbear/sshd, this is handled with the
// native ssh permission system.
func (s *SSHSession) execHandler(ch ssh.Channel, raw string) {
	conn := s.sshMux.ServerConn
	isOwner := conn.Permissions.Extensions["role"] == "admin"

	if !isOwner {
		fmt.Fprintln(ch, "Only owner can run commands", conn.RemoteAddr(), conn.Permissions.Extensions, conn.User())
		ch.Close()
		return
	}
	t0 := time.Now()
	defer func() {
		s.Close()
		slog.Info("sshd_exec_close", "dur", time.Since(t0),
			"cmd", raw)
	}()

	cmd := buildCmd(s.Env, raw)
	s.Cmd = cmd
	
	if s.PTY == nil {
		err := handleNoTTY(cmd, ch, ch, ch.Stderr())
		if err != nil {
			sendErrAndExit(ch, err)
		} else {
			exit(ch, 0)
		}
		return
	}

	if len(s.PTY.Term) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", s.PTY.Term))
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true

	// A PTY request is set and we have a pty handler
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(s.PTY.Window.Height), Cols: uint16(s.PTY.Window.Height)})
	if err != nil {
		sendErrAndExit(ch, err)
		return
	}
	s.tty = f
	defer f.Close()

	go func() {
		io.Copy(f, ch) // stdin
	}()
	go func() {
		io.Copy(ch, f) // stdout and stderr - with pty we can't split
	}()

	if err := cmd.Wait(); err != nil {
		exerr := err.(*exec.ExitError)
		exit(ch, exerr.ExitCode())
		return
	}

	exit(ch, 0)
}

func sendErrAndExit(s ssh.Channel, err error) {
	msg := strings.TrimPrefix(err.Error(), "exec: ")
	if _, err := s.Stderr().Write([]byte(msg)); err != nil {
		log.Println("failed to write error back to session", err)
	}

	if err := exit(s, getExitStatusFromError(err)); err != nil {
		log.Println(err, "pty session failed to exit")
	}
}

var SftpHandler func(ctx context.Context, s *SSHSession, req *ssh.Request) int
var SftpPath = os.Getenv("SFTP_PATH")

func (s *SSHSession) SFTPHandler(ctx context.Context, req *ssh.Request) {
	if SftpHandler != nil {
		code := SftpHandler(ctx, s, req)
		exit(s.Channel, code)
		return
	}
	if SftpPath == "" {
		SftpPath = "/usr/lib/openssh/sftp-server"
	}
	path := SftpPath
	// Run the SFTP server as a command, with in and out redirected
	// to the channel

	// -e = stderr instead of syslog
	// -d PATH - chroot
	// -R - read only
	//
	cmd := exec.Command(path, "-e", "-d", "/tmp")
	cmd.Env = []string{}
	cmd.Stdin = s.Channel
	cmd.Stdout = s.Channel
	cmd.Stderr = os.Stderr
	cmd.Start()

	cmd.Wait()
	// TODO: run sftp
}

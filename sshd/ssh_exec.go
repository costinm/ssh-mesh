package sshd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// Based on okteto code: https://raw.githubusercontent.com/okteto/remote/main/pkg/ssh/ssh.go
// Removed deps on logger, integrated with ugate.

// Handles PTY/noPTY shell sessions and sftp.

// gliderlabs: current version doesn't work with certs. config() method requires a PublicKeyHandler, which
// doesn't have a reference to the conn ( because gliderlabs decided to invent it's 'better' interface ).
// In general the interface and abstractions are too complex and not needed.

var (
	//idleTimeout = 60 * time.Second

	// ErrEOF is the error when the terminal exits
	ErrEOF = errors.New("EOF")
)

// sessionHandler handles the "session" channel.
// Based on build flags, it may handle sftp, PTY channels and exec.
// TODO: If "exec" is called, it may invoke http handlers and handle
// internal console/logs
func sessionHandler(ctx context.Context, ssht *Transport, conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	ch, reqs, _ := newChannel.Accept()

	sess := &ptySession{
		Channel: ch,
		conn:    conn,
	}

	// Requests are actively used.
	// Extension: shell/exec can be called multiple times on a channel.
	// Standard clients won't do this - no harm to skip an extra call.
	go func() {
		t0 := time.Now()
		for req := range reqs {
			switch req.Type {
			// shell has no args, should run a default shell
			// exec may be a command (/..) or may need to be evaluated.
			case "shell", "exec":
				// This is normally the last command in a channel.
				// Env and pty are called first.
				//
				var payload = struct{ Value string }{}
				ssh.Unmarshal(req.Payload, &payload)
				sess.rawCmd = payload.Value
				req.Reply(true, nil)

				if conn.Permissions.Extensions["sub"] != "admin" {
					go func() {
						sess.Write([]byte("Dummy session"))
						d := make([]byte, 1024)
						for {
							_, err := sess.Read(d)
							if err != nil {
								break
							}
						}
						slog.Info("ssh_exec_log", "dur", time.Since(t0), "cmd", sess.rawCmd,
							"type", req.Type)
						exit(ch, 0)
					}()
					continue
				}

				go func() {
					ssht.execHandler(sess)
					slog.Info("ssh_exec", "dur", time.Since(t0), "cmd", sess.rawCmd,
						"type", req.Type)
					exit(ch, 0)
				}()
			case "subsystem":
				subsystemHandler(req, conn, ch)
			case "env":
				var kv KV
				// Typical: LANG
				ssh.Unmarshal(req.Payload, &kv)
				sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
				req.Reply(true, nil)
			default:
				// Typical pty-req, only for shell ( no params)
				sess.handleRequest(req)
			}
		}

	}()
}

type KV struct {
	Key, Value string
}

func exit(sess ssh.Channel, code int) error {
	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, ssh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func getExitStatusFromError(err error) int {
	if err == nil {
		return 0
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return 1
	}

	waitStatus, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		if exitErr.Success() {
			return 0
		}

		return 1
	}

	return waitStatus.ExitStatus()
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

func handleNoTTY(cmd *exec.Cmd, s ssh.Channel) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println(err, "couldn't get StdoutPipe")
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Println(err, "couldn't get StderrPipe")
		return err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println(err, "couldn't get StdinPipe")
		return err
	}

	if err = cmd.Start(); err != nil {
		log.Println(err, "couldn't start nopty command '%s'", cmd.String())
		return err
	}

	go func() {
		defer stdin.Close()
		if _, err := io.Copy(stdin, s); err != nil {
			log.Println(err, "failed to write session to stdin.")
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s, stdout); err != nil {
			log.Println(err, "failed to write stdout to session.")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s.Stderr(), stderr); err != nil {
			log.Println(err, "failed to write stderr to session.")
		}
	}()

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		log.Println(err, "command failed while waiting")
		return err
	}

	return nil
}

// Handle exec and shell commands.
func (ssht *Transport) execHandler(s *ptySession) {
	t0 := time.Now()
	defer func() {
		s.Close()
		slog.Info("sshd_exec_close", "dur", time.Since(t0),
			"cmd", s.rawCmd)
	}()

	cmd := ssht.buildCmd(s)

	if true {
		ok, err := s.handlePTY(cmd)
		if ok {
			if err != nil {
				sendErrAndExit(s, err)
				return
			}

			exit(s, 0)
			return
		}
	}

	if err := handleNoTTY(cmd, s); err != nil {
		sendErrAndExit(s, err)
		return
	}

	exit(s, 0)
}

func (ssht *Transport) buildCmd(s *ptySession) *exec.Cmd {
	var cmd *exec.Cmd

	if len(s.rawCmd) == 0 {
		cmd = exec.Command(ssht.Shell)
	} else {
		args := []string{"-c", s.rawCmd}
		cmd = exec.Command(ssht.Shell, args...)
	}

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, s.env...)

	return cmd
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

type RemoteExec struct {
	ssh.Channel
	sessionServerReq <-chan *ssh.Request
}

// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}

// TODO: client side sftp.

// Exec opens a client session channel for a command.
func (ssht *SSHConn) Exec(cmd string, env map[string]string) (*RemoteExec, error) {
	if ssht.scl == nil {
		return nil, errors.New("Only for client connections")
	}
	sessionCh, sessionServerReq, err := ssht.scl.OpenChannel("session", nil)
	if err != nil {
		log.Println("Error opening session", err)
		ssht.scl.Close()
		return nil, err
	}

	re := &RemoteExec{
		Channel:          sessionCh,
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

	// TODO: send env first

	ok, err := sessionCh.SendRequest("exec", true, ssh.Marshal(&req))
	if err == nil && !ok {
		log.Println("SSHC: Message channel failed", err)
		return nil, err
	}

	return re, nil
}

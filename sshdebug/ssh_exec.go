package sshdebug

import (
	"context"
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

	sshd "github.com/costinm/ssh-mesh"

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
func SessionHandler(ctx context.Context, sconn *sshd.SSHSMux, newChannel ssh.NewChannel) {
	ch, reqs, _ := newChannel.Accept()

	ssht := sconn.SSHServer
	conn := sconn.ServerConn

	isOwner := conn.Permissions.Extensions["sub"] == "admin"

	env := []*KV{}

	if !isOwner {
		for req := range reqs {
			switch req.Type {
			case "shell", "exec":
				// This is normally the last command in a channel.
				// Env and pty are called first.
				//
				var payload = struct{ Value string }{}
				ssh.Unmarshal(req.Payload, &payload)
				req.Reply(true, nil)

				go execHandlerInternal(ssht, conn, ch, env, payload.Value)
			case "env":
				var kv KV
				// Typical: LANG
				ssh.Unmarshal(req.Payload, &kv)
				env = append(env, &kv)
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}
		return
	}

	sess := &ptySession{
		Channel: ch,
		conn:    conn,
	}

	// Requests are actively used.
	// Extension: shell/exec can be called multiple times on a channel.
	// Standard clients won't do this - no harm to skip an extra call.
	for req := range reqs {
		switch req.Type {
		// shell has no args, should run a default shell.
		// It is usually sent after requesting a pty.

		// exec may be a command (/..) or may need to be evaluated.
		// as a shell.
		case "shell", "exec":
			// This is normally the last command in a channel.
			// Env and pty are called first.
			//
			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value
			req.Reply(true, nil)

			go execHandler(ssht, conn, sess, env, payload.Value)
		case "subsystem":
			subsystemHandler(req, conn, ch)
		case "env":
			var kv KV
			// Typical: LANG
			ssh.Unmarshal(req.Payload, &kv)
			env = append(env, &kv)
			if req.WantReply {
				req.Reply(true, nil)
			}
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
		default:
			// Typical pty-req, only for shell ( no params)
			sess.handleRequest(req)
		}
	}

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
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
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

func execHandlerInternal(ssht *sshd.SSHMesh, conn *ssh.ServerConn,
	ch ssh.Channel, env []*KV, rawCmd string) {
	t0 := time.Now()
	defer func() {
		slog.Info("sshd_exec_close", "dur", time.Since(t0),
			"cmd", rawCmd)
	}()

	ch.Write([]byte("Dummy session"))

	d := make([]byte, 1024)
	for {
		_, err := ch.Read(d)
		if err != nil {
			break
		}
	}
	exit(ch, 0)
	return

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
func execHandler(ssht *sshd.SSHMesh, conn *ssh.ServerConn, s *ptySession, env []*KV, raw string) {
	t0 := time.Now()
	defer func() {
		s.Close()
		slog.Info("sshd_exec_close", "dur", time.Since(t0),
			"cmd", s.rawCmd)
	}()

	cmd := buildCmd(ssht, env, raw)

	if s.pty != nil {
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

func buildCmd(ssht *sshd.SSHMesh, env []*KV, rawCmd string) *exec.Cmd {
	// TODO: differentiate between admin and user - run as UID if not admin.
	// ( assuming the command is run as regular user)
	var cmd *exec.Cmd

	sh := "/bin/bash"

	if len(rawCmd) == 0 {
		cmd = exec.Command(sh)
	} else {
		// Running the exec in a shell is nice - no need for full path, etc.
		// However with distroless there is no shell.
		args := []string{"-c", rawCmd}
		cmd = exec.Command(sh, args...)
	}

	cmd.Env = append(cmd.Env, os.Environ()...)
	for _, k := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k.Key, k.Value))
	}

	return cmd
}

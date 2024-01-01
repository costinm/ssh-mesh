package ssh_mesh

import (
	"context"
	"fmt"
	"log"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

// WIP: The SSH 'gateway' will not have a shell / sftp session. Instead, the session is used as a
// general purpose communication.
//
// Notes on sessions:
// -N - do not start a session at all
// -T - do not get a pty
// If ssh is piped, a terminal will not be allocated - but no flushing seems to happen.
//
// Inside a session - ~. close, ~B break, ~C CLI, ~# connections, ~? help

func SessionHandler(ctx context.Context, sconn *SSHSMux, newChannel ssh.NewChannel) {
	ch, reqs, _ := newChannel.Accept()

	go func() {
		for req := range reqs {
			// "shell", "exec", "env", "subsystem"
			// For pty: signal, break, pty-req, window-change
			slog.Info("ssh-session", "type", req.Type)
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	fmt.Fprint(ch, "{}\n")
	// Logs or other info can be sent
	sconn.SessionStream = ch

	data := make([]byte, 1024)
	for {
		n, err := ch.Read(data)
		if err != nil {
			return
		}
		slog.Info("ssh-session-in", "data", string(data[0:n]))
	}
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

//+build nopty

package sshpty

import (
	"os/exec"

	"golang.org/x/crypto/ssh"
)

type PTY struct {
	ssh.Channel
	Conn *ssh.ServerConn

	// Will be nil
	PTY *PTY
	RawCmd string
}

func (p PTY) HandleSSHRequest(req *ssh.Request) {
	if req.WantReply {
		req.Reply(true, nil)
	}
}

func (p PTY) Exec(cmd *exec.Cmd) (bool, error) {
	return false, nil
}

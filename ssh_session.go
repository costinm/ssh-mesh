package ssh_mesh

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"

	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"
)

// WIP: The SSH 'gateway' will not have a real shell / sftp session (except for debug). Instead, the session is used as a
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

	env := []*KV{}

	for req := range reqs {
		// "shell", "exec", "env", "subsystem"
		// For pty: signal, break, pty-req, window-change
		slog.Info("ssh-session", "type", req.Type)

		switch req.Type {
		case "shell", "exec":
			// This is normally the last command in a channel.
			// Env and pty are called first.
			//
			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)

			sconn.SessionStream = ch
			go execHandlerInternal(ch, env, payload.Value)
		case "subsystem":
			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if "sftp" != payload.Value {
				req.Reply(false, nil)
			} else {
				sftpHandler(req, sconn, ch)
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
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}
}

func sftpHandler(req *ssh.Request, sconn *SSHSMux, ch ssh.Channel) {
	sftp.NewRequestServer(ch, sftp.Handlers{
		FileGet:  sconn,
		FilePut:  sconn,
		FileCmd:  sconn,
		FileList: sconn,
	})
}

func (c *SSHSMux) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	//TODO implement me
	panic("implement me")
}

func (c *SSHSMux) Filecmd(request *sftp.Request) error {
	//TODO implement me
	panic("implement me")
}


func (c *SSHSMux) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	//TODO implement me
	panic("implement me")
}



func (c *SSHSMux) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	//TODO implement me
	panic("implement me")
}


func execHandlerInternal(ch ssh.Channel, kv []*KV, cmd string) {
	fmt.Fprint(ch, "{}\n")
	// Logs or other info can be sent

	data := make([]byte, 1024)
	for {
		n, err := ch.Read(data)
		if err != nil {
			return
		}
		slog.Info("ssh-session-in", "data", string(data[0:n]))
	}
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

package ssh

import (
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
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Exec can be used with streams - SSH, H2 or other tunnels.
type Exec struct {
	Args []string
	Env  map[string]string
	WD   string

	// If true, the command will be launched at startup and kept alive.
	//
	OnStart bool

	// If set, the app will create this UDS and use it to communicate.
	// New streams will be forwarded to the stream.
	UDS string

	In    io.Reader
	Out   io.WriteCloser // will be a ssh.Channel for ssh
	id    uint32
	sconn *SSHSMux
	kv    []*KV
	cmd   string
}

//
func (*Exec) Start() error {
	return nil
}

func (*Exec) Run() {

}

// WIP: for untrusted users - only forward is allowed. Exec is used as a
// messaging channel.
func (e *Exec) execHandlerInternal(ch ssh.Channel, kv []*KV, cmd string) {
	defer func() {
		ch.Close()
		e.sconn.m.Lock()
		delete(e.sconn.SessionStream, e.id)
		e.sconn.m.Unlock()
	}()

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


// Handle exec and shell commands.
// "raw" is the string command - like a URL, but with space separators.
//
// "admin" ( owner key or user ID in a client cert) can run shell session
// or run any command.
//
// Regular users have access to a restricted set of internal commands
// When the server is a real dropbear/sshd, this is handled with the
// native ssh permission system.
func execHandler(ch ssh.Channel, ssht *SSHMesh, conn *ssh.ServerConn, s *SSHSession, env []*KV, raw string) {

	t0 := time.Now()
	defer func() {
		s.Close()
		slog.Info("sshd_exec_close", "dur", time.Since(t0),
			"cmd", raw)
	}()

	cmd := buildCmd(ssht, env, raw)

	if s.PTY != nil && len(s.PTY.Term) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", s.PTY.Term))
	}
	// This is done for both PTY package and default
	if s.PTY != nil {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setctty = true
	}

	if s.PTY != nil {
		// A PTY request is set and we have a pty handler
		f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(s.PTY.Window.Height), Cols: uint16(s.PTY.Window.Height)})
		defer f.Close()
		s.tty = f
		if err != nil {
			sendErrAndExit(ch, err)
			return
		}
		go func() {
			io.Copy(f, ch) // stdin
		}()

		waitCh := make(chan struct{})

		go func() {
			defer close(waitCh)
			io.Copy(ch, f) // stdout and stderr - with pty we can't split
		}()

		if err := cmd.Wait(); err != nil {
			exerr := err.(*exec.ExitError)
			log.Println("pty command failed while waiting", err)
			exit(ch, exerr.ExitCode())
			return
		}

		exit(ch, 0)

		return
	}

	err := handleNoTTY(cmd, ch)
	if err != nil {
		sendErrAndExit(ch, err)
	}
}

func handleNoTTY(cmd *exec.Cmd, s ssh.Channel) error {
	// Creates a os.Pipe. returns the reader side. Also handles the childIOFiles/parentIOPipes, to be closed at end.
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

	if err := cmd.Wait(); err != nil {
		exerr := err.(*exec.ExitError)
		log.Println("pty command failed while waiting", err)
		exit(s, exerr.ExitCode())
		return err
	}

	wg.Wait()
	exit(s, 0)
	return nil
}


func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
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


func buildCmd(ssht *SSHMesh, env []*KV, rawCmd string) *exec.Cmd {
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

// StartWithSize starts the command with a pty - normally creack/pty, but avoiding the dep in this package.
var StartWithSize func(cmd *exec.Cmd,  w, h, x, y uint16) (*os.File, error)


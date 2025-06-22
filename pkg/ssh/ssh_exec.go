package ssh

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// Exec can be used with streams - SSH, H2 or other tunnels.
type Exec struct {
	// Host of VM where this command will be executed. It will create a
	// SSH or https connection or reuse existing client mux for remote
	// connections, or use a command to enter the VM.
	Host string

	Args []string
	Env  map[string]string
	WD   string

	In  io.Reader
	Out io.WriteCloser // will be a ssh.Channel for ssh

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
}

type KV struct {
	Key, Value string
}

func handleNoTTY(cmd *exec.Cmd, in io.Reader, out io.WriteCloser, errs io.ReadWriter) error {
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
		if _, err := io.Copy(stdin, in); err != nil {
			log.Println(err, "failed to write session to stdin.")
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(out, stdout); err != nil {
			log.Println(err, "failed to write stdout to session.")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(errs, stderr); err != nil {
			log.Println(err, "failed to write stderr to session.")
		}
	}()

	if err := cmd.Wait(); err != nil {

		return err
	}

	wg.Wait()
	return nil
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
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

func buildCmd(env []*KV, rawCmd string) *exec.Cmd {
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
var StartWithSize func(cmd *exec.Cmd, w, h, x, y uint16) (*os.File, error)

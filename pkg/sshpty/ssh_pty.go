//+build !nopty

package sshpty

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"

	"golang.org/x/crypto/ssh"

	"log/slog"
)

// PTY is used to allow exec shells.
// This is mainly for debug purpose - a simpler option is to just include native dropbear or sshd and use ssh-mesh
// as a jump host only.

// TODO: remove

type PTY struct {
	sync.Mutex
	ssh.Channel
	Conn *ssh.ServerConn

	env    []string
	RawCmd string

	handled bool
	exited  bool

	PTY *Pty

	winch   chan Window
	sigCh   chan<- Signal
	sigBuf  []Signal
	breakCh chan<- bool
}

func (s *PTY) Exec(cmd *exec.Cmd) (bool, error) {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		return false, nil
	}
	if len(ptyReq.Term) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	f, err := pty.Start(cmd)
	if err != nil {
		log.Println("failed to start pty session", err)
		return true, err
	}

	go func() {
		for win := range winCh {
			setWinsize(f, win.Width, win.Height)
		}
	}()

	go func() {
		io.Copy(f, s) // stdin
	}()

	waitCh := make(chan struct{})
	go func() {
		defer close(waitCh)
		io.Copy(s, f) // stdout
	}()

	if err := cmd.Wait(); err != nil {
		log.Println("pty command failed while waiting", err)
		return true, err
	}

	select {
	case <-waitCh:
		log.Println("stdout finished")
	case <-time.NewTicker(1 * time.Second).C:
		log.Println("stdout didn't finish after 1s")
	}

	return true, nil
}


type Signal string

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

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}


func (sess *PTY) Write(p []byte) (n int, err error) {
	if sess.PTY != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.Replace(p, []byte{'\n'}, []byte{'\r', '\n'}, -1)
		p = bytes.Replace(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'}, -1)
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *PTY) Pty() (Pty, <-chan Window, bool) {
	if sess.PTY != nil {
		return *sess.PTY, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *PTY) Close() error {
	// when reqs is closed
	if sess.winch != nil {
		close(sess.winch)
		sess.winch = nil
	}
	return sess.Channel.Close()
}

func (sess *PTY) Signals(c chan<- Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *PTY) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

const maxSigBufSize = 128

func (sess *PTY) HandleSSHRequest(req *ssh.Request) {
	switch req.Type {
	case "signal":
		var payload struct{ Signal string }
		ssh.Unmarshal(req.Payload, &payload)
		sess.Lock()
		if sess.sigCh != nil {
			sess.sigCh <- Signal(payload.Signal)
		} else {
			if len(sess.sigBuf) < maxSigBufSize {
				sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
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
		if sess.PTY != nil {
			req.Reply(false, nil)
			return
		}
		ptyReq, ok := parsePtyRequest(req.Payload)
		if !ok {
			req.Reply(false, nil)
			return
		}
		sess.PTY = &ptyReq
		sess.winch = make(chan Window, 1)
		sess.winch <- ptyReq.Window
		req.Reply(ok, nil)
	case "window-change":
		if sess.PTY == nil {
			req.Reply(false, nil)
			return
		}
		win, ok := parseWinchRequest(req.Payload)
		if ok {
			sess.PTY.Window = win
			sess.winch <- win
		}
		req.Reply(ok, nil)

	default:
		slog.Info("unknown session req", req.Type)
		req.Reply(false, nil)
	}
}

// handle requests on the "PTY" stream.
func (sess *PTY) handleRequests(reqs <-chan *ssh.Request) {
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

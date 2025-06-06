package nio

import (
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CloseWriter is one of possible interfaces implemented by RequestInPipe to send a FIN, without closing
// the input. Some writers only do this when Close is called.
type CloseWriter interface {
	CloseWrite() error
}

// TODO: benchmark different sizes.
var Debug = false
var DebugRW = false

// ReaderCopier copies from In to Out, keeping track of copied bytes and errors.
type ReaderCopier struct {
	// Number of bytes copied.
	Written int64
	MaxRead int
	ReadCnt int

	// First error - may be on reading from In (InError=true) or writing to Out.
	Err error

	InError bool

	In io.Reader

	// For tunneled connections, this can be a tls.Writer. Close will write an TOS close.
	Out io.Writer

	// An ID of the copier, for debug purpose.
	ID string

	// Set if out doesn't implement Flusher and a separate function is needed.
	// Example: tunneled mTLS over http, Out is a tls.Conn which writes to a http Body.
	Flusher http.Flusher
}

func (rc *ReaderCopier) Close() {
	if c, ok := rc.In.(io.Closer); ok {
		c.Close()
	}
	if c, ok := rc.Out.(io.Closer); ok {
		c.Close()
	}

}

// Verify if in and out can be spliced. Used by proxy code to determine best
// method to copy.
//
// Tcp connections implement ReadFrom, not WriteTo
// ReadFrom is only spliced in few cases
func CanSplice(in io.Reader, out io.Writer) bool {
	if _, ok := in.(*net.TCPConn); ok {
		if _, ok := out.(*net.TCPConn); ok {
			return true
		}
	}
	return false
}

// Old style buffer pool

var (
	// createBuffer to get a buffer. io.Copy uses 32k.
	bufferPoolCopy = sync.Pool{New: func() interface{} {
		return make([]byte, 16*64*1024) // 1M
	}}
)

var StreamId uint32

// Copy will copy src to dst, using a pooled intermediary buffer.
//
// Blocking, returns when src returned an error or EOF/graceful close.
//
// May also return with error if src or dst return errors.
//
// Copy may be called in a go routine, for one of the streams in the
// connection - the stats and error are returned on a channel.
func (s *ReaderCopier) Copy(ch chan int, close bool) {
	if ch != nil {
		defer func() {
			ch <- int(0)
		}()
	}

	if CanSplice(s.In, s.Out) {
		n, err := s.Out.(io.ReaderFrom).ReadFrom(s.In)
		s.Written += n
		if err != nil {
			s.rstWriter(err)
			s.Err = err
		}
		//VarzReadFromC.Add(1)
		return
	}

	buf1 := bufferPoolCopy.Get().([]byte)
	defer bufferPoolCopy.Put(buf1)
	bufCap := cap(buf1)
	buf := buf1[0:bufCap:bufCap]

	//st := ReaderCopier{}

	// For netstack: src is a gonet.ReaderCopier, doesn't implement WriterTo. Dst is a net.TcpConn - and implements ReadFrom.
	// Copy is the actual implementation of Copy and CopyBuffer.
	// if buf is nil, one is allocated.
	// Duplicated from io

	// This will prevent stats from working.
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}
	if s.ID == "" {
		s.ID = strconv.Itoa(int(atomic.AddUint32(&StreamId, 1)))
	}
	if Debug {
		log.Println(s.ID, "startCopy()")
	}
	for {
		if srcc, ok := s.In.(net.Conn); ok {
			srcc.SetReadDeadline(time.Now().Add(15 * time.Minute))
		}
		nr, er := s.In.Read(buf)
		if DebugRW && nr < 1024 {
			log.Println(s.ID, "read()", nr, er)
		}
		if nr > s.MaxRead {
			s.MaxRead = nr
		}

		// Even if we have an error, send the bytes we've read.
		if nr > 0 { // before dealing with the read error
			s.ReadCnt++
			// If RequestInPipe is a ResponseWriter, bad things may happen.
			// There is no deadline - the buffer is put on a queue, and then there is a wait on a ch.
			// The ch is signaled when the frame is sent - if window update has been received.
			// We could try to add a deadline - or directly expose the flow control.
			// See server.go writeDataFromHandler.

			// Write will never return hanging the handler if the client doesn't read. No way to interupt.
			// This may happen if the client is done but didn't close the connection or request, it
			// may still be sending.

			// DoneServing is checked - so it is possible to do this in background, but only works for proxy.

			nw, ew := s.Out.Write(buf[0:nr])
			if DebugRW && nw < 1024 {
				log.Println(s.ID, "write()", nw, ew)
			}
			if nw > 0 {
				s.Written += int64(nw)
			}
			if f, ok := s.Out.(http.Flusher); ok {
				f.Flush()
			}
			if nr != nw && ew == nil { // Should not happen
				ew = io.ErrShortWrite
				if Debug {
					log.Println(s.ID, "write error - short write", s.Err)
				}
			}
			if ew != nil {
				s.Err = ew
				if close {
					s.rstWriter(ew)
				}
				if Debug {
					log.Println(s.ID, "write error rst writer, close in", close, s.Err)
				}
				return
			}
		}

		// Handle Read errors - EOF or real error
		if er != nil {
			if strings.Contains(er.Error(), "NetworkIdleTimeout") {
				er = io.EOF
			}
			if er == io.EOF {
				if Debug {
					log.Println(s.ID, "EOF received, closing writer", close)
				}
				if close {
					// read is already closed - we need to close out
					// TODO: if err is not nil, we should send RST not FIN
					closeWriter(s.Out)
					// close in as well - won't receive more data.
					// However: in many cases this causes the entire net.Conn to close
					//if c, ok := s.In.(io.Closer); ok {
					//	c.Close()
					//}
				}
			} else {
				s.Err = er
				s.InError = true
				if Debug {
					log.Println(s.ID, "readError()", s.Err)
				}
				if close {
					// read is already closed - we need to close out
					// TODO: if err is not nil, we should send RST not FIN
					s.rstWriter(er)
				}
			}

			if Debug {
				log.Println(s.ID, "read DONE", close, s.Err)
			}
			return
		}
	}
}

func (s *ReaderCopier) rstWriter(err error) error {
	if c, ok := s.In.(io.Closer); ok {
		// Otherwise it keeps getting data - this should send a RST
		// TODO: should have a method that also allows errr to be set.
		c.Close()
	}
	dst := s.Out
	if c, ok := dst.(io.Closer); ok {
		return c.Close()
	}
	if c, ok := s.In.(io.Closer); ok {
		// Otherwise it keeps getting data - this should send a RST
		// TODO: should have a method that also allows errr to be set.
		c.Close()
	}
	if rw, ok := dst.(http.ResponseWriter); ok {
		// Server side HTTP stream. For client side, FIN can be sent by closing the pipe (or
		// request body). For server, the FIN will be sent when the handler returns - but
		// this only happen after request is completed and body has been read. If server wants
		// to send FIN first - while still reading the body - we are in trouble.

		// That means HTTP2 TCP servers provide no way to send a FIN from server, without
		// having the request fully read.

		// This works for H2 with the current library - but very tricky, if not set as trailer.
		rw.Header().Set("X-Close", "0")
		rw.(http.Flusher).Flush()
		return nil
	}
	log.Println("Server out not Closer nor CloseWriter nor ResponseWriter", dst)
	return nil
}

func closeWriter(dst io.Writer) error {
	if cw, ok := dst.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	if c, ok := dst.(io.Closer); ok {
		return c.Close()
	}
	if rw, ok := dst.(http.ResponseWriter); ok {
		// Server side HTTP stream. For client side, FIN can be sent by closing the pipe (or
		// request body). For server, the FIN will be sent when the handler returns - but
		// this only happen after request is completed and body has been read. If server wants
		// to send FIN first - while still reading the body - we are in trouble.

		// That means HTTP2 TCP servers provide no way to send a FIN from server, without
		// having the request fully read.

		// This works for H2 with the current library - but very tricky, if not set as trailer.
		rw.Header().Set("X-Close", "0")
		rw.(http.Flusher).Flush()
		return nil
	}
	log.Println("Server out not Closer nor CloseWriter nor ResponseWriter", dst)
	return nil
}


package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/costinm/ssh-mesh/nio"
)

// Egress capture using SOCKS5, for whitebox mode.

// curl --socks5 127.0.0.1:15004 ....
// export HTTP_PROXY=socks5://127.0.0.1:15004

// TODO: tor extensions
// - send client data in advance, forward to the server
// - resolve

// Note: max DNS size is 255 ( including trailing 0, and len labels )

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

/*
  RFC1928

  1. Req:
  VER 0x05
  NMETHODS 0x01
  METHOD 0x00 [one byte for each method - NoAuth]
  (other auth not supported - we bind on 127.0.0.1 or use mtls)

  Res:
  VER 0x05
	METHOD 0x00

	2.  VER: X'05'
      CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
      RSV    RESERVED 0x00
      ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
      DST.ADDR       desired destination address
      DST.PORT desired destination port in network octet order
*/

type SocksConn struct {
	Dest     string
	DestAddr *net.TCPAddr

	Conn net.Conn

	Socks *Socks
}

func (s *SocksConn) Run() {

	brin := nio.NewBufferReader(s.Conn)

	s.HandleSocks(brin, s.Conn)

	//t0 := time.Now()
	dest := s.Dest
	if dest == "" {
		dest = s.DestAddr.String()
	}
	nc, err := s.Socks.Dialer.DialContext(context.Background(), "tcp", s.Dest)
	if err != nil {
		s.PostDialHandler(nil, err)
		return
	}
	s.PostDialHandler(nc.LocalAddr(), nil)

	nio.Proxy(nc, s.Conn, s.Conn, s.Dest)
}

type Socks struct {
	//Address string `json:"address,omitempty"`

	// NetListener and Dialer can be set by the user.
	NetListener net.Listener `json:"-"`
	Dialer ContextDialer `json:"-"`
}

type ContextDialer interface {
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}


func (l *Socks) Start(ctx context.Context) error {
	//if l.Address == "" {
	//	l.Address = "127.0.0.1:15008"
	//}
	//if l.NetListener == nil {
	//	listener, err := net.Listen("tcp", l.Address)
	//	if err != nil {
	//		return err
	//	}
	//	l.NetListener = listener
	//}
	if l.Dialer == nil {
		l.Dialer = &net.Dialer{}
	}
	go l.Sock5Capture()
	return nil
}

func (l *Socks) With(_, dep any) {
	if netDialer, ok := dep.(ContextDialer); ok {
		l.Dialer = netDialer
	}
	if netDialer, ok := dep.(net.Listener); ok {
		l.NetListener = netDialer
	}
}

func (l *Socks) Sock5Capture()  {
		for {
			c, err := l.NetListener.Accept()
			if err != nil {
				if ne, ok := err.(interface {
					Temporary() bool
				}); ok && ne.Temporary() {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				return
			}
			s := &SocksConn{Conn: c, Socks: l}

			//
			go s.Run()
		}
}

// Must be called before sending any data, to send the local addr used when
// dialing. This is rarely used - tproxy doesn't send anything back either.
func (s *SocksConn) PostDialHandler(localAddr net.Addr, err error) {
	if err != nil {
		// TODO: write error code
		s.Conn.Write([]byte{5, 1})
		s.Conn.Close()
		return
	}
	// Not accurate for tcp-over-http.
	// TODO: pass a 'on connect' callback

	tcpAddr := localAddr.(*net.TCPAddr)
	r := make([]byte, len(tcpAddr.IP)+6)
	r[0] = 5
	r[1] = 0 // success
	r[2] = 0 // rsv
	off := 4
	if tcpAddr.IP.To4() != nil {
		r[3] = 1
		copy(r[off:off+4], []byte(tcpAddr.IP))
		off += 4
	} else {
		r[3] = 2
		copy(r[off:off+16], []byte(tcpAddr.IP))
		off += 16
	}
	binary.BigEndian.PutUint16(r[off:], uint16(tcpAddr.Port))
	off += 2
	s.Conn.Write(r[0:off])
}

func (s *SocksConn) HandleSocks(br *nio.BufferReader, w io.WriteCloser) (err error) {
	// Fill the read buffer with one Read.
	// Typically 3-4 bytes unless client is eager.

	head, err := br.Peek(3)
	if err != nil {
		return err
	}

	if head[0] != 5 {
		return errors.New("invalid header")
	}
	// Client: 0x05 0x01 0x00
	//         0x05 0x02  0x00 0x01
	// Server: 0x05 0x00
	off := 1
	sz := int(head[off])
	off++                   // 2
	if len(head) < off+sz { // if it only read 2, probably malicious - 2 < 2 + 1
		head, err = br.Peek(off + sz)
		if err != nil {
			return err
		}
	}
	off += sz // 3

	w.Write([]byte{5, 0})

	// We may have bytes in the buffer, in case sender didn't wait
	if len(head) <= off+6 {
		head, err = br.Peek(off + sz)
		if err != nil {
			return err
		}
	}
	// We have at least 6 bytes
	if head[off] != 5 {
		return errors.New("invalid header 2")
	}
	off++
	if head[off] != 1 {
		return errors.New("invalid method " + strconv.Itoa(int(head[off])))
	}
	off++
	off++ // rsvd

	atyp := head[off]
	off++

	destName := ""
	var destIP []byte
	// off should be 3 or 4
	switch atyp {
	case 1:
		if len(head) <= off+6 {
			head, err = br.Peek(off + 6)
		}
		destIP = make([]byte, 4)
		copy(destIP, head[off:off+4])
		off += 4
	case 4:
		if len(head) <= off+18 {
			head, err = br.Peek(off + 18)
		}
		destIP = make([]byte, 16)
		copy(destIP, head[off:off+16])
		off += 16

	case 3:
		dlen := int(head[off])
		off++
		if len(head) <= off+dlen+2 {
			head, err = br.Peek(off + dlen + 2)
		}
		destName = string(head[off : off+dlen])
		off += dlen
	}
	if err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(head[off:])
	off += 2

	// Any reminding bytes are eager sent
	br.Discard(off)

	if atyp == 3 {
		s.Dest = net.JoinHostPort(destName, strconv.Itoa(int(port)))
	} else {
		s.DestAddr = &net.TCPAddr{IP: destIP, Port: int(port)}
		s.Dest = s.DestAddr.String()
	}

	return nil
}

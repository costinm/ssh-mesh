//go:build !android
// +build !android

package tproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Based on https://github.com/LiamHaworth/go-tproxy/blob/master/tproxy_tcp.go and many others

// Doesn't compile with gomobile - syscall.SYS_GETSOCKOPT - and
// it is not needed, using LWIP with VPN API.

// TProxy captures streams using TPROXY or REDIRECT, and forwards them using
//
//	a Dialer or OnConn callback.
type TProxy struct {
	// If not set, 127.0.0.1:15006
	Addr string

	NetListener *net.TCPListener

	OnConn func(nc net.Conn, dest string, la *net.TCPAddr, postDial func(net.Addr, error))
}

func (t *TProxy) Provision(ctx context.Context) error {
	if t.Addr == "" {
		t.Addr = "127.0.0.1:15006"
	}
	na, err := net.ResolveTCPAddr("tcp", t.Addr)
	if err != nil {
		log.Println("Failed to configure tproxy", err)
		return err
	}
	nl, err := listenTProxy(ctx, "tcp", na)
	if err != nil {
		log.Println("Failed to capture tproxy", err)
		return err
	}
	t.NetListener = nl
	return nil
}

func (t *TProxy) Start(ctx context.Context) {
	localPort := t.NetListener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			remoteConn, err := acceptTProxy(t.NetListener)

			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			if err != nil {
				log.Println("Accept error, closing iptables listener ", err)
				return
			}
			dst := remoteConn.LocalAddr().(*net.TCPAddr)

			// Redirect capture - for tproxy the destination port is the target
			// (we don't support sending to the capture port, it's reserved)
			if dst.Port == localPort {
				realAddr, err := GetREDIRECTOriginalDst(remoteConn)
				if err != nil {
					return
				}
				dst = realAddr
				if realAddr.Port == localPort {
					log.Println("No redirect or looping ", err)
					return
				}
			}

			slog.Info("ACCEPTED_TPROXY", "addr", remoteConn.RemoteAddr(), "dst", dst)

			if t.OnConn != nil {
				t.OnConn(remoteConn, dst.String(), remoteConn.RemoteAddr().(*net.TCPAddr), nil)
			}
		}
	}()
}

// AcceptTProxy will accept a TCP connection
// and wrap it to a TProxy connection to provide
// TProxy functionality
func acceptTProxy(l *net.TCPListener) (*net.TCPConn, error) {
	tcpConn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}

	return tcpConn, nil
}

// ListenTProxy will construct a new TCP listener
// socket with the Linux IP_TRANSPARENT option
// set on the underlying socket
func listenTProxy(ctx context.Context, network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	fileDescriptorSource, err := listener.File()
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %s", err)}
	}
	defer fileDescriptorSource.Close()

	// Allow socket to bind on any port.
	if err = syscall.SetsockoptInt(int(fileDescriptorSource.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err == nil {
		slog.InfoContext(ctx, "TPROXY enabled")
	}

	return listener, nil
}

// Status:
//   https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
//
// Using: https://github.com/Snawoot/transocks/blob/v1.0.0/original_dst_linux.go
// ServeConn is used to serve a single TCP UdpNat.
// See https://github.com/cybozu-go/transocks
// https://github.com/ryanchapman/go-any-proxy/blob/master/any_proxy.go,
// and other examples.
// Based on REDIRECT.

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname),
		uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

// Should be used only for REDIRECT capture.
func GetREDIRECTOriginalDst(clientConn *net.TCPConn) (rawaddr *net.TCPAddr, err error) {
	// test if the underlying fd is nil
	remoteAddr := clientConn.RemoteAddr()
	if remoteAddr == nil {
		err = errors.New("fd is nil")
		return
	}

	// net.TCPConn.File() will cause the receiver's (clientConn) socket to be placed in blocking mode.
	// The workaround is to take the File returned by .File(), do getsockopt() to get the original
	// destination, then create a new *net.TCPConn by calling net.InOutStream.FileConn().  The new TCPConn
	// will be in non-blocking mode.  What a pain.
	clientConnFile, err := clientConn.File()
	if err != nil {
		return
	}
	defer clientConnFile.Close()

	fd := int(clientConnFile.Fd())
	if err = syscall.SetNonblock(fd, true); err != nil {
		return
	}

	// Get original destination
	// this is the only syscall in the Golang libs that I can find that returns 16 bytes
	// Example result: &{Multiaddr:[2 0 31 144 206 190 36 45 0 0 0 0 0 0 0 0] Interface:0}
	// port starts at the 3rd byte and is 2 bytes long (31 144 = port 8080)
	// IPv6 version, didn't find a way to detect network family
	//addr, err := syscall.GetsockoptIPv6Mreq(int(clientConnFile.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	v6 := clientConn.LocalAddr().(*net.TCPAddr).IP.To4() == nil
	if v6 {
		var addr syscall.RawSockaddrInet6
		var len uint32
		len = uint32(unsafe.Sizeof(addr))
		err = getsockopt(fd, syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST,
			unsafe.Pointer(&addr), &len)
		if err != nil {
			return
		}
		ip := make([]byte, 16)
		for i, b := range addr.Addr {
			ip[i] = b
		}
		pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
		return &net.TCPAddr{
			IP:   ip,
			Port: int(pb[0])*256 + int(pb[1]),
		}, nil
	} else {
		var addr syscall.RawSockaddrInet4
		var len uint32
		len = uint32(unsafe.Sizeof(addr))
		err = getsockopt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST,
			unsafe.Pointer(&addr), &len)
		if err != nil {
			return nil, os.NewSyscallError("getsockopt", err)
		}
		ip := make([]byte, 4)
		for i, b := range addr.Addr {
			ip[i] = b
		}
		pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
		return &net.TCPAddr{
			IP:   ip,
			Port: int(pb[0])*256 + int(pb[1]),
		}, nil
	}
}

//func isLittleEndian() bool {
//	var i int32 = 0x01020304
//	u := unsafe.Pointer(&i)
//	pb := (*byte)(u)
//	b := *pb
//	return (b == 0x04)
//}

//var (
//	NativeOrder binary.ByteOrder
//)
//
//func init() {
//	if isLittleEndian() {
//		NativeOrder = binary.LittleEndian
//	} else {
//		NativeOrder = binary.BigEndian
//	}
//}

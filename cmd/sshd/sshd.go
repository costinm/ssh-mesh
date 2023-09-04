package main

import (
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/costinm/ssh-mesh/sshc"
	"github.com/costinm/ssh-mesh/sshd"
	"github.com/costinm/ssh-mesh/util"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"golang.org/x/crypto/ssh"
)

// SSHD is an extended version of the mesh ssh service, intended for jump (gateway) and CA servers.
// Like SSHC, it can maintain a connection to an upstream host.
// Like SSHC, it can act as a middle jump server for clients authenticating with the CA or JWTs
//
// It also includes a H2C server (and TODO: HTTPS) routing requests.
// It adds a K8S controller watching EndpointSlice and tracking clients.
func main() {
	configF := util.MainStart()

	var pubk ssh.PublicKey
	authca := configF("SSH_AUTHORIZED_CA")
	if authca != "" {
		pubk, _, _, _, _ = ssh.ParseAuthorizedKey([]byte(authca))
	}

	// Server providing reverse tunneling and jump host.
	addr := configF("SSHD")
	if addr != "" {
		sshc, err := sshc.NewSSHC(&sshc.SSHClientConf{})
		if err != nil {
			log.Fatal(err)
		}
		// If not set - skip checking the host key. This is normally very dangerous,
		// but ok if we're just forwarding encrypted connections ( a jump host ).
		// TODO: list of ssh servers for redundancy
		// TODO: use https to fetch the server public key
		if pubk != nil {
			sshc.AuthorizedCA = append(sshc.AuthorizedCA, pubk)
		}
		go sshc.StayConnected(addr)
	}

	var st *sshd.Transport
	// Default is to start a sshd on 15022.
	st, err := sshd.NewSSHTransport(&sshd.TransportConfig{})

	sshdPort := configF("SSHD_PORT")
	if sshdPort != "" {
		p, _ := strconv.Atoi(sshdPort)
		st.Port = p
		if err != nil {
			log.Fatal(err)
		}

		iss := configF("SSHD_ISSUERS")
		util.InitJWT(strings.Split(iss, ","))

		// Add the authorized keys for incoming SSH
		authc := configF("SSH_AUTHORIZED_KEY")
		if authc != "" {
			st.AddAuthorized(authc)
		}

		// Add authorized CA users
		if pubk != nil {
			st.AuthorizedCA = append(st.AuthorizedCA, pubk)
		}

		st.Start()
	}

	// Start a small http server, for status.
	// Tunneling of h2 or ws: different project or extension (ugate?), too many deps.
	haddr := configF("SSHD_HTTP")
	if haddr != "" {
		go func() {
			mux := http.NewServeMux()
			st.InitMux(mux)

			// Adds about 400k to binary size
			h2ch := h2c.NewHandler(mux, &http2.Server{})

			http.ListenAndServe(haddr, h2ch)
		}()
	}

	socksAddr := configF("socksAddr")
	if socksAddr != "" {

	}

	tproxyAddr := configF("tproxyAddr")
	if tproxyAddr != "" {
		util.IptablesCapture(tproxyAddr, func(nc net.Conn, dest, la *net.TCPAddr) {

		})
	}

	// Log the start
	hn, _ := os.Hostname()
	slog.Info("sshd-start", "hostaddr", haddr,
		"sshd", addr, "hostname", hn, "env", os.Environ())
	util.MainEnd()
}

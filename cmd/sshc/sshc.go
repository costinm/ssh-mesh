package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/costinm/ssh-mesh/sshc"
	"github.com/costinm/ssh-mesh/sshd"
	"github.com/costinm/ssh-mesh/util"

	"golang.org/x/crypto/ssh"
)

// Connect to a SSH server and keeps the connection alive.
// Sish is one such server, providing a lot of interesting features.
// Works with regular sshd - but only for one connection, since it'll forward
// remote port 22.
//
// Can optionally start a local sshd server, with sshfs included.
//
// Can optionally start a jump host/server, using same protocol.
//
// Equivalent with
// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://host
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

		go st.Start()
	}

	// Start a small http server, for status.
	// Tunneling of h2 or ws: different project or extension (ugate?), too many deps.
	haddr := configF("SSHD_HTTP")
	if haddr != "" {
		go func() {
			mux := http.NewServeMux()
			st.InitMux(mux)
			http.ListenAndServe(haddr, mux)
		}()
	}

	// Log the start
	hn, _ := os.Hostname()
	slog.Info("sshd-start", "hostaddr", haddr,
		"sshd", addr, "hostname", hn, "env", os.Environ())
	util.MainEnd()
}

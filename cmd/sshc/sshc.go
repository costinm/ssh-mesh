package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/costinm/ssh-mesh/sshc"
	"github.com/costinm/ssh-mesh/sshd"
	"github.com/costinm/ssh-mesh/util"

	"golang.org/x/crypto/ssh"
)

// Connect to a SSH server and keeps the connection alive.
// Sish is a convenient server.
//
// Equivalent with
// SSH_ADKPASS_REQUIRE=force
// SSH_ASKPASS=gcloud auth print-identity-token $GSA --audiences=https://host
// ssh host
func main() {
	jsh := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
	})
	slog.SetDefault(slog.New(jsh))

	addr := os.Getenv("SSHD")
	if addr == "" {
		addr = "localhost:2222"
	}

	sshc, err := sshc.NewSSHC()
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range os.Environ() {
		kv := strings.SplitN(v, "=", 2)
		if strings.HasPrefix(kv[0], "SSH_R_") {
			rport := kv[0][6:]
			lport := kv[1]
			sshc.Forwards[rport] = lport
		}
	}

	go sshc.StayConnected(addr)

	st, err := sshd.NewSSHTransport(&sshd.TransportConfig{
		Port:       15022,
		SignerHost: sshc.Signer,
	})
	if err != nil {
		log.Fatal(err)
	}

	authc := os.Getenv("SSH_AUTHORIZED_KEY")
	if authc != "" {
		st.AddAuthorized(authc)
	}
	authca := os.Getenv("SSH_AUTHORIZED_CA")
	if authca != "" {
		pubk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authca))
		if err == nil {
			st.AuthorizedCA = append(st.AuthorizedCA, pubk)
			sshc.AuthorizedCA = append(sshc.AuthorizedCA, pubk)
		}
	}
	go st.Start()

	haddr := os.Getenv("SSHD_HTTP")
	if haddr != "" {
		go func() {
			http.DefaultServeMux.HandleFunc("/_ssh/status", func(writer http.ResponseWriter, request *http.Request) {
				//jb, _ := json.Marshal(sshc)
				//log.Println(request, string(jb))
				//writer.Write(jb)
			})
			http.DefaultServeMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
				writer.Write([]byte("ok"))

			})
			http.ListenAndServe(haddr, http.DefaultServeMux)
		}()
	}
	hn, _ := os.Hostname()
	log.Println("Starting ", haddr, addr, hn, os.Environ())
	util.MainEnd()
}

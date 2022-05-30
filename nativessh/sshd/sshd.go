package nativessh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"

	gossh "golang.org/x/crypto/ssh"
)

// Helpers around sshd, using exec.
// Will be used if /usr/bin/sshd is added to the docker image.
// WIP: the code is using a built-in sshd, but it may be easier to use the official sshd if present and reduce code size.
// The 'special' thing about the built-in is that it's using SSH certificates - but they can also be created as
// secrets or provisioned the same way as Istio certs, in files by the agent.

var SshdConfig = `
Port {{ .Cfg.Port }}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
Protocol 2
LogLevel INFO

HostKey {{ .Cfg.Dir }}/ssh_host_ecdsa_key

PermitRootLogin yes

AuthorizedKeysFile	{{ .Dir }}/authorized_keys

PasswordAuthentication yes
PermitUserEnvironment yes

AcceptEnv LANG LC_*
PrintMotd no
#UsePAM no

Subsystem	sftp	/usr/lib/openssh/sftp-server
`

type SSHDConfig struct {
	Port int
	Dir  string
}

// StartSSHD will start sshd.
// If running as root, listens on port 22
// If started as user, listen on port 15022
func StartSSHD(cfg *SSHDConfig, sshCM map[string][]byte) {

	// /usr/sbin/sshd -p 15022 -e -D -h ~/.ssh/ec-key.pem
	// -f config
	// -c host_cert_file
	// -d debug - only one connection processed
	// -e debug to stderr
	// -h or -o HostKey
	// -p or -o Port
	//
	if cfg == nil {
		cfg = &SSHDConfig{}
	}
	if cfg.Port == 0 {
		cfg.Port = 15022
	}

	pwd, _ := os.Getwd()
	sshd := pwd + "/var/run/secrets/sshd"
	sshd = "/run/sshd"

	os.Mkdir(sshd, 0700)
	for k, v := range sshCM {
		err := os.WriteFile(sshd+"/"+k, v, 0700)
		if err != nil {
			log.Println("Secret write error", k, err)
			return
		}
	}

	NewKeyPair(sshd + "/ssh_host_ecdsa_key")

	//os.StartProcess("/usr/bin/ssh-keygen",
	//	[]string{
	//		"-q",
	//		"-f",
	//		"/tmp/sshd/ssh_host_ecdsa_key",
	//		"-N",
	//		"",
	//		"-t",
	//		"ecdsa",
	//		},
	//	&os.ProcAttr{
	//	})

	if _, err := os.Stat(sshd + "/sshd_config"); os.IsNotExist(err) {
		ioutil.WriteFile("/run/sshd/sshd_confing", []byte(SshdConfig), 0700)
	}

	cmd := exec.Command("/usr/sbin/sshd",
		"-f", sshd+"/sshd_config",
		"-e",
		"-D",
		"-p", strconv.Itoa(cfg.Port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// kr.Children = append(kr.Children, cmd)

	go func() {
		err := cmd.Start()
		log.Println("sshd exit", "err", err, "state", cmd.ProcessState)
	}()

}

func NewKeyPair(name string) (*ecdsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(name)
	if err != nil {
		keyb, err := gossh.ParseRawPrivateKey(key)
		if err == nil {
			return keyb.(*ecdsa.PrivateKey), nil
		}
	}

	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ecb, _ := x509.MarshalECPrivateKey(privk1)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	err = ioutil.WriteFile(name, keyPEM, 0700)
	if err != nil {
		return nil, err
	}

	casigner1, _ := gossh.NewSignerFromKey(privk1)
	pubString := string(gossh.MarshalAuthorizedKey(casigner1.PublicKey()))
	err = ioutil.WriteFile(name+".pub", []byte(pubString), 0700)
	if err != nil {
		return nil, err
	}

	return privk1, nil
}

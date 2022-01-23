package nativessh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strconv"

	gossh "golang.org/x/crypto/ssh"
)

// Helpers around sshd, using exec.

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
	Dir string
}

// StartSSHD will start sshd.
// If running as root, listens on port 22
// If started as user, listen on port 15022
func StartSSHD(cfg *SSHDConfig) {

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

	os.Mkdir("/run/sshd", 0700)

	NewKeyPair("/run/sshd/ssh_host_ecdsa_key")

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

	ioutil.WriteFile("/run/sshd/sshd_confing", []byte(SshdConfig), 0700)

	os.StartProcess("/usr/sbin/sshd",
		[]string{"-f", "/run/sshd/sshd_config",
			"-e",
			"-D",
			"-p", strconv.Itoa(cfg.Port),
		}, nil)

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
	err = ioutil.WriteFile(name + ".pub", []byte(pubString), 0700)
	if err != nil {
		return nil, err
	}

	return privk1, nil
}


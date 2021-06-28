module github.com/costinm/cert-ssh/ssh

go 1.16

//replace github.com/costinm/cert-ssh/sshca => ../sshca

require (
	github.com/costinm/cert-ssh/sshca v0.0.0-20210628220432-a23b998ca61c
	github.com/creack/pty v1.1.13
	github.com/pkg/sftp v1.13.1
	golang.org/x/crypto v0.0.0-20210503195802-e9a32991a82e
	google.golang.org/grpc v1.38.0
)

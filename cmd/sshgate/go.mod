module github.com/costinm/ssh-mesh/cmd/sshgate

replace github.com/costinm/ssh-mesh => ../../

go 1.17

replace github.com/costinm/krun => ../../../krun

require (
	github.com/costinm/krun v0.0.0-20211023180841-3b6ad9c083e8
	github.com/costinm/ssh-mesh v0.0.0-00010101000000-000000000000
)

require (
	cloud.google.com/go v0.84.0 // indirect
	github.com/creack/pty v1.1.13 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.1 // indirect
	golang.org/x/crypto v0.0.0-20210503195802-e9a32991a82e // indirect
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f // indirect
	golang.org/x/sys v0.0.0-20210603125802-9665404d3644 // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

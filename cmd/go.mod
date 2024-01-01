module github.com/costinm/ssh-mesh/cmd

go 1.21

replace github.com/costinm/ssh-mesh => ../

replace github.com/costinm/ssh-mesh/sshdebug => ../sshdebug

require (
	github.com/costinm/ssh-mesh v0.0.0-20230906012826-f773274052ff
	github.com/costinm/ssh-mesh/sshdebug v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.17.0
	golang.org/x/net v0.19.0
)

require (
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/creack/pty v1.1.21 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20231219180239-dc181d75b848 // indirect
	golang.org/x/oauth2 v0.15.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

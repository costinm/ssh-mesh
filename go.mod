module github.com/costinm/cert-ssh

go 1.16

require (
	go.opencensus.io v0.23.0
	contrib.go.opencensus.io/exporter/prometheus v0.4.0
	github.com/prometheus/client_golang v1.11.0

	github.com/creack/pty v1.1.13

	golang.org/x/crypto v0.0.0-20210503195802-e9a32991a82e
	github.com/pkg/sftp v1.13.1

	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
)

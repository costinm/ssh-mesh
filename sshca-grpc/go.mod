module github.com/costinm/ssh-mesh/sshca-grpc

go 1.17

replace github.com/costinm/ssh-mesh v0.0.0-20220112163338-6405dcdfe7e6 => ../

require (
	contrib.go.opencensus.io/exporter/prometheus v0.4.0
	github.com/costinm/cert-ssh/sshca v0.0.0-20211012002824-b2c496cfd468
	github.com/costinm/ssh-mesh v0.0.0-20220112163338-6405dcdfe7e6
	github.com/prometheus/client_golang v1.11.0
	go.opencensus.io v0.23.0
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	google.golang.org/grpc v1.43.0
	google.golang.org/protobuf v1.27.1
)

require (
	cloud.google.com/go v0.65.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/census-instrumentation/opencensus-proto v0.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4 // indirect
	github.com/cncf/xds/go v0.0.0-20211011173535-cb28da3451f1 // indirect
	github.com/creack/pty v1.1.13 // indirect
	github.com/envoyproxy/go-control-plane v0.9.10-0.20210907150352-cf90f659a021 // indirect
	github.com/envoyproxy/protoc-gen-validate v0.1.0 // indirect
	github.com/go-kit/log v0.1.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.28.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/genproto v0.0.0-20200825200019-8632dd797987 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

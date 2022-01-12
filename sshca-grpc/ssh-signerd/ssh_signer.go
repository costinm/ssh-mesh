package main

import (
	"log"
	"net"
	"net/http"
	"os"

	ssh "github.com/costinm/ssh-mesh/sshca"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/runmetrics"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/zpages"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/xds"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
)


func init() {
       if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
       if err := view.Register(ocgrpc.DefaultClientViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }

			 // Similar with pilot-agent
			 registry := prometheus.NewRegistry()
			 wrapped := prometheus.WrapRegistererWithPrefix("sshca_",
					prometheus.Registerer(registry))
			 wrapped.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
			 wrapped.MustRegister(collectors.NewGoCollector())

			//promRegistry = registry
			// go collector metrics collide with other metrics.
			exporter, err := ocprom.NewExporter(ocprom.Options{Registry: registry,
				Registerer: wrapped})
			if err != nil {
				log.Fatalf("could not setup exporter: %v", err)
			}
			view.RegisterExporter(exporter)

}

func main() {

	sshs := &ssh.SSHSigner{
	}

	err := sshs.Init()
	if err != nil {
		panic(err)
	}

	servicePort := ":8080"
	greeterLis, err := net.Listen("tcp", servicePort)
	if err != nil {
		log.Fatalf("net.Listen(tcp, %q) failed: %v", servicePort, err)
	}

	creds := insecure.NewCredentials()

	grpcOptions := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
	}
	// ocgrpc adds ~300k

	err = runmetrics.Enable(runmetrics.RunMetricOptions{
		EnableCPU:    true,
		EnableMemory: true,
		Prefix:       "sshca/",
	})
	if err != nil {
		log.Println(err)
	}

	// Adds about 10M to the binary. See ssh-signerd for the same gRPC service, without
	// xds.
	xdsBootstrap := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if xdsBootstrap != "" {
		var err error
		if creds, err = xdscreds.NewServerCredentials(xdscreds.ServerOptions{FallbackCreds: insecure.NewCredentials()}); err != nil {
			log.Fatalf("failed to create server-side xDS credentials: %v", err)
		}
		grpcServer := xds.NewGRPCServer(grpcOptions...)
		ssh.RegisterSSHCertificateServiceServer(grpcServer, sshs)
		admin.Register(grpcServer)
		//reflection.Register(grpcServer)
		go grpcServer.Serve(greeterLis)
	} else {
		grpcServer := grpc.NewServer(grpcOptions...)
		ssh.RegisterSSHCertificateServiceServer(grpcServer, sshs)
		admin.Register(grpcServer)
		reflection.Register(grpcServer)

		go func () {
			err := grpcServer.Serve(greeterLis)
			if err != nil {
				panic(err)
			}
		}()
	}

	// Status
	mux := &http.ServeMux{}
	zpages.Handle(mux, "/debug")

	log.Println("SSH signer started on ", servicePort)
	log.Println(sshs.Root)
	log.Println("@cert-authority * " + string(gossh.MarshalAuthorizedKey(sshs.Signer.PublicKey())))

	http.ListenAndServe("127.0.0.1:8081", mux)
}


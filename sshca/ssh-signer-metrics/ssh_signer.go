package main

import (
	"log"
	"net"
	"net/http"

	ssh "github.com/costinm/cert-ssh/sshca"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/zpages"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)


func init() {
       if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
       if err := view.Register(ocgrpc.DefaultClientViews...); err != nil {
               log.Println("Failed to register ocgrpc server views: %v", err)
       }
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

	grpcServer := grpc.NewServer(grpcOptions...)
	ssh.RegisterSSHCertificateServiceServer(grpcServer, sshs)
	// ~200k
	admin.Register(grpcServer)
	reflection.Register(grpcServer)

	go func () {
		err := grpcServer.Serve(greeterLis)
		if err != nil {
			panic(err)
		}
	}()

	// Status
	mux := &http.ServeMux{}

	// ~ 100k
	zpages.Handle(mux, "/debug")

	log.Println("SSH signer started on ", servicePort)
	log.Println(sshs.Root)
	log.Println("@cert-authority * " + string(gossh.MarshalAuthorizedKey(sshs.Signer.PublicKey())))

	http.ListenAndServe("127.0.0.1:8081", mux)
}


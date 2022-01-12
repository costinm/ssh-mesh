package main

import (
	"log"
	"net"
	"net/http"

	ssh "github.com/costinm/ssh-mesh/sshca"
	gossh "golang.org/x/crypto/ssh"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)


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
	}

	grpcServer := grpc.NewServer(grpcOptions...)
	ssh.RegisterSSHCertificateServiceServer(grpcServer, sshs)
	reflection.Register(grpcServer)

	go func () {
		err := grpcServer.Serve(greeterLis)
		if err != nil {
			panic(err)
		}
	}()

	// Status
	mux := &http.ServeMux{}
	//zpages.Handle(mux, "/debug")

	log.Println("SSH signer started on ", servicePort)
	log.Println(sshs.Root)
	log.Println("@cert-authority * " + string(gossh.MarshalAuthorizedKey(sshs.Signer.PublicKey())))

	http.ListenAndServe("127.0.0.1:8081", mux)
}


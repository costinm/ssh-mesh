package main

import (
	"log"
	"net"

	"github.com/costinm/ssh-mesh/sshca-grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	xdscreds "google.golang.org/grpc/credentials/xds"
	"google.golang.org/grpc/xds"

)

// Same as minimal, plus proxyless gRPC. No telemetry or any other extra plugin.
//
func main() {

	sshs := &sshca_grpc.SSHSigner{
	}

	err := sshs.Init()
	if err != nil {
		panic(err)
	}

	servicePort := ":8080"
	lis, err := net.Listen("tcp", servicePort)
	if err != nil {
		log.Fatalf("net.Listen(tcp, %q) failed: %v", servicePort, err)
	}

	// Replaces: creds := insecure.NewCredentials()
	creds, err := xdscreds.NewServerCredentials(xdscreds.ServerOptions{FallbackCreds: insecure.NewCredentials()})

	grpcOptions := []grpc.ServerOption{
		grpc.Creds(creds),
	}

	// Replaces: grpc.NewServer(grpcOptions...)
	grpcServer := xds.NewGRPCServer(grpcOptions...)

	sshca_grpc.RegisterSSHCertificateServiceServer(grpcServer, sshs)

	err = grpcServer.Serve(lis)
	if err != nil {
		// Will fail if GRPC_XDS_BOOTSTRAP is not set
		panic(err)
	}
}


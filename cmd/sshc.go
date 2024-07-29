package cmd

import (
	"context"
	"os"

	"github.com/costinm/meshauth"
	sshd "github.com/costinm/ssh-mesh"
)

func NewSSHC(ug *meshauth.Module) error {
	if ug.Address == "" {
		ug.Address = os.Getenv("SSHD")
	}
	if ug.Address == "" {
		return nil
	}

	sshdm := ug.Mesh.Module("sshd")
	if sshdm == nil {
		return nil
	}
	sshTransport := sshdm.Module.(*sshd.SSHMesh)
	// , err := sshd.NewSSHMesh(ug.Mesh)
	//if err != nil {
	//	return err
	//}
	sshc, err := sshTransport.Client(context.Background(), ug.Address)
	if err != nil {
		return err
	}
	go sshc.StayConnected(ug.Address)

	//ug.Mesh.Dst[ug.Address] = &meshauth.Dest{Proto: "ssh-upstream"}
	//sshTransport.StayConnected(context.Background())

	return nil
}

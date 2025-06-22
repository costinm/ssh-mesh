package h2

import (
	"context"
	"net/http"
	"testing"
)

func TestH2Base(t *testing.T) {
	ctx := context.Background()
	h2s := &H2{
		Server: http.Server {
			Addr: ":0",
		},
	}

	h2s.Provision(ctx)
	h2s.Start()

	h2c := &H2 {

	}
	h2c.Provision(ctx)
	// Not starting it - just a client transport.
	h2c.DialContext(ctx, "", h2s.NetListener.Addr().String())
}

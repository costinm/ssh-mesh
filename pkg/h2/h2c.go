package h2

import (
	"context"
	"net"
	"net/http"
)

// H2C is a per-client http transport.
//
// Can't do h2c using the std client - need custom code.
type H2C struct {
	http.Transport

	// client handles cookies, redirects
	//client *http.Client
}

func (h *H2C) Provision(ctx context.Context) error {

	//h.ReadIdleTimeout = 10000 * time.Second
	//h.StrictMaxConcurrentStreams = false
	h.Protocols = new(http.Protocols)
	h.Protocols.SetUnencryptedHTTP2(true)
	h.Protocols.SetHTTP1(true)
	h.Protocols.SetHTTP2(true)

	return nil
}



func (st *H2) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {

	hc := st.clients[addr]
	if hc == nil {

		hc = &H2C{}
		// TODO: use resource store to load config for this addr.
		// TODO: configure TCP and HTTP proxy for each client.
		hc.Provision(ctx)

		// TODO: remove unused clients
		st.clients[addr] = hc
	}

	return NewStreamH2(ctx, &hc.Transport, addr, "", st.TokenSource)
}

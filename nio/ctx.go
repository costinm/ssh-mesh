package nio

import (
	"context"
	"log/slog"
	"time"
)

// RequestContext is a context associated with a request (HTTP, connection).
// This may be derived from a MeshContext, or wrap a context created by a framework.
type RequestContext struct {
	Context context.Context
	Start time.Time

	Error error

	// Slog
	Logger *slog.Logger

	// Client is the client identity - usually from a JWT or header.
	Client string

	// Peer is the peer identity - usually from mTLS client cert.
	Peer   string
}

func (a *RequestContext) Deadline() (deadline time.Time, ok bool) {
	return a.Context.Deadline()
}

func (a *RequestContext) Done() <-chan struct{} {
	return a.Context.Done()
}

func (a *RequestContext) Err() error {
	return a.Context.Err()
}

// Value may return the AuthContext, if chained - or one of the fields.
// Otherwise, will pass to parent.
func (a *RequestContext) Value(key any) any {
	switch key {
	case "client": return a.Client
	}
	return a.Context.Value(key)
}


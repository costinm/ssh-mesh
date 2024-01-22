package util

import (
	"time"
)

// Stats holds telemetry for a stream or peer.
type Stats struct {
	Open time.Time

	// last receive from local (and send to remote)
	LastWrite time.Time

	// last receive from remote (and send to local)
	LastRead time.Time

	// Sent from client to server ( client is initiator of the proxy )
	SentBytes   int
	SentPackets int

	// Received from server to client
	RcvdBytes   int
	RcvdPackets int
}

// StreamState provides metadata around a stream.
//
// Stream is a net.Conn with metadata.
type StreamState struct {
	// Stream MuxID - odd for streams initiated from server (push and reverse)
	// Unique withing a mux connection.
	MuxID uint32

	// It is the key in the Active table.
	// Streams may also have local ids associated with the transport.
	StreamId string

	// WritErr indicates that Write failed - timeout or a RST closing the stream.
	WriteErr error `json:"-"`
	// ReadErr, if not nil, indicates that Read() failed - connection was closed with RST
	// or timedout instead of FIN
	ReadErr error `json:"-"`

	Stats

	// Original or infered destination.
	Dest string

	// Source - should be a FQDN hostname.
	Src string

	// Extracted source identity.
	SrcID []string
}

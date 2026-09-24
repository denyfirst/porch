package main

import (
	"strings"
	"testing"
)

// HTTP/2 stays off, and the reason it rests on is one that survives.
//
// The encryption is TLS's and is identical either way. What HTTP/2 adds is
// multiplexing, and what it adds with it is a stream state machine, flow
// control and HPACK — three mechanisms that have each produced denial-of-
// service classes, Rapid Reset among them. This service is four small files
// and one request, so the protocol would be attack surface bought with
// nothing.
//
// The note used to give a different reason: that tuning HTTP/2 needs
// golang.org/x/net/http2, which this project does not carry. That stopped
// being true — Go 1.26 has Server.Protocols and http.HTTP2Config — and a
// decision resting on a reason the toolchain can remove is a decision that
// quietly loses its ground. This test holds the decision; the note beside it
// holds the reason.
func TestTheServiceDoesNotSpeakHTTP2(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")

	// A non-nil but empty TLSNextProto is what stops http.Server enabling it
	// alongside TLS. Nil would enable it.
	if !strings.Contains(source, "TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},") {
		t.Error("the service no longer switches HTTP/2 off, or switches it off some other way")
	}

	// And nothing turns it back on by another door.
	// Written as code rather than as prose: the note beside the decision names
	// the x/net package as the reason that expired, and a test that read
	// comments would fire on the explanation for the thing it is checking.
	for _, unwanted := range []string{"Protocols:", "HTTP2:", `"golang.org/x/net/http2"`} {
		if strings.Contains(source, unwanted) {
			t.Errorf("the service configures %s, which enables a protocol it deliberately does not speak", unwanted)
		}
	}

	// The reason is written where the decision is, and is the one that
	// survives the toolchain gaining the feature.
	if !strings.Contains(source, "attack surface and nothing this service") {
		t.Error("the decision no longer says why, or says why in words this test cannot find")
	}
}

package smtptls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"
)

// serverHello is the first record of a server's answer choosing version and
// suite, with no extensions.
func serverHello(version, suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // no session id
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0) // no compression
	handshake := append([]byte{2, 0, 0, byte(len(body))}, body...)
	record := []byte{22, 3, 1, 0, byte(len(handshake))}
	return append(record, handshake...)
}

func probeLegacy(t *testing.T, p *Prober) Legacy {
	t.Helper()
	done := make(chan Legacy, 1)
	go func() { done <- p.ProbeLegacy(context.Background(), exchanger) }()
	select {
	case got := <-done:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("ProbeLegacy did not return; a conversation with one exchanger is bounded")
		return Legacy{}
	}
}

// A server that answers an old hello with an old version is said to accept
// it, and by name; nothing follows the hello.
func TestAnExchangerThatChoosesAnOldVersionIsSaidToAcceptIt(t *testing.T) {
	s := offering(nil)
	s.legacy = serverHello(tls.VersionTLS10, 0xC013)
	got := probeLegacy(t, pipeProber(s, nil))
	if !got.Asked || !got.Accepted || got.Version != "TLS 1.0" || got.Reason != "" {
		t.Errorf("read %+v", got)
	}
	heard := s.commands()
	if len(heard) != 2 || heard[1] != "STARTTLS" {
		t.Errorf("the server heard %q; after STARTTLS there is the hello and nothing else", heard)
	}

	// The hello offered nothing newer than TLS 1.1, on a TLS 1.0 record.
	s.mu.Lock()
	hello := s.hello
	s.mu.Unlock()
	if len(hello) < 11 || hello[0] != 22 || hello[1] != 3 || hello[2] != 1 || hello[9] != 3 || hello[10] != 2 {
		t.Errorf("the hello begins %x, and offers TLS 1.1 at most", hello[:min(len(hello), 11)])
	}
}

// A server that refuses, by alert or by choosing a version it was not
// offered, refuses; one that closes without a word has said nothing (R4).
func TestARefusalAndASilenceAreTwoAnswers(t *testing.T) {
	cert, roots := certificateFor(t, exchanger)
	// Go's own server, which has refused TLS 1.1 since Go 1.22, answers with
	// an alert.
	if got := probeLegacy(t, pipeProber(offering(cert), roots)); !got.Asked || !got.Refused || got.Accepted {
		t.Errorf("an alert reads %+v", got)
	}

	s := offering(nil)
	s.legacy = serverHello(tls.VersionTLS12, 0xC02F)
	if got := probeLegacy(t, pipeProber(s, nil)); !got.Refused || got.Accepted {
		t.Errorf("a version it was not offered reads %+v", got)
	}

	s = offering(nil)
	s.legacy = []byte{}
	if got := probeLegacy(t, pipeProber(s, nil)); !got.Asked || got.Refused || got.Accepted || got.Reason == "" {
		t.Errorf("a silent close reads %+v", got)
	}
}

// Nothing is asked where the conversation does not reach the point a hello
// belongs at, and the reason says where it stopped.
func TestTheOldVersionQuestionNeedsTheWholeOpening(t *testing.T) {
	plain := plainly()
	if got := probeLegacy(t, pipeProber(plain, nil)); got.Asked || got.Reason == "" {
		t.Errorf("an exchanger without STARTTLS reads %+v", got)
	}

	early := offering(nil)
	early.legacy = serverHello(tls.VersionTLS10, 0xC013)
	early.afterStarttls = "250 injected\r\n"
	if got := probeLegacy(t, pipeProber(early, nil)); got.Asked || got.Accepted || got.Reason == "" {
		t.Errorf("bytes before encryption read %+v", got)
	}
}

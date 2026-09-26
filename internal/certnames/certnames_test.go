package certnames

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// certificateFor makes a self-signed certificate carrying the names given.
//
// Self-signed on purpose: nothing here trusts what it reads, and the
// certificates worth finding with this are exactly the ones no public
// authority issued.
func certificateFor(t *testing.T, commonName string, names ...string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("making a key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("making a certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve answers TLS on a loopback address with the certificate given, and
// reports whether anything was sent over the connection after the handshake.
func serve(t *testing.T, cert tls.Certificate) (addr string, sent *atomic.Int64) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	sent = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()

				server := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				})
				if err := server.Handshake(); err != nil {
					return
				}
				_ = server.SetReadDeadline(time.Now().Add(time.Second))

				buf := make([]byte, 512)
				n, err := server.Read(buf)
				if n > 0 {
					sent.Add(int64(n))
				}
				if err != nil && !errors.Is(err, io.EOF) {
					// A deadline here is the expected outcome: the reader
					// closes without saying anything.
					return
				}
			}()
		}
	}()

	return ln.Addr().String(), sent
}

// readerTo sends every connection to one address, whatever host was asked for.
//
// The package refuses loopback of its own accord — safedial is what it uses
// when no dialler is given — and that refusal is the guard the product must
// keep, so it is replaced here and nowhere else.
func readerTo(addr string) *Reader {
	return &Reader{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}

// A host names itself, and the names under the domain are kept.
//
// This is the source that finds what a private authority issued: no public log
// holds such a certificate, because nothing submitted it and nothing would
// accept it, and the host hands it over in the first packet it sends back.
func TestTheNamesAHostPresents(t *testing.T) {
	cert := certificateFor(t, "www.example.test",
		"www.example.test",
		"api.example.test",
		"*.dev.example.test",
		"somebody-else.test",
		"notexample.test",
	)
	addr, _ := serve(t, cert)

	got := readerTo(addr).Under(context.Background(), "example.test", []string{"www.example.test"})

	if got.Reason != "" {
		t.Fatalf("the read failed: %s", got.Reason)
	}
	if got.Hosts != 1 || got.Answered != 1 {
		t.Errorf("%d hosts asked and %d answered", got.Hosts, got.Answered)
	}
	if len(got.Names) != 2 || got.Names[0] != "api.example.test" || got.Names[1] != "www.example.test" {
		t.Errorf("the names kept are %v", got.Names)
	}

	// A wildcard is kept apart, because nothing resolves one and a report that
	// put it in the list would have something to ask about it.
	if len(got.Wildcards) != 1 || got.Wildcards[0] != "*.dev.example.test" {
		t.Errorf("the wildcards kept are %v", got.Wildcards)
	}

	// And what belonged to somebody else is counted rather than listed. Two:
	// the other estate, and the name that ends with this domain as text.
	if got.Foreign != 2 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 2", got.Foreign)
	}
}

// A certificate nobody trusts is still read.
//
// It is the whole point. A certificate from a private authority fails
// verification here by construction, and its names are the ones no other
// source in this inventory can produce. The name it was asked under does not
// have to match either: a host presenting a certificate for something else is
// a finding rather than an error.
func TestACertificateNobodyTrustsIsStillRead(t *testing.T) {
	cert := certificateFor(t, "", "internal-billing.example.test")
	addr, _ := serve(t, cert)

	got := readerTo(addr).Under(context.Background(), "example.test", []string{"www.example.test"})

	if len(got.Names) != 1 || got.Names[0] != "internal-billing.example.test" {
		t.Errorf("an untrusted certificate was not read: %+v", got)
	}
}

// Nothing is sent over the connection after the handshake.
//
// The certificate arrives during it, so there is nothing left to ask for. A
// request here would make this a scan of every host in an estate rather than a
// reading of what each one says about itself, and the promise in the report
// would stop being true.
func TestNothingIsSentToAHostAfterTheHandshake(t *testing.T) {
	cert := certificateFor(t, "www.example.test", "www.example.test")
	addr, sent := serve(t, cert)

	got := readerTo(addr).Under(context.Background(), "example.test", []string{"www.example.test"})
	if len(got.Names) != 1 {
		t.Fatalf("the certificate was not read: %+v", got)
	}

	// The server reads with a deadline and the reader closes without saying
	// anything, so nothing arrives.
	time.Sleep(200 * time.Millisecond)
	if n := sent.Load(); n != 0 {
		t.Errorf("%d bytes were sent to the host after the handshake", n)
	}
}

// A host that does not answer is counted and nothing is invented for it.
//
// The difference between the hosts asked and the hosts that answered is the
// measure of how much this could not see, and an inventory that quietly
// reported only the ones that answered would be shorter than the estate with
// nothing saying so (R4).
func TestAHostThatDoesNotAnswerIsCountedAndNotInvented(t *testing.T) {
	cert := certificateFor(t, "www.example.test", "www.example.test")
	addr, _ := serve(t, cert)

	// A second address nothing is listening on, so one host answers and one
	// does not.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	r := &Reader{
		Timeout: 2 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			to := addr
			if address == net.JoinHostPort("silent.example.test", port) {
				to = deadAddr
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, to)
		},
	}

	got := r.Under(context.Background(), "example.test",
		[]string{"www.example.test", "silent.example.test"})

	if got.Hosts != 2 {
		t.Errorf("%d hosts were asked, want 2", got.Hosts)
	}
	if got.Answered != 1 {
		t.Errorf("%d hosts answered, want 1", got.Answered)
	}
	if len(got.Names) != 1 || got.Names[0] != "www.example.test" {
		t.Errorf("the names kept are %v", got.Names)
	}
}

// Asking no hosts is an answer, and it is not a failure.
//
// An estate where nothing answers has no certificates to read, and that is a
// fact about the estate rather than about this. Reporting it as a failure
// would put a red line under a report that is correct.
func TestAskingNoHostsIsNotAFailure(t *testing.T) {
	got := (&Reader{}).Under(context.Background(), "example.test", nil)

	if !got.Asked || got.Reason != "" {
		t.Errorf("asking no hosts came back as %+v", got)
	}
	if got.Hosts != 0 || got.Answered != 0 || len(got.Names) != 0 {
		t.Errorf("asking no hosts produced %+v", got)
	}
}

// A name is kept only on a label boundary, and a wildcard belongs to the
// domain behind its star.
func TestANameFromACertificateBelongsToTheEstateOnlyOnALabelBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"example.test", true},
		{"www.example.test", true},
		{"*.example.test", true},
		{"*.dev.example.test", true},
		{"notexample.test", false},
		{"example.test.evil.test", false},
		{"*.notexample.test", false},
	} {
		if got := under(tc.name, "example.test"); got != tc.want {
			t.Errorf("under(%q) is %v, want %v", tc.name, got, tc.want)
		}
	}
}

// What a host says is cleaned before it is kept.
//
// A certificate is chosen by whoever runs the host that presents it, which is
// not always the person reading the report.
func TestWhatAHostSaysIsCleanedBeforeItIsKept(t *testing.T) {
	if got := clean("api\x1b[31m.example.test"); got != "api[31m.example.test" {
		t.Errorf("a control character survived: %q", got)
	}
	if got := clean("  www.example.test  "); got != "www.example.test" {
		t.Errorf("a name was kept with its spaces: %q", got)
	}
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	if got := clean(string(long)); len(got) != 253 {
		t.Errorf("a name of %d characters was kept", len(got))
	}
}

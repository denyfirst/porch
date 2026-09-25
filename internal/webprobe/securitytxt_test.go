package webprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The one other address this check asks for is asked for, and only where the
// site answered.
//
// Two things are being held at once. The fetch has to happen, or the row in
// every report reads "none published" about sites that publish one — a fact
// about this program printed as a finding about somebody else (R4). And it has
// to not happen where nothing answered, because a host that refused two
// connections has nothing to say about its security contact either, and a
// third refused connection in its log buys no fact at all.
func TestTheSecurityFileIsAskedForOnceAndOnlyWhereTheSiteAnswered(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var askedOf string

	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/.well-known/security.txt" {
			askedOf = r.Host
		}
		mu.Unlock()

		// The site sends a visitor somewhere else, which is the ordinary case
		// and the one that decides whose file gets read.
		if r.URL.Path == "/" && strings.HasPrefix(r.Host, "example.com") {
			http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
			return
		}
		if r.URL.Path == "/.well-known/security.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Contact: mailto:security@example.test\nExpires: 2027-02-01T00:00:00Z\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	mu.Lock()
	asked := append([]string(nil), paths...)
	mu.Unlock()

	var times int
	for _, path := range asked {
		if path == "/.well-known/security.txt" {
			times++
		}
	}
	if times != 1 {
		t.Errorf("the file was asked for %d times, want once: %v", times, asked)
	}

	// And what came back reached the report, rather than being fetched and
	// dropped — which is a request made of somebody else's server for nothing.
	if got := report.SecurityTxt; !got.Asked || !got.Served || got.Contacts != 1 {
		t.Errorf("the file was read and the report carries %+v", got)
	}
	if got := report.SecurityTxt.Expires.Format("2006-01-02"); got != "2027-02-01" {
		t.Errorf("the expiry reached the report as %q", got)
	}

	if report.SecurityTxt.Reason != "" {
		t.Errorf("a file that was read gave a reason: %q", report.SecurityTxt.Reason)
	}

	// And it was asked of the host that was scanned, not of wherever the
	// redirect chain ended. RFC 9116 puts the file at the domain being asked
	// about; reading the file of the site a visitor is sent to and printing it
	// under the name that was typed would be reporting one party's contact as
	// another's — and on a shared host, somebody else's entirely.
	mu.Lock()
	of := askedOf
	mu.Unlock()
	if !strings.HasPrefix(of, "example.com") {
		t.Errorf("the file was asked of %q, and the host scanned was example.com", of)
	}
}

// A host nothing answers is not asked for its security contact as well.
//
// The other form of the name is still asked about, and deliberately: a bare
// name that answers nothing while its www form serves the site is exactly the
// arrangement worth reporting, and it cannot be found by giving up.
func TestNothingIsAskedOfAHostThatAnsweredNothing(t *testing.T) {
	var mu sync.Mutex
	var asked int

	// A listener that accepts and says nothing usable, so every chain ends
	// without a response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			asked++
			mu.Unlock()
			_ = c.Close()
		}
	}()

	p := &Prober{
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   10 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, ln.Addr().String())
		},
	}

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	if report.SecurityTxt.Asked {
		t.Error("a host that answered nothing was asked for its security contact as well")
	}

	mu.Lock()
	n := asked
	mu.Unlock()
	// Two chains and one more for the other form of the name, which is asked
	// about even here: a bare name that answers nothing while its www form
	// works is precisely the arrangement worth reporting. The dialler in this
	// test sends every name to the one listener, so the third connection counts
	// here although it is a connection to a different name.
	//
	// A fourth would be the security.txt fetch, which the assertion above says
	// was not made.
	if n > 3 {
		t.Errorf("%d connections were opened, want at most three: two chains and the other form of the name", n)
	}
}

// twoNameServer starts an HTTPS server whose certificate covers both a name
// and its www form, so that a redirect from one to the other completes.
//
// httptest issues for example.com alone, which makes every redirect to another
// name a failed handshake — and a chain that fails answers nothing, so the
// case this exists to test never arises. The certificate is its own authority
// and the pool holds only it, so nothing here depends on the machine's store.
func twoNameServer(t *testing.T, h http.HandlerFunc) (*Prober, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("making a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com", "www.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading back what was signed: %v", err)
	}

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	addr := srv.Listener.Addr().String()

	return &Prober{
		Roots:          pool,
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   20 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}, addr
}

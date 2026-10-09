package web

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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/mtasts"
)

const mailPolicyHost = "mta-sts.denyfirst.dev"

// The policy for mail to denyfirst.dev is one Porch's own mail check accepts,
// fetched the way a sending server fetches it: over TLS to mta-sts.<domain>,
// verified against a root, with redirects refused.
//
// A policy this project's own check called invalid would be the first thing
// a reader of our domain's report saw, and a sender would ignore it the same
// way. The fetch goes through the real handler chain, Hosts included, with
// the Host header a sender writes, port and all.
func TestOurMailPolicyIsOneOurOwnCheckAccepts(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the policy is the demonstration's domain's")
	}
	cert, roots := policyHostCertificate(t)
	srv := httptest.NewUnstartedServer(hostsHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	f := &mtasts.Fetcher{
		Roots: roots,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	p := f.Fetch(context.Background(), "denyfirst.dev")
	if !p.Fetched || p.Invalid != "" {
		t.Fatalf("our own check does not accept the policy: fetched=%v reason=%q invalid=%q", p.Fetched, p.Reason, p.Invalid)
	}
	if p.Mode != mtasts.Testing {
		t.Errorf("the policy's mode is %q; it moves to enforce on purpose, once the TLS reports are clean", p.Mode)
	}
	if p.MaxAge != 604800 {
		t.Errorf("the policy's max_age is %d, want one week while it is testing", p.MaxAge)
	}
	for _, mx := range []string{"aspmx1.migadu.com", "aspmx2.migadu.com"} {
		if !p.Covers(mx) {
			t.Errorf("the policy does not cover %s, one of the domain's exchangers", mx)
		}
	}
	if len(p.MX) != 2 {
		t.Errorf("the policy names %v; it should name the two exchangers and nothing else", p.MX)
	}
}

// The policy's name answers the policy and nothing else, and never redirects.
//
// It is a policy host, not another way into the site: the pages and the API
// are not served there, and a request for anything but the policy is refused
// rather than sent on, because RFC 8461 §3.3 forbids a sender to follow a
// redirect and a person has no reason to be there.
func TestThePolicyNameAnswersThePolicyAndNothingElse(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation has no policy name")
	}
	for _, host := range []string{mailPolicyHost, "MTA-STS.denyfirst.dev.", mailPolicyHost + ":443"} {
		w := getOn(t, http.MethodGet, host, mailPolicyPath)
		if w.Code != http.StatusOK || w.Body.String() != mailPolicy {
			t.Errorf("GET %s%s = %d %q, want the policy", host, mailPolicyPath, w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
			t.Errorf("the policy is served as %q; RFC 8461 §3.3 has senders check for text/plain", ct)
		}
	}

	w := getOn(t, http.MethodHead, mailPolicyHost, mailPolicyPath)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("HEAD on the policy = %d with %d bytes, want 200 and no body", w.Code, w.Body.Len())
	}
	w = getOn(t, http.MethodPost, mailPolicyHost, mailPolicyPath)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST on the policy = %d, Allow %q; want 405 naming GET and HEAD", w.Code, w.Header().Get("Allow"))
	}

	for _, target := range []string{"/", porchRoot, "/privacy", "/api/v1/scan", "/healthz", SecurityTxtPath, "/style.css", mailPolicyPath + "x", "/.well-known/"} {
		w := getOn(t, http.MethodGet, mailPolicyHost, target)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on the policy name = %d, want 404", target, w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("GET %s on the policy name redirects to %s; nothing there is sent anywhere", target, loc)
		}
		if strings.Contains(w.Body.String(), "api") || strings.Contains(w.Body.String(), "<html") {
			t.Errorf("GET %s on the policy name reached the site behind it", target)
		}
	}
}

// The policy is answered only at its own name. denyfirst.dev and
// porch.denyfirst.dev do not serve it, and neither does an installation,
// whose operator's mail is not ours to describe.
func TestThePolicyIsServedOnlyAtItsOwnName(t *testing.T) {
	hosts := []string{"192.0.2.1", "localhost"}
	if demo.Enabled {
		hosts = append(hosts, organisationHost, porchHost)
	}
	for _, host := range hosts {
		w := getOn(t, http.MethodGet, host, mailPolicyPath)
		if strings.Contains(w.Body.String(), "STSv1") {
			t.Errorf("%s answers %s with the policy; only %s should", host, mailPolicyPath, mailPolicyHost)
		}
	}
	if !demo.Enabled {
		w := getOn(t, http.MethodGet, mailPolicyHost, mailPolicyPath)
		if strings.Contains(w.Body.String(), "STSv1") {
			t.Error("an installation answers the demonstration's policy name with its policy")
		}
	}
}

// The policy is written as RFC 8461 §3.2 writes it: one key and value per
// line, each line ended by CRLF, the version first.
func TestThePolicyIsWrittenAsTheRFCWritesIt(t *testing.T) {
	if !strings.HasPrefix(mailPolicy, "version: STSv1\r\n") {
		t.Error("the policy does not open with its version")
	}
	if !strings.HasSuffix(mailPolicy, "\r\n") {
		t.Error("the policy's last line is not ended")
	}
	lines := strings.Split(strings.TrimSuffix(mailPolicy, "\r\n"), "\r\n")
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\n") || !strings.Contains(line, ": ") {
			t.Errorf("policy line %q is not one key and value", line)
		}
	}
	if !slices.Contains(lines, "mode: testing") && !slices.Contains(lines, "mode: enforce") {
		t.Error("the policy's mode is neither testing nor enforce")
	}
}

// policyHostCertificate makes a self-signed certificate for the policy's name
// and a pool that trusts it, so the fetch is verified as a sender's would be.
func policyHostCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: mailPolicyHost},
		DNSNames:              []string{mailPolicyHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

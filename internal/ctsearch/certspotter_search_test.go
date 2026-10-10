package ctsearch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// logged makes a certificate as a log would hold it: with the serial and dates
// given, and, for a precertificate, the poison extension a certificate never
// carries.
func logged(t *testing.T, serial int64, notBefore time.Time, precert bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(90 * 24 * time.Hour),
	}
	if precert {
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
			Critical: true,
			Value:    []byte{0x05, 0x00},
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// The search for one name asks for that name only, and for the certificates
// themselves, because the comparison a report makes needs their serials.
//
// Asked with subdomains, a report about example.com would count the
// certificates of every host under it as certificates for this name that the
// server did not present — on a domain with a dozen hosts, a dozen alarms
// about nothing.
func TestTheSearchForOneNameAsksForThatNameAndItsCertificates(t *testing.T) {
	var q map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			q = r.URL.Query()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).Search(context.Background(), "Example.COM.")

	if got.Reason != "" {
		t.Fatalf("an empty answer failed: %s", got.Reason)
	}
	if d := q["domain"]; len(d) != 1 || d[0] != "example.com" {
		t.Errorf("asked about %v", d)
	}
	if s := q["include_subdomains"]; len(s) != 1 || s[0] != "false" {
		t.Errorf("include_subdomains=%v; one name is one name", s)
	}
	want := map[string]bool{"cert_der": false, "issuer": false}
	for _, e := range q["expand"] {
		if _, ok := want[e]; ok {
			want[e] = true
		}
	}
	for e, asked := range want {
		if !asked {
			t.Errorf("the search did not expand %s", e)
		}
	}
	if got.Monitor != "Cert Spotter" {
		t.Errorf("the answer names its monitor as %q", got.Monitor)
	}
}

// Each certificate's serial is read from the certificate, and a
// precertificate and its certificate are one.
//
// The serial is what a report compares with the certificate the server
// presented. A precertificate shares it and hashes differently, so counting by
// hash would list every certificate twice, once as somebody else's.
func TestTheSerialComesFromTheCertificateAndAPrecertificateIsTheSame(t *testing.T) {
	older := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	answer := []certSpotterEntry{
		{ID: "1", SHA256: "aa", DNSNames: []string{"example.com"}, CertDER: logged(t, 0x06fe4d40, older, true),
			Issuer: &certSpotterIssuer{Name: "C=US, O=Let's Encrypt, CN=YE2"}},
		{ID: "2", SHA256: "bb", DNSNames: []string{"example.com"}, CertDER: logged(t, 0x06fe4d40, older, false)},
		{ID: "3", SHA256: "cc", DNSNames: []string{"example.com"}, CertDER: logged(t, 0x05d7e415, newer, false),
			Issuer: &certSpotterIssuer{Name: "C=US, O=Let's Encrypt, CN=YE1"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("after") != "" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).Search(context.Background(), "example.com")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	if got.Distinct != 2 || len(got.Entries) != 2 {
		t.Fatalf("%d certificates (%d listed), want 2: a precertificate counted on its own", got.Distinct, len(got.Entries))
	}
	// Newest first, as the other monitor answers.
	if got.Entries[0].Serial != "5d7e415" || got.Entries[1].Serial != "6fe4d40" {
		t.Errorf("serials %q, %q", got.Entries[0].Serial, got.Entries[1].Serial)
	}
	if got.Entries[0].Issuer != "C=US, O=Let's Encrypt, CN=YE1" {
		t.Errorf("the issuer reads %q", got.Entries[0].Issuer)
	}
	if !got.Entries[1].NotBefore.Equal(older) {
		t.Errorf("the older certificate begins %v", got.Entries[1].NotBefore)
	}
}

// A certificate the answer carries and this cannot read makes the answer no
// answer.
//
// Every entry it could not compare would be counted as a certificate valid
// today that the server did not present.
func TestAnAnswerWithACertificateThisCannotReadIsNoAnswer(t *testing.T) {
	for name, der := range map[string]string{
		"not base64":         "%%%",
		"not a certificate":  base64.StdEncoding.EncodeToString([]byte("hello")),
		"missing altogether": "",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Query().Get("after") != "" {
					_, _ = w.Write([]byte(`[]`))
					return
				}
				_ = json.NewEncoder(w).Encode([]certSpotterEntry{{ID: "1", SHA256: "aa", DNSNames: []string{"example.com"}, CertDER: der}})
			}))
			t.Cleanup(srv.Close)

			got := spotter(t, srv).Search(context.Background(), "example.com")
			if got.Reason == "" || len(got.Entries) != 0 || got.Distinct != 0 {
				t.Errorf("an unreadable certificate gave %+v", got)
			}
		})
	}
}

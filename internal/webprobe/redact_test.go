package webprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// What a redirect carries is followed, and not kept.
//
// A password reset or a sign-on redirect puts a token in the query string. The
// probe has to request it as sent, or the chain it reports is not the chain a
// visitor gets; the report must not carry it (audit A27).
func TestARedirectsTokenIsFollowedAndNotKept(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.RequestURI())
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/next?token=s3cr3t-value&next=%2Fhome&flag#frag-s3cr3t")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	chain := p.chain(context.Background(), p.client(), srv.URL+"/", anywhere())

	mu.Lock()
	followed := len(asked) == 2 && asked[1] == "/next?token=s3cr3t-value&next=%2Fhome&flag"
	mu.Unlock()
	if !followed {
		t.Errorf("the redirect was not followed as sent: %v", asked)
	}

	body, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "s3cr3t") {
		t.Errorf("the report carries the redirect's token: %s", body)
	}
	if len(chain.Hops) != 2 || !strings.HasSuffix(chain.Hops[1].URL, "/next?token=redacted&next=redacted&flag") {
		t.Errorf("the redacted address does not keep its shape: %+v", chain.Hops)
	}
	if got := chain.Hops[0].Headers["Location"]; len(got) != 1 || got[0] != "/next?token=redacted&next=redacted&flag" {
		t.Errorf("the recorded Location is %v", got)
	}
}

func TestRedactAddress(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/":                     "https://example.com/",
		"https://example.com/login":                "https://example.com/login",
		"https://user:pass@example.com/a?b=c#d":    "https://example.com/a?b=redacted",
		"/reset?token=abc":                         "/reset?token=redacted",
		"https://example.com/?a=1&a=2&empty=&bare": "https://example.com/?a=redacted&a=redacted&empty=redacted&bare",
		"https://example.com/?":                    "https://example.com/",
		"https://example.com:8443/x?%zz=1":         "https://example.com:8443/x?%zz=redacted",
		"http://[::1]:80/%zz?token=abc":            "http://[::1]:80/%zz",
		"http://u:p@[::1]:80/%zz?token=abc":        "http://[::1]:80/%zz",
		"u:p@host/%zz#x":                           "u:redacted",
		"mailto:someone@example.com":               "mailto:redacted",
		"https://example.com/p#only-a-fragment":    "https://example.com/p",
	} {
		if got := redactAddress(in); got != want {
			t.Errorf("redactAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// Which version of HTTP carried a response travels with the hop.
//
// The client already knew it — the transport settles it during the handshake —
// and nothing was reading it, so a report could not say whether a visitor is
// served over HTTP/2 or over a protocol from 1997. It is a fact and not a
// finding: this project's own service answers HTTP/1.1 on purpose, so a rule
// here would grade a deliberate choice as a fault.
func TestTheVersionOfHTTPThatCarriedTheResponseIsRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	chain := p.chain(context.Background(), p.client(), srv.URL+"/", anywhere())
	if len(chain.Hops) == 0 {
		t.Fatal("nothing answered")
	}
	// A test server without TLS speaks HTTP/1.1, and what matters here is that
	// whatever it spoke reached the hop rather than being dropped.
	if chain.Hops[0].Protocol != "HTTP/1.1" {
		t.Errorf("the hop records the protocol as %q", chain.Hops[0].Protocol)
	}
}

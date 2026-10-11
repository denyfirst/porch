package hstspreload

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func listing(t *testing.T, status int, body string) (*Client, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("domain"))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return &Client{
		Endpoint: srv.URL + "/api/v2/status",
		Roots:    pool,
		Timeout:  5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}, &asked
}

// The list's answer is read, and the entry that covers the host is named.
func TestTheListIsAskedAboutTheHost(t *testing.T) {
	c, asked := listing(t, http.StatusOK,
		`{"name":"www.example.test","status":"preloaded","bulk":true,"preloadedDomain":"example.test"}`)

	got := c.Status(context.Background(), "WWW.example.test.")
	if got.State != "preloaded" || got.PreloadedDomain != "example.test" || !got.Bulk || got.Reason != "" {
		t.Errorf("read %+v", got)
	}
	if len(*asked) != 1 || (*asked)[0] != "www.example.test" {
		t.Errorf("asked %v", *asked)
	}
}

// A covering entry that does not cover the host is not believed, and a state
// the service does not define is no answer.
func TestOnlyWhatTheServiceDefinesIsBelieved(t *testing.T) {
	c, _ := listing(t, http.StatusOK, `{"status":"preloaded","preloadedDomain":"notexample.test"}`)
	if got := c.Status(context.Background(), "example.test"); got.PreloadedDomain != "" {
		t.Errorf("another domain's entry was taken as this one's: %+v", got)
	}
	for name, body := range map[string]string{
		"an unknown state": `{"status":"probably"}`,
		"not json":         `<html>`,
		"too large":        strings.Repeat("x", maxAnswer+1),
	} {
		c, _ := listing(t, http.StatusOK, body)
		if got := c.Status(context.Background(), "example.test"); got.Reason == "" || got.State != "" {
			t.Errorf("%s: read %+v", name, got)
		}
	}
	c, _ = listing(t, http.StatusBadGateway, "")
	if got := c.Status(context.Background(), "example.test"); got.Reason == "" || got.State != "" {
		t.Errorf("a failed answer read %+v", got)
	}
}

// A redirect is not followed.
func TestARedirectIsNotFollowed(t *testing.T) {
	c, _ := listing(t, http.StatusFound, "")
	if got := c.Status(context.Background(), "example.test"); got.Reason == "" {
		t.Errorf("a redirect read %+v", got)
	}
}

// An answer is reused for an hour, and a failure is not kept.
func TestAnAnswerIsKeptForAnHour(t *testing.T) {
	c, asked := listing(t, http.StatusOK, `{"status":"unknown"}`)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }

	c.Status(context.Background(), "example.test")
	now = now.Add(59 * time.Minute)
	c.Status(context.Background(), "example.test")
	if len(*asked) != 1 {
		t.Errorf("asked %d times within the hour", len(*asked))
	}
	now = now.Add(2 * time.Minute)
	c.Status(context.Background(), "example.test")
	if len(*asked) != 2 {
		t.Errorf("asked %d times, and the answer was over an hour old", len(*asked))
	}

	failing, failed := listing(t, http.StatusBadGateway, "")
	failing.Status(context.Background(), "example.test")
	failing.Status(context.Background(), "example.test")
	if len(*failed) != 2 {
		t.Errorf("a failure was kept: asked %d times", len(*failed))
	}
}

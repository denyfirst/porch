package leaks

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// site serves the files given and answers everything else as many sites do:
// 200 with a page of its own.
func site(t *testing.T, files map[string]string) (*Prober, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("<!doctype html><html><body>Welcome. KEY=value\nOTHER=thing</body></html>"))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return &Prober{
		Roots:   pool,
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
	}, &asked
}

// A file is served only if it is that file: a site answering every path with
// its own page has nothing exposed, however many 200s it gives.
func TestASiteThatAnswersEverythingHasNothingExposed(t *testing.T) {
	p, asked := site(t, nil)
	got := p.Probe(context.Background(), "example.com")
	if got.Reason != "" || len(got.Exposed) != 0 || got.Paths != len(Files) || got.Unanswered != 0 {
		t.Errorf("read %+v", got)
	}
	if len(*asked) != len(Files) {
		t.Errorf("%d requests, want one per file", len(*asked))
	}
	for _, a := range *asked {
		if !strings.HasPrefix(a, "GET /") || strings.Contains(a, "?") {
			t.Errorf("asked %q", a)
		}
	}
}

// Each file is recognised by what it looks like, and what it held is not kept.
func TestEachFileIsRecognisedByWhatItIs(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	p, _ := site(t, map[string]string{
		"/.git/HEAD":     "ref: refs/heads/main\n",
		"/.env":          "DB_HOST=db\nDB_PASSWORD=" + secret + "\nexport API_KEY=x\n",
		"/.DS_Store":     "\x00\x00\x00\x01Bud1\x00\x00",
		"/.htpasswd":     "admin:$apr1$abcdefgh$0123456789abcdefghijk.\n",
		"/phpinfo.php":   "<html><title>phpinfo()</title>PHP Version 8.3</html>",
		"/server-status": "<h1>Apache Server Status for example.com</h1>",
	})
	got := p.Probe(context.Background(), "example.com")
	paths := map[string]Kind{}
	for _, e := range got.Exposed {
		paths[e.Path] = e.Kind
	}
	want := map[string]Kind{"/.git/HEAD": Source, "/.env": Secrets, "/.DS_Store": Listing,
		"/.htpasswd": Secrets, "/phpinfo.php": Diagnostics, "/server-status": Diagnostics}
	for path, kind := range want {
		if paths[path] != kind {
			t.Errorf("%s read as %q", path, paths[path])
		}
	}
	if len(got.Exposed) != len(want) {
		t.Errorf("%d exposed: %+v", len(got.Exposed), got.Exposed)
	}
	if strings.Contains(strings.Join(func() []string {
		var s []string
		for _, e := range got.Exposed {
			s = append(s, e.Path+e.What+string(e.Kind))
		}
		return s
	}(), " "), secret) {
		t.Error("what a file held reached the result")
	}
}

// Look-alikes are not the file.
func TestALookAlikeIsNotTheFile(t *testing.T) {
	p, _ := site(t, map[string]string{
		"/.git/HEAD": "<html>ref: refs/heads/main</html>",
		"/.env":      "<!DOCTYPE html>\nA=1\nB=2\n",
		"/.htpasswd": "this is not a password file",
		"/.DS_Store": "Bud1 but not at the start",
	})
	if got := p.Probe(context.Background(), "example.com"); len(got.Exposed) != 0 {
		t.Errorf("look-alikes read as files: %+v", got.Exposed)
	}
}

// A site that cannot be reached, or whose certificate does not verify, is
// said to be one, and is not a site with nothing exposed.
func TestASiteNotReachedIsNotASiteWithNothingExposed(t *testing.T) {
	p, _ := site(t, nil)
	p.Roots = x509.NewCertPool()
	if got := p.Probe(context.Background(), "example.com"); !strings.Contains(got.Reason, "certificate does not verify") {
		t.Errorf("an untrusted site read %+v", got)
	}
	gone := &Prober{Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, net.UnknownNetworkError("no network in tests")
	}}
	if got := gone.Probe(context.Background(), "example.com"); got.Reason == "" || len(got.Exposed) != 0 {
		t.Errorf("an unreachable site read %+v", got)
	}
}

// A path that got no answer is named, so a list of what was asked can say
// which went unanswered rather than calling them absent.
func TestAPathWithNoAnswerIsNamed(t *testing.T) {
	p, _ := site(t, nil)
	dial := p.Dial
	var mu sync.Mutex
	lost := false
	p.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		first := !lost
		lost = true
		mu.Unlock()
		if first {
			return nil, net.UnknownNetworkError("this one is lost on the way")
		}
		return dial(ctx, network, address)
	}
	got := p.Probe(context.Background(), "example.com")
	if got.Reason != "" || got.Unanswered != 1 || len(got.NoAnswer) != 1 {
		t.Fatalf("read %+v", got)
	}
	known := false
	for _, f := range Files {
		known = known || f.Path == got.NoAnswer[0]
	}
	if !known {
		t.Errorf("the unanswered path %q is not on the list", got.NoAnswer[0])
	}
}

// The list is the list, and every entry can recognise its file.
func TestTheListIsFixedAndEveryEntryRecognisesSomething(t *testing.T) {
	if len(Files) != 11 {
		t.Errorf("%d files; the list changes in the open, with this test", len(Files))
	}
	for _, f := range Files {
		if !strings.HasPrefix(f.Path, "/") || f.What == "" || f.Kind == "" || f.matches == nil {
			t.Errorf("entry %+v", f)
		}
		if f.matches([]byte("<!doctype html><html></html>")) {
			t.Errorf("%s matches an ordinary page", f.Path)
		}
	}
}

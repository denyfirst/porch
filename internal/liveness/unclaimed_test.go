package liveness

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// seen is one request the stand-in service received.
type seen struct{ host, path, agent string }

// service stands in for whatever a name's alias points at: every name in a
// case resolves to one public address, and its port 80 is this server.
func service(t *testing.T, answers map[string]dnsclient.ZoneAnswer, h http.HandlerFunc) (*Checker, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var asked []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, seen{r.Host, r.URL.Path, r.Header.Get("User-Agent")})
		mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	c := &Checker{
		Resolver: &stubResolver{answers: answers},
		Timeout:  2 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "93.184.216.40:80" {
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			}
			return nil, errors.New("refused")
		},
	}
	return c, func() []seen {
		mu.Lock()
		defer mu.Unlock()
		return append([]seen(nil), asked...)
	}
}

func alias(t *testing.T, chain ...string) dnsclient.ZoneAnswer {
	return dnsclient.ZoneAnswer{Addresses: addrs(t, "93.184.216.40"), Alias: chain, Existed: true}
}

// A name that is an alias to a service on the list, and that the service
// answers as it answers a name nobody has claimed, says so — and names the
// service, because that is where the operator goes next.
func TestANameTheServiceSaysNobodyClaimedIsSaid(t *testing.T) {
	c, asked := service(t, map[string]dnsclient.ZoneAnswer{
		"docs.example.test":   alias(t, "someone.github.io."),
		"assets.example.test": alias(t, "assets.example.test.s3.amazonaws.com.", "s3-1-w.amazonaws.com."),
	}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if strings.HasPrefix(r.Host, "docs.") {
			_, _ = w.Write([]byte("<html><h1>404</h1><p>There isn't a GitHub Pages site here.</p></html>"))
			return
		}
		_, _ = w.Write([]byte("<Error><Code>NoSuchBucket</Code></Error>"))
	})

	got := c.Check(context.Background(), []string{"docs.example.test", "assets.example.test"})
	for i, want := range []string{"GitHub Pages", "Amazon S3"} {
		if got[i].Status != Unclaimed || got[i].Provider != want {
			t.Errorf("%s reads as %+v, want unclaimed at %s", got[i].Name, got[i], want)
		}
	}

	// One GET of the root each, as the name, saying what asked.
	requests := asked()
	if len(requests) != 2 {
		t.Fatalf("%d requests were made, want one per name: %+v", len(requests), requests)
	}
	for _, r := range requests {
		if r.path != "/" || r.agent != UserAgent || !strings.HasSuffix(r.host, ".example.test") {
			t.Errorf("the request was %+v", r)
		}
	}
}

// Only the service's own answer counts, and only where it is the answer to a
// name nobody claimed: a 404. A page quoting the sentence, a redirect, or the
// sentence past what is read is a site that is there.
func TestOnlyTheServicesOwnAnswerCounts(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter, r *http.Request)
	}{
		{"a page quoting it", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("Our post about There isn't a GitHub Pages site here."))
		}},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/There isn't a GitHub Pages site here.", http.StatusMovedPermanently)
		}},
		{"a 404 of its own", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not here"))
		}},
		{"past what is read", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(strings.Repeat(" ", maxUnclaimedBody) + "There isn't a GitHub Pages site here."))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			checker, asked := service(t, map[string]dnsclient.ZoneAnswer{
				"docs.example.test": alias(t, "someone.github.io."),
			}, c.answer)
			got := checker.Check(context.Background(), []string{"docs.example.test"})
			if got[0].Status != Live || got[0].Provider != "" {
				t.Errorf("read as %+v, want live", got[0])
			}
			if n := len(asked()); n != 1 {
				t.Errorf("%d requests, want one and nothing followed", n)
			}
		})
	}
}

// Nothing is asked of a name that is not an alias to a service on the list.
// The connection already says it is live; a request would buy no fact.
func TestNoRequestIsMadeOfANameOffTheList(t *testing.T) {
	c, asked := service(t, map[string]dnsclient.ZoneAnswer{
		"plain.example.test": {Addresses: addrs(t, "93.184.216.40"), Existed: true},
		"other.example.test": alias(t, "somewhere.example.net."),
		"near.example.test":  alias(t, "github.io.example.net."),
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here. NoSuchBucket"))
	})

	for _, n := range c.Check(context.Background(), []string{"plain.example.test", "other.example.test", "near.example.test"}) {
		if n.Status != Live {
			t.Errorf("%s reads as %+v", n.Name, n)
		}
	}
	if r := asked(); len(r) != 0 {
		t.Errorf("names off the list were asked: %+v", r)
	}
}

// Which names are a service's, by the names it hands out.
func TestWhichAliasesAreAServicesOwn(t *testing.T) {
	for alias, want := range map[string]string{
		"someone.github.io":                         "GitHub Pages",
		"github.io":                                 "",
		"someone.github.io.example.net":             "",
		"bucket.s3.amazonaws.com":                   "Amazon S3",
		"www.example.com.s3.amazonaws.com":          "Amazon S3",
		"bucket.s3-website-us-east-1.amazonaws.com": "Amazon S3",
		"bucket.s3.eu-west-1.amazonaws.com":         "Amazon S3",
		"s3.amazonaws.com":                          "",
		"evil-s3.amazonaws.com":                     "",
		"ec2-1-2-3-4.compute-1.amazonaws.com":       "",
		"bucket.s3.amazonaws.com.example.net":       "",
		"site.pantheonsite.io":                      "Pantheon",
		"site.surge.sh":                             "Surge",
	} {
		got := ""
		if p := providerOf([]string{alias + "."}); p != nil {
			got = p.name
		}
		if got != want {
			t.Errorf("%s reads as %q, want %q", alias, got, want)
		}
	}
}

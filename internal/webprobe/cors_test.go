package webprobe

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The question is put to the page a visitor lands on, once, and differs from
// the first request by the Origin header and nothing else.
//
// The page rather than the root, because a root that redirects carries no
// content and the rules read the page it sends people to. Once, because a
// server that copies the origin it is sent copies any, and a second guess
// would be searching for a weakness rather than measuring a configuration.
func TestTheSecondRequestGoesToTheLandingPageWithOnlyTheOriginAdded(t *testing.T) {
	type seen struct{ path, origin, agent string }
	var mu sync.Mutex
	var asked []seen

	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "example.com") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		asked = append(asked, seen{r.URL.Path, r.Header.Get("Origin"), r.Header.Get("User-Agent")})
		mu.Unlock()
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/home?x=1", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}
	if !report.CORS.Asked || !report.CORS.Answered || report.CORS.Origin != CORSOrigin {
		t.Fatalf("the question was recorded as %+v", report.CORS)
	}

	mu.Lock()
	defer mu.Unlock()
	var withOrigin []seen
	for _, a := range asked {
		if a.origin != "" {
			withOrigin = append(withOrigin, a)
		}
	}
	if len(withOrigin) != 1 {
		t.Fatalf("%d requests carried an Origin, want one: %+v", len(withOrigin), asked)
	}
	got := withOrigin[0]
	if got.path != "/home" {
		t.Errorf("the question went to %q, not to the page the chain landed on", got.path)
	}
	if got.origin != CORSOrigin {
		t.Errorf("the question said it came from %q", got.origin)
	}
	if got.agent != p.userAgent() {
		t.Errorf("the question went out as %q rather than as the scan says it does", got.agent)
	}
}

// What a browser would do with the answer, header by header.
//
// Exact, as Fetch compares them: a repeated header is joined into text that
// matches nothing, and "True" is not "true". A report that read these more
// generously than a browser does would describe a site sharing something no
// browser shares.
func TestThePageIsReadAsABrowserReadsIt(t *testing.T) {
	copyOrigin := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	}
	for _, c := range []struct {
		name        string
		answer      func(w http.ResponseWriter, r *http.Request)
		reflected   bool
		credentials bool
	}{
		{"copies it with credentials", func(w http.ResponseWriter, r *http.Request) {
			copyOrigin(w, r)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}, true, true},
		{"copies it without credentials", copyOrigin, true, false},
		{"says nothing", func(http.ResponseWriter, *http.Request) {}, false, false},
		{"shares with everybody", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}, false, true},
		{"names a partner", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://partner.example")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}, false, true},
		{"repeats the header", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Add("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}, false, true},
		{"capitalises true", func(w http.ResponseWriter, r *http.Request) {
			copyOrigin(w, r)
			w.Header().Set("Access-Control-Allow-Credentials", "True")
		}, true, false},
		{"capitalises the origin", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://PORCH-CORS-CHECK.invalid")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}, false, true},
		{"pads the value", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", " "+r.Header.Get("Origin")+"\t")
			w.Header().Set("Access-Control-Allow-Credentials", " true ")
		}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Origin") != "" {
					c.answer(w, r)
				}
				w.WriteHeader(http.StatusOK)
			})
			report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
			if err != nil {
				t.Fatalf("probing: %v", err)
			}
			got := report.CORS
			if !got.Answered || got.Reflected != c.reflected || got.Credentials != c.credentials {
				t.Errorf("read as %+v, want reflected %v and credentials %v", got, c.reflected, c.credentials)
			}
		})
	}
}

// No page reached over TLS, no question: there is nothing to ask it of, and a
// report that said "not named back" here would be describing a page nobody
// spoke to (R4).
func TestNoPageReachedOverTLSIsNotAskedWhomItTrusts(t *testing.T) {
	p := local()
	for _, c := range []*Chain{
		nil,
		{},
		{Hops: []Hop{{TLS: true, Err: "the connection was refused", target: "https://example.com/"}}},
		{Hops: []Hop{{TLS: false, Status: 200, target: "http://example.com/"}}},
	} {
		if got := p.cors(context.Background(), p.client(), c); got.Asked {
			t.Errorf("a chain with no page over TLS was asked: %+v", got)
		}
	}
}

// With no time left the question is not put, and the answer says it was the
// scan's clock rather than the site.
//
// Asked directly rather than through Probe, because a budget spent before the
// chains leaves no page to ask about at all; the case this is for is the one
// where the chains spent it.
func TestTheQuestionSaysTheScanRanOutRatherThanThatThePageWouldNotAnswer(t *testing.T) {
	var mu sync.Mutex
	var origins int

	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			mu.Lock()
			origins++
			mu.Unlock()
			// Held until the request gives up, so the deadline passes while
			// the question is in flight.
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	client := p.clientWith(p.Roots)
	chain := p.chain(context.Background(), client, "https://example.com/", anywhere())

	spent, cancel := context.WithCancel(context.Background())
	cancel()
	if got := p.cors(spent, client, chain); got.Reason != outOfTime || got.Answered {
		t.Errorf("with no time left the question read as %+v", got)
	}
	mu.Lock()
	if origins != 0 {
		t.Errorf("the question was put %d times with no time left", origins)
	}
	mu.Unlock()

	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := p.cors(short, client, chain); got.Reason != outOfTime {
		t.Errorf("a deadline passing mid-question read as %+v, which blames the page", got)
	}

	// And the other way round: a page slower than one request may be, with
	// the scan's own time to spare, is the page's answer and not the clock's.
	p.RequestTimeout = 200 * time.Millisecond
	if got := p.cors(context.Background(), client, chain); got.Reason != notAnsweredAgain {
		t.Errorf("a page that did not answer in time read as %+v, which blames the scan", got)
	}
}

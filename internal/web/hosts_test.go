package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

const (
	organisationHost = "denyfirst.dev"
	porchHost        = "porch.denyfirst.dev"
)

// porchLink is how the layout writes a link to one of Porch's pages: with
// Porch's address in front on the demonstration, where Porch has a name of
// its own, and bare on an installation, where every page is its own.
func porchLink(path string) string {
	if demo.Enabled {
		return PorchURL + path
	}
	return path
}

// hostsHandler is what porchd serves: an API beside the pages, both behind
// Hosts. The API is a stand-in that says it was reached, so a test can tell
// an answered call from a redirected one.
func hostsHandler() http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api"))
	})
	root.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	root.Handle("/", Handler())
	return Hosts(root)
}

func getOn(t *testing.T, method, host, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	hostsHandler().ServeHTTP(w, r)
	return w
}

// The organisation and Porch each answer at their own name, and each sends
// what is the other's there.
//
// Since 2026-10-05 the demonstration is two names on one binary: denyfirst.dev
// is the organisation's front page, its undertakings and its contacts, and
// porch.denyfirst.dev is Porch, API included. Every address that worked before
// still works — the other name answers it with a permanent redirect — because
// reports, notices and user agents already printed carry the old ones.
func TestTheOrganisationAndPorchEachAnswerAtTheirOwnName(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation is one name, its operator's")
	}
	for _, tc := range []struct {
		method, host, target string
		status               int
		location             string // empty: answered here
	}{
		// The organisation's own.
		{"GET", organisationHost, "/", 200, ""},
		{"GET", organisationHost, "/organisation", 200, ""},
		{"GET", organisationHost, SecurityTxtPath, 200, ""},
		{"GET", organisationHost, PGPKeyPath, 200, ""},
		{"GET", organisationHost, "/style.css", 200, ""},
		// The machine's health, which a deploy check asks either name for.
		{"GET", organisationHost, "/healthz", 200, ""},
		{"GET", porchHost, "/healthz", 200, ""},

		// Porch's, asked of the organisation, keeping path and query.
		{"GET", organisationHost, "/tls", 301, PorchURL + "/tls"},
		{"GET", organisationHost, "/tls/method?from=report", 301, PorchURL + "/tls/method?from=report"},
		{"HEAD", organisationHost, "/privacy", 301, PorchURL + "/privacy"},
		{"GET", organisationHost, "/porch", 301, PorchURL + "/"},
		{"GET", organisationHost, "/no-such-page", 301, PorchURL + "/no-such-page"},
		// A call to the API keeps its method and body.
		{"POST", organisationHost, "/api/v1/scan", 308, PorchURL + "/api/v1/scan"},

		// Porch's own.
		{"GET", porchHost, "/tls", 200, ""},
		{"GET", porchHost, "/privacy", 200, ""},
		{"GET", porchHost, "/style.css", 200, ""},
		{"POST", porchHost, "/api/v1/scan", 200, ""},

		// The organisation's, asked of Porch.
		{"GET", porchHost, "/organisation", 301, SiteURL + "/organisation"},
		{"GET", porchHost, SecurityTxtPath, 301, SiteURL + SecurityTxtPath},
		{"GET", porchHost, PGPKeyPath, 301, SiteURL + PGPKeyPath},
		{"GET", porchHost, "/porch", 301, PorchURL + "/"},

		// A name is a name however a browser writes it.
		{"GET", "PORCH.denyfirst.dev.", "/organisation", 301, SiteURL + "/organisation"},
		{"GET", "denyfirst.dev:443", "/tls", 301, PorchURL + "/tls"},
	} {
		w := getOn(t, tc.method, tc.host, tc.target)
		where := tc.method + " " + tc.host + tc.target
		if w.Code != tc.status {
			t.Errorf("%s: %d, want %d", where, w.Code, tc.status)
		}
		if got := w.Header().Get("Location"); got != tc.location {
			t.Errorf("%s: sent to %q, want %q", where, got, tc.location)
		}
	}

	// And Porch's name opens on Porch.
	front := getOn(t, "GET", porchHost, "/").Body.String()
	if !strings.Contains(front, `<title>`+pages[porchRoot].Title+`</title>`) {
		t.Error("porch.denyfirst.dev/ is not Porch's page")
	}
	if !strings.Contains(getOn(t, "GET", organisationHost, "/").Body.String(), `<title>`+pages["/"].Title+`</title>`) {
		t.Error("denyfirst.dev/ is not the organisation's front page")
	}
}

// A redirect cannot be steered off this site.
//
// The target is one of two fixed addresses with the request's path after it,
// so a path that looks like another host is a path on Porch's, and nothing a
// request carries becomes a header line.
func TestTheRedirectsStayOnThisSite(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation redirects nothing between names")
	}
	for _, target := range []string{
		"//evil.example/x",
		"/%2F%2Fevil.example",
		"/x?next=https://evil.example",
		"/%0d%0aSet-Cookie:%20a=b",
	} {
		w := getOn(t, "GET", organisationHost, target)
		location := w.Header().Get("Location")
		if !strings.HasPrefix(location, PorchURL+"/") {
			t.Errorf("GET %s: sent to %q, which is not on %s", target, location, PorchURL)
		}
		if strings.ContainsAny(location, "\r\n") || w.Header().Get("Set-Cookie") != "" {
			t.Errorf("GET %s: a header line was written from the path: %q", target, location)
		}
	}
}

// Any other name, or an address, is served everything, as one name was
// before the split, and so is every name on an installation.
func TestAnyOtherNameIsServedEverything(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8080", "localhost", "scan.example.com"} {
		for _, path := range []string{"/", "/tls", "/privacy", "/style.css"} {
			if w := getOn(t, "GET", host, path); w.Code != http.StatusOK {
				t.Errorf("GET %s%s: %d, want 200", host, path, w.Code)
			}
		}
	}
	if !demo.Enabled {
		for _, host := range []string{organisationHost, porchHost} {
			if w := getOn(t, "GET", host, "/tls"); w.Code != http.StatusOK {
				t.Errorf("an installation reached as %s redirected /tls: %d", host, w.Code)
			}
		}
	}
}

// Every page has one home, and the address it states as its own is that
// home and answers without a redirect.
func TestEveryPageIsAnsweredAtTheAddressItStates(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation states no address")
	}
	for path := range pages {
		canonical := canonicalURL(path)
		host, target, _ := strings.Cut(strings.TrimPrefix(canonical, "https://"), "/")
		w := getOn(t, "GET", host, "/"+target)
		if w.Code != http.StatusOK {
			t.Errorf("%s states %s, which answers %d", path, canonical, w.Code)
		}
	}
}

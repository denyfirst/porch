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
	mailPolicyHost   = "mta-sts.denyfirst.dev"
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

// Porch answers at its own name, and the organisation's names are not
// answered here at all.
//
// From 2026-10-05 the demonstration was three names on one binary, each
// sending what was the other's there with a permanent redirect. Since v0.37.0
// denyfirst.dev and mta-sts.denyfirst.dev are denyfirst/site's, at an address
// of their own. A request for either that still reaches this program is told
// 421, Misdirected Request, rather than redirected: a client holding this
// address for that name would follow a redirect back here. The contacts
// Porch's name served until then lead to denyfirst.dev, because reports and
// pages already printed carry those addresses.
func TestPorchAnswersAtItsOwnNameAndNotAtTheOrganisations(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation is one name, its operator's")
	}
	for _, tc := range []struct {
		method, host, target string
		status               int
		location             string // empty: answered here
	}{
		// Porch's own.
		{"GET", porchHost, "/", 200, ""},
		{"GET", porchHost, "/tls", 200, ""},
		{"GET", porchHost, "/privacy", 200, ""},
		{"GET", porchHost, "/undertakings", 301, "/privacy#promises"},
		{"GET", porchHost, "/style.css", 200, ""},
		{"GET", porchHost, "/healthz", 200, ""},
		{"POST", porchHost, "/api/v1/scan", 200, ""},
		{"GET", porchHost, "/porch", 301, "/"},

		// The organisation's contacts, at the addresses Porch's name served
		// them at, lead to denyfirst.dev.
		{"GET", porchHost, SecurityTxtPath, 301, SiteURL + SecurityTxtPath},
		{"GET", porchHost, "/security.txt", 301, SiteURL + SecurityTxtPath},
		{"GET", porchHost, PGPKeyPath, 301, SiteURL + PGPKeyPath},
		// And the organisation's pages are not here under any address.
		{"GET", porchHost, "/organisation", 404, ""},
		{"GET", porchHost, "/og-denyfirst.png", 404, ""},
		{"GET", porchHost, "/icon-denyfirst.svg", 404, ""},

		// The organisation's names, whatever is asked of them.
		{"GET", organisationHost, "/", 421, ""},
		{"GET", organisationHost, "/tls", 421, ""},
		{"GET", organisationHost, SecurityTxtPath, 421, ""},
		{"GET", organisationHost, "/healthz", 421, ""},
		{"POST", organisationHost, "/api/v1/scan", 421, ""},
		{"GET", mailPolicyHost, "/.well-known/mta-sts.txt", 421, ""},

		// A name is a name however a browser writes it.
		{"GET", "PORCH.denyfirst.dev.", "/tls", 200, ""},
		{"GET", "DenyFirst.dev.", "/", 421, ""},
		{"GET", "denyfirst.dev:443", "/tls", 421, ""},
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
	if !strings.Contains(front, `<title>`+pages["/"].Title+`</title>`) || !strings.Contains(front, `id="porch-form"`) {
		t.Error("porch.denyfirst.dev/ is not Porch's page")
	}
}

// A request for one of the organisation's names is refused without sending
// the visitor anywhere and without repeating anything it carried: the path is
// the request's, and nothing of it becomes a header line or a word on the
// page (I3).
func TestTheOrganisationsNamesAreRefusedWithoutAnEcho(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation refuses no name here")
	}
	for _, target := range []string{
		"//evil.example/x",
		"/%2F%2Fevil.example",
		"/x?next=https://evil.example",
		"/%0d%0aSet-Cookie:%20a=b",
		"/<script>alert(1)</script>",
	} {
		w := getOn(t, "GET", organisationHost, target)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("GET %s: %d, want 421", target, w.Code)
		}
		if w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
			t.Errorf("GET %s: a header was written from the request: %v", target, w.Header())
		}
		if body := w.Body.String(); strings.Contains(body, "evil") || strings.Contains(body, "script") || strings.Contains(body, "Set-Cookie") {
			t.Errorf("GET %s: the refusal repeats the request: %q", target, body)
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

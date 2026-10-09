package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/denyfirst/porch/internal/demo"
)

// The demonstration answers to two names since 2026-10-05.
//
// denyfirst.dev is the organisation: its front page, its undertakings, and the
// contacts RFC 9116 points at. porch.denyfirst.dev is Porch: its page, its
// checks, its documents and its API. Before, one name carried both, and a
// second product would have had to live under the first one's address or move
// it. A name each also means a browser keeps their pages apart — a fault in one
// product's script cannot read the other's — and that the address a report is
// shared at says which tool wrote it.
//
// One binary still serves both, so moving costs nobody a link: every address
// that belongs to the other name answers with a permanent redirect to the same
// path there. An installation somebody runs is one name, its operator's, and
// none of this applies to it.
//
// A third name, mta-sts.denyfirst.dev, answers one file and nothing else: the
// policy for mail to denyfirst.dev. See mailpolicy.go.

// organisationPaths are what denyfirst.dev serves itself. Everything else on
// it is Porch's, and redirected.
var organisationPaths = map[string]bool{
	"/":             true,
	"/privacy":      true,
	SecurityTxtPath: true,
	"/security.txt": true,
	PGPKeyPath:      true,
	"/robots.txt":   true,
	"/sitemap.xml":  true,
}

// sharedPaths are on both names, each with its own: the front page, the
// privacy page and the crawler files.
var sharedPaths = map[string]bool{"/": true, "/privacy": true, "/robots.txt": true, "/sitemap.xml": true}

// organisationIcons are the icon addresses a browser asks of every name,
// answered at denyfirst.dev with the organisation's mark rather than Porch's.
var organisationIcons = map[string]string{
	"/favicon.ico":          "/denyfirst.ico",
	"/apple-touch-icon.png": "/denyfirst-touch.png",
}

// orgPrivacy is the page denyfirst.dev serves at /privacy. Its key in the
// table is not /privacy, which is Porch's privacy page.
const orgPrivacy = "/organisation"

// porchRoot is the page porch.denyfirst.dev serves at "/". It is served at
// /porch where one name carries everything — a test, or the demonstration
// reached by its address — and /porch on porch.denyfirst.dev redirects to "/".
const porchRoot = "/porch"

// site is which of the demonstration's names a request was addressed to.
type site int

const (
	// either is any other name or an address: a test, a local run, a
	// connection made to the IP. It is served everything, as one name was
	// until the split, because there is no other address to send it to that
	// it asked for.
	either site = iota
	organisationSite
	porchSite
	mailPolicySite
)

// siteOf reads the Host header the way a browser writes it: any case, an
// optional port, an optional trailing dot.
func siteOf(host string) site {
	if !demo.Enabled {
		return either
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch host {
	case strings.TrimPrefix(SiteURL, "https://"):
		return organisationSite
	case strings.TrimPrefix(PorchURL, "https://"):
		return porchSite
	case "mta-sts." + strings.TrimPrefix(SiteURL, "https://"):
		return mailPolicySite
	}
	return either
}

// canonicalURL is the one address a page states as its own.
func canonicalURL(path string) string {
	switch path {
	case "/":
		return SiteURL + "/"
	case orgPrivacy:
		return SiteURL + "/privacy"
	case porchRoot:
		return PorchURL + "/"
	}
	return PorchURL + path
}

// Hosts sends a request addressed to the wrong one of the demonstration's
// names to the right one, and passes everything else to next. It goes in
// front of the API as well as the pages, so that nothing of Porch's is
// answered from the organisation's name.
//
// The target is always one of two constant addresses with the request's own
// path after it, so it cannot be steered off this site: a path of
// "//elsewhere.example" becomes a path on porch.denyfirst.dev. GET and HEAD
// are answered with 301, which every client and search engine understands;
// anything else with 308, which keeps the method and the body, so a POST to
// the old address is not silently turned into a GET.
//
// On an installation it is next, unchanged.
func Hosts(next http.Handler) http.Handler {
	if !demo.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch siteOf(r.Host) {
		case mailPolicySite:
			// Answered here and never passed on: the API and the pages are
			// not served at this name, so a sender fetching the policy gets
			// the policy and anybody else gets nothing.
			serveMailPolicy(w, r)
			return
		case organisationSite:
			if path == orgPrivacy {
				elsewhere(w, r, SiteURL, "/privacy")
				return
			}
			if !organisationPaths[path] && !isAsset(path) {
				if path == porchRoot {
					path = "/"
				}
				elsewhere(w, r, PorchURL, path)
				return
			}
		case porchSite:
			if path == porchRoot {
				elsewhere(w, r, PorchURL, "/")
				return
			}
			if path == orgPrivacy {
				elsewhere(w, r, SiteURL, "/privacy")
				return
			}
			if organisationPaths[path] && !sharedPaths[path] {
				elsewhere(w, r, SiteURL, path)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isAsset is a stylesheet, script or icon, which both names serve, or the
// health check, which is about the machine rather than either product: a
// deploy check or a monitor that asks the organisation's name for it is
// answered, not sent elsewhere and told "301" where it expects "ok".
func isAsset(path string) bool {
	if path == "/healthz" {
		return true
	}
	_, ok := files[path]
	return ok
}

// elsewhere redirects to the same path, and query, on the name base is.
func elsewhere(w http.ResponseWriter, r *http.Request, base, path string) {
	setHeaders(w, r)
	target := url.URL{
		Scheme:   "https",
		Host:     strings.TrimPrefix(base, "https://"),
		Path:     path,
		RawQuery: r.URL.RawQuery,
	}
	if path == r.URL.Path {
		// As it arrived, so an escaped character stays escaped.
		target.RawPath = r.URL.RawPath
	}
	status := http.StatusPermanentRedirect
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		status = http.StatusMovedPermanently
	}
	// #nosec G710 -- the scheme and host are one of the two constants above,
	// never the request's; only the path and query are, and with a host in
	// front a path cannot name another site (TestTheRedirectsStayOnThisSite).
	http.Redirect(w, r, target.String(), status)
}

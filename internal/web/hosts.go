package web

import (
	"net"
	"net/http"
	"strings"

	"github.com/denyfirst/porch/internal/demo"
)

// The demonstration answers to one name since v0.37.0: porch.denyfirst.dev.
//
// From 2026-10-05 one binary answered to three. denyfirst.dev was the
// organisation: its front page, its undertakings and the contacts RFC 9116
// points at. porch.denyfirst.dev was Porch. mta-sts.denyfirst.dev was the mail
// policy for the first. On 2026-11-26 the organisation's two names moved to a
// program of their own, denyfirst/site, at an address of their own, and this
// one stopped serving them. Their pages, and the tests that hold them, are in
// that repository.
//
// A request for one of those names that still reaches this program came by an
// old address, or by a name somebody else pointed here. It is answered 421,
// Misdirected Request (RFC 9110, section 15.5.20), rather than redirected: the
// name's own address is the right one, and a client still holding this one
// for it would follow a redirect straight back here.
//
// The organisation's contacts keep their old addresses on this name as
// redirects to denyfirst.dev (contactsMoved, in web.go), because reports and
// pages already shared link them here.
//
// An installation somebody runs is one name, its operator's, and none of this
// applies to it.

// organisationNames are the names denyfirst/site answers to.
var organisationNames = map[string]bool{
	strings.TrimPrefix(SiteURL, "https://"):              true,
	"mta-sts." + strings.TrimPrefix(SiteURL, "https://"): true,
}

// Hosts answers a request for one of the organisation's names with 421, and
// passes everything else to next. It goes in front of the API as well as the
// pages, so that nothing of Porch's answers to the organisation's names.
//
// On an installation it is next, unchanged.
func Hosts(next http.Handler) http.Handler {
	if !demo.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if organisationName(r.Host) {
			setHeaders(w, r)
			// The rule, never the name that was sent (I3).
			http.Error(w, "That name is not served at this address.", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// organisationName reads the Host header the way a browser writes it: any
// case, an optional port, an optional trailing dot.
func organisationName(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return organisationNames[strings.TrimSuffix(strings.ToLower(host), ".")]
}

// canonicalURL is the one address a page states as its own: the path on
// Porch's name.
func canonicalURL(path string) string {
	return PorchURL + path
}

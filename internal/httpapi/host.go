package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// GuardHost puts the one check that has to see every request in front of
// next: over plain HTTP, a request is answered only when it names this machine
// by an address or as localhost.
//
// # Why a name is refused
//
// A service on loopback, with no password, is offered to its operator on the
// argument that nobody else can reach it — the inventory and the address range
// walk are both given to that caller without proof (N12). A browser can reach
// it for somebody else. A page on another site names its own domain, points
// the domain at 127.0.0.1 once it has loaded, and its script then calls
// "its own" server: the browser sends the request to this service, as
// same-origin, and reads the answer. Every guard the API has is satisfied,
// because Sec-Fetch-Site says same-origin and it is. What that page gets is an
// open scanner leaving from the operator's address, the operator's inventory
// and the operator's reverse records — DNS rebinding, and the loopback default
// is exactly the arrangement it exists to reach.
//
// The Host header is what gives it away. The page's browser sends the page's
// own name, and a name this service was never told is its own is the one
// thing the attack cannot change. An address cannot be rebound, because the
// origin is then the address itself; localhost is resolved by the browser
// without asking anybody. So both are answered and every other name is not.
//
// Over TLS it is not asked. A browser that rebinds a name to this machine
// still expects the certificate for that name, and this service cannot present
// one, so the handshake fails before any request exists. An operator who
// serves a name over HTTPS has already said which name is theirs.
//
// Refused before the gate, the pages and the API alike, because the pages
// carry the script that calls the API and a guard in one of them is a guard
// the other walks around (N6). Counted, like every refusal (A7), and held to
// the read allowance, because a refusal is cheap and not free (A6).
func (s *Server) GuardHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || servedHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		setSecurityHeaders(w, r)
		if !s.reads.allow("read:" + clientKey(r, s.limits.TrustedProxies, s.limits.TrustedProxyHops)) {
			w.Header().Set("Retry-After", "1")
			s.refuse(w, http.StatusTooManyRequests, "rate_limited",
				"Too many requests from this address. Try again shortly.")
			return
		}
		// The rule, never the name that was sent (I3).
		s.refuse(w, http.StatusMisdirectedRequest, "host_not_served",
			"Over plain HTTP this installation answers only to an address or to localhost. "+
				"A page on another site can point its own name at this machine and call it "+
				"through the visitor's browser, so a name is refused. Use the address, or serve "+
				"the installation over HTTPS under its own name.")
	})
}

// servedHost reports whether a Host header names this machine in a way no
// other site can arrange: an address, localhost, or nothing at all.
//
// Nothing at all is HTTP/1.0 without the header, which a browser never sends,
// so it is not the request this guard is for.
func servedHost(host string) bool {
	if host == "" {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

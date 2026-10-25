package rdap

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// registry stands in for IANA and a registry at once: the list at /dns.json
// and domains under /rdap/domain/.
type registry struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	asked    []string
	lists    int
	domains  map[string]string
	list     string
	status   int
	redirect bool
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{t: t, domains: map[string]string{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	r.list = `{"services":[[["test"],["http://plain.invalid/","` + r.srv.URL + `/rdap/"]],[["plain"],["http://plain.invalid/"]]]}`
	return r
}

func (r *registry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path == "/dns.json" {
		r.lists++
		_, _ = w.Write([]byte(r.list))
		return
	}
	name := strings.TrimPrefix(req.URL.Path, "/rdap/domain/")
	r.asked = append(r.asked, name)
	if r.redirect {
		http.Redirect(w, req, "https://elsewhere.invalid/", http.StatusFound)
		return
	}
	if r.status != 0 {
		w.WriteHeader(r.status)
		return
	}
	body, ok := r.domains[name]
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/rdap+json")
	_, _ = w.Write([]byte(body))
}

func (r *registry) client() *Client {
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	addr := r.srv.Listener.Addr().String()
	return &Client{
		Bootstrap: r.srv.URL + "/dns.json",
		Roots:     pool,
		Timeout:   5 * time.Second,
		// safedial refuses loopback, as it should everywhere but here.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}

// What a registry answers, in the shape RFC 9083 gives it: this project's own
// domain as Google Registry would describe it.
const held = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.TEST",
  "status": ["client transfer prohibited", "active"],
  "events": [
    {"eventAction": "registration", "eventDate": "2026-07-28T10:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-07-28T10:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2026-10-01T09:00:00Z"}
  ],
  "secureDNS": {"delegationSigned": true},
  "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Namecheap, Inc.\u0007"]]]}
  ]
}`

// The registration is read from the registry, and the registry is told the
// registered domain and nothing longer.
//
// Asked from the shortest name up: a scan of www.example.test asks about
// example.test, and stops there, so the registry never learns which host
// under it was being looked at.
func TestTheRegistrationIsReadAndOnlyTheDomainIsNamed(t *testing.T) {
	r := newRegistry(t)
	r.domains["example.test"] = held

	got := r.client().Lookup(context.Background(), "WWW.Example.test.")
	if got.Reason != "" {
		t.Fatalf("the lookup failed: %s", got.Reason)
	}
	if len(r.asked) != 1 || r.asked[0] != "example.test" {
		t.Errorf("the registry was asked about %v, want only example.test", r.asked)
	}
	if got.Domain != "example.test" || got.Registrar != "Namecheap, Inc." {
		t.Errorf("read %+v", got)
	}
	if !got.Expires.Equal(time.Date(2027, 7, 28, 10, 0, 0, 0, time.UTC)) || got.Created.IsZero() || got.Changed.IsZero() {
		t.Errorf("the dates read as %v, %v, %v", got.Created, got.Expires, got.Changed)
	}
	if !got.TransferLocked() || got.RegistryLocked() || !got.DelegationSigned {
		t.Errorf("the statuses read as %v, signed %v", got.Statuses, got.DelegationSigned)
	}
}

// A name the registry does not hold is passed over for the one above it, and a
// suffix that is not a domain is too.
func TestADomainUnderASuffixIsFoundAboveIt(t *testing.T) {
	r := newRegistry(t)
	r.domains["example.co.test"] = strings.Replace(held, "EXAMPLE.TEST", "example.co.test", 1)

	got := r.client().Lookup(context.Background(), "mail.example.co.test")
	if got.Reason != "" || got.Domain != "example.co.test" {
		t.Errorf("read %+v", got)
	}
	if strings.Join(r.asked, " ") != "co.test example.co.test" {
		t.Errorf("asked %v", r.asked)
	}
}

// Anything that is not an answer is said to be one that was not established.
func TestNothingThatIsNotARegistrationReadsAsOne(t *testing.T) {
	for name, set := range map[string]func(r *registry){
		"the registry broke":        func(r *registry) { r.status = http.StatusBadGateway },
		"the registry rate limits":  func(r *registry) { r.status = http.StatusTooManyRequests },
		"a redirect":                func(r *registry) { r.redirect = true },
		"something else":            func(r *registry) { r.domains["example.test"] = `{"objectClassName":"entity"}` },
		"another name":              func(r *registry) { r.domains["example.test"] = strings.Replace(held, "EXAMPLE.TEST", "other.test", 1) },
		"not a document":            func(r *registry) { r.domains["example.test"] = "<html>" },
		"larger than this reads":    func(r *registry) { r.domains["example.test"] = strings.Repeat("x", maxAnswer+1) },
		"nothing held at any level": func(r *registry) {},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRegistry(t)
			set(r)
			got := r.client().Lookup(context.Background(), "example.test")
			if got.Reason == "" || got.Registrar != "" || !got.Expires.IsZero() || !got.Asked {
				t.Errorf("read %+v", got)
			}
			// A question put and not answered: not a registry with no service,
			// which is the one failure that does not withhold strong (dns-v5).
			if got.NoService {
				t.Errorf("a registry that was asked is reported as publishing no service: %+v", got)
			}
			for _, leak := range []string{"127.0.0.1", "dial ", "tcp ", "x509", "json"} {
				if strings.Contains(got.Reason, leak) {
					t.Errorf("the reason describes the machine: %s", got.Reason)
				}
			}
		})
	}
}

// A registry listed only over plain HTTP is not asked, and a top-level domain
// with no registry says so.
func TestARegistryIsAskedOnlyOverHTTPS(t *testing.T) {
	r := newRegistry(t)
	c := r.client()
	for _, name := range []string{"example.plain", "example.none"} {
		if got := c.Lookup(context.Background(), name); !strings.Contains(got.Reason, "publishes no RDAP service") || !got.NoService {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if len(r.asked) != 0 {
		t.Errorf("a registry was asked: %v", r.asked)
	}
}

// IANA's list is read once and kept, so it is not fetched for every scan.
func TestTheListIsReadOnceAndKept(t *testing.T) {
	r := newRegistry(t)
	r.domains["example.test"] = held
	c := r.client()
	for range 3 {
		c.Lookup(context.Background(), "example.test")
	}
	if r.lists != 1 {
		t.Errorf("IANA's list was read %d times", r.lists)
	}
}

// A list that cannot be read is not read again on every scan.
func TestAListThatCannotBeReadIsNotHammered(t *testing.T) {
	r := newRegistry(t)
	r.list = "not json"
	c := r.client()
	for range 3 {
		if got := c.Lookup(context.Background(), "example.test"); !strings.Contains(got.Reason, "IANA's list") || got.NoService {
			t.Errorf("read %+v; a list that could not be read is not a registry with no service", got)
		}
	}
	if r.lists != 1 {
		t.Errorf("a broken list was read %d times in a row", r.lists)
	}
}

// A name with no domain above a top-level one is not asked about.
func TestATopLevelNameIsNotAskedAbout(t *testing.T) {
	r := newRegistry(t)
	if got := r.client().Lookup(context.Background(), "test"); got.Reason == "" {
		t.Errorf("read %+v", got)
	}
	if r.lists != 0 || len(r.asked) != 0 {
		t.Error("something was asked about a bare top-level domain")
	}
}

// The registry lock is all three server prohibitions, not one of them.
func TestARegistryLockIsAllThreeServerProhibitions(t *testing.T) {
	two := Registration{Statuses: []string{"server transfer prohibited", "server update prohibited"}}
	if two.RegistryLocked() || !two.TransferLocked() {
		t.Errorf("two prohibitions read as locked %v, transfer locked %v", two.RegistryLocked(), two.TransferLocked())
	}
	three := Registration{Statuses: append(two.Statuses, "server delete prohibited")}
	if !three.RegistryLocked() {
		t.Error("all three prohibitions are not a registry lock")
	}
}

// The scan's own clock running out is said as that, not as the registry being
// unreachable.
func TestAnAnswerTooLateSaysSo(t *testing.T) {
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	t.Cleanup(slow.Close)
	pool := x509.NewCertPool()
	pool.AddCert(slow.Certificate())
	addr := slow.Listener.Addr().String()
	c := &Client{Bootstrap: slow.URL + "/dns.json", Roots: pool, Timeout: 200 * time.Millisecond,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.get(ctx, slow.URL+"/dns.json", maxBootstrap, "application/json")
	if err == nil || err.Error() != "the registry did not answer in the time the scan allows" {
		t.Errorf("read %v", err)
	}
}

// Package certnames reads the names the hosts themselves present.
//
// # The one source that is not somebody else's register
//
// Every other source of names is a record kept by a third party: a
// transparency log, a passive register, or the domain's own published records
// read through a resolver. This one asks the estate. One handshake with each
// host that is already known to answer, and the names written in the
// certificate it presents.
//
// What that finds is the half of an estate no register can hold:
//
//   - A certificate issued by a **private authority** is in no public log, by
//     definition — nothing submitted it and nothing would accept it. An
//     internal service on a company's own CA is invisible to every other
//     source here and names itself in the first packet it sends back.
//   - A certificate covering several names, presented by a host only one of
//     those names pointed at. The others are in the log too where the
//     authority was public, and are not where it was not.
//   - A name still on a certificate after it stopped being used, which is the
//     opposite of the wildcard problem and reads the same way in a report:
//     something exists that nobody is looking after.
//
// # What it sends, and why that is not the same as the rest
//
// A handshake, with the name in it. That is more than the other sources send —
// the registers get a question about the domain and the estate gets nothing,
// while this opens a TLS connection to each host and names it in the
// ClientHello. So it is off unless somebody asks for it, on both faces, and on
// a service it is behind the same proof of control as everything else.
//
// No request is made over the connection and nothing is sent after the
// handshake: it is closed as soon as the certificate has been read. The
// certificate is not judged, either. Verification would fail on exactly the
// certificates this exists to read, and the names in an unverified certificate
// are still the names its operator put there — a report says which host
// presented it and grades nothing (R17, R21).
package certnames

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
)

// Found is what the hosts presented.
type Found struct {
	// Asked reports that the hosts were asked. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the hosts named in the certificates, under the domain,
	// folded and sorted. Wildcards are kept apart because nothing resolves
	// one.
	Names     []string `json:"names,omitempty"`
	Wildcards []string `json:"wildcards,omitempty"`

	// Hosts is how many hosts were asked and Answered how many presented a
	// certificate. Both, because the difference is the measure of how much
	// this could not see: an estate where two hosts in twenty answered has
	// eighteen certificates nobody here read.
	Hosts    int `json:"hosts"`
	Answered int `json:"answered"`

	// Foreign is how many names the certificates carried that belong to other
	// domains, and were therefore not listed. A count rather than a list, for
	// the reason every other source here keeps one: a certificate covering two
	// estates is evidence about the answer rather than part of this estate.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// DialFunc matches net.Dialer.DialContext and safedial.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const (
	// defaultTimeout bounds one host: its connection and its handshake.
	defaultTimeout = 5 * time.Second

	// defaultParallel bounds how many hosts are in flight.
	//
	// The same pace internal/liveness keeps, and for the same reason: an
	// estate's own firewall is watching, and a burst of handshakes from one
	// address is the shape of something nobody wants to explain.
	defaultParallel = 8

	// maxHosts bounds how many hosts are asked at all.
	maxHosts = 500

	// maxNamesPerHost bounds what one certificate may contribute. A
	// certificate carrying a thousand names is a shared one.
	maxNamesPerHost = 200

	// maxNames bounds the whole answer.
	maxNames = 2000

	// port is the only port asked. A port sweep is a different instrument:
	// it guesses at services, which is the thing this project does not do.
	port = "443"
)

// Reader asks hosts what names their certificates carry.
type Reader struct {
	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations — so a name pointing at
	// the machine this runs on, or at a metadata address, is never dialled.
	Dial DialFunc

	// Timeout bounds one host. Zero means five seconds.
	Timeout time.Duration

	// Parallel bounds how many hosts are in flight. Zero means eight.
	Parallel int
}

// Under asks each host for its certificate and keeps the names under the
// domain.
//
// The hosts are the ones something already established answer — asking a name
// that does not resolve spends a timeout to learn what the report already
// says.
func (r *Reader) Under(ctx context.Context, domain string, hosts []string) Found {
	domain = fold(domain)
	out := Found{Asked: true}
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	out.Hosts = len(hosts)
	if len(hosts) == 0 {
		return out
	}

	type answer struct {
		names    []string
		answered bool
	}

	answers := make([]answer, len(hosts))
	slots := make(chan struct{}, r.parallel())
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()

			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}

			names, ok := r.one(ctx, host)
			answers[i] = answer{names: names, answered: ok}
		}(i, host)
	}
	wg.Wait()

	found := map[string]bool{}
	wildcards := map[string]bool{}

	for _, a := range answers {
		if !a.answered {
			continue
		}
		out.Answered++

		for _, raw := range a.names {
			name := fold(clean(raw))
			if name == "" || !under(name, domain) {
				if name != "" {
					out.Foreign++
				}
				continue
			}
			if len(found)+len(wildcards) >= maxNames {
				break
			}
			if strings.HasPrefix(name, "*.") {
				wildcards[name] = true
				continue
			}
			found[name] = true
		}
	}

	for name := range found {
		out.Names = append(out.Names, name)
	}
	for name := range wildcards {
		out.Wildcards = append(out.Wildcards, name)
	}
	sort.Strings(out.Names)
	sort.Strings(out.Wildcards)
	return out
}

// one asks a single host and reads the names off what it presents.
func (r *Reader) one(ctx context.Context, host string) (names []string, answered bool) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	conn, err := r.dial()(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	// The certificate is read, not judged.
	//
	// Verification would fail on exactly the certificates this exists to find:
	// one from a private authority is untrusted here by construction, and
	// refusing it would leave the names on it out of the inventory — which is
	// the half of an estate no other source holds. Nothing is graded on what
	// comes back and no verdict is derived from it; the names are read and the
	// connection is closed.
	//
	// #nosec G402 -- deliberate: this reads the names in a certificate rather
	// than deciding whether to trust it, and the certificates worth finding
	// here are the ones no public authority issued
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}

	client := tls.Client(conn, cfg)
	if err := client.HandshakeContext(ctx); err != nil {
		return nil, false
	}
	defer client.Close()

	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}

	leaf := state.PeerCertificates[0]
	for i, name := range leaf.DNSNames {
		if i >= maxNamesPerHost {
			break
		}
		names = append(names, name)
	}

	// The subject's common name too, where it carries one that is not already
	// a subject alternative name. It is deprecated as an identifier and is
	// still where an old private authority puts the only name a certificate
	// has.
	if cn := leaf.Subject.CommonName; cn != "" {
		names = append(names, cn)
	}
	return names, true
}

// under reports whether a name belongs to the domain asked about.
//
// The same label boundary every other source draws, and a wildcard is matched
// on the name behind the star: `*.example.com` belongs to example.com.
func under(name, domain string) bool {
	name = strings.TrimPrefix(name, "*.")
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// fold is one spelling of a name, so that two sources naming one host produce
// one entry.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// clean bounds a name and strips what no name may carry.
//
// A certificate is chosen by whoever obtained it, and one presented by a host
// this connected to is chosen by whoever runs that host. Neither is a reason
// to print control characters into somebody's terminal.
func clean(s string) string {
	const maxName = 253

	s = strings.TrimSpace(s)
	if len(s) > maxName {
		s = s[:maxName]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (r *Reader) dial() DialFunc {
	if r.Dial != nil {
		return r.Dial
	}
	d := &safedial.Dialer{Timeout: r.timeout(), AllowedPorts: []string{port}}
	return d.DialContext
}

func (r *Reader) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}

func (r *Reader) parallel() int {
	if r.Parallel > 0 {
		return r.Parallel
	}
	return defaultParallel
}

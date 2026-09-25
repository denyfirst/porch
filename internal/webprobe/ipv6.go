package webprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"

	"github.com/denyfirst/porch/internal/safedial"
)

// IPv6Facts is whether the site answered on its IPv6 address, and — where it
// did not — which of the several reasons for that this was.
//
// The check exists because the report could not answer the question at all.
// A dialler that tries a name's addresses until one answers is the right way
// to reach a site and the wrong way to measure it: a host with one working
// IPv4 address and an AAAA record pointing at nothing answers every scan,
// looks perfect, and is unreachable from a network that has only IPv6. The
// operator is the last person to find out, because their own machine has both.
type IPv6Facts struct {
	// Asked reports that this was measured at all.
	Asked bool

	// Published is how many IPv6 addresses the name has. Zero is a fact about
	// the zone rather than a failure: a site with no AAAA record has not
	// claimed to be reachable over IPv6, and nothing is wrong with that.
	Published int

	// Answered reports that one of them completed a TLS handshake on 443.
	Answered bool

	// Verified reports that the certificate presented over IPv6 verified for
	// the name asked about. A host answering on IPv6 with a certificate for
	// something else is reachable and unusable, which is a different fault
	// from not answering.
	Verified bool

	// Reason says the shape of the failure, where there was one. It never
	// carries an address: which addresses a name publishes is in its own DNS,
	// and what this machine's network looks like is nobody's business (I6).
	Reason string

	// NoRouteFromHere reports that this machine has no IPv6 address of its
	// own, so nothing about the site was learned.
	//
	// The distinction safedial's SingleFamilyError draws, in the one place
	// where it decides what a report says: "unreachable" and "unreachable from
	// here" are different findings, and printing the second as the first is a
	// fact about the scanner published as a fault in somebody's server (R4).
	NoRouteFromHere bool
}

// reachOverIPv6 asks whether the site answers on an address it published for
// the newer protocol.
//
// One connection, to one address, over the same dialler and the same trust
// store as everything else here — a second place that decided which
// destinations may be reached would be a second place to walk around (N6).
func (p *Prober) reachOverIPv6(ctx context.Context, host string, roots *x509.CertPool) IPv6Facts {
	out := IPv6Facts{Asked: true}

	addrs, err := p.lookupIPv6(ctx, host)
	if err != nil || len(addrs) == 0 {
		// A name with no AAAA record and a name whose lookup failed are not
		// the same, but from here they read the same and guessing between
		// them would be guessing. Published stays zero and the row says the
		// site publishes no IPv6 address, which is what the resolver said.
		return out
	}

	published, usable := usableIPv6(addrs)
	out.Published = published
	if len(usable) == 0 {
		return out
	}

	answered, verified, reason := p.handshakeOverIPv6(ctx, host, usable[0], roots)
	out.Answered, out.Verified, out.Reason = answered, verified, reason

	// The local network is read only after a failure, and only to decide
	// whether that failure says anything about the site. Asking before there is
	// something to explain would be reading this machine's configuration for
	// no reason at all.
	if !answered && reason != "" {
		out.NoRouteFromHere = unmeasurable(answered, reason, machineHasIPv6())
	}
	return out
}

// unmeasurable says whether a failure to reach an address is a fact about the
// site or a fact about the machine doing the scanning.
//
// Its own function because it is the one judgement in this file that could
// print somebody else's server as broken on the strength of the scanner's
// network (R4), and a judgement like that is worth being able to state as a
// table rather than read out of a branch.
func unmeasurable(answered bool, reason string, machineHasIPv6 bool) bool {
	return !answered && reason != "" && !machineHasIPv6
}

// machineHasIPv6 is what the decision above consults, and it is a variable so
// that the decision can be tested.
//
// This machine's own network is not a property of the scan and so is not a
// parameter of one; there is nowhere honest to pass it in from. The seam exists
// because the alternative is a line nothing can check — and the sabotage that
// found this had replaced exactly that line, in both directions, with nothing
// failing.
var machineHasIPv6 = func() bool { return hasGlobalIPv6(localAddresses()) }

// lookupIPv6 asks for the addresses a name publishes for the newer protocol.
func (p *Prober) lookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.LookupIPv6 != nil {
		return p.LookupIPv6(ctx, host)
	}
	return defaultLookupIPv6(ctx, host)
}

// defaultLookupIPv6 is the machine's own resolver, and it is a variable for one
// reason: so that the tests of this package can be made to send no query to
// anybody at all. main_test.go replaces it. A test that means to exercise a
// lookup sets the hook on the Prober instead, which is the honest way to say
// what a name answers.
var defaultLookupIPv6 = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip6", host)
}

// usableIPv6 says how many IPv6 addresses a name published and which of them
// may be dialled.
//
// Separate from the connection for two reasons. It is the half that decides
// what the report counts, so it is worth being able to state what it does
// without a network; and the safety check belongs before the dial rather than
// inside it, where an address in a refused range is counted as published —
// because the zone did publish it — and never connected to.
func usableIPv6(addrs []netip.Addr) (published int, usable []netip.Addr) {
	// Ordered and cut the way everything else here orders them, so that a name
	// with many addresses is asked about the same one twice running.
	candidates, _ := safedial.Candidates(addrs, safedial.DefaultMaxAddrs)

	for _, addr := range candidates {
		if addr.Unmap().Is4() {
			// A resolver asked for ip6 can hand back a mapped IPv4 address,
			// and counting one as an IPv6 address the name published would
			// make a name with no AAAA record read as having one.
			continue
		}
		published++
		if safedial.CheckAddr(addr) != nil {
			continue
		}
		usable = append(usable, addr)
	}
	return published, usable
}

// handshakeOverIPv6 opens one connection to one address and says what came
// back.
//
// The dialler is the package's own, so the destination is checked a second time
// by whatever decides that for every other connection here (N6). Answered
// means the port answered; verified means the certificate was valid for the
// name asked about, which is the difference between a site that is unreachable
// over IPv6 and one that is reachable and unusable.
func (p *Prober) handshakeOverIPv6(ctx context.Context, host string, addr netip.Addr, roots *x509.CertPool) (answered, verified bool, reason string) {
	conn, err := p.dialFunc()(ctx, "tcp6", net.JoinHostPort(addr.String(), securePort))
	if err != nil {
		return false, false, "the address did not answer on 443"
	}
	defer conn.Close()

	// The same configuration the chains use, with the name set: here there is
	// exactly one host and no redirect can move it, so the name can be checked
	// against the certificate that arrives.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return true, false, "the certificate presented over IPv6 did not verify for this name"
	}
	_ = tlsConn.Close()

	return true, true, ""
}

// hasGlobalIPv6 reports whether a list of a machine's own addresses holds one
// that could reach an IPv6 host on the internet.
//
// A machine with no global IPv6 address cannot reach any IPv6 host, so
// reporting "did not answer" from one would be reporting the scanner's network
// as the scanned party's fault. It is not proof of a working route — a machine
// can hold an address and have no path — which is why the sentence it leads to
// says nothing was measured rather than claiming the site is fine.
//
// A link-local address is the case this exists to exclude. Every IPv6-capable
// interface has one whether or not anything is routed, so counting it would
// make every machine look connected and the distinction would quietly stop
// existing.
func hasGlobalIPv6(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if addr.Is4() || addr.Is4In6() {
			continue
		}
		if addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// localAddresses is every address on an interface that is up and is not
// loopback.
func localAddresses() []netip.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			out = append(out, prefix.Addr())
		}
	}
	return out
}

// dialFunc is the dialler every connection this package makes goes through.
//
// One copy, because the thing it decides is which destinations may be reached
// at all, and a second copy is a second place somebody has to remember to
// change (N6).
func (p *Prober) dialFunc() DialFunc {
	if p.Dial != nil {
		return p.Dial
	}
	d := &safedial.Dialer{
		Timeout: p.requestTimeout(),
		// Ports as well as addresses. A redirect can name any port on any
		// host, and a probe that follows one has been aimed by the server
		// rather than by the operator.
		AllowedPorts: []string{securePort, plainPort},
	}
	return d.DialContext
}

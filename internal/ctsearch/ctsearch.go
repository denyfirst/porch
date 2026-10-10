// Package ctsearch finds the certificates a public log has recorded for a name.
//
// Every publicly trusted certificate is submitted to append-only logs before a
// browser will accept it. That is what makes this possible: a certificate
// somebody obtained for your name, from any authority, is in those logs whether
// or not you know about it. Finding one you did not order is the earliest
// warning available that a name has been issued for behind your back — and it
// is a warning nothing in a handshake can give, because the certificate you are
// looking for is on somebody else's server.
//
// # Where the answer comes from
//
// A log is an append-only structure of billions of entries with no index by
// name, so "which certificates exist for example.com" cannot be asked of a log
// directly. It is asked of a monitor that reads every log as it grows and
// indexes what it reads, and the question contains the domain.
//
// That is asking the source, not telling an intermediary. The certificates for
// a name are published to anyone who looks, and the monitor holds them whether
// or not anybody asks; what it learns is that somebody looked at a name this
// installation was shown control of. What this project refuses is the other
// thing — a service in the middle that collects what everybody checks — and
// running Porch on your own machine is how that is refused.
//
// So the search runs on every deployment, for every name a scan may reach: a
// proven domain on an installation, this project's own on the demonstration.
//
// # One monitor
//
// Cert Spotter, run by SSLMate. Until 2026-10-10 crt.sh was asked as well, and
// it is not any more: on 2026-10-09 it listed one of this project's four valid
// certificates while Cert Spotter listed all four, and a monitor that answers
// late answers wrongly without saying so. A search that fails says it failed;
// a search that is behind says nothing at all.
package ctsearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/display"
	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	// maxBody bounds one answer. A name with a long issuance history produces
	// a large document, and this is a scanner rather than an archive.
	maxBody = 4 << 20

	// maxEntries bounds what is kept after parsing. A report listing hundreds
	// of certificates is a report nobody reads; the count is still reported in
	// full, and Result.Truncated says the list is not.
	maxEntries = 50

	defaultTimeout = 15 * time.Second

	// maxField bounds one string taken from an answer. Issuer names and subject
	// names come from certificates anybody may log, so they are chosen by
	// whoever obtained them rather than by the operator being scanned.
	maxField = 256

	// maxNames bounds the names kept from one entry.
	maxNames = 20
)

// Entry is one certificate a log recorded.
type Entry struct {
	// Serial is the certificate's serial number, read from the certificate,
	// lowercase hexadecimal.
	//
	// It is what deduplication is done on, and that is not a detail. Every
	// certificate is logged twice — once as a precertificate and once as
	// itself — so a name with one certificate comes back as two entries with
	// one serial. Reporting the raw count would tell an operator they have
	// twice as many certificates as they do, which on this scanner's own
	// domain was the first thing the real answer showed.
	Serial string `json:"serial"`

	// Issuer is the authority that signed it, as the monitor names it,
	// truncated and stripped of anything unprintable.
	Issuer string `json:"issuer"`

	// Names are the names the certificate covers.
	Names []string `json:"names,omitempty"`

	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

// Result is what one search established.
type Result struct {
	// Entries are the distinct certificates found, newest first.
	Entries []Entry `json:"entries,omitempty"`

	// Distinct is how many distinct certificates the monitor reported, which
	// is not len(Entries) when the list was truncated.
	Distinct int `json:"distinct"`

	// Truncated is true when more certificates exist than are listed.
	Truncated bool `json:"truncated,omitempty"`

	// Reason says why nothing was established. Empty on success.
	//
	// This project's own sentence, never an error from the network or the
	// decoder: those name resolvers, addresses and internal types, and this
	// string reaches a report a stranger reads (I6).
	Reason string `json:"reason,omitempty"`

	// Monitor names the monitor that answered, or that failed to. A monitor
	// can be behind the logs, so an answer says whose it is.
	Monitor string `json:"monitor,omitempty"`

	// Checked is when the monitor gave this answer, where that was not just
	// now: an answer kept for a while and handed out again says how old it is.
	Checked time.Time `json:"checked,omitzero"`
}

// Searcher answers which certificates a log has recorded for a name.
//
// An interface so the monitor can be replaced without touching anything that
// reads a result. See the package comment.
type Searcher interface {
	Search(ctx context.Context, name string) Result
}

// UserAgent identifies this client to the monitor, as everything else here
// identifies itself. A search that hides is one nobody can ask about.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// clean bounds one string from the monitor and strips what should not travel.
//
// These come from certificates anybody may obtain and log, so the values are
// chosen by whoever obtained them. A report is rendered in a browser and pasted
// into chat windows, and a control character in a subject is an old trick for
// making one line look like another.
//
// C0 and DEL are dropped, as they always were. C1 and Unicode's format
// characters are replaced with U+FFFD rather than dropped, which is the rule
// internal/certinfo applies to the certificates a handshake carries (R10): a
// terminal takes 0x9b as CSI, U+202E reverses what follows it in a terminal
// and a browser alike, and a zero-width character makes one name read as
// another. Dropping those would do the disguise's work for it — a name with a
// zero-width space in it would come out as the name it imitates — so a reader
// is shown that something was there. These strings reach a person now: the
// certificates a TLS report counts are listed, and the inventory prints names.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxField {
		s = s[:maxField]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return display.Mark(b.String())
}

// stamp reads the monitor's timestamps.
func stamp(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// monitorClient builds the client the monitor is asked through.
//
// What it decides is which destinations may be reached and which store judges
// a certificate, and those are the same decisions every other connection here
// makes (N6, R7).
func monitorClient(dial func(ctx context.Context, network, address string) (net.Conn, error), roots *x509.CertPool) *http.Client {
	if dial == nil {
		d := &safedial.Dialer{Timeout: defaultTimeout, AllowedPorts: []string{"443", "80"}}
		dial = d.DialContext
	}

	resolved, _ := truststore.Resolve(roots)

	return &http.Client{
		// A redirect from a monitor is an address that monitor chose. The hop
		// is not followed and the search is reported as not established, which
		// is the honest outcome.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: dial,
			Proxy:       nil,

			// As everywhere: RootCAs and nothing that would weaken a
			// handshake. No InsecureSkipVerify, no pinned ServerName, no
			// shared session cache, no version named here.
			TLSClientConfig: &tls.Config{RootCAs: resolved},

			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: defaultTimeout,
		},
	}
}

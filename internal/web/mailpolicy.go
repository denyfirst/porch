package web

import (
	"net/http"
)

// The demonstration's third name, mta-sts.denyfirst.dev, exists for one file:
// the MTA-STS policy (RFC 8461) for mail addressed to denyfirst.dev.
//
// Without it a server sending us mail may deliver in the clear when somebody
// on the path strips STARTTLS, and Porch's own mail check says so about our
// domain. With it, a sender that has fetched the policy over a certificate it
// trusts refuses to deliver to an exchanger the policy does not name, or over
// a connection that does not verify.
//
// The file is answered only at the name and path a sender asks for, and
// nothing else is answered at that name: it is a policy host, not another way
// into the site. Nothing is redirected there either, because RFC 8461 §3.3
// forbids a sender to follow one. An installation has no such name; its
// operator's mail is not ours to describe.

// mailPolicyPath is where RFC 8461 §3.2 puts the policy.
const mailPolicyPath = "/.well-known/mta-sts.txt"

// mailPolicy is the policy itself.
//
// The exchangers are the domain's MX records, Migadu's two. Changing anything
// here means publishing a new id in the _mta-sts.denyfirst.dev TXT record in
// the same deploy: a sender re-reads the file only when the id changes, and
// otherwise keeps the old policy for max_age.
//
// mode is testing: senders report through TLS-RPT (_smtp._tls) and deliver
// anyway. It moves to enforce, with a max_age of weeks rather than one week,
// once the reports show every sender reaching both exchangers over TLS.
//
// Lines end in CRLF, as RFC 8461 §3.2 writes them.
const mailPolicy = "version: STSv1\r\n" +
	"mode: testing\r\n" +
	"mx: aspmx1.migadu.com\r\n" +
	"mx: aspmx2.migadu.com\r\n" +
	"max_age: 604800\r\n"

// serveMailPolicy answers a request addressed to mta-sts.denyfirst.dev.
func serveMailPolicy(w http.ResponseWriter, r *http.Request) {
	setHeaders(w, r)
	if r.URL.Path != mailPolicyPath {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// text/plain and nothing after it. RFC 8461 §3.3 asks senders to check the
	// media type, and one that compares the header as a string would refuse
	// the policy over a charset parameter.
	w.Header().Set("Content-Type", "text/plain")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(mailPolicy))
}

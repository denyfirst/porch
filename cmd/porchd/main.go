// Command porchd serves the scanner over HTTP.
//
// The handler in internal/httpapi guards what arrives in a request. This
// binary guards what happens before a request is complete — the part
// http.Server owns and leaves unbounded by default.
//
// Usage:
//
//	porchd -listen 127.0.0.1:8080
//	porchd -listen :443 -tls-cert /etc/ssl/denyfirst.pem -tls-key /etc/ssl/denyfirst.key
//
// Certificates are read from disk rather than obtained through an ACME
// library, because every Go ACME client is a third-party module and this
// project has none. A renewal tool writes the files; this process notices and
// reloads them without restarting.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/denyfirst/porch/internal/access"
	"github.com/denyfirst/porch/internal/certnames"
	"github.com/denyfirst/porch/internal/challenge"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/httpapi"
	"github.com/denyfirst/porch/internal/nsecnames"
	"github.com/denyfirst/porch/internal/ocspquery"
	"github.com/denyfirst/porch/internal/passivedns"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/results"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/smtptls"
	"github.com/denyfirst/porch/internal/truststore"
	"github.com/denyfirst/porch/internal/vault"
	"github.com/denyfirst/porch/internal/verify"
	"github.com/denyfirst/porch/internal/web"
	"github.com/denyfirst/porch/internal/zonenames"
)

// version is the release this binary was built from, set by scripts/build.sh
// with -ldflags -X. An unset value means it was not built by that script.
//
// -buildvcs=false is deliberate, and the tag in the filename does not survive
// being renamed or packaged, so without this an operator had no way to ask a
// running service which build it is. -version printed the policy version,
// which answers a different question: which rules produce a verdict, not
// which binary is producing them.
var version = "(unknown: not built by scripts/build.sh)"

const (
	// shutdownGrace is how long in-flight requests have to finish once a
	// signal arrives. A scan can hold a connection for the whole request
	// timeout, so this must exceed it or a clean stop truncates responses.
	shutdownGrace = 45 * time.Second

	// maxHeaderBytes caps request headers. The default of 1 MiB is generous
	// for an endpoint whose entire request is one JSON field.
	maxHeaderBytes = 16 << 10

	// writeMargin is added to the scan budget to produce WriteTimeout.
	//
	// WriteTimeout covers the whole exchange, so setting it at or below the
	// scan budget cuts the response off mid-encode. The user then sees a
	// truncated body with no explanation, which is worse than an error.
	writeMargin = 10 * time.Second

	// statsInterval is how often the counters are written to disk.
	//
	// On a timer rather than per request. Writing per request would put disk
	// latency in the scan path and, worse, would make the file's modification
	// time a record of when somebody used the service.
	statsInterval = time.Minute
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		listen = flag.String("listen", "127.0.0.1:8080",
			"address to listen on; loopback by default so an accidental start\n"+
				"\tis not immediately public")

		tlsCert = flag.String("tls-cert", "", "path to a PEM certificate chain; empty serves plain HTTP")
		tlsKey  = flag.String("tls-key", "", "path to the matching private key")

		requestTimeout = flag.Duration("request-timeout", httpapi.DefaultRequestTimeout,
			"budget for one scan")
		maxConcurrent = flag.Int("max-concurrent", httpapi.DefaultMaxConcurrent,
			"scans allowed to run at the same time; this also bounds how fast\n"+
				"\tthe per-target table can be spent, so raising it past a few dozen\n"+
				"\tneeds a wider table — see targetKeyBits in internal/httpapi")
		maxConnections = flag.Int("max-connections", httpapi.DefaultMaxConnections,
			"connections allowed to be open at once, before any request exists")
		burst = flag.Int("burst", httpapi.DefaultBurst,
			"scans one client may run back to back")
		refill = flag.Duration("refill", httpapi.DefaultRefill,
			"how long one rate limit token takes to return")
		maxTracked = flag.Int("max-tracked-clients", httpapi.DefaultMaxTrackedIPs,
			"how many clients the rate limiter remembers before refusing new ones")

		// There is no -trusted-proxy-hops flag, and the omission is the point.
		//
		// Reading X-Forwarded-For needs two things: how many proxies stand in
		// front, and which networks they connect from. httpapi.Limits carries
		// both, and clientKey ignores the header entirely unless the second is
		// set — otherwise any client could pick its own rate limit key by
		// inventing a header.
		//
		// A flag for the hop count alone could never take effect. It looked
		// like a setting and silently did nothing, which is worse than not
		// offering it: an operator would believe the real client address was
		// being used when the connection address was.
		//
		// This service runs with no proxy in front of it, deliberately, so
		// that the promise to record nothing lives in code rather than in
		// somebody else's configuration file. TrustedProxies stays on
		// httpapi.Limits for a caller embedding the package behind a proxy of
		// their own. If a proxy is ever put here, both fields come back
		// together, with a test.

		// The secret comes from a file rather than from a flag value.
		//
		// A flag lands in the process list, where every user on the machine
		// reads it, and in whatever shell history or unit file put it there.
		// The secret is what every token is derived from, so a deployment that
		// leaked it is a deployment anyone can add domains to.
		verifySecretFile = flag.String("verification-secret-file", "",
			"path to a file holding this deployment's verification secret, created if\n"+
				"\tabsent; when set, only domains that have published the matching challenge\n"+
				"\tare scanned, and the page shows the record to publish")

		// Which transparency monitor the inventory endpoint asks, if any.
		//
		// Empty means none, and the endpoint then answers that this installation
		// has no monitor. Off unless asked for, like every other question this
		// service puts to a third party (N12).
		namesMonitor = flag.String("names-monitor", "",
			"the certificate transparency monitor the name inventory asks: `crtsh` or\n"+
				"\tcertspotter. Empty offers no inventory. The question names a domain to a\n"+
				"\tservice this project does not run")

		namesMonitorURL = flag.String("names-monitor-url", "",
			"the `address` of the monitor named by -names-monitor, if not its own")

		// The register the inventory asks as well, if any.
		//
		// Off unless named, like the monitor, and for one more reason: the key
		// is the operator's own account with a company they chose, and the
		// question is billed to them. It is the only source that finds names a
		// wildcard certificate hides, and the only one holding what somebody's
		// resolver saw rather than what the domain published (N12).
		namesPassive = flag.String("names-passive", "",
			"a passive DNS register the name inventory asks as well: `securitytrails`\n"+
				"\tor virustotal. Empty asks none. The key is read from\n"+
				"\tSECURITYTRAILS_TOKEN or VIRUSTOTAL_TOKEN")

		namesPassiveURL = flag.String("names-passive-url", "",
			"the `address` of the register named by -names-passive, if not its own")

		// The zone itself, where an operator asked for it.
		//
		// The DNS check asks whether a zone transfers to anybody and reads
		// none of it, because that zone belongs to whoever runs it. This reads
		// one, and only for a domain this installation has been shown control
		// of — which is what makes it the asker's own zone rather than
		// somebody else's.
		namesReadZone = flag.Bool("names-read-zone", false,
			"ask a domain's own name servers to hand over the zone, and keep the\n"+
				"\tnames in it. Only for a domain this installation has been shown\n"+
				"\tcontrol of. Almost every server refuses, which is correct and is\n"+
				"\treported as such")

		// The other way a zone lists itself, and the one that works where a
		// transfer does not.
		//
		// A signed zone that has not moved to NSEC3 proves a name absent by
		// naming the two it lies between, so following those proofs reads the
		// zone out of records it serves to any resolver. Same condition as the
		// transfer: only for a domain this installation has been shown control
		// of, because the records being public does not make walking somebody
		// else's estate with them anything but enumeration.
		namesWalkProofs = flag.Bool("names-walk-proofs", false,
			"follow a domain's own DNSSEC absence proofs to list the names in its\n"+
				"\tzone. Only for a domain this installation has been shown control of.\n"+
				"\tIt works on a signed zone that has not moved to NSEC3, which is the\n"+
				"\tstate the DNS check reports as walkable")

		// The fifth source: the certificate each answering host presents.
		//
		// Off unless asked for. It is the one part of the inventory that opens
		// a connection to the estate on purpose, and what it finds is what a
		// private authority issued — which no public log holds and no register
		// saw. Behind proof of control like everything else this endpoint does.
		namesReadCertificates = flag.Bool("names-read-certificates", false,
			"ask each name that answers for the certificate it presents, and keep\n"+
				"\tthe names on it. One handshake per host, nothing requested over it,\n"+
				"\tand the certificate is read rather than judged")

		askResponder = flag.Bool("ask-responder", false,
			"ask each certificate's own authority whether it has been revoked. Needs\n"+
				"\tproof of control, because the question tells that authority which\n"+
				"\tcertificate is being looked at, from this address and when — so it is\n"+
				"\tonly a disclosure to make about your own estate")

		// Signed proof only, for an operator whose resolver is theirs. The
		// record is read from the zone's own servers either way; this adds the
		// resolver's AD bit, which is its word and worth what the path to it is
		// worth, so this is a choice about a resolver, not a switch that makes
		// DNS safe (audit 2026-09-16, A06).
		requireSigned = flag.Bool("verification-requires-dnssec", false,
			"accept a challenge record only where the zone's own servers carry it and\n"+
				"\tthe resolver also reports it DNSSEC-validated, and no challenge file.\n"+
				"\tWorth it only with a validating resolver you trust: see -resolver")

		verifyToken = flag.String("verification-token", "",
			"print what the named domain must publish at "+verify.Label+", then exit")

		statsFile = flag.String("stats-file", "",
			"path to a file holding the aggregate counters; empty keeps them in\n"+
				"\tmemory only, so a restart resets the published total")

		// Where to keep results, if anywhere.
		//
		// Empty keeps nothing, which is the default and the promise this
		// project is built on. What changes on an installation somebody runs
		// themselves is whose data it is: their scans of their own estate, on
		// their own disk, because they asked.
		//
		// Written and never served. A browsable history of an estate's
		// weaknesses is a thing worth attacking, so this plain store is read
		// back by porch-scan on the machine itself; behind -access-file the
		// history is the sealed one instead, and the two are refused together.
		// See internal/results and internal/vault.
		resultsDir = flag.String("results-dir", "",
			"`directory` to keep results in, readable with porch-scan -history. Never\n"+
				"\tserved over HTTP. Empty keeps nothing, which is the default")

		resultsKeep = flag.Int("results-keep", 0,
			"how many results to keep per target, oldest dropped first; 0 keeps all")

		// The name the mail check gives each exchanger with EHLO. The default is
		// this machine's own name or address, which an exchanger's operator then
		// reads; behind NAT that is a private address. The same flag porch-scan
		// has (audit A26).
		heloName = flag.String("helo", "",
			"the `name` the mail check gives each mail exchanger with EHLO. Empty means\n"+
				"\tthis machine's fully qualified host name, or its address, as RFC 5321 says")

		// Which resolver the lookups this service makes itself are asked: CAA,
		// the mail records, and the proof-of-control challenge.
		//
		// The same flag porch-scan has, for the same reason (R7): the machine's
		// own configuration is assembled rather than read on Windows, and a
		// home router that rewrites answers is a resolver whose answers are
		// about the router. No default — a public resolver chosen here would
		// decide who learns which names are looked up.
		//
		// An address, not a name. A resolver named by hostname has to be found
		// through the machine's resolver first, which is the one this flag
		// exists to step around.
		resolver = flag.String("resolver", "",
			"`address` of the resolver for the lookups this service makes, ip:port; empty\n"+
				"\treads this machine's own configuration. The addresses scans connect to\n"+
				"\tare still resolved by the machine, and a proof of control is read from\n"+
				"\tthe zone's own servers, never through a resolver")

		// One password in front of the whole installation, and the key its kept
		// data is encrypted with, sealed by it. See internal/access.
		accessFile = flag.String("access-file", "",
			"path to this installation's access file, created with a new password if\n"+
				"\tabsent; when set, nothing is served without signing in, and what is\n"+
				"\tkept is encrypted under a key the password seals")

		showVersion = flag.Bool("version", false, "print the release and policy versions, then exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "porchd serves the denyfirst scanner over HTTP.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags]\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	// Two flags are gone, and an installation started with either is told why
	// rather than handed the flag package's "provided but not defined".
	if err := removedFlags(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	flag.Parse()

	// Before anything reads it, so a mistyped resolver stops the process rather
	// than costing every lookup a timeout once the service is answering.
	if err := resolverAddress(*resolver); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if *showVersion {
		// Three kinds of line, because they answer three questions. The
		// release names this build; each policy line names the rules one check
		// grades by, and a verdict from one policy version is not comparable
		// with a verdict from another; and the last says which hosts this
		// binary will connect to at all.
		//
		// The third line exists because the two builds are indistinguishable
		// from the outside until one refuses something. A deploy that
		// installed the wrong one would look entirely correct — the file is
		// in place, the service answers, the version matches — and the only
		// symptom would be a public scanner nobody meant to run. The deploy
		// procedure reads this line rather than trusting the filename.
		// The scope is read before the line is printed, so the line can say
		// what this deployment is rather than what the build alone decides. A
		// -version describing a deployment it has not yet configured would be
		// guessing at the one thing it exists to state.
		if err := smtptls.CheckHeloName(*heloName); err != nil {
			fmt.Fprintln(os.Stderr, "-helo: "+err.Error())
			return 2
		}

		scope, err := verificationScope(*verifySecretFile, *resolver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}

		fmt.Print(versionLines(reach(scope != nil)))
		return 0
	}

	// The scope this deployment will scan, read before anything is served.
	//
	// A secret configured with no way to check it, or a file that cannot be
	// read, stops the process rather than starting one that admits everything.
	// The alternative is a service that was asked to require proof, could not,
	// and scanned whatever it was given — the failure mode this whole boundary
	// exists to prevent, arriving through a typo in a path.
	// A path that names no file gets a new secret, so turning proof on is one
	// flag rather than a flag and a command to remember. Created exclusively
	// and readable by this user alone. A mistyped path therefore means a new
	// secret and every existing record refused, which fails closed: nothing is
	// scanned that was not proven to this secret. Here and not under -version,
	// which is a question and writes nothing.
	if *verifySecretFile != "" {
		if err := createSecret(*verifySecretFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	// The access file, the same way: a path that names no file gets one, with a
	// password printed once. Never on the demonstration, which is public by
	// design and keeps nothing to protect.
	if *accessFile != "" {
		if demo.Enabled {
			fmt.Fprintln(os.Stderr, "-access-file is not available on the demonstration, which is public and keeps nothing")
			return 2
		}
		if err := createAccess(*accessFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	scope, err := verificationScope(*verifySecretFile, *resolver)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *requireSigned {
		if scope == nil {
			fmt.Fprintln(os.Stderr, "-verification-requires-dnssec needs -verification-secret-file")
			return 2
		}
		scope.RequireSigned = true
	}

	// A service without proof is refused, wherever it listens.
	//
	// docs/scope.md said proof was on by default for a service and the code
	// did not (audit A01): a porchd bound to a public interface with no secret
	// scanned whatever anyone asked. Loopback stayed open after that, on the
	// ground that only this machine can reach it — and on 2026-09-29 that
	// ground was found to be thinner than it reads: another user on the
	// machine, another container, a web application with an SSRF in it and a
	// reverse proxy set up in a hurry all reach loopback too. Nothing turns
	// this off; -open did, and removedFlags says why it went. The
	// demonstration's hosts are compiled in, which is a narrower boundary
	// than any proof.
	if err := proofRequired(scope != nil || demo.Enabled); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// A flag that would do nothing is refused rather than ignored.
	//
	// -ask-responder discloses a certificate to the authority that issued it,
	// and that is a disclosure to make about your own estate: without a scope
	// the names are not the operator's. Accepting it silently would be the
	// failure the comment on -trusted-proxy-hops describes — a setting that
	// looks applied and is not, which is worse than not offering it.
	if *askResponder && scope == nil {
		fmt.Fprintln(os.Stderr, "-ask-responder needs -verification-secret-file: "+
			"the question names a certificate to its authority, which is a disclosure to make "+
			"only about domains this installation has been shown control of")
		return 2
	}

	// And a service beyond loopback has a password in front of it, always.
	// Proof of control is about which domains may be checked, not who may ask:
	// an example that dropped -access-file while adding a certificate (audit
	// 2026-09-18, D01) made every proven domain scannable by anyone who could
	// reach the address. The demonstration is public by design.
	if err := passwordAllowed(*listen, *accessFile != "" || demo.Enabled); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Behind a password the history is kept sealed. The results directory
	// writes a plain copy beside it, under the checked name, and the two
	// together kept in the clear what the password was there to seal (D02).
	// Asked for together, they are refused rather than one quietly winning.
	if *accessFile != "" && *resultsDir != "" {
		fmt.Fprintln(os.Stderr, "-results-dir keeps results in the clear, and -access-file keeps them "+
			"encrypted in History; use one. Existing files in the results directory are left as they are")
		return 2
	}

	// Printing what a domain must publish is a question, not a service, so it
	// answers and exits. It needs the secret and nothing else — no network, no
	// listener, and no trust store.
	if *verifyToken != "" {
		if scope == nil {
			fmt.Fprintln(os.Stderr, "-verification-token needs -verification-secret-file")
			return 2
		}
		fmt.Printf("%s.%s. IN TXT \"%s\"\n", verify.Label, *verifyToken, verify.Token(scope.Secret, *verifyToken))
		return 0
	}

	// An empty trust store is not a configuration, it is a wrong answer.
	//
	// Every chain a scan reads is judged against the trust store of the
	// machine this runs on. A machine with none — a container built FROM
	// scratch with nothing mounted is the ordinary way to get one — does not
	// fail to verify: it verifies everything as untrusted. The reports still
	// arrive, they are still confident, and every one of them says the
	// scanned server's certificate does not reach a trusted root.
	//
	// That is a finding about this machine printed as a finding about
	// somebody else's server, which is the exact failure this project exists
	// to avoid. So it refuses to start, and says where the store is looked
	// for rather than leaving the reader to guess.
	//
	// The pool is kept and handed to the scanner rather than read, checked
	// and dropped. It was dropped, and that was the defect: x509.Verify with
	// no Roots does not mean "the pool this program just looked at", it means
	// "decide for yourself" — and on Windows and macOS deciding means the
	// platform verifier, which reads a different store. So this check passed
	// against one store and every chain was then judged against another, on
	// the two platforms self-hosting is most likely to run on.
	roots, rootsErr := truststore.Resolve(nil)
	if err := trustStoreUsable(roots, rootsErr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be given together")
		return 2
	}

	limits := httpapi.Limits{
		RequestTimeout: *requestTimeout,
		MaxConcurrent:  *maxConcurrent,
		Burst:          *burst,
		Refill:         *refill,
		MaxTrackedIPs:  *maxTracked,
	}

	// The scanner is left at its defaults on purpose. It dials through
	// safedial, enforces the port allow list, and takes hostnames rather than
	// addresses. There is no flag here that would turn any of it off.
	//
	// Two things are passed in and both are boundaries this binary decided,
	// so both have to survive the trip. Roots is the pool checked above:
	// leaving it nil would send every verification back to whatever the
	// platform picks, which is the store this program did not check. Verify
	// is the scope read before that: leaving it nil is a service that scans
	// whatever it is asked to.
	api := httpapi.New(serviceScanner(roots, scope, *resolver, *askResponder, *requestTimeout), limits, nil)

	// Where results are kept, if anywhere. Before serving, like every other
	// piece of configuration here: a service that could start keeping records
	// while running would be one whose promise depends on when somebody looked.
	api.KeepResults(&results.Store{Dir: *resultsDir, Keep: *resultsKeep})
	api.UseHeloName(*heloName)

	// Whether anybody but this machine's operator can reach this service.
	//
	// It decides one thing: whether a capability meant for somebody looking at
	// their own estate is offered without proof. A copy nobody else can reach is
	// the command line with a browser in front of it, and the command line has
	// never asked the operator to prove they own their own domain.
	exposed := beyondLoopback(*listen)
	api.ReachableByOthers(exposed)

	// The monitor the inventory endpoint asks, if the operator named one.
	//
	// Off unless asked for, like every other question this service puts to a
	// third party: the question names a domain to somebody this project does not
	// run, and that is the operator's disclosure to enable rather than a default
	// to inherit (N12). Nil leaves the endpoint answering that this installation
	// has no monitor, which is true.
	if *namesMonitor != "" {
		searcher, err := namesSearcher(*namesMonitor, *namesMonitorURL, *requestTimeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		api.SearchNames(searcher)
	}

	// The demonstration lists this project's own estate, and both halves of
	// that are compiled in rather than flagged.
	//
	// A monitor, because the page promises what this build does and a unit
	// file is not the build: a flag left out of it would leave the
	// demonstration showing half an inventory while the privacy page described
	// a whole one. And a kept copy, because every visitor asks the same
	// question — producing it per visitor would spend crt.sh on an answer that
	// has not changed, and a page anybody can refresh would be a way to make
	// this installation hammer a third party.
	//
	// An hour: long enough that a monitor sees a handful of questions a day,
	// short enough that what each name is doing is still worth reading. The
	// answer carries the time it was made, so nobody has to take that on
	// trust.
	if demo.Enabled {
		api.SearchNames(&ctsearch.CRTSh{Timeout: *requestTimeout})
		api.ReadHostCertificates(&certnames.Reader{Timeout: *requestTimeout})
		api.KeepInventoryFor(time.Hour)

		// And a kept copy of every check's report, for the same reason and one
		// more. The demonstration shows the whole report of its own estate, so
		// a scan there asks a transparency monitor, the authority's revocation
		// list, the mail exchangers on port 25 and the servers of the zone
		// above as well as the host; a page anybody can refresh would make it
		// press on every one of them. Kept, each check runs at most once an
		// hour for each host, and the answer says when it was made.
		api.KeepReportsFor(time.Hour)
	}

	// The register, the same way: named or not asked. It is wired even where
	// no monitor is, so that the endpoint's refusal stays the monitor's to
	// decide — this adds a source to an inventory that is offered, and offers
	// none of its own.
	if *namesPassive != "" {
		register, err := namesRegister(*namesPassive, *namesPassiveURL, *requestTimeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		api.AskPassiveRegister(register)
	}

	// And the estate itself, where the operator asked for it. One handshake
	// per name that answers, nothing requested over it, and the certificate
	// read rather than judged — which is how a name a private authority issued
	// reaches an inventory at all.
	if *namesReadZone {
		api.ReadZoneTransfers(&zonenames.Reader{
			Resolver: &dnsclient.Client{Server: *resolver},
			Timeout:  *requestTimeout,
		})
	}

	if *namesWalkProofs {
		api.WalkAbsenceProofs(&nsecnames.Reader{
			Resolver: &dnsclient.Client{Server: *resolver},
			Timeout:  *requestTimeout,
		})
	}

	if *namesReadCertificates {
		api.ReadHostCertificates(&certnames.Reader{Timeout: *requestTimeout})
	}

	if *statsFile != "" {
		if snapshot, err := loadStats(*statsFile); err == nil {
			api.RestoreStats(snapshot)
		} else if !os.IsNotExist(err) {
			// A corrupt or unreadable file costs a counter, not a service.
			// Starting from zero is wrong; refusing to start is worse.
			fmt.Fprintf(os.Stderr, "counters could not be read from %s, starting from zero: %v\n", *statsFile, err)
		}
	}

	// The API and the pages are routed separately because they need different
	// security headers. The API needs no resources at all and denies
	// everything; a page needs its own stylesheet and script. Serving both
	// through one policy would mean the API inherits permission it never
	// needed, which is the usual way a strict header becomes a loose one.
	// The paths come from the API rather than being listed again here. A
	// second hand-written list is a list that falls behind, and one did: the
	// mail endpoint was registered inside the API and unreachable through this
	// binary, because this mux had never heard of it.
	root := http.NewServeMux()
	for _, path := range api.Paths() {
		root.Handle(path, api)
	}

	// Behind a password, every report is kept whole in a vault sealed by it,
	// beside the access file, and read back only through the gate. Without
	// one nothing of the sort exists: no vault, no route to one.
	var gate *access.Gate
	if *accessFile != "" {
		gate = access.NewGate(*accessFile, web.PublicPaths())
		history := &vault.Vault{Dir: filepath.Join(filepath.Dir(*accessFile), "history"), Key: gate.Key}
		api.KeepReports(history)
		root.Handle("/api/v1/history", history.Handler())
		root.Handle("/api/v1/history/", history.Handler())
		domains := &vault.Domains{Path: filepath.Join(filepath.Dir(*accessFile), "domains.sealed"), Key: gate.Key}
		root.Handle("/api/v1/domains", domains.Handler())
		root.Handle("/api/v1/domains/", domains.Handler())
	}

	// The pages are told what this installation is before any of them is
	// served. The console says whether a boundary was configured, and an
	// operator reading a report needs that to be true rather than plausible.
	// A password in front of the service means its callers are people the
	// operator let in, which is what decides whether an address range may be
	// walked: no proof can establish that a range belongs to whoever asked, so
	// it is read for whoever runs the installation and for nobody else.
	api.BehindPassword(gate != nil)

	web.Configure(web.Installation{
		Verified:          scope != nil,
		Keeps:             *resultsDir != "" || gate != nil,
		Guarded:           gate != nil,
		Monitor:           *namesMonitor,
		Register:          *namesPassive,
		ReadsCertificates: *namesReadCertificates,
		AsksResponder:     *askResponder,
		OperatorOnly:      !exposed || gate != nil,
	})
	root.Handle("/", web.Handler())

	// On the demonstration, a request for one of its two names that belongs
	// to the other is sent there — the API with the pages, so that nothing of
	// Porch's answers from the organisation's address. An installation is one
	// name and passes straight through. See web.Hosts.
	var handler http.Handler = web.Hosts(root)

	// The gate goes in front of everything, pages and API alike, so a route
	// added later is behind it without anybody remembering to put it there.
	// Only the sign-in page and what it draws with are open.
	if gate != nil {
		handler = gate.Wrap(handler)
	}

	// And in front of the gate, the one check every request meets: over plain
	// HTTP, only an address or localhost is answered. A page on another site
	// can point its own name at this machine and call the service through its
	// visitor's browser, and on loopback with no password that visitor is the
	// operator the service trusts. See httpapi.GuardHost.
	handler = api.GuardHost(handler)

	srv := &http.Server{
		Handler: handler,

		// ReadHeaderTimeout is the one that matters most. Without it, a
		// client can open a connection and send headers one byte at a time
		// for as long as it likes, holding a slot the whole while. A few
		// hundred such connections exhaust the server without sending a
		// single complete request. Go leaves this unset by default.
		ReadHeaderTimeout: 5 * time.Second,

		// ReadTimeout covers headers and body together, so a slow body gets
		// no more room than a slow header.
		ReadTimeout: 10 * time.Second,

		// WriteTimeout must outlast the scan or the response is truncated
		// while it is still being written.
		WriteTimeout: *requestTimeout + writeMargin,

		// IdleTimeout closes kept-alive connections that have gone quiet,
		// so an idle client cannot hold a slot indefinitely.
		IdleTimeout: 60 * time.Second,

		MaxHeaderBytes: maxHeaderBytes,

		// The default logger writes lines such as "http: panic serving
		// 203.0.113.7" to standard error. That is a client address in a log
		// file, which this project undertakes not to keep. The promise has to
		// survive a library default, so the logger is replaced rather than
		// trusted to stay quiet.
		ErrorLog: httpapi.SilentErrorLog(),

		// HTTP/2 is switched off. A non-nil but empty TLSNextProto is what
		// stops http.Server from enabling it alongside TLS.
		//
		// It is off because it adds attack surface and nothing this service
		// needs. The encryption is TLS's and is identical either way; what
		// HTTP/2 adds is multiplexing, and what it adds with it is a stream
		// state machine, flow control and HPACK — three mechanisms that have
		// each produced denial-of-service classes, Rapid Reset among them.
		// This site is four small files and one request, which keep-alive over
		// HTTP/1.1 covers entirely, so the protocol would be surface bought
		// with nothing.
		//
		// This note used to say that tuning HTTP/2 needs golang.org/x/net/http2
		// and that this project does not carry it. That stopped being true: Go
		// 1.26 has Server.Protocols and http.HTTP2Config, MaxConcurrentStreams
		// included, so the protocol could now be enabled and bounded from the
		// standard library alone. The decision is unchanged and the reason it
		// rests on is the one above — a reason that survives the toolchain
		// gaining the feature, which the old one did not.
		//
		// The scanner is not affected by any of this. What a target answers
		// with is what a report says it answered with, and "Served over" is a
		// row rather than a rule precisely because an operator may switch the
		// protocol off on purpose, as this does.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	if *tlsCert != "" {
		reloader, err := newCertReloader(*tlsCert, *tlsKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loading the certificate: %v\n", err)
			return 1
		}

		srv.TLSConfig = &tls.Config{
			// GetCertificate is consulted per handshake, so a renewal that
			// rewrites the files is picked up without a restart. Reading the
			// certificate once at startup would mean an outage every sixty
			// days, or a restart script nobody tests.
			GetCertificate: reloader.get,

			MinVersion: tls.VersionTLS12,

			// Session resumption is switched off.
			//
			// A ticket is a token the server hands out and the client
			// presents on its next connection. Nothing is written down here
			// — the state travels inside the ticket — but anyone watching
			// the wire sees the same token twice and learns that two
			// connections are the same person, across a change of address
			// and across days.
			//
			// This service undertakes not to record who asked about what. A
			// mechanism that lets somebody else do the correlating instead
			// is the same promise broken by a different party, and the site
			// is small enough that a full handshake each time costs nothing
			// worth having.
			SessionTicketsDisabled: true,

			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},

			// HTTP/2 is not offered, so it is not advertised either. A server
			// that names a protocol it will not speak invites a client to
			// select it and then fail.
			NextProtos: []string{"http/1.1"},
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Closed when the periodic writer has stopped, so the final write below is
	// the only writer left. Without it the two overlap during shutdown, which
	// is the one moment they are both certain to run.
	persistDone := make(chan struct{})
	if *statsFile != "" {
		go func() {
			defer close(persistDone)
			persistStats(ctx, api, *statsFile, statsInterval)
		}()
	} else {
		close(persistDone)
	}

	// Request-level limits arrive too late for one attack: a TLS handshake
	// costs an elliptic curve operation before any HTTP is parsed, so a
	// client that connects, completes a handshake and then does nothing never
	// reaches a single one of them.
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listening on %s: %v\n", *listen, err)
		return 1
	}
	listener = httpapi.LimitListener(listener, *maxConnections)

	errc := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			// The paths are already in TLSConfig.GetCertificate.
			errc <- srv.ServeTLS(listener, "", "")
			return
		}
		errc <- srv.Serve(listener)
	}()

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	// The only line this process prints in normal operation. It names the
	// service, not a request.
	fmt.Fprintf(os.Stderr, "porchd listening on %s://%s, policy %s\n",
		scheme, *listen, policy.TLSVersion)

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server stopped: %v\n", err)
			return 1
		}
		return 0

	case <-ctx.Done():
	}

	// Stop accepting, then give in-flight scans their remaining budget.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)

	// Written after the shutdown so the figure includes the scans that were
	// still running when the signal arrived. The timer writes at most a
	// minute behind; this makes the last write exact.
	if *statsFile != "" {
		// The periodic writer stops on the same context that stopped the
		// server, but it only checks between ticks. Waiting for it to return
		// means one writer at a time rather than two racing into the same
		// rename.
		<-persistDone
		if err := saveStats(*statsFile, api.Stats()); err != nil {
			fmt.Fprintf(os.Stderr, "counters could not be written to %s: %v\n", *statsFile, err)
		}
	}

	if shutdownErr != nil {
		// Forcing the close loses in-flight responses, which is the point of
		// reporting it rather than exiting quietly.
		fmt.Fprintf(os.Stderr, "shutdown did not complete within %s: %v\n", shutdownGrace, shutdownErr)
		_ = srv.Close()
		return 1
	}

	fmt.Fprintln(os.Stderr, "porchd stopped")
	return 0
}

// loadStats reads the counters left by a previous run.
func loadStats(path string) (httpapi.Snapshot, error) {
	var snapshot httpapi.Snapshot

	// The path comes from a command line flag set by whoever runs this
	// process. Nothing a stranger sends reaches here: the service has no
	// endpoint that names a file, and internal/httpapi touches no filesystem
	// at all. An operator who can pass this flag can already read the file
	// themselves.
	//
	// #nosec G304 -- operator-supplied path, never request-supplied
	body, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return snapshot, fmt.Errorf("parsing %s: %w", path, err)
	}
	return snapshot, nil
}

// saveStats writes the counters.
//
// The file holds totals and nothing else: no hostname, no address, no
// per-request timestamp. Whoever seizes this machine learns that the service
// was used and by how much, which is already published on the site, and
// learns nothing about who used it or what they looked at.
//
// The write goes to a temporary file, is synced, and is then renamed. A
// process killed mid-write would otherwise leave a truncated file the next
// start cannot read, and a machine that loses power would otherwise come back
// to a rename the disk never received. Rename is atomic on the filesystems
// this runs on, so a reader sees either the old file or the new one.
func saveStats(path string, snapshot httpapi.Snapshot) error {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	// A name of its own for each write, rather than one fixed ".tmp".
	//
	// The rename is atomic; what was not atomic was two writers sharing one
	// temporary. The periodic writer only notices a shutdown between ticks, so
	// a signal arriving mid-write leaves it finishing into the same path the
	// final write is about to truncate, and the file that survives is a mixture
	// of two. That is a corrupt counter rather than a lost one, and the
	// comment above promised a reader sees either the old file or the new.
	//
	// CreateTemp also refuses to reuse an existing name, so a temporary left
	// behind by a killed process cannot be written into by the next one.
	//
	// #nosec G304 -- the path is a command line flag, set by whoever started
	// this process. No request reaches it, and an operator who can pass a
	// flag can already write anywhere this process can. The rule is aimed at
	// paths that come from a caller; this one has no caller.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporary := f.Name()
	// Removed on every failure below. Left behind, it is a file of counters
	// nobody reads and nobody deletes.
	defer os.Remove(temporary)

	// CreateTemp makes the file 0600 already; setting it is what keeps that
	// true if the mode above ever changes.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// persistStats writes the counters periodically until the context ends.
func persistStats(ctx context.Context, api *httpapi.Server, path string, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	var last httpapi.Snapshot

	for {
		select {
		case <-ctx.Done():
			// The final write happens in run, after the shutdown, so that it
			// includes whatever finished during the grace period.
			return

		case <-ticker.C:
			current := api.Stats()
			if current.Equal(last) {
				// Nothing happened, so nothing is written. An idle service
				// leaves an idle file, and the modification time then says
				// only when the service last did something.
				continue
			}
			if err := saveStats(path, current); err != nil {
				fmt.Fprintf(os.Stderr, "counters could not be written to %s: %v\n", path, err)
				continue
			}
			last = current
		}
	}
}

// certReloader serves the current certificate from disk.
//
// Certificates now last a matter of weeks and are renewed by a timer. A
// process that reads the files once at startup goes on presenting an expired
// certificate until somebody notices, so the files are re-read when they
// change on disk.
type certReloader struct {
	certPath string
	keyPath  string

	mu       sync.RWMutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
}

// statInterval bounds how often the files are checked, so a busy server does
// not stat twice per handshake.
const statInterval = 30 * time.Second

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, last := r.cert, r.lastStat
	r.mu.RUnlock()

	if time.Since(last) < statInterval {
		return cert, nil
	}

	if changed, err := r.changed(); err == nil && changed {
		// A failed reload leaves the previous certificate in place. Serving a
		// certificate that worked a moment ago beats refusing every
		// handshake because a renewal wrote a partial file.
		_ = r.reload()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

func (r *certReloader) changed() (bool, error) {
	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return false, err
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	r.lastStat = time.Now()
	same := certInfo.ModTime().Equal(r.certMod) && keyInfo.ModTime().Equal(r.keyMod)
	r.mu.Unlock()

	return !same, nil
}

func (r *certReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("reading %s and %s: %w", r.certPath, r.keyPath, err)
	}

	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cert = &cert
	r.certMod = certInfo.ModTime()
	r.keyMod = keyInfo.ModTime()
	r.lastStat = time.Now()
	return nil
}

// serviceScanner is the scanner the service is built on.
//
// A function rather than a literal inside run(), so that what each flag
// reaches can be asserted: run() parses flags and binds a port. porch-scan
// learned this when its -resolver was parsed, documented and never assigned.
func serviceScanner(roots *x509.CertPool, scope *verify.Scope, resolver string, askResponder bool, timeout time.Duration) *scan.Scanner {
	scanner := &scan.Scanner{Roots: roots, Verify: scope}

	// What a service with proof of control may find out about the certificates
	// it is shown.
	//
	// Both of these were decided on this page years before they were wired to
	// anything. N12's table says a service that requires proof of control
	// searches the transparency logs with no switch, because the certificates
	// for a name are published to anyone who looks and the name belongs to
	// whoever proved it; the switch was written for the command line, where
	// the name may be somebody else's. The table said so and nothing in this
	// program did it.
	//
	// The responder is the other half and needs the switch, because what it
	// discloses is not public: the authority learns which certificate is being
	// looked at, from which address and when. R3a refused it to a service on
	// the ground that its operator had not chosen it scan by scan — and an
	// operator who passes a flag at start has chosen it for every scan the
	// installation will run, which is the same choice the command line makes
	// one scan at a time. Off by default, and only alongside proof of control:
	// without a scope the names are not the operator's to disclose.
	if scope != nil {
		scanner.Logs = &ctsearch.CRTSh{Timeout: timeout}
		if askResponder {
			scanner.Responder = &ocspquery.Fetcher{Timeout: timeout}
		}

		// Whether the report names the addresses a certificate gives for
		// checking its own revocation is not decided here. It is decided with
		// every other part of a report that is shown whole only to the person
		// it is about, in httpapi's operatorView, which covers a scope and
		// more: the demonstration's own estate, and a copy only its operator
		// can call.
	}

	// And the demonstration searches the logs too, with no scope: its hosts are
	// compiled in, so the name it asks about is only ever this project's own.
	// The responder stays out, because it is asked only where an operator said
	// so and nobody says so to the demonstration.
	if demo.Enabled {
		scanner.Logs = &ctsearch.CRTSh{Timeout: timeout}
	}

	// Always, and never nil. An empty Server already means this machine's own
	// configuration, which is what every check here falls back to anyway.
	//
	// It was set only where -resolver was given, out of care for a real trap:
	// a nil *dnsclient.Client copied into an interface field is not nil, so a
	// package reading "nil means build a default" never builds one and
	// dereferences nothing on first use. That trap needs a nil pointer, and
	// this is not one — internal/mailscan also refuses a typed nil of its own
	// accord now, which is where the guard belongs.
	//
	// What the condition cost was three of the inventory's four sources. The
	// domain's own records, what each name is doing now, and the certificates
	// its hosts present all hang off this field, and the certificates only run
	// where something answered — so a copy started without the flag read one
	// source and its page described four. The demonstration shipped that way
	// and reached denyfirst.dev; every self-hosted copy had it too, and said
	// "this installation has no resolver" to anybody who named an address
	// range.
	scanner.Resolver = &dnsclient.Client{Server: resolver}
	return scanner
}

// resolverAddress refuses a -resolver that is not an IP address and a port.
//
// Empty is accepted: it means this machine's own configuration.
func resolverAddress(resolver string) error {
	if resolver == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(resolver)
	if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" {
		return errors.New("-resolver must be an IP address and a port, such as 192.0.2.53:53 or [2001:db8::53]:53")
	}
	return nil
}

// trustStoreUsable reports whether chains can be judged against anything.
//
// Written to take what truststore.Resolve returns rather than to call it,
// because the standard library builds that pool once per process: a test that
// arranged an empty store would get whatever the first caller in the test
// binary had already cached, and would pass or fail on the order the tests ran
// in. The decision is the part worth testing, so the decision is the part that
// is separable.
func trustStoreUsable(pool *x509.CertPool, err error) error {
	if err != nil {
		return fmt.Errorf("the system trust store could not be read: %w", err)
	}
	if pool == nil || pool.Equal(x509.NewCertPool()) {
		// One line, lower case, no full stop. An error string is a fragment
		// that callers wrap and print in sentences of their own, which is why
		// staticcheck refuses a capital or a newline in one (ST1005) — and
		// why the guidance is joined on with a semicolon rather than set on a
		// second line.
		return errors.New("the system trust store is empty, so every certificate would be reported " +
			"as untrusted; mount a trust store, or point SSL_CERT_FILE or SSL_CERT_DIR at one")
	}
	return nil
}

// versionLines is what -version prints: the release, every rule set this
// binary grades by, and the reach line last, where the deploy check reads it.
//
// Every rule set, and a test holds it to that. It named three of four until
// 2026-09-28: the DNS check has graded by porch-dns-v2 since it was written and
// -version never said so, so a reader holding a DNS report could not learn from
// the binary which rules had produced it.
func versionLines(reach string) string {
	return fmt.Sprintf("porchd %s\npolicy %s\npolicy %s\npolicy %s\npolicy %s\n%s\n",
		version, policy.TLSVersion, policy.WebVersion, policy.MailVersion, policy.DNSVersion, reach)
}

// reach says which hosts this binary will connect to.
//
// Written from the same list the scanner enforces rather than from a constant
// of its own, so a binary cannot say one thing and do another.
//
// Two sources of authority, and the line has to carry both or it is false for
// half the deployments that read it. The compiled-in list is fixed at build
// time; the verification scope is established when the process starts. A line
// that named only the first told an operator running a bounded service that it
// "scans whatever it is pointed at", which is the sentence they would read as
// a reason to check their configuration — and a line that is wrong in the
// alarming direction is still a line nobody trusts the second time.
//
// scoped is whether a proof of control is required, which the caller knows and
// this does not: it is decided by a flag, and reading it here would put the
// flag in two places.
func reach(scoped bool) string {
	if demo.Enabled {
		hosts := demo.Targets()
		if len(hosts) == 0 {
			return "scans nothing: this is a demonstration build with an empty list"
		}
		return "demonstration: scans " + strings.Join(hosts, ", ") + " and nothing else"
	}

	if scoped {
		return "scans only domains it has been shown control of"
	}
	// Not a configuration porchd starts in: proofRequired refuses it. Said
	// here for -version, which answers without starting.
	return "will not start: it scans only domains it has been shown control of, and was given no -verification-secret-file"
}

// verificationScope reads the deployment secret, or reports why it could not.
//
// Nil and no error means no proof is required. That is the state docs/scope.md
// calls the open one, and openAllowed keeps it to loopback unless the operator
// says -open: a service beyond loopback that scans anything was the default
// until the 2026-09-16 audit (A01) found the page promising otherwise.
//
// The secret is read from a file rather than a flag: a flag value is in the
// process list, where every user on the machine reads it.
//
// resolver is the -resolver flag. The challenge is not read through it: it is
// read from the zone's own servers, reached from the root, and the resolver is
// asked only for the signed bit -verification-requires-dnssec wants.
func verificationScope(path, resolver string) (*verify.Scope, error) {
	if path == "" {
		return nil, nil
	}

	secret, err := verify.ReadSecret(path)
	if err != nil {
		return nil, err
	}

	return &verify.Scope{
		Secret: secret,

		// The challenge is read from the zone's own servers, from the root,
		// and no resolver's word is taken for it. The resolver stays for the
		// signed bit -verification-requires-dnssec asks for, and a record then
		// counts only where both carry it.
		Authority: &dnsclient.Authority{Client: &dnsclient.Client{Timeout: 3 * time.Second}},
		Resolver:  &dnsclient.Client{Server: resolver},

		// The file method, for teams without access to their own DNS. It
		// is consulted only when the zone proof was not found, and only for
		// a check that reads a site the way a browser does — a file proves
		// control of one hostname over HTTPS and nothing about port 993 on
		// the same name.
		Fetcher: &challenge.Fetcher{},
	}, nil
}

// secretOut is where the creation of a secret is announced.
var secretOut io.Writer = os.Stderr

// createSecret writes 32 random bytes, base64-encoded, to path if nothing is
// there. An existing file is left alone, whatever it holds: reading and judging
// it is verificationScope's job.
func createSecret(path string) error {
	created, err := verify.CreateSecret(path)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintln(secretOut, "a new verification secret was written; every domain has to publish its record again")
	}
	return nil
}

// proofRequired refuses a service that would scan a domain nobody proved,
// wherever it listens.
func proofRequired(scoped bool) error {
	if scoped {
		return nil
	}
	return errors.New("porchd scans only domains it has been shown control of: " +
		"anyone who can reach it — on this machine or beyond it — could otherwise point it at " +
		"any host, from this machine's address. Add -verification-secret-file")
}

// removedFlags refuses the two flags that turned the rules above off, and
// says why they went.
//
// -open served any name beyond loopback, and -without-password served anyone.
// Each was a sentence in its help text — "only for a network nobody else can
// reach" — and nothing that could check it: an operator's belief about their
// network was the whole of the boundary. A porchd reachable by others scans
// only what it has been shown control of, for whoever signed in, with no
// switch. Scanning a name nobody proved is what porch-scan is for, run by the
// person at the terminal, who is the one answerable for it.
func removedFlags(args []string) error {
	for _, arg := range args {
		if arg == "--" {
			return nil
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch name {
		case "open":
			return errors.New("-open was removed: porchd always requires " +
				"-verification-secret-file, loopback included, and so does porch-scan")
		case "without-password":
			return errors.New("-without-password was removed: porchd beyond loopback always " +
				"requires -access-file")
		}
	}
	return nil
}

// beyondLoopback reports whether an address somebody other than this machine's
// operator could reach.
//
// One function, because two things now depend on the answer and a second
// reading of it is a second thing to keep in step (N6): whether this service
// may start at all without proof, and whether a capability meant for the
// operator's own machine is offered.
//
// An address that cannot be parsed is treated as reachable. Guessing in the
// direction of "nobody else can see this" is the guess that costs something,
// and the one that would be made silently.
func beyondLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return true
	}
	if host == "localhost" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err != nil || !ip.IsLoopback()
}

// createAccess writes an access file with a new password if nothing is at
// path, and says the password once. An existing file is left alone: replacing
// it would make everything kept under its key unreadable, which is a decision
// made by deleting it, not a side effect of starting.
func createAccess(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("the access file could not be read: %w", err)
	}
	password, err := access.GeneratePassword()
	if err != nil {
		return err
	}
	// Before the new key exists, what the old one sealed goes aside, or the
	// new key meets it and cannot open it (audit 2026-09-18, D03 and D09).
	retired, err := retireSealed(filepath.Dir(path), time.Now().UTC().Format("2006-01-02"))
	if err != nil {
		return err
	}
	if err := access.Create(path, password); err != nil {
		return err
	}
	fmt.Fprintf(secretOut, "porchd: this installation's password is\n\n    %s\n\n"+
		"Sign in with it and change it. It is shown once and written nowhere. If it is\n"+
		"lost, move %s aside and restart for a new one; what was kept under the\n"+
		"old one can no longer be read with the new one.\n", password, path)
	if retired != "" {
		fmt.Fprintf(secretOut, "\nWhat the earlier password kept was moved, not deleted, to\n\n    %s\n\n"+
			"It opens only with the earlier access file and its password. Delete the\n"+
			"folder once you are sure nobody needs it.\n", retired)
	}
	return nil
}

// sealed names what an installation keeps under its data key, beside the
// access file. The same names main makes the vault with.
var sealed = []string{"history", "domains.sealed"}

// retireSealed moves whatever an earlier key sealed into a new folder named
// for the date, and says where; it returns "" when there was nothing.
//
// A new access file makes a new data key. What the old key sealed does not
// open under it, and left in place it made the domain list refuse every
// change and the history count files it could not see. Nothing is deleted:
// whoever has the old access file and remembers its password can put both
// back, and only the person who runs the machine decides the rest.
func retireSealed(dir, today string) (string, error) {
	var found []string
	for _, name := range sealed {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			found = append(found, name)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("what the earlier password kept could not be read: %w", err)
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	var to string
	for i := 1; ; i++ {
		to = filepath.Join(dir, "retired-"+today)
		if i > 1 {
			to += fmt.Sprintf("-%d", i)
		}
		err := os.Mkdir(to, 0o700)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("what the earlier password kept could not be moved aside: %w", err)
		}
	}
	for _, name := range found {
		if err := os.Rename(filepath.Join(dir, name), filepath.Join(to, name)); err != nil {
			return "", fmt.Errorf("what the earlier password kept could not be moved aside: %w", err)
		}
	}
	return to, nil
}

// passwordAllowed refuses a service without a password on an address other
// than loopback. The same shape as openAllowed: loopback is reachable only
// from this machine.
//
// It reads the address through beyondLoopback, as openAllowed does. It had a
// reading of its own that answered the other way for an address it could not
// parse — reachable to one, loopback to the other — which is the second copy
// of one decision that beyondLoopback exists to prevent.
func passwordAllowed(listen string, guarded bool) error {
	if guarded || !beyondLoopback(listen) {
		return nil
	}
	return errors.New("porchd will not listen beyond loopback without a password: anyone who " +
		"can reach it could use it. Add -access-file")
}

// namesSearcher builds the transparency monitor the inventory endpoint asks.
//
// The same two this command line offers everywhere else, named rather than
// described by an address, because which monitor is being asked decides how its
// answer is read. crt.sh and SSLMate agree on nothing but the idea.
func namesSearcher(name, address string, timeout time.Duration) (ctsearch.EstateSearcher, error) {
	if err := httpsEndpoint(address); err != nil {
		return nil, fmt.Errorf("-names-monitor-url: %w", err)
	}
	switch name {
	case "crtsh":
		if address != "" && !strings.Contains(address, "%s") {
			return nil, fmt.Errorf("-names-monitor-url for crtsh needs %%s where the name goes")
		}
		return &ctsearch.CRTSh{Timeout: timeout, Endpoint: address}, nil
	case "certspotter":
		// From the environment rather than a flag: a credential on a command
		// line is a credential in a process listing, and this one is read by
		// the service as it starts.
		return &ctsearch.CertSpotter{
			Timeout:  timeout,
			Endpoint: address,
			Token:    os.Getenv("CERTSPOTTER_TOKEN"),
		}, nil
	}
	return nil, fmt.Errorf("unknown -names-monitor %q: it is crtsh or certspotter", name)
}

// namesRegister builds the passive register the inventory asks, where one was
// named.
//
// The key is read from the environment, as the monitor's is, and a register
// named with no key is refused at startup rather than at the first request:
// naming somebody's domain to a company that will not answer buys nothing and
// discloses the same thing a successful search would. An operator finds out
// when they start the service, which is when they can fix it.
func namesRegister(name, address string, timeout time.Duration) (passivedns.Register, error) {
	if err := httpsEndpoint(address); err != nil {
		return nil, fmt.Errorf("-names-passive-url: %w", err)
	}
	switch name {
	case "securitytrails":
		token := os.Getenv("SECURITYTRAILS_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("-names-passive securitytrails needs a key in SECURITYTRAILS_TOKEN")
		}
		return &passivedns.SecurityTrails{Timeout: timeout, Endpoint: address, Token: token}, nil
	case "virustotal":
		token := os.Getenv("VIRUSTOTAL_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("-names-passive virustotal needs a key in VIRUSTOTAL_TOKEN")
		}
		return &passivedns.VirusTotal{Timeout: timeout, Endpoint: address, Token: token}, nil
	}
	return nil, fmt.Errorf("unknown -names-passive %q: it is securitytrails or virustotal", name)
}

// httpsEndpoint refuses a monitor or register address that is not HTTPS.
//
// Either is asked about a domain, and a register or CertSpotter is sent the
// operator's key with the question. The dialler allows port 80 for both, so an
// http:// address given here sent the key and the domain across every network
// on the way in the clear — a credential somebody pays for, and the disclosure
// N12 is written about, handed to whoever is on the path. Empty is the
// provider's own address, which is HTTPS.
//
// No userinfo either: a key belongs in the environment, where the builders
// above read it, and not in an address that is printed in an error.
func httpsEndpoint(address string) error {
	if address == "" {
		return nil
	}
	// The monitor's address carries %s where the name goes, which is not a
	// valid escape; it is read as the name it will become.
	u, err := url.Parse(strings.ReplaceAll(address, "%s", "name"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("the address must be an https:// URL with a host and no credentials in it, " +
			"because the question names a domain and may carry this installation's key")
	}
	return nil
}

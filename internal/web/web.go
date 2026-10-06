// Package web serves the pages a person sees.
//
// Everything is embedded in the binary. That is not only a convenience: a
// handler that reads from disk has a path to get wrong, a directory that can
// be listed, and a traversal to defend. An embedded filesystem has fixed
// contents decided at build time, so none of those questions arise.
//
// The routes are an explicit table rather than a file server. The same
// reasoning applies as to hostname characters elsewhere in this project:
// listing what is allowed cannot be surprised by something nobody thought to
// forbid.
//
// Pages share one layout. Four copies of a header would be four places for
// it to drift, and a footer that disagrees with itself is a small thing that
// costs more than it looks on a site whose argument is that it can be
// checked. Each page is a fragment; the shell is applied once at startup and
// the result is served as fixed bytes.
package web

import (
	"bytes"
	"embed"
	"encoding/xml"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/httpapi"
	"github.com/denyfirst/porch/internal/ociimage"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/promises"
)

//go:embed assets
var assets embed.FS

// contentSecurityPolicy is deliberately not the one the API uses.
//
// The API returns JSON and needs nothing at all, so its policy denies
// everything. A page needs a stylesheet and, on one route, a script, so its
// policy must be looser. Sharing one policy between them is the usual way a
// strict header quietly becomes a permissive one: the page forces 'self' into
// it, and the API silently inherits permission it never needed.
//
// There is no 'unsafe-inline' anywhere, which is what makes this policy worth
// having. That in turn is why there is no inline style or script in any asset.
// The two trusted-types directives are the same rule as the test in
// internal/web that forbids innerHTML in app.js, moved from build time to run
// time. The test reads the file this repository ships; the header binds the
// script the browser actually ran. They answer different questions and the
// second is the one a user is exposed to, so a page that argues its script
// cannot reach a markup parser should say so where a browser can enforce it.
//
// 'none' rather than a policy name because app.js creates no policy: it builds
// every node with createElement and textContent, so there is no sink to feed
// and nothing to allow. Browsers that do not implement this ignore both
// directives, which costs nothing and is why they are safe to send.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"require-trusted-types-for 'script'; " +
	"trusted-types 'none'"

// SiteURL is where the demonstration is served from, and it is written down
// for one job: the address a page gives as its own.
//
// Search engines had the old shape of this project — a TLS checker called
// denyfirst — because that is what the pages said for months, and the pages
// now say something else. A canonical address and the same title in the
// social tags is how a page states which address it is, so that the one being
// read is the one indexed.
//
// Only the demonstration says it. An installation somebody runs is on their
// address, not ours, and pointing it here would tell a search engine their
// pages are copies of ours.
//
// SiteURL is the organisation's address since 2026-10-05: the front page, the
// organisation's undertakings, and the contacts RFC 9116 points at. Porch's
// pages and its API are at PorchURL, a name of their own, so that a second
// product beside it has one too and neither speaks from the other's address.
// What is at each is decided by organisationPaths and the Hosts handler.
const (
	SiteURL  = "https://denyfirst.dev"
	PorchURL = "https://porch.denyfirst.dev"
)

// SecurityTxtPath is where RFC 9116 requires the file to be served, and where
// the demonstration serves ours. An installation serves nothing there; see
// denyfirstFiles.
//
// Exported because the test parses the same file the handler serves, and a
// second copy of this string is a second thing to keep in step.
const SecurityTxtPath = "/.well-known/security.txt"

// PGPKeyPath serves the key a reporter encrypts to.
const PGPKeyPath = "/pgp-key.txt"

// PGPFingerprint identifies the key at PGPKeyPath.
//
// A key served from this domain and identified only by this domain proves
// nothing: whoever takes the domain serves their own key beside their own
// fingerprint, and a reporter encrypts an unpublished vulnerability straight
// to them. The fingerprint is therefore also in SECURITY.md, which lives on
// GitHub behind a different account and a different set of credentials. A
// reporter compares the two; taking one is not taking both.
//
// A test fails if the two copies disagree, because two sources that always
// agree because nobody checks are one source written twice.
const PGPFingerprint = "75B7A18A89715E3775DBCA2EA8D994D1221AA045"

// page is one rendered document.
type page struct {
	Title       string
	Description string

	// Fragment names the file holding the body.
	Fragment string

	// Script is true only where one is needed. A page that carries no script
	// should not load one, however harmless it is: the fewer routes that
	// execute code, the smaller the question of what that code does.
	Script bool

	// Data, when set, means the fragment is a template rather than fixed
	// markup, and is executed with this value before the layout wraps it.
	//
	// One page needs it. The limits of this method are declared once in
	// internal/policy, where the code that emits them lives, and the page
	// that explains them ranges over that declaration. Copying the sentences
	// into the markup would put them in two places, and two places drift —
	// which is the whole argument of R16, applied to a third renderer.
	Data any

	// Section is which part of an installation's workspace the page belongs
	// to: check, domains, history or installation, or reference for the
	// documents. The rail marks it current. Empty is reference, set by render;
	// the demonstration has no rail and ignores it.
	Section string

	// SignedIn says the page is behind a password, so it offers a way to sign
	// out. Set by render.
	SignedIn bool

	// Heading is what the workspace's top bar names the page, set by render
	// from Section where a page gives none.
	Heading string

	// Brand is true on the demonstration, which is the denyfirst site and
	// carries its wordmark; an installation somebody runs is porch, by
	// denyfirst, and says so in the footer. Set by render from the build.
	Brand bool

	// Organisation marks a page that speaks for denyfirst rather than for
	// Porch: the front page and the organisation's undertakings. On the
	// demonstration, which is the denyfirst site, it shows no verdict and its
	// links and buttons keep the brand red; every other page draws them in
	// Porch's violet, which no verdict uses. An installation is Porch from end
	// to end, names its maker only in the footer, and ignores it.
	Organisation bool

	// Path is the address this page is served at, set at startup from the
	// table, and Canonical is that address on the demonstration's own host.
	// Empty on an installation somebody runs, where the layout then sends no
	// canonical address and no social tags at all.
	Path      string
	Canonical string

	// SiteBase and PorchBase are what the layout puts in front of a link to
	// the organisation's pages and to Porch's: the two addresses on the
	// demonstration, where they are different names, and nothing on an
	// installation, where every page is its own. Set by render.
	SiteBase  string
	PorchBase string

	// Body is filled in at startup. It is template.HTML because the fragment
	// is a file in this repository rather than anything a user supplied.
	Body template.HTML
}

// pages is the whole site.
//
// There were five of these and now there are three. Splitting the
// explanation across separate pages for scanning, privacy and guarantees
// meant a reader had to already know which one answered their question, and
// somebody who arrives because a scan reached their server does not. One page
// with headings and a set of jump links reads better than three that each
// tell a third of the story.
var pages = map[string]*page{
	// The scanner has an address of its own.
	//
	// It was at "/", which is the project's address rather than this check's.
	// One service and one site were the same thing while there was one
	// service; they stop being the same thing the moment there is a second,
	// and by then every report anybody has shared points at "/" — so the
	// front page cannot become a front page without moving the tool out from
	// under those links.
	//
	// Moved now, while nobody is hurt by it. What is at "/" today is a
	// temporary redirect here, and when the project has a front page to put
	// there the redirect goes and this address does not move.
	"/tls": {
		Title:       "Transport check — Porch by denyfirst",
		Description: "Checks a server's TLS versions, ciphers and certificate against cited standards.",
		Fragment:    "assets/index.html",
		Script:      true,

		// The page has to say which deployment it is, because the two answer
		// differently and a visitor who cannot tell them apart will read a
		// refusal as a fault. One template, branching once, rather than two
		// pages that drift.
		Data: scanPage{Demo: demo.Enabled, Hosts: demo.Hosts()},
	},
	"/privacy": {
		Title:       "Privacy — Porch by denyfirst",
		Description: "What this service keeps, what a scan sends, and how to stop one.",
		Fragment:    "assets/privacy.html",
	},
	// The organisation's undertakings, whatever you run.
	"/organisation": {
		Title:        "What the maker undertakes — denyfirst",
		Organisation: true,
		Description:  "What denyfirst undertakes for everything it publishes, and how to check each one.",
		Fragment:     "assets/organisation.html",
		Data: organisationPage{
			Organisation: promises.Organisation,
			Products:     productPages(),
		},
	},
	// What Porch adds to the organisation's undertakings, on Porch's own name.
	undertakingsPath: {
		Title:       "What Porch undertakes — Porch by denyfirst",
		Description: "What Porch adds to denyfirst's undertakings, and how to check each one.",
		Fragment:    "assets/undertakings.html",
		Data: undertakingsPage{
			Product:  promises.Porch,
			SiteBase: siteBase(),
		},
	},
	// The name inventory, and the page that says what it cannot show.
	//
	// Its own address space rather than a section under a check: it grades
	// nothing, it is about a domain rather than a host, and it carries a
	// paragraph about its own limits that would read as a disclaimer if it sat
	// inside a graded report.
	// The data is here rather than only on the demonstration's branch, and
	// that is not tidiness: render parses a fragment as a template only where
	// there is data for it, so a page whose fragment gained a condition and
	// whose entry did not gain a value serves `{{if .Demo}}` to a reader as
	// text. Every self-hosted copy of v0.23.x did.
	"/names": {
		Title:       "The names under your domain — Porch by denyfirst",
		Description: "Lists the names under a domain from public certificates and its DNS records.",
		Fragment:    "assets/names.html",
		Script:      true,
		Data:        namesPage{},

		// Named, because render defaults a page with no section to the
		// reference one — and the rail then drew the current-page mark on
		// Docs while somebody stood on Names. A workspace page that says
		// which part of the workspace it is cannot be marked as another.
		Section: "names",
	},

	"/terms": {
		Title:       "Terms of use — Porch by denyfirst",
		Description: "What you agree to when you use this, and what a result is not.",
		Fragment:    "assets/terms.html",
		Data:        struct{ Demo bool }{demo.Enabled},
	},

	// The web check, beside the TLS one rather than under it.
	//
	// Neither is a subset of the other. A site can negotiate TLS 1.3 with a
	// clean chain and still serve content on port 80 with no policy declared,
	// and the handshake check grades that host strong — correctly, and while
	// saying nothing about the way it is actually reached. Two checks, two
	// addresses, two rule sets, and a front page at "/" later that runs both
	// against one name.
	"/web": {
		Title:       "Reach check — Porch by denyfirst",
		Description: "Checks HTTPS redirects, HSTS, cookies and headers.",
		Fragment:    "assets/web.html",
		Script:      true,
		Data:        scanPage{Demo: demo.Enabled, Hosts: demo.Hosts()},
	},
}

// scanPage is what assets/index.html branches on.
type scanPage struct {
	// Demo is true in the build that runs on denyfirst.dev.
	Demo bool

	// Hosts is what that build offers, and is empty in the other one.
	Hosts []demo.Host
}

// ToolName is what this tool is called on the pages it serves.
//
// One constant, because the name appears in a heading, in a page title and in a
// description, and three copies of a name is three places for it to be changed
// in two. It is deliberately not the rule-set names: those carry the name too,
// and they are declared in internal/policy where the rules are, so that a
// report and the page that explains it cannot disagree about which tool graded
// it.
const ToolName = "porch"

// consoleCheck is one row of the console's check list.
//
// Built from internal/policy rather than written into the markup, so the rule
// set a box offers is the rule set the report comes back carrying. A page that
// named its own would be a second source for the one string a reader uses to
// decide whether two reports are comparable.
type consoleCheck struct {
	ID     string
	Label  string
	Says   string
	Policy string

	// Page is where this row goes instead of being run beside the others.
	//
	// Empty for a check: a box the console ticks, runs, and reports under the
	// same heading as the rest. Set for the name inventory, which is on this
	// list because that is where somebody looks and is not a check — it asks
	// about a whole domain rather than one host, it grades nothing, and it
	// takes an input the four boxes have no field for: an address range.
	//
	// A box was tried first and was worse than either option it sat between.
	// The console has nowhere to type a range, so a run from here reported the
	// reverse walk as never asked, every time, with nothing on the page to do
	// about it — a control that half-runs the thing it offers. A door to the
	// page that runs all of it costs one click and hides nothing.
	Page string
}

// consolePage is what assets/console.html reads.
type consolePage struct {
	Tool   string
	Checks []consoleCheck

	// Guarded says a password is in front of this installation.
	Guarded bool

	// Keeps says this installation writes results to disk.
	//
	// The console said "Not kept" unconditionally, which was true of every
	// installation until one could be told to keep them. A page still saying it
	// after an operator set -results-dir would be telling them their own
	// configuration did not take — and the sentence it replaces is the one they
	// would have read as a promise.
	Keeps bool

	// Verified says this installation was given a boundary, and ReadsPages
	// follows from it: a page is read only where control was proven.
	//
	// Both are on the page because an operator reading a report has to know
	// which were true when it was produced. A report silent about mixed content
	// because no body was read looks exactly like one silent because the page
	// had none, and only one of those is a fact about the site (R4).
	Verified   bool
	ReadsPages bool
}

// consoleChecks is the list the console offers, in the order it runs them.
//
// Named for what each one reads rather than for how hard it pushes. docs/scope.md
// refuses the words full, deep and active, because each quietly authorises
// something this project has already declined to do, and a control labelled
// "Full scan" would undo that argument in the one place a user actually looks.
func consoleChecks() []consoleCheck {
	return []consoleCheck{
		{"tls", "Transport", "TLS versions, ciphers and the certificate", policy.TLSVersion, ""},
		{"web", "Reach", "HTTPS redirects, HSTS, cookies and headers", policy.WebVersion, ""},
		{"mail", "Mail", "SPF, DKIM, DMARC, MTA-STS and the mail servers", policy.MailVersion, ""},
		{"dns", "DNS", "name servers, DNSSEC and zone transfers", policy.DNSVersion, ""},

		// The inventory, last, and a door rather than a box.
		//
		// It was reachable only from its own page until 2026-09-28, which
		// meant somebody had to know it existed to find it — the worst way to
		// offer the one mode that answers "what have I got". It is on the
		// list now, and it opens the page that runs all of it: the console
		// has no field for an address range, so a box here reported the
		// reverse walk as never asked every time it ran, with nothing on the
		// page to do about it.
		//
		// The column where the others carry a rule-set name carries a word,
		// so nothing on the row claims a verdict is coming.
		{"names", "Names", "names under the domain, from certificates and DNS",
			policy.Informational, "/names"},
	}
}

// moved are paths that used to be pages of their own, or that a reader is
// likely to guess.
//
// A permanent redirect rather than a 404, because the old address is the one
// printed on a scanning notice and may be sitting in somebody's notes.
//
// /security.txt is here for a different reason. RFC 9116 puts the file under
// /.well-known/ and treats the top-level path as legacy, but a person looking
// for a way to report a vulnerability will try the short one, and answering
// that with a 404 costs a report. Redirecting rather than serving two copies
// keeps the canonical URL in the file true.
var moved = map[string]string{
	"/scanning": "/privacy#scans",
	"/about":    "/privacy",

	// How the checks work, and the docs, are on GitHub. These addresses are
	// in user agents, command-line output and reports already shared.
	"/docs":         DocsURL,
	"/method":       ChecksURL + "#tls",
	"/tls/method":   ChecksURL + "#tls",
	"/web/method":   ChecksURL + "#web",
	"/mail/method":  ChecksURL + "#mail",
	"/dns/method":   ChecksURL + "#dns",
	"/names/method": ChecksURL + "#names",
}

// DocsURL is where Porch's documentation is, and ChecksURL the document on
// how each check works, which reports and the command line link to.
const (
	DocsURL   = "https://github.com/denyfirst/porch/tree/main/docs"
	ChecksURL = "https://github.com/denyfirst/porch/blob/main/docs/checks.md"
)

// standingIn are addresses serving something other than what they will serve,
// and there are none.
//
// It is empty rather than gone because the distinction it holds is worth
// keeping: a permanent redirect is a promise that an address has finished
// changing, and a temporary one is the opposite promise. `moved` above is for
// the first. This is where an address of the second kind goes, so that nobody
// writing a route has to work out which kind they meant from the status code
// somebody else typed.
//
// It held "/" until both builds had a front page. The demonstration's root
// stood in for /tls while there was one check to explain — a console asking a
// visitor to pick between checks answered a question they had not asked — and
// an installation's root stood in for the tool. Both have a page of their own
// now, so nothing stands in for anything.
//
// This comment said otherwise until 2026-09-25, in twenty-four lines describing
// a project with one check and a root that redirects. It sat directly above a
// function whose own comment said the opposite, which is the state a comment
// reaches when the code under it is changed and the paragraph above it is not.
// In a project whose method is that the reasoning is written down, that is a
// defect rather than untidiness: a reader who trusts it learns a routing model
// this program does not have.
//
// Every response here carries Cache-Control: no-store, so neither kind is
// cached in practice. The status code is still the honest one, because it is
// read by people and by intermediaries that ignore the header.
var standingIn = map[string]string{}

// servedFile is an asset served as it is.
type servedFile struct {
	name        string
	contentType string
}

// files are the assets served as they are.
var files = map[string]servedFile{
	"/style.css":   {"assets/style.css", "text/css; charset=utf-8"},
	"/app.js":      {"assets/app.js", "text/javascript; charset=utf-8"},
	"/theme.js":    {"assets/theme.js", "text/javascript; charset=utf-8"},
	"/session.js":  {"assets/session.js", "text/javascript; charset=utf-8"},
	"/hero.js":     {"assets/hero.js", "text/javascript; charset=utf-8"},
	"/favicon.svg": {"assets/favicon.svg", "image/svg+xml"},
}

// denyfirstFiles are this project's own contacts: where to report a security
// problem in it, and the key to encrypt the report to. The demonstration
// serves them, because it is denyfirst.dev. Nothing else does.
//
// Every build served them until 2026-09-28, and on an installation each one
// was wrong. Its Canonical named denyfirst.dev, so by RFC 9116 the file was
// not authoritative for the host serving it. It sent somebody who found a
// fault in that host — somebody else's machine — to us, who cannot fix it and
// should not be told about it. Its Expires date was fixed in the binary, so an
// installation left on one release would one day serve a lapsed file, which
// D1 calls worse than none. And it answered anyone who could reach an
// installation with our name, which is a way to find installations of this
// tool that their operators never agreed to. An operator who wants a
// security.txt publishes their own, naming themselves.
var denyfirstFiles = map[string]servedFile{
	SecurityTxtPath: {"assets/security.txt", "text/plain; charset=utf-8"},

	// text/plain rather than application/pgp-keys, so a browser shows it
	// instead of offering to download a file a reporter then has to find.
	// gpg reads it either way.
	PGPKeyPath: {"assets/pgp-key.txt", "text/plain; charset=utf-8"},
}

// rendered holds every page as finished bytes.
//
// Built once at startup rather than per request. A template executed on every
// request is a small cost and a large surface: nothing here varies per
// visitor, so nothing here should be assembled per visitor.
var rendered = map[string][]byte{}

func init() {
	// Our contacts, and the short path to them, on the one deployment that is
	// ours to answer for.
	if demo.Enabled {
		for path, file := range denyfirstFiles {
			files[path] = file
		}
		moved["/security.txt"] = SecurityTxtPath
	}

	// The denyfirst front page and the Porch page exist on the demonstration
	// only. An installation somebody runs is the tool at "/" and needs
	// neither: nobody there needs the product explained to them.
	if demo.Enabled {
		pages["/"] = &page{
			Title:        "denyfirst — independent security and privacy tools",
			Organisation: true,
			Description:  "denyfirst builds security and privacy tools that keep your data with you. Porch checks TLS, websites, mail and DNS.",
			Fragment:     "assets/home.html",
		}
		// The name inventory is here, and it lists this project's own estate.
		//
		// Both pages were deleted until 2026-09-27, on the ground that this
		// deployment queries no transparency log. That promise was written
		// when the demonstration scanned whatever it was given, and it
		// protected a visitor's domain from being named to a monitor. The
		// hosts this build may touch are compiled in, so there is no visitor's
		// domain to protect any more — and what the deletion cost was the
		// demonstration of the one mode that reads several sources and says
		// which named what. A demonstration that shows less than the product
		// misrepresents it downwards.
		//
		// The form is fixed to the estate this deployment owns rather than
		// left open, because an open field on a page that then refuses is the
		// thing the deletion was right about (N12).
		pages["/names"].Data = namesPage{Target: demoDomain(), Demo: true}

		pages["/porch"] = &page{
			Title:       "Porch — TLS, web, mail and DNS checks — denyfirst",
			Description: "Porch checks what your servers show the outside world: TLS, website, mail and DNS. Self-hosted. See it run on our own domain.",
			Fragment:    "assets/porch.html",
			Script:      true,
			Data:        porchPage{Hosts: demo.Hosts(), Checks: consoleChecks(), ImageDigest: pageImageDigest()},
		}
	}

	for path, p := range pages {
		p.Path = path
		body, err := render(p)
		if err != nil {
			// At startup, so a broken page stops the process instead of
			// reaching a visitor with a hole in it.
			panic("web: rendering " + path + ": " + err.Error())
		}
		rendered[path] = body
	}

	buildPlain()

	// The console, with nothing configured yet. Configure replaces it once the
	// program knows what this installation is; until then it describes the
	// stricter reading of its own state, which is the safe way round.
	//
	// Rendered here at all so that every path in the table answers from the
	// moment the package loads, including in a test that never calls Configure.
	if !demo.Enabled {
		renderWorkspace(false, false, Installation{})
	}
}

// render turns one page into the bytes served for it.
//
// Split out of init() so that a page whose content depends on how the program
// was started can be built later, through exactly the same steps. Two rendering
// paths would be two chances for the shell, the method link or the escaping to
// differ between pages, and the one that differs is the one nobody is looking
// at.
func render(p *page) ([]byte, error) {
	layout, err := template.ParseFS(assets, "assets/layout.html")
	if err != nil {
		return nil, err
	}

	p.Brand = demo.Enabled
	if p.Brand {
		p.SiteBase, p.PorchBase = siteBase(), porchBase()
		if p.Path != "" {
			p.Canonical = canonicalURL(p.Path)
		}
	}
	p.SignedIn = signedIn && p.Section != "login"
	if p.Section == "" {
		p.Section = "reference"
	}
	if p.Heading == "" {
		p.Heading = sectionHeadings[p.Section]
	}
	if p.Heading == "" {
		// A document is named by its own title, without the maker, which some
		// titles put first and some last.
		title := strings.TrimPrefix(p.Title, "denyfirst — ")
		p.Heading, _, _ = strings.Cut(title, " — ")
	}

	fragment, err := assets.ReadFile(p.Fragment)
	if err != nil {
		return nil, err
	}
	if p.Data != nil {
		// Parsed as a template, and its values escaped by html/template on the
		// way in. They come from this repository either way; the escaping is
		// not a defence against them but the reason a sentence containing an
		// angle bracket cannot silently become markup.
		body, err := template.New(p.Fragment).Parse(string(fragment))
		if err != nil {
			return nil, err
		}

		var filled bytes.Buffer
		if err := body.Execute(&filled, p.Data); err != nil {
			return nil, err
		}
		fragment = filled.Bytes()
	}
	p.Body = template.HTML(fragment) //nolint:gosec // a file in this repository, not user input

	var out bytes.Buffer
	if err := layout.Execute(&out, p); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Handler serves the site.
// Configure tells the pages what this installation is.
//
// Called once, before Handler, by whatever builds the service. Everything else
// here is rendered at init() from facts that are true at build time; this is
// the one thing that is not, because whether a boundary was configured is
// decided on the command line.
//
// Not calling it leaves the console saying no proof of control is required and
// no page is read, which is the safe direction for it to be wrong in. A page
// claiming a boundary that is not there would tell an operator their service is
// safe to expose when it is not; a page understating one costs them a second
// look at a flag.
//
// guarded says a password is in front of the installation. Every page is then
// rendered again, because each carries a way to sign out, and the sign-in page
// is added.
// Installation is what this copy of the service is, as its pages describe it.
//
// A struct rather than three booleans and then five: the privacy page has to
// say which third parties this installation asks, and every one of those is a
// flag somebody set. It said "no certificate transparency log and no
// revocation responder is asked by this service" unconditionally, which stopped
// being true the day -names-monitor and -ask-responder existed — a page telling
// an operator something false about their own installation is the worst thing
// on this site, because it is the page they would quote (N14).
type Installation struct {
	// Verified says a boundary was configured, Keeps that results are written
	// to disk, and Guarded that a password is in front of the service.
	Verified bool
	Keeps    bool
	Guarded  bool

	// Monitor names the certificate transparency monitor the inventory asks,
	// and Register the passive register. Empty means none was configured.
	Monitor  string
	Register string

	// OperatorOnly says the only people who can call this installation are the
	// one running it and whoever they let in: nobody else can reach it, or a
	// password stands in front. It decides the one capability proof of control
	// cannot grant — reading the reverse records of an address range.
	OperatorOnly bool

	// ReadsCertificates says each name that answers may be asked for the
	// certificate it presents, and AsksResponder that a certificate's own
	// authority may be asked whether it has been revoked.
	ReadsCertificates bool
	AsksResponder     bool
}

// AsksNobodyElse reports that no third party is asked anything a scan does
// not already send to the host: no monitor, no register, no responder, and no
// certificate read for the inventory.
//
// Verified is on the list because a scope turns on the transparency search in
// the TLS check (N12): every name a proven installation checks is also named to
// crt.sh. The page said nobody was asked on exactly those installations until
// 2026-09-28, because this list was written about the inventory's flags and
// the TLS check's search was wired to the scope, not to a flag.
func (i Installation) AsksNobodyElse() bool {
	return !i.Verified && i.Monitor == "" && i.Register == "" && !i.ReadsCertificates && !i.AsksResponder
}

// Whole reports that a report here is read by the person the estate belongs
// to: a scope proved it, or nobody but the operator can call this copy. It is
// httpapi's operatorView, told to the page, and it decides what the page says
// a scan reads and shows.
func (i Installation) Whole() bool {
	return i.Verified || i.OperatorOnly
}

func Configure(in Installation) {
	verified, keeps, guarded := in.Verified, in.Keeps, in.Guarded
	// The demonstration's root is its front page and its privacy page is its
	// own; neither depends on how it was started.
	if demo.Enabled {
		return
	}
	signedIn = guarded
	for path, p := range pages {
		body, err := render(p)
		if err != nil {
			panic("web: rendering " + path + ": " + err.Error())
		}
		rendered[path] = body
	}
	renderWorkspace(verified, keeps, in)
	if guarded {
		rendered["/login"] = renderSignIn()
	} else {
		delete(rendered, "/login")
	}
}

// signedIn is true where a password is in front of the installation: every
// page past the gate is one somebody signed in to see, and offers a way out.
var signedIn bool

// PublicPaths are what anybody may reach on an installation behind a
// password: the sign-in page and what it draws and runs with.
func PublicPaths() []string {
	return []string{"/login", "/style.css", "/theme.js", "/session.js", "/favicon.svg"}
}

// renderSignIn is the one page an installation behind a password shows to
// somebody who has not signed in.
func renderSignIn() []byte {
	body, err := render(&page{
		Title:       "Sign in — " + ToolName,
		Description: "Sign in to this installation.",
		Fragment:    "assets/login.html",
		Section:     "login",
	})
	if err != nil {
		panic("rendering the sign-in page: " + err.Error())
	}
	return body
}

// renderConsole builds the tool surface.
//
// A function rather than an entry in the pages table, because it is the one
// page whose content depends on how the program was started. It is rendered at
// init() too, so that a caller who never calls Configure still gets a page
// rather than a blank response.
// sectionHeadings names each part of the workspace in its top bar.
var sectionHeadings = map[string]string{
	"check":        "New check",
	"domains":      "Domains",
	"history":      "History",
	"names":        "Names",
	"installation": "This installation",
}

// renderWorkspace renders every page whose content depends on how this
// installation was started: the four parts of the workspace, and the privacy
// page, which says what this copy keeps.
func renderWorkspace(verified, keeps bool, in Installation) {
	rendered["/"] = renderConsole(verified, keeps)
	rendered["/privacy"] = renderPrivacy(verified, keeps, in)

	// The inventory page, because whether it offers a field for address ranges
	// depends on who can call this installation.
	if p, ok := pages["/names"]; ok && !demo.Enabled {
		p.Data = namesPage{Ranges: in.OperatorOnly}
		body, err := render(p)
		if err != nil {
			panic("rendering /names: " + err.Error())
		}
		rendered["/names"] = body
	}
	for _, part := range []struct{ path, section, fragment, description string }{
		{"/domains", "domains", "assets/domains.html",
			"The domains this installation may check, and the record that shows each one is yours."},
		{"/history", "history", "assets/history.html",
			"What this installation has kept of the checks it ran."},
		{"/installation", "installation", "assets/installation.html",
			"How this installation was started: what it may check, what it reads and what it keeps."},
	} {
		p := &page{
			Title:       sectionHeadings[part.section] + " — " + ToolName,
			Description: part.description,
			Fragment:    part.fragment,
			Section:     part.section,
			Script:      part.section == "domains" || (part.section == "history" && signedIn),
			Data:        workspaceData(verified, keeps),
		}
		body, err := render(p)
		if err != nil {
			panic("rendering " + part.path + ": " + err.Error())
		}
		rendered[part.path] = body
	}
}

// workspaceData is what every part of the workspace is told about this
// installation.
func workspaceData(verified, keeps bool) consolePage {
	return consolePage{
		Tool:   ToolName,
		Checks: consoleChecks(),

		// ReadsPages follows from Verified rather than being passed beside
		// it. They are one fact — internal/httpapi sets ReadMarkup from the
		// same scope — and two fields could be made to disagree by a caller,
		// which would put a claim about what was read on a page with nothing
		// behind it.
		Verified:   verified,
		ReadsPages: verified,
		Keeps:      keeps,
		Guarded:    signedIn,
	}
}

func renderConsole(verified, keeps bool) []byte {
	p := &page{
		Title:       ToolName,
		Description: "Check a name: TLS, website, mail and DNS.",
		Fragment:    "assets/console.html",
		Script:      true,
		Section:     "check",
		Data:        workspaceData(verified, keeps),
	}

	body, err := render(p)
	if err != nil {
		// At startup, so a broken template stops the process rather than
		// serving half a page to whoever asks first.
		panic("rendering the console: " + err.Error())
	}
	return body
}

func Handler() http.Handler {
	return http.HandlerFunc(serve)
}

func serve(w http.ResponseWriter, r *http.Request) {
	setHeaders(w, r)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Only GET and HEAD are served here.", http.StatusMethodNotAllowed)
		return
	}

	if to, found := moved[r.URL.Path]; found {
		http.Redirect(w, r, to, http.StatusMovedPermanently)
		return
	}

	if to, found := standingIn[r.URL.Path]; found {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}

	// porch.denyfirst.dev's front page is Porch's, and its crawler files
	// list its own pages; see hosts.go.
	porch := siteOf(r.Host) == porchSite
	if porch && r.URL.Path == "/" {
		write(w, r, "text/html; charset=utf-8", rendered[porchRoot])
		return
	}

	if body, found := rendered[r.URL.Path]; found {
		write(w, r, "text/html; charset=utf-8", body)
		return
	}

	crawler := plain
	if porch {
		crawler = plainPorch
	}
	if text, found := crawler[r.URL.Path]; found {
		write(w, r, text.contentType, text.body)
		return
	}

	if file, found := files[r.URL.Path]; found {
		body, err := assets.ReadFile(file.name)
		if err != nil {
			// Unreachable unless the table and the embedded tree disagree,
			// which a test checks.
			http.Error(w, "That page is unavailable.", http.StatusInternalServerError)
			return
		}
		write(w, r, file.contentType, body)
		return
	}

	http.Error(w, "There is nothing at that address.", http.StatusNotFound)
}

func write(w http.ResponseWriter, r *http.Request, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))

	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func setHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()

	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")

	// The privacy page promises no fonts from elsewhere, no content delivery
	// network, and no tag of any kind. That promise currently holds because
	// nobody has added one. This makes a browser refuse the resource if
	// somebody does: same-origin subresources need nothing extra, so it costs
	// nothing today and fails loudly the first time it would stop being true.
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")

	h.Set("Permissions-Policy",
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

	// The whole site is a few kilobytes, so revalidating costs almost
	// nothing, and a cache that holds nothing cannot leak anything.
	h.Set("Cache-Control", "no-store")

	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}

// privacyPage is what assets/privacy-selfhost.html reads.
type privacyPage struct {
	Tool string

	// Monitor, Register, ReadsCertificates and AsksResponder say which third
	// parties this installation asks, and AsksNobodyElse that it asks none of
	// them. The page said the last of those unconditionally until 2026-09-27.
	Monitor           string
	Register          string
	ReadsCertificates bool
	AsksResponder     bool
	AsksNobodyElse    bool

	// WalksRanges says this installation will read the reverse records of an
	// address range the person asking names, which it does only where that
	// person is the one running it.
	WalksRanges bool
	Verified    bool
	Keeps       bool
	Threshold   int

	// Whole says a report here shows the operator everything a scan read:
	// the page, the security.txt contacts, the MTA-STS policy, the exchangers
	// and the zone's own servers. See Installation.Whole.
	Whole bool

	// Guarded says a password is in front of the installation, which is when
	// it sets its one cookie.
	Guarded bool
}

// renderPrivacy builds the privacy page of an installation somebody runs.
//
// The demonstration's page is written about a machine this project runs, and
// read on a self-hosted copy it promised things that copy does differently.
// This one is filled in from how the installation was started, like the
// console, and the demonstration keeps its own (audit A21).
func renderPrivacy(verified, keeps bool, in Installation) []byte {
	p := &page{
		Title:       "Privacy — " + ToolName,
		Description: "What this installation keeps, what a scan sends, and who else is asked.",
		Fragment:    "assets/privacy-selfhost.html",
		Data: privacyPage{
			Tool:              ToolName,
			Monitor:           in.Monitor,
			Register:          in.Register,
			ReadsCertificates: in.ReadsCertificates,
			AsksResponder:     in.AsksResponder,
			AsksNobodyElse:    in.AsksNobodyElse(),
			WalksRanges:       in.OperatorOnly,
			Verified:          verified,
			Whole:             in.Whole(),
			Keeps:             keeps,
			Threshold:         httpapi.TargetThreshold(),
			Guarded:           signedIn,
		},
	}

	body, err := render(p)
	if err != nil {
		panic("rendering the privacy page: " + err.Error())
	}
	return body
}

// namesPage is what assets/names.html and assets/names-method.html read.
//
// Target is the estate a demonstration lists, and Demo says this is one. An
// installation somebody runs has neither: the person typing owns the domain
// they type, and the page says so in its own words.
type namesPage struct {
	Target string
	Demo   bool

	// Ranges says this installation will read the reverse records of an
	// address range the person asking names, which it does only where that
	// person is the one running it. The field is not drawn otherwise: an input
	// that is always refused is worse than no input.
	Ranges bool
}

// demoDomain is the estate a demonstration build lists, which is the first
// domain in its compiled-in boundary.
//
// Read from the boundary rather than written again here: two lists that have
// to agree are two lists that will not, and the one that decides what may be
// reached is the one that must be right.
func demoDomain() string {
	if targets := demo.Targets(); len(targets) > 0 {
		return targets[0]
	}
	return ""
}

// porchPage is what assets/porch.html reads.
type porchPage struct {
	Hosts  []demo.Host
	Checks []consoleCheck

	// ImageDigest is the release's image, as its compose file pins it.
	ImageDigest string
}

// imageDigest is set by scripts/build.sh on the demonstration build, from the
// image it built for the same release, so the compose file the Porch page
// shows is the one the release ships. Empty on any other build, where the
// page shows the repository's placeholder rather than a digest it does not
// know.
var imageDigest string

func pageImageDigest() string {
	if imageDigest == "" {
		return ociimage.Placeholder
	}
	return imageDigest
}

// plainFile is a file a crawler reads.
type plainFile struct {
	contentType string
	body        []byte
}

// plain holds the two files a crawler reads, built at startup beside the
// pages, and plainPorch the same two for porch.denyfirst.dev, which lists its
// own pages and names its own sitemap.
var (
	plain      = map[string]plainFile{}
	plainPorch = map[string]plainFile{}
)

// buildPlain writes robots.txt and, on the demonstration, a sitemap.
//
// The demonstration wants to be found, and the pages it wants found are the
// ones in the table, so the sitemap is that table rather than a list somebody
// keeps in step by hand.
//
// An installation somebody runs wants the opposite. It is one company's
// instrument on one company's address, often behind a password, and the
// addresses it serves are not for a search index: robots.txt there refuses
// everything. That is a request a crawler honours rather than a guard — the
// password is the guard — but the crawlers anybody is likely to meet honour
// it, and asking costs nothing.
func buildPlain() {
	robots := "User-agent: *\nDisallow: /\n"
	plain["/robots.txt"] = plainFile{"text/plain; charset=utf-8", []byte(robots)}
	if !demo.Enabled {
		return
	}

	// Each name lists the pages it serves, at the address each states as its
	// own, so nothing in either sitemap is a redirect.
	var organisation, porch []string
	for path := range rendered {
		if organisationPaths[path] {
			organisation = append(organisation, canonicalURL(path))
		} else {
			porch = append(porch, canonicalURL(path))
		}
	}
	for _, crawler := range []struct {
		files map[string]plainFile
		base  string
		urls  []string
	}{
		{plain, SiteURL, organisation},
		{plainPorch, PorchURL, porch},
	} {
		sort.Strings(crawler.urls)
		var sitemap strings.Builder
		sitemap.WriteString(xml.Header)
		sitemap.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
		for _, u := range crawler.urls {
			sitemap.WriteString("  <url><loc>" + u + "</loc></url>\n")
		}
		sitemap.WriteString("</urlset>\n")
		crawler.files["/sitemap.xml"] = plainFile{"application/xml; charset=utf-8", []byte(sitemap.String())}
		crawler.files["/robots.txt"] = plainFile{"text/plain; charset=utf-8",
			[]byte("User-agent: *\nAllow: /\n\nSitemap: " + crawler.base + "/sitemap.xml\n")}
	}
}

// organisationPage is what assets/organisation.html reads.
//
// The undertakings are passed in rather than written into the markup, for the
// reason the Data field exists at all: a second product would otherwise mean
// the organisation's undertakings written out twice, and the day one copy is
// improved and the other is not, a reader has two documents from the same
// people that disagree — worse evidence than one vague document.
type organisationPage struct {
	Organisation []promises.Promise
	Products     []productPage
}

// productPage is a product as the organisation's page names it: what it is,
// and where its own undertakings are. The undertakings themselves are not
// carried, because they are that product's word and its page says them.
type productPage struct {
	Name, What, Page string
}

// undertakingsPath is where Porch's undertakings are, on Porch's name.
const undertakingsPath = "/undertakings"

// productPages is every product in internal/promises with the address of its
// own page. Porch's is on this site wherever this copy runs. A product this
// repository does not build has no address here until somebody writes one
// down, and startup stops rather than link a reader to a guess.
func productPages() []productPage {
	var out []productPage
	for _, p := range promises.Products {
		if p.Name != promises.Porch.Name {
			panic("web: " + p.Name + " is in internal/promises with no address for its undertakings")
		}
		out = append(out, productPage{Name: p.Name, What: p.What, Page: porchBase() + undertakingsPath})
	}
	return out
}

// undertakingsPage is what assets/undertakings.html reads.
type undertakingsPage struct {
	Product  promises.Product
	SiteBase string
}

// siteBase and porchBase are what render sets SiteBase and PorchBase to, for
// the pages whose own text links across names.
func siteBase() string {
	if demo.Enabled {
		return SiteURL
	}
	return ""
}

func porchBase() string {
	if demo.Enabled {
		return PorchURL
	}
	return ""
}

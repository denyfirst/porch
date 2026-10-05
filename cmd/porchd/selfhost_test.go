package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"html"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
)

// The files somebody runs this from, and what they are allowed to say.
//
// A container image and a compose file are configuration, which is the part of
// a system nobody tests and everybody edits. These are the promises they make.

func repoFile(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("../../" + name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(body)
}

// The image has no base system.
//
// A container built on alpine or debian carries several hundred packages this
// project does not audit and cannot reproduce, which would put a supply chain
// underneath a program that deliberately has none: go.mod has no require
// block. An image with a base system is a second distribution channel with
// weaker guarantees than the first, and the weakest channel is the real
// security level.
func TestTheImageHasNoBaseSystem(t *testing.T) {
	dockerfile := repoFile(t, "Dockerfile")

	from := regexp.MustCompile(`(?mi)^FROM\s+(\S+)`).FindAllStringSubmatch(dockerfile, -1)
	if len(from) == 0 {
		t.Fatal("the Dockerfile has no FROM line")
	}
	for _, m := range from {
		if m[1] != "scratch" {
			t.Errorf("the image is built on %q; only scratch carries nothing to audit", m[1])
		}
	}
	if len(from) != 1 {
		t.Errorf("the Dockerfile has %d stages; a builder stage produces bytes nobody verified, "+
			"and the binary is meant to be the one from the signed release", len(from))
	}

	// It must not build. A RUN line in an image with no shell cannot work
	// anyway, and its presence would mean somebody had reached for a base.
	if regexp.MustCompile(`(?mi)^RUN\s`).MatchString(dockerfile) {
		t.Error("the Dockerfile runs a command, which an image with no shell cannot do")
	}

	// And it must say where the binary comes from, because an image built
	// around an unverified download is the whole chain undone.
	if !strings.Contains(dockerfile, "docs/verify.md") {
		t.Error("the Dockerfile does not point at the verification procedure")
	}
}

// The container is given nothing it does not need, and one thing it does.
//
// The trust store is the one that matters. Every verdict about a chain is a
// verdict against some trust store, and an image with none does not fail to
// verify — it verifies everything as untrusted, and prints a finding about the
// container as a finding about the scanned server.
func TestTheComposeFileTakesAwayWhatItSays(t *testing.T) {
	compose := repoFile(t, "docker-compose.yml")

	for _, want := range []string{
		"read_only: true",
		"no-new-privileges:true",
		"cap_drop",
		"- ALL",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("the compose file no longer sets %q", want)
		}
	}

	if !strings.Contains(compose, "/etc/ssl/certs:/etc/ssl/certs:ro") {
		t.Error("the trust store is not mounted read-only from the host, so a report would " +
			"reflect whatever an image was built with, or nothing at all")
	}
	if !strings.Contains(compose, "SSL_CERT_DIR") {
		t.Error("nothing points the process at the mounted trust store")
	}

	// The container binds an unprivileged port, so no capability is needed
	// inside. A privileged bind here would be a capability added to a
	// container that drops all of them. And it is published on the host's
	// loopback only, so the example as written exposes nothing.
	if !strings.Contains(compose, `"127.0.0.1:8080:8080"`) {
		t.Error("the example publishes beyond the host's loopback, or the container binds a different port")
	}

	// Proof of control is on in the example and in the image. A container
	// listens beyond loopback by construction, and porchd refuses to do that
	// scanning anything (audit A01, A02).
	for name, file := range map[string]string{"docker-compose.yml": compose, "Dockerfile": repoFile(t, "Dockerfile")} {
		if !strings.Contains(file, `"-verification-secret-file"`) || !strings.Contains(file, `"/data/secret"`) {
			t.Errorf("%s does not turn proof of control on", name)
		}
		if strings.Contains(file, `"-open"`) || strings.Contains(file, `"-without-password"`) {
			t.Errorf("%s names a flag that was removed", name)
		}
	}
	if !strings.Contains(compose, "./porch-data:/data") || !strings.Contains(compose, "chown 65534:65534 porch-data") {
		t.Error("the secret has nowhere writable to live, or nothing says how to make it so")
	}
	if regexp.MustCompile(`(?m)^\s*privileged:\s*true`).MatchString(compose) {
		t.Error("the compose file asks for a privileged container")
	}
}

// The self-hosting page checks the signature the way docs/verify.md does, and
// points there for what each part proves.
//
// It used to point there and give no check of its own, on the rule that two
// copies of a verification procedure drift and the copy nobody reads is the
// one that goes wrong. The cost was that its steps downloaded and started
// without checking anything, and a link is the step a reader skips. The
// install now checks one file, the compose file that names the image by
// digest, in one line on the page and in the guide — and the drift the rule
// was about is held here instead: that line has to use the key file, the
// identity and the namespace docs/verify.md gives.
func TestSelfHostChecksTheSignatureTheWayVerifyMdDoes(t *testing.T) {
	doc := repoFile(t, "docs/self-host.md")

	if !strings.Contains(doc, "verify.md") {
		t.Error("the self-hosting page does not point at docs/verify.md")
	}
	procedure := repoFile(t, "docs/verify.md")
	if !strings.Contains(procedure, "https://raw.githubusercontent.com/denyfirst/porch/main/.allowed_signers") {
		t.Error("docs/verify.md no longer says where the key file is published")
	}
	for _, part := range []string{
		"-I releases@denyfirst.dev",
		"-n file",
		"sha256sum --ignore-missing -c SHA256SUMS",
	} {
		if !strings.Contains(procedure, part) {
			t.Fatalf("docs/verify.md no longer gives %q; the guide's check follows it, so look at both", part)
		}
		if !strings.Contains(doc, part) {
			t.Errorf("the guide checks the signature without %q, which docs/verify.md uses", part)
		}
	}

	// It has to say the thing that is only true here: the trust store is the
	// reader's, and an empty one is a wrong answer rather than a failure.
	for _, want := range []string{
		"trust store",
		"refuses to start",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the self-hosting page does not say %q", want)
		}
	}
}

// Everything that points somewhere points at something that exists.
func TestTheSelfHostingPageIsReachableAndItsLinksResolve(t *testing.T) {
	if !strings.Contains(repoFile(t, "README.md"), "docs/self-host.md") {
		t.Error("the README does not point at the self-hosting page")
	}

	doc := repoFile(t, "docs/self-host.md")
	for _, m := range regexp.MustCompile(`\]\(([a-z0-9./-]+\.md)[^)]*\)`).FindAllStringSubmatch(doc, -1) {
		if _, err := os.Stat("../../docs/" + m[1]); err != nil {
			t.Errorf("docs/self-host.md links %s, which is not there", m[1])
		}
	}
}

// An empty trust store is refused before anything is served.
//
// It is the failure that does not look like one. A machine with no trust store
// — a container built FROM scratch with nothing mounted is the ordinary way to
// get one — does not fail to verify chains. It verifies them all as untrusted,
// and every report says the scanned server's certificate does not reach a
// trusted root: a finding about this machine, printed as a finding about
// somebody else's server, which is the exact mistake this project exists to
// avoid.
func TestAnEmptyTrustStoreStopsTheServiceStarting(t *testing.T) {
	if err := trustStoreUsable(x509.NewCertPool(), nil); err == nil {
		t.Error("an empty trust store was accepted; every report would call every certificate untrusted")
	}
	if err := trustStoreUsable(nil, nil); err == nil {
		t.Error("a nil trust store was accepted")
	}
	if err := trustStoreUsable(nil, errors.New("no")); err == nil {
		t.Error("an unreadable trust store was accepted")
	}

	// The message has to say what to do. "Trust store empty" sends a reader
	// looking for a bug in this program.
	err := trustStoreUsable(x509.NewCertPool(), nil)
	for _, want := range []string{"untrusted", "SSL_CERT_DIR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// And a real one is accepted, or this test would pass with the check
	// wired backwards.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(selfSignedPEM(t)) {
		t.Fatal("the test certificate did not parse")
	}
	if err := trustStoreUsable(pool, nil); err != nil {
		t.Errorf("a populated trust store was refused: %v", err)
	}

	// And something calls it, before anything is served.
	//
	// A guard nothing reaches is a guard that passes its own tests and stops
	// nothing: removing the call from run() left every assertion above green.
	// Read from the source because run() parses flags and binds a port, and a
	// test that did both would be testing the harness.
	source := repoFile(t, "cmd/porchd/main.go")

	call := strings.Index(source, "trustStoreUsable(")
	if call < 0 {
		t.Fatal("nothing checks the trust store before the service starts")
	}
	serve := strings.Index(source, "ListenAndServe")
	if serve >= 0 && call > serve {
		t.Error("the trust store is checked after the service is already answering")
	}

	// And the store that was checked is the store that decides.
	//
	// This half was missing, and its absence was the defect. The check read a
	// pool, satisfied itself that it was not empty, and dropped it; the
	// scanner was then built with no Roots at all. x509.Verify reads a nil
	// Roots as "decide for yourself", and on Windows and macOS deciding means
	// the platform verifier — a different store, which this check never
	// looked at. So the guard passed against one thing and every chain was
	// judged against another, on the two platforms self-hosting is most
	// likely to run on.
	//
	// Asserted on the source for the same reason the call above is: run()
	// parses flags and binds a port, and a test that did both would be
	// testing the harness. Matched on the pool reaching the scanner rather
	// than on any particular spelling of the call, so that improving the
	// prose around it does not fail this.
	if !strings.Contains(source, "scan.Scanner{Roots:") {
		t.Error("the scanner is built without a trust store, so the pool checked above decides " +
			"nothing and every chain is judged against whatever the platform picks")
	}
}

// selfSignedPEM is one certificate, so a pool can be non-empty.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trust store test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A binary says which hosts it will connect to.
//
// The two builds are indistinguishable from outside until one of them refuses
// something. A deploy that installed the wrong one would look entirely
// correct — the file is in place, the service answers, the version matches —
// and the only symptom would be a public scanner nobody meant to run. So the
// binary says, and the deploy procedure reads what it says rather than
// trusting a filename.
func TestAVersionSaysWhichHostsTheBinaryWillReach(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		line := reach(scoped)

		if strings.TrimSpace(line) == "" {
			t.Fatal("a binary says nothing about which hosts it will reach")
		}
		if strings.HasSuffix(line, ".") {
			t.Error("the line ends in a full stop; the deploy procedure matches on its start and shape")
		}

		if demo.Enabled {
			if !strings.HasPrefix(line, "demonstration: ") {
				t.Errorf("a demonstration build says %q, which the deploy check does not match", line)
			}
			// Read from the list the scanner enforces, so a binary cannot say
			// one thing and do another.
			for _, host := range demo.Targets() {
				if !strings.Contains(line, host) {
					t.Errorf("the binary reaches %s and does not say so: %q", host, line)
				}
			}
			continue
		}

		if strings.HasPrefix(line, "demonstration") {
			t.Errorf("the ordinary build calls itself a demonstration: %q", line)
		}
	}
}

// The line says which of the two boundaries this deployment has.
//
// It named only the compiled-in list, so a service requiring proof of control
// said it "scans whatever it is pointed at" — the sentence an operator reads as
// a reason to go and check their configuration. Wrong in the alarming direction
// is still a line nobody trusts the second time, and the deploy procedure reads
// this line rather than trusting a filename.
func TestTheReachLineSaysWhetherAScopeIsConfigured(t *testing.T) {
	if demo.Enabled {
		// A demonstration build's list is compiled in and a scope cannot widen
		// or narrow it, so the line says the same thing either way. Asserted
		// rather than skipped: a build that started describing a scope it does
		// not enforce would be the same defect in the other direction.
		if reach(false) != reach(true) {
			t.Errorf("a demonstration build describes itself differently with a scope: %q and %q",
				reach(false), reach(true))
		}
		return
	}

	open, bounded := reach(false), reach(true)
	if open == bounded {
		t.Fatalf("a deployment that requires proof of control says the same thing as one that "+
			"does not: %q", open)
	}
	// Since 2026-09-29 porchd does not start unbounded, so -version asked
	// without a secret says that rather than describing a service that will
	// never run.
	if !strings.Contains(open, "will not start") || !strings.Contains(open, "-verification-secret-file") {
		t.Errorf("-version without a secret does not say the service will not start, or why: %q", open)
	}
	if !strings.Contains(bounded, "shown control of") {
		t.Errorf("a bounded deployment does not say what bounds it: %q", bounded)
	}
	if strings.Contains(bounded, "whatever it is pointed at") {
		t.Errorf("a bounded deployment describes itself as unbounded: %q", bounded)
	}
}

// And -version prints it.
//
// A line nothing prints is a line the deploy check greps for and never finds,
// which fails in the direction of refusing a correct deploy — but it would
// also pass silently if somebody replaced the grep. Read from the source,
// because -version calls os.Exit's neighbour and a test that drove it would
// be testing the harness.
func TestTheVersionOutputCarriesTheReachLine(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")

	block := source[strings.Index(source, "if *showVersion {"):]
	block = block[:strings.Index(block, "return 0")]

	if !strings.Contains(block, "reach(") {
		t.Error("-version does not say which hosts the binary will reach, so the deploy check " +
			"has nothing to read and the two builds stay indistinguishable")
	}
}

// The demonstration build is released, and the deploy installs that one.
//
// A property compiled into a binary is worth nothing until the binary
// carrying it is the binary that runs — and a binary that runs here is one
// that was released: signed, listed in SHA256SUMS, and rebuilt by the
// reproduction workflow like every other artifact.
func TestTheDemonstrationBuildIsReleasedAndDeployed(t *testing.T) {
	build := repoFile(t, "scripts/build.sh")

	if !strings.Contains(build, "-tags demo") {
		t.Fatal("the release does not build the demonstration binary, so there is nothing signed to deploy")
	}
	if !strings.Contains(build, "porchd-demonstration_${tag}_linux_amd64") {
		t.Error("the demonstration artifact is not named as the deploy procedure expects")
	}

	// The deploy commands are private since 2026-10-01 (S15): they named the
	// machine. The public page says what they do, and these two are what this
	// invariant rests on — the demonstration build is the one installed, and
	// the file proves it is before it reaches the live path, rather than its
	// name being trusted.
	releasing := repoFile(t, "docs/releasing.md")
	said := strings.Join(strings.Fields(releasing), " ")

	if !strings.Contains(said, "Only the demonstration build runs there") {
		t.Error("the deploy procedure does not say it installs the demonstration binary")
	}
	if !strings.Contains(said, "the file has to say so before it is installed") {
		t.Error("the deploy procedure does not say it checks which build it is installing")
	}
	if strings.Contains(releasing, "porchd_${V}_linux_amd64") {
		t.Error("the deploy procedure installs the unrestricted binary")
	}
}

// The self-hosting page says plainly what an unbounded service is.
//
// It described the defaults accurately and left the consequence to be worked
// out: a table row saying "which hosts: whichever you point it at" is true, and
// it reads as a capability rather than as a warning. Somebody binding the
// service to an interface so their team can reach it has then built, inside
// their own network, the arrangement this project dismantled for its own public
// deployment — and it is their address in the scanned party's logs.
//
// On this page rather than only in docs/scope.md, because this is the page
// somebody follows while setting the service up. A warning they meet afterwards
// is a warning about something they have already done.
func TestTheSelfHostingPageSaysWhatAnUnboundedServiceIs(t *testing.T) {
	page := repoFile(t, "docs/self-host.md")

	for _, want := range []string{
		"open scanner",
		"-verification-secret-file",
		"your* address",
	} {
		// The middle phrase is the flag that fixes it; a warning naming no
		// remedy is one a reader cannot act on.
		if want == "your* address" {
			if !strings.Contains(page, "*your* address") {
				t.Error("the page does not say whose address ends up in the scanned party's logs")
			}
			continue
		}
		if !strings.Contains(page, want) {
			t.Errorf("docs/self-host.md does not mention %q", want)
		}
	}

	// And it says which of the two a running service is, because that is what
	// an operator checks rather than what they remember configuring.
	if !strings.Contains(page, "shown control of") {
		t.Error("the page does not show what a bounded deployment's -version line says, so an " +
			"operator has no way to confirm which one they have")
	}
}

// The release procedure does not tell anybody to run a command that cannot work.
//
// `gh pr checks --watch` in the same breath as `gh pr create` reports that no
// checks exist and exits, because none has registered yet. The merge then fails
// with required checks not satisfied, which reads like a branch-protection
// problem — and branch protection is working correctly, so the next half hour
// goes on the wrong thing.
func TestTheReleaseProcedureSaysToWaitForChecksToRegister(t *testing.T) {
	page := repoFile(t, "docs/releasing.md")

	if !strings.Contains(page, "gh pr checks --watch") {
		t.Fatal("the procedure no longer watches the checks at all")
	}
	if !strings.Contains(page, "no checks exist") {
		t.Error("the procedure does not warn that watching too early reports nothing and exits, " +
			"which is the failure that reads like a policy block")
	}
}

// The self-hosting page says how to keep results, and what that does not mean.
//
// The sentence it replaces was a promise: "nothing about a scan is written to
// disk". That is still the default and it is no longer the whole story, so the
// page has to carry both halves — and the half a reader most needs is the one
// about what keeping results does *not* turn on.
func TestTheSelfHostingPageExplainsKeepingResults(t *testing.T) {
	page := repoFile(t, "docs/self-host.md")

	for _, want := range []string{
		"-results-dir",
		"-results-keep",
		"porch-scan -history",

		// The three things that make it safe to offer at all.
		"never served over HTTP",
		"65534:65534",
		"read_only: true",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/self-host.md does not mention %q", want)
		}
	}

	// The ownership step is the one that fails silently and confusingly: the
	// image is scratch, so there is no shell in the container to fix it with.
	if !strings.Contains(page, "chown 65534:65534") {
		t.Error("the page does not say the volume must be owned before it is mounted, which is " +
			"a permission denied with no shell in the image to diagnose it")
	}
}

// The demonstration is wired to list its own estate, and to keep what it
// produced.
//
// Both halves are compiled in rather than flagged, because the privacy page
// promises what the build does and a unit file is not the build. A monitor
// left out of the unit would leave the demonstration showing half an inventory
// while the page described a whole one; a kept copy left out would make a page
// anybody can refresh into a way of making this installation ask a third party
// as often as they like.
//
// Read as text, for the reason the gate above is: what is being checked is
// that the wiring exists at all, and a test that called the setters itself
// would pass with main.go calling none of them.
func TestTheDemonstrationIsWiredToListItsOwnEstate(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")

	for _, want := range []string{
		"if demo.Enabled {",
		"api.SearchNames(&ctsearch.CRTSh{Timeout: *requestTimeout})",
		"api.ReadHostCertificates(&certnames.Reader{Timeout: *requestTimeout})",
		"api.KeepInventoryFor(time.Hour)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("main.go does not wire the demonstration with %q", want)
		}
	}
}

// Every installation has a resolver, and no condition stands in front of it.
//
// Three of the four sources the inventory reads hang off scanner.Resolver: the
// domain's own records, what each name is doing now, and the certificates its
// hosts present — which only runs where something answered. The field was set
// only when -resolver was given, so a copy started without it read one source
// while its page described four.
//
// The demonstration shipped that way and reached the live deployment. The fix
// that followed covered the demonstration alone and left every self-hosted copy
// exactly where it was — which is how the same defect got found twice, the
// second time by somebody naming an address range and being told this
// installation has no resolver.
//
// Read as text, like the rest of the wiring here: what is being checked is that
// no condition came back.
func TestEveryInstallationIsWiredAResolver(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")

	if !strings.Contains(src, "scanner.Resolver = &dnsclient.Client{Server: resolver}") {
		t.Fatal("main.go no longer hands the scanner a resolver")
	}
	for _, condition := range []string{`if resolver != "" {`, `if resolver != "" || demo.Enabled {`} {
		if strings.Contains(src, condition) {
			t.Errorf("the resolver is behind %s again, so three of the inventory's four "+
				"sources depend on a flag somebody remembered to type", condition)
		}
	}
}

// The service names the revocation addresses where the report is read by the
// person it is about, and decides that in one place.
//
// The addresses are written by whoever issued the certificate, which on a name
// nobody proved means they are written by the party being measured — and a
// report a stranger asked for does not repeat a string that party wrote back
// at its reader. For a domain somebody has shown is theirs, for the
// demonstration's own estate, and on a copy only its operator can call, the
// authority is their own, and the sentence a count cannot write is the one
// they need: when revocation could not be established, which address failed.
//
// That is operatorView's question, and httpapi answers it for every part of a
// report shown whole only to its owner. This was set here, inside the branch
// for a scope, which left the demonstration and the operator's own copy
// printing a count of their own addresses. main.go setting it again, anywhere,
// is a second place for one decision; httpapi's tests check the answer.
func TestTheRevocationAddressesFollowTheOperatorsView(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	if strings.Contains(src, "ShowRevocationURLs") {
		t.Error("main.go decides whether the revocation addresses are named, which httpapi's " +
			"operatorView decides for every part of a report shown whole only to its owner")
	}
}

// A server running the service holds the release and nothing else.
//
// The way to the Dockerfile and the compose file was a clone of this
// repository onto the server, which put the source tree, its documents and
// its history on a machine that runs one binary — found there on 2026-09-29.
// The release carries both files now, listed in SHA256SUMS beside the binary,
// so the one signature covers them. The Porch page and the guide fetch those
// five files and clone nothing, and a build from a checkout is sent the
// binary alone.
func TestAServerHoldsTheReleaseAndNothingElse(t *testing.T) {
	build := repoFile(t, "scripts/build.sh")
	if !strings.Contains(build, `go run ./internal/ociimage/porch-image build -tag "${tag}" -dist "${out}" -compose docker-compose.yml`) {
		t.Error("scripts/build.sh no longer builds the release's image and the compose file that pins it")
	}
	if strings.Contains(build, "cp Dockerfile") {
		t.Error("the release carries a Dockerfile again, for a server to build an image the signature does not name")
	}

	// The ignore file travels with the Dockerfile, because the build on a
	// server is sent the directory porch-data lives in. Named for the
	// Dockerfile so a release can carry it: a ".dockerignore" in the checkout
	// would be read there and missing on every server.
	ignore := strings.Fields(strings.Join(nonComments(repoFile(t, "Dockerfile.dockerignore")), "\n"))
	if strings.Join(ignore, " ") != "* !porchd !porch-scan" {
		t.Errorf("the build is sent %v, want the two binaries alone", ignore)
	}
	if _, err := os.Stat(filepath.Join("..", "..", ".dockerignore")); err == nil {
		t.Error("a .dockerignore is back beside the Dockerfile; the release cannot carry it, " +
			"and a checkout reading it would hide that servers have none")
	}

	// The compose file and the signed list that covers it, checked before
	// anything starts: the compose file names the image by digest, so it is
	// the one file a server has to verify.
	fetch := []string{
		`for f in docker-compose.yml SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/latest/download/${f}"; done`,
		`ssh-keygen -Y verify -f allowed_signers -I releases@denyfirst.dev -n file -s SHA256SUMS.sig < SHA256SUMS && sha256sum --ignore-missing -c SHA256SUMS || { rm -f docker-compose.yml; echo 'STOP: docker-compose.yml did not verify and was removed'; }`,
	}
	for _, path := range []string{"internal/web/assets/porch.html", "docs/self-host.md"} {
		// The page colours its commands with spans; what it says is the text.
		// Whole lines, so that a line found inside a longer one does not
		// stand in for it. Only the page is markup: in the guide a "<" is a
		// shell redirect, and stripping from it would eat the line.
		body := repoFile(t, path)
		if strings.HasSuffix(path, ".html") {
			body = html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(body, ""))
		}
		lines := map[string]bool{}
		for _, line := range strings.Split(body, "\n") {
			lines[strings.TrimSpace(line)] = true
		}
		for _, want := range fetch {
			found := lines[want]
			if strings.HasSuffix(want, "; do") {
				found = strings.Contains(body, want)
			}
			if !found {
				t.Errorf("%s does not give %s", path, want)
			}
		}
	}
	if strings.Contains(repoFile(t, "internal/web/assets/porch.html"), "git clone") {
		t.Error("the Porch page puts the source on the server again")
	}
}

// nonComments is a file's lines without comments or blank lines.
func nonComments(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// The command line on a server runs with the service's secret, in the
// service's sandbox, and can change nothing the service keeps.
//
// So one record proves a domain to both, and the secret never leaves the
// directory it was made in. Read out of the compose file service by service,
// because the hardening the file's own test looks for anywhere in it would be
// satisfied by the service alone while the command line went without.
func TestTheCommandLineOnTheServerUsesTheServicesSecretAndChangesNothing(t *testing.T) {
	compose := repoFile(t, "docker-compose.yml")
	service := func(name string) string {
		at := regexp.MustCompile(`(?m)^  ` + name + `:$`).FindStringIndex(compose)
		if at == nil {
			t.Fatalf("the compose file has no %s service", name)
		}
		rest := compose[at[1]:]
		if next := regexp.MustCompile(`(?m)^  \S`).FindStringIndex(rest); next != nil {
			rest = rest[:next[0]]
		}
		return strings.Join(nonComments(rest), "\n")
	}
	scan, porch := service("scan"), service("porch")

	for _, want := range []string{
		`entrypoint: ["/porch-scan", "-verification-secret-file", "/data/secret"]`,
		"- ./porch-data:/data:ro",
		"- /etc/ssl/certs:/etc/ssl/certs:ro",
		"SSL_CERT_DIR: /etc/ssl/certs",
		"read_only: true",
		"- no-new-privileges:true",
		"cap_drop:\n- ALL",
		"image: ghcr.io/denyfirst/porch@sha256:",
		`profiles: ["cli"]`,
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("the scan service does not have %q:\n%s", want, scan)
		}
	}
	if strings.Contains(scan, "ports:") || strings.Contains(scan, "build:") {
		t.Error("the scan service publishes a port or builds an image of its own")
	}
	// Both services start the release's image by its digest, never by a tag.
	for name, service := range map[string]string{"porch": porch, "scan": scan} {
		if !regexp.MustCompile(`(?m)^image: ghcr\.io/denyfirst/porch@sha256:[0-9a-f]{64}$`).MatchString(service) {
			t.Errorf("the %s service does not start the release's image by its digest", name)
		}
		if strings.Contains(service, "build:") {
			t.Errorf("the %s service builds an image the signature does not name", name)
		}
	}

	if !regexp.MustCompile(`(?m)^COPY --chmod=0555 porchd porch-scan /$`).MatchString(repoFile(t, "Dockerfile")) {
		t.Error("the image does not carry the command line beside the service")
	}
}

// The release's image is built with the binaries, published by digest only
// once the release's own gates have passed, read back anonymously before a
// draft can name it, and read back again by the reproduction after the
// maintainer has signed. The demonstration carries its digest, so the page
// shows the compose file the release ships.
func TestTheReleaseImageIsPublishedByDigestAndChecked(t *testing.T) {
	build := repoFile(t, "scripts/build.sh")
	if !strings.Contains(build, `-X github.com/denyfirst/porch/internal/web.imageDigest=${digest}`) {
		t.Error("the demonstration build does not carry the image's digest")
	}
	if strings.Index(build, "porch-image build") > strings.Index(build, "porchd-demonstration_${tag}") {
		t.Error("the demonstration is built before the image whose digest it carries")
	}

	release := repoFile(t, ".github/workflows/build-release.yml")
	gates := strings.Index(release, "Refuse to stage a build with a known vulnerability")
	push := strings.Index(release, "porch-image push -archive")
	check := strings.Index(release, "porch-image check -archive")
	stage := strings.Index(release, "- name: Stage a draft release")
	if gates < 0 || push < gates || check < push || stage < check {
		t.Error("the image is not published after the release's gates, read back, and only then staged")
	}
	if !strings.Contains(release, "packages: write") {
		t.Error("the release workflow cannot publish the image")
	}
	if strings.Count(release, "packages: write") != 1 {
		t.Error("more than one job may publish packages")
	}
	if strings.Contains(release, "REGISTRY_PASSWORD: ${{ github.token }}") == false {
		t.Error("the image is published with something other than the workflow's own token")
	}

	reproduce := repoFile(t, ".github/workflows/reproduce.yml")
	if !strings.Contains(reproduce, "porch-image check -archive") {
		t.Error("the reproduction does not check what the registry serves")
	}

	// And neither step can be switched off by a condition: an `if:` on it
	// leaves every line above in place and runs nothing.
	for name, workflow := range map[string]string{
		"Publish the image by digest, and read it back as a stranger would": release,
		"Check the registry serves the image the release signed":            reproduce,
	} {
		at := strings.Index(workflow, "- name: "+name)
		if at < 0 {
			t.Errorf("no step %q", name)
			continue
		}
		step := workflow[at+len("- name: "):]
		if next := strings.Index(step, "- name: "); next >= 0 {
			step = step[:next]
		}
		if regexp.MustCompile(`(?m)^\s*(if|continue-on-error):`).MatchString(step) {
			t.Errorf("the step %q runs only on a condition, or may fail without failing the job", name)
		}
	}
	if strings.Contains(reproduce, "packages: write") || strings.Contains(reproduce, "porch-image push") {
		t.Error("the reproduction can publish an image; it only reads")
	}
}

// The install names the fingerprint of the key that signs releases, worked
// out here from .allowed_signers rather than copied, on the Porch page and in
// the guide as docs/verify.md does.
//
// The key file and the release both come from GitHub, so a signature checked
// against that key alone proves only that the two agree. The page is served
// by denyfirst.dev, which GitHub does not run: a key replaced on GitHub alone
// prints a fingerprint that does not match the one the page shows. A key
// rotated without the page following fails here rather than on a server.
func TestTheInstallNamesTheReleaseKeysFingerprint(t *testing.T) {
	var fingerprints []string
	for _, line := range nonComments(repoFile(t, ".allowed_signers")) {
		// principals, options, the key's type, the key, a comment: the key
		// is the field after its type, wherever the options leave it.
		fields := strings.Fields(line)
		at := -1
		for i, f := range fields {
			if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") || strings.HasPrefix(f, "sk-") {
				at = i
				break
			}
		}
		if at < 0 || at+1 >= len(fields) {
			t.Fatalf("an allowed_signers line with no key: %q", line)
		}
		blob, err := base64.StdEncoding.DecodeString(fields[at+1])
		if err != nil {
			t.Fatalf("the key in .allowed_signers is not base64: %v", err)
		}
		sum := sha256.Sum256(blob)
		fingerprints = append(fingerprints, "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]))
	}
	if len(fingerprints) == 0 {
		t.Fatal(".allowed_signers names no key")
	}
	for _, fp := range fingerprints {
		for _, path := range []string{"internal/web/assets/porch.html", "docs/self-host.md", "docs/verify.md"} {
			if !strings.Contains(repoFile(t, path), fp) {
				t.Errorf("%s does not name the release key's fingerprint %s", path, fp)
			}
		}
	}
}

// The install carries the release key rather than fetching it, and a check
// that fails leaves nothing for the next step to start.
//
// Fetched from GitHub, the key came from where the release came from, so
// whoever could replace one could replace the other, and only a reader
// comparing the fingerprint by eye stood in the way. Written out on the Porch
// page, which denyfirst.dev serves, a release signed by another key fails on
// its own. And a failed check used to leave docker-compose.yml where step 2
// would start it: now the same line removes it (audit 2026-10-05, F3 and F4).
func TestTheInstallCarriesTheReleaseKeyAndFailsClosed(t *testing.T) {
	var lines []string
	for _, line := range nonComments(repoFile(t, ".allowed_signers")) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			t.Fatalf("an allowed_signers line too short to hold a key: %q", line)
		}
		// The principal, the key's type and the key: what ssh-keygen needs,
		// without the comment.
		lines = append(lines, strings.Join(fields[:3], " "))
	}
	if len(lines) != 1 {
		t.Fatalf(".allowed_signers names %d keys; the install writes out exactly one", len(lines))
	}
	want := "echo '" + lines[0] + "' > allowed_signers"

	for _, path := range []string{"internal/web/assets/porch.html", "docs/self-host.md"} {
		body := repoFile(t, path)
		if strings.HasSuffix(path, ".html") {
			body = html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(body, ""))
		}
		found := false
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not write out the release key from .allowed_signers: want %q", path, want)
		}
		if strings.Contains(body, "main/.allowed_signers -o allowed_signers") {
			t.Errorf("%s still fetches the release key from GitHub", path)
		}
		if !strings.Contains(body, "|| { rm -f docker-compose.yml; echo 'STOP:") {
			t.Errorf("%s leaves the compose file in place when a check fails", path)
		}
	}
}

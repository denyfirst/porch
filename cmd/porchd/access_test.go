package main

import (
	"bytes"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/access"
	"github.com/denyfirst/porch/internal/vault"
)

// A missing access file waits for its first password: a setup code is said
// once and written nowhere, and nothing is created until the operator
// chooses the password with it. An existing file is left alone, because
// replacing it would make everything kept under its key unreadable.
func TestAMissingAccessFileWaitsForASetupCodeSaidOnce(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	path := filepath.Join(t.TempDir(), "access")
	until := time.Date(2026, 11, 20, 9, 45, 0, 0, time.UTC)
	code, err := prepareAccess(path, until)
	if err != nil {
		t.Fatal(err)
	}
	shown := regexp.MustCompile(`(?m)^    ([a-z2-7]{4}(-[a-z2-7]{4}){3})$`).FindStringSubmatch(said.String())
	if shown == nil || shown[1] != code {
		t.Fatalf("the setup code was not said as returned: %q", said.String())
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 0 {
		t.Errorf("waiting for setup wrote %d files; the code is said, not saved", len(entries))
	}
	for _, want := range []string{"works once", "until\n09:45 UTC", "restart porchd for a new one", "cannot be recovered"} {
		if !strings.Contains(said.String(), want) {
			t.Errorf("the announcement does not say %q: %q", want, said.String())
		}
	}

	if err := access.Create(path, "a long chosen password"); err != nil {
		t.Fatal(err)
	}
	said.Reset()
	if code, err := prepareAccess(path, until); err != nil || code != "" || said.Len() != 0 {
		t.Errorf("an existing access file waits for setup: %q, %v, %q", code, err, said.String())
	}
	if _, err := access.Unlock(path, "a long chosen password"); err != nil {
		t.Error("starting again replaced the access file")
	}
}

// The gate is in front of the whole mux, so a route added later is behind it
// without anybody remembering to put it there, and the compose file turns it
// on.
func TestTheGateIsInFrontOfEverything(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"var handler http.Handler = web.Hosts(root)",
		"handler = gate.Wrap(handler)",
		"Handler: handler,",
		"web.Configure(web.Installation{",
		"passwordRequired(*accessFile != \"\" || demo.Enabled)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("main.go no longer contains %q", want)
		}
	}
	if strings.Contains(src, "Handler: root,") {
		t.Error("the server is handed the mux directly, around the gate")
	}
	// The demonstration's redirect between its two names is inside the gate,
	// not around it: what the gate guards is everything the mux answers,
	// redirects included (web.Hosts).
	if strings.Index(src, "web.Hosts(root)") > strings.Index(src, "handler = gate.Wrap(handler)") {
		t.Error("the gate is wrapped before the redirect between names, so the redirect is in front of it")
	}

	compose := repoFile(t, "docker-compose.yml")
	if !strings.Contains(compose, `"-access-file"`) || !strings.Contains(compose, `"/data/access"`) {
		t.Error("the compose file does not put a password in front of the installation")
	}
}

// The command the setup page gives finds the setup code: it names the
// folder and the compose service, and greps for words the log line carries,
// and the code is on one of the two lines after them.
func TestTheSetupPageCommandFindsTheCode(t *testing.T) {
	// Read as text: the command is coloured with spans, and what matters is
	// what a person copies.
	page := html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(repoFile(t, "internal/web/assets/setup.html"), ""))
	const command = `cd ~/porch && sudo docker compose logs porch 2>&1 | grep -A2 "setup code"`
	if !strings.Contains(page, command) {
		t.Fatalf("the setup page no longer gives %q", command)
	}
	if !regexp.MustCompile(`(?m)^  porch:$`).MatchString(repoFile(t, "docker-compose.yml")) {
		t.Error("the compose file has no service called porch for the command to name")
	}

	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })
	if _, err := prepareAccess(filepath.Join(t.TempDir(), "access"), time.Now().Add(access.SetupLife)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(said.String(), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "setup code") {
			continue
		}
		for _, after := range lines[i+1 : min(i+3, len(lines))] {
			if regexp.MustCompile(`^    [a-z2-7]{4}(-[a-z2-7]{4}){3}$`).MatchString(after) {
				return
			}
		}
	}
	t.Errorf("grep -A2 \"setup code\" would not show the code in: %q", said.String())
}

// The update check exists only behind a password and never on the
// demonstration: the service that asks GitHub, and the routes that start it,
// are made in the one branch that has a gate and is not the demonstration,
// and nowhere else.
func TestTheUpdateCheckExistsOnlyBehindThePassword(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	const block = "\tvar releases *updates.Service\n" +
		"\tif gate != nil && !demo.Enabled {\n" +
		"\t\treleases = &updates.Service{\n"
	start := strings.Index(src, block)
	if start < 0 {
		t.Fatal("the update service is no longer made in a branch that requires the gate")
	}
	end := strings.Index(src[start:], "\n\t}\n")
	if end < 0 {
		t.Fatal("the branch that makes the update service is not closed where expected")
	}
	branch := src[start : start+end]
	for _, want := range []string{`root.Handle("/api/v1/updates", releases.Handler())`, `root.Handle("/api/v1/updates/", releases.Handler())`} {
		if !strings.Contains(branch, want) {
			t.Errorf("the branch does not register %s", want)
		}
	}
	rest := src[:start] + src[start+end:]
	for _, never := range []string{"updates.Service{", "releases.Handler()", "updates.Checker{", "/api/v1/updates"} {
		if strings.Contains(rest, never) {
			t.Errorf("main.go uses %q outside the branch that requires the gate", never)
		}
	}
	if gate := strings.Index(src, "handler = gate.Wrap(handler)"); gate < start {
		t.Error("the gate is not wrapped around the handler after the update routes are added")
	}
}

// The history exists only behind a password: the vault, the reports kept in
// it, the domain list, what proof checks tell that list, and the routes that
// read them are made inside the one branch that makes the gate, and nowhere
// else.
func TestTheHistoryExistsOnlyBehindThePassword(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	const block = "\tif *accessFile != \"\" {\n" +
		"\t\tgate = access.NewGate(*accessFile, web.PublicPaths())\n" +
		"\t\tif setupCode != \"\" {\n" +
		"\t\t\tgate.AwaitSetup(setupCode, setupUntil)\n" +
		"\t\t}\n" +
		"\t\thistory := &vault.Vault{Dir: filepath.Join(filepath.Dir(*accessFile), \"history\"), Key: gate.Key}\n" +
		"\t\tapi.KeepReports(history)\n" +
		"\t\troot.Handle(\"/api/v1/history\", history.Handler())\n" +
		"\t\troot.Handle(\"/api/v1/history/\", history.Handler())\n" +
		"\t\tdomains := &vault.Domains{Path: filepath.Join(filepath.Dir(*accessFile), \"domains.sealed\"), Key: gate.Key}\n" +
		"\t\tapi.RememberProof(domains)\n" +
		"\t\troot.Handle(\"/api/v1/domains\", domains.Handler())\n" +
		"\t\troot.Handle(\"/api/v1/domains/\", domains.Handler())\n" +
		"\t}\n"
	if !strings.Contains(src, block) {
		t.Fatal("the vault is no longer made in the branch that makes the gate")
	}
	rest := strings.Replace(src, block, "", 1)
	for _, never := range []string{"KeepReports(", "RememberProof(", "history.Handler()", "vault.Vault{", "vault.Domains{", "domains.Handler()"} {
		if strings.Contains(rest, never) {
			t.Errorf("main.go uses %q outside the branch that makes the gate", never)
		}
	}
	if !strings.Contains(src, "if gate != nil {\n\t\thandler = gate.Wrap(handler)\n\t}") {
		t.Error("the gate is not what the server is handed")
	}
}

// A lost password is replaced without leaving the new key facing what the old
// one sealed (audit 2026-09-18, D03 and D09): the history and the domain
// list move to a dated folder, nothing is deleted, the new key starts with an
// empty list it can change, and the old key still opens what was moved.
func TestANewPasswordMovesWhatTheOldOneKeptAside(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	dir := t.TempDir()
	path := filepath.Join(dir, "access")
	// setUp starts as porchd does and chooses the password as the setup page
	// would, and returns the key it seals.
	setUp := func() []byte {
		t.Helper()
		if _, err := prepareAccess(path, time.Now().Add(access.SetupLife)); err != nil {
			t.Fatal(err)
		}
		if err := access.Create(path, "a long chosen password"); err != nil {
			t.Fatal(err)
		}
		key, err := access.Unlock(path, "a long chosen password")
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	stores := func(at string, key []byte) (*vault.Vault, *vault.Domains) {
		k := func() []byte { return key }
		return &vault.Vault{Dir: filepath.Join(at, "history"), Key: k},
			&vault.Domains{Path: filepath.Join(at, "domains.sealed"), Key: k}
	}

	oldKey := setUp()
	if strings.Contains(said.String(), "moved") {
		t.Errorf("a first password said something was moved: %q", said.String())
	}
	history, domains := stores(dir, oldKey)
	if err := history.Keep("tls", "old.example", "strong", "p", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := domains.Add("old.example"); err != nil {
		t.Fatal(err)
	}

	// The password is lost: the access file goes aside, and porchd restarts.
	if err := os.Rename(path, path+".lost"); err != nil {
		t.Fatal(err)
	}
	said.Reset()
	history, domains = stores(dir, setUp())
	if added, err := domains.Add("new.example"); err != nil || !added {
		t.Fatalf("the new key cannot add a domain: %v", err)
	}
	if list, err := domains.List(); err != nil || len(list) != 1 || list[0].Name != "new.example" {
		t.Errorf("the new list reads %v, %v", list, err)
	}
	if err := domains.Remove("new.example"); err != nil {
		t.Errorf("the new key cannot remove a domain: %v", err)
	}
	if entries, st, err := history.List(); err != nil || len(entries) != 0 || st != (vault.Status{}) {
		t.Errorf("the new history is %v, %+v, %v; want empty with nothing unreadable", entries, st, err)
	}

	retired := regexp.MustCompile(`(?m)^    (.*retired-\d{4}-\d{2}-\d{2})$`).FindStringSubmatch(said.String())
	if retired == nil {
		t.Fatalf("where the old data went was not said: %q", said.String())
	}
	oldHistory, oldDomains := stores(retired[1], oldKey)
	if entries, _, err := oldHistory.List(); err != nil || len(entries) != 1 {
		t.Errorf("the old key no longer opens the moved history: %v, %v", entries, err)
	}
	if list, err := oldDomains.List(); err != nil || len(list) != 1 || list[0].Name != "old.example" {
		t.Errorf("the old key no longer opens the moved domain list: %v, %v", list, err)
	}

	// A second reset the same day does not touch the first folder.
	if err := os.Rename(path, path+".lost2"); err != nil {
		t.Fatal(err)
	}
	said.Reset()
	setUp()
	if !strings.Contains(said.String(), retired[1]+"-2") {
		t.Errorf("a second reset did not get a folder of its own: %q", said.String())
	}
	if list, err := oldDomains.List(); err != nil || len(list) != 1 {
		t.Errorf("a second reset changed the first folder: %v, %v", list, err)
	}

	// The names moved are the names main keeps under, and the second
	// factor's, which the access package keeps beside the access file.
	src := repoFile(t, "cmd/porchd/main.go")
	if !strings.Contains(repoFile(t, "internal/access/factor.go"), "filepath.Join(filepath.Dir(accessPath), FactorFile)") {
		t.Error("the second factor is no longer kept beside the access file, where a reset moves it from")
	}
	for _, name := range sealed {
		if name == access.FactorFile {
			continue
		}
		if !strings.Contains(src, `filepath.Join(filepath.Dir(*accessFile), "`+name+`")`) {
			t.Errorf("%q is moved aside on a reset, and main keeps nothing under it", name)
		}
	}
}

// The pages are told everything this installation asks of a source an
// operator chooses.
//
// The privacy page names them, and it can only name what it is handed. A flag
// wired into the scanner and not into web.Installation produces a page that
// says this service asks nobody while it asks a register on every inventory —
// which is the failure the page exists to prevent, arriving through the one
// line nobody looks at (N14). The monitor and the authority are asked
// wherever there is a scope, which is every installation.
//
// Read as text, like the gate above, because what is being checked is that the
// wiring exists at all: a test that called Configure itself would pass with
// main.go passing nothing.
func TestThePagesAreToldWhatThisInstallationAsks(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"Register:          *namesPassive,",
		"ReadsCertificates: *namesReadCertificates,",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("main.go does not hand the pages %q", want)
		}
	}
}

// A folder the access file cannot be written to is said when porchd starts,
// not after somebody has typed a password into the setup page.
func TestAnUnwritableFolderIsSaidAtStart(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	missing := filepath.Join(t.TempDir(), "porch-data", "access")
	code, err := prepareAccess(missing, time.Now().Add(access.SetupLife))
	if err == nil || code != "" || said.Len() != 0 {
		t.Fatalf("a missing folder: code %q, error %v, said %q", code, err, said.String())
	}
	if !strings.Contains(err.Error(), "cannot be written to") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(filepath.Dir(missing)))
	if len(entries) != 0 {
		t.Errorf("checking the folder left %d files behind", len(entries))
	}
}

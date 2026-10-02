package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	buildTargets = regexp.MustCompile(`(?m)^targets="([^"]+)"`)
	vetLoop      = regexp.MustCompile(`for os in ([a-z ]+); do`)
)

// Every platform the release ships is type-checked by CI.
//
// `go vet ./...` on the Linux runner does not read a file behind `//go:build
// windows`. It is not merely unvetted, it is never compiled — so a syntax error
// in one passes every gate in this repository and fails in scripts/build.sh on
// a release evening, at the step the procedure assumes is already known to
// work. That stopped being hypothetical the day internal/dnsclient grew a
// per-platform resolver so the CAA check would run on Windows (R7).
//
// The platform list is read out of the build script rather than written here,
// because adding a release target and forgetting the gate is the same omission
// one file further along.
func TestEveryReleasedPlatformIsVetted(t *testing.T) {
	script, err := os.ReadFile("../../scripts/build.sh")
	if err != nil {
		t.Fatalf("reading the build script: %v", err)
	}
	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("reading the CI workflow: %v", err)
	}

	targets := buildTargets.FindSubmatch(script)
	if targets == nil {
		t.Fatal("scripts/build.sh no longer declares targets=\"...\"; this test is reading " +
			"nothing and would pass for a workflow that vets one platform")
	}

	shipped := map[string]bool{}
	for _, target := range strings.Fields(string(targets[1])) {
		shipped[strings.SplitN(target, "/", 2)[0]] = true
	}
	if len(shipped) < 2 {
		t.Fatalf("found only %v in the build targets, which cannot be right", keys(shipped))
	}

	loop := vetLoop.FindSubmatch(workflow)
	if loop == nil {
		t.Fatal("the CI workflow has no `for os in ...` vet loop, so a file behind another " +
			"platform's build tag is compiled nowhere before a release")
	}

	vetted := map[string]bool{}
	for _, os := range strings.Fields(string(loop[1])) {
		vetted[os] = true
	}

	for os := range shipped {
		if !vetted[os] {
			t.Errorf("the release builds for %s and CI vets %v; a file behind //go:build %s "+
				"is never compiled until somebody tags a release", os, keys(vetted), os)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var staticcheckVersion = regexp.MustCompile(`staticcheck@(v[0-9]+\.[0-9]+\.[0-9]+)`)

// The staticcheck CONTRIBUTING.md tells you to run is the one CI runs.
//
// It was in neither place for a while, which is how an unused test helper — a
// U1000 that go vet says nothing about — reached a pull request instead of a
// terminal. Writing the command down fixes that once; writing a version down in
// two files is the next way it goes wrong, since a bump in ci.yml would leave
// the documented gate quietly checking something else.
func TestTheDocumentedStaticcheckIsTheOneCIRuns(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("reading the CI workflow: %v", err)
	}
	guide, err := os.ReadFile("../../CONTRIBUTING.md")
	if err != nil {
		t.Fatalf("reading CONTRIBUTING.md: %v", err)
	}

	inCI := staticcheckVersion.FindSubmatch(workflow)
	if inCI == nil {
		t.Fatal("the CI workflow no longer pins a staticcheck version, so this test is reading " +
			"nothing and the documented gate has nothing to agree with")
	}

	documented := staticcheckVersion.FindSubmatch(guide)
	if documented == nil {
		t.Fatalf("CONTRIBUTING.md does not say how to run staticcheck, so the only place it runs is "+
			"CI and every change that trips it finds out from a pull request. CI pins %s",
			inCI[1])
	}

	if string(documented[1]) != string(inCI[1]) {
		t.Errorf("CONTRIBUTING.md runs staticcheck %s and CI runs %s; the gate somebody runs before "+
			"pushing has to be the gate that decides", documented[1], inCI[1])
	}
}

// Every workflow that asks whether a known vulnerability is reachable asks the
// same govulncheck.
//
// Three of them do: CI on every change, the release build before it stages a
// draft, and the weekly watch against code nobody touched. A release gate and a
// merge gate pinned to different versions are two answers to what is known,
// and the one nobody notices is the one that ships. Moved together on
// 2026-10-02, to v1.8.0, with the toolchain (S7).
func TestEveryGovulncheckIsTheSameOne(t *testing.T) {
	pin := regexp.MustCompile(`golang\.org/x/vuln/cmd/govulncheck@(v[0-9]+\.[0-9]+\.[0-9]+)`)
	seen := map[string]string{}
	for _, path := range []string{
		"../../.github/workflows/ci.yml",
		"../../.github/workflows/build-release.yml",
		"../../.github/workflows/security-watch.yml",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		found := pin.FindAllSubmatch(body, -1)
		if len(found) == 0 {
			t.Errorf("%s no longer runs a pinned govulncheck", path)
		}
		for _, m := range found {
			seen[string(m[1])] = path
		}
	}
	if len(seen) > 1 {
		t.Errorf("the workflows pin different govulncheck versions: %v", seen)
	}
}

// Somebody is told, every week, when go.mod falls behind.
//
// On 2026-10-02 go.mod named 1.26.7, five weeks after 1.26.8 and 1.27.1 were
// out, and nothing had said so: the vulnerability watch asks whether a known
// problem is reachable, not whether the toolchain is one Go still fixes. A
// script on the production server used to watch for releases instead, which
// put a toolchain and an outbound check on the one machine that needs neither.
// The watch is a job in security-watch.yml now, reading the same list the
// toolchain is fetched from, and failing for both reasons S7 gives: a newer
// patch of the line in use, and a line Go no longer supports.
func TestTheToolchainIsWatchedWeekly(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/security-watch.yml")
	if err != nil {
		t.Fatal(err)
	}
	watch := string(body)
	if !regexp.MustCompile(`(?m)^\s+- cron: "[^"]+"`).MatchString(watch) {
		t.Fatal("security-watch.yml no longer runs on a schedule, so nothing here runs on its own")
	}
	job := regexp.MustCompile(`(?s)\n  toolchain:\n.*`).FindString(watch)
	if job == "" {
		t.Fatal("security-watch.yml has no job checking that the toolchain is current")
	}
	for _, step := range []struct{ text, why string }{
		{"go.mod", "the version checked is the one the build uses"},
		{"https://proxy.golang.org/golang.org/toolchain/@v/list", "the list of releases is the one the toolchain is fetched from"},
		{"tail -n 2", "Go supports the two newest lines, and a line outside them is due now"},
		{"is no longer supported", "a line Go no longer fixes fails the job"},
		{"is out.", "a newer patch of the line in use fails the job"},
	} {
		if !strings.Contains(job, step.text) {
			t.Errorf("the toolchain job no longer covers %q: %s", step.text, step.why)
		}
	}
	if strings.Contains(job, "continue-on-error") {
		t.Error("the toolchain job is allowed to fail without anybody seeing it")
	}
}

// Every analysis tool is built by the toolchain go.mod names.
//
// `go install tool@version` builds the tool with the oldest toolchain the tool
// itself accepts, and a tool built by an older Go cannot type-check code for a
// newer one: it reports that every package "requires newer Go version" and
// fails. On 2026-10-02 that failed staticcheck and govulncheck on the move to
// 1.27.1, with versions of both that read 1.27 (S7). A gate that fails for a
// reason nobody reads is one somebody turns off.
func TestEveryAnalysisToolIsBuiltByTheModulesToolchain(t *testing.T) {
	install := regexp.MustCompile(`(?m)^(.*)go install ((?:golang\.org/x/vuln/cmd/govulncheck|honnef\.co/go/tools/cmd/staticcheck|github\.com/securego/gosec/v2/cmd/gosec)@\S+)`)
	tools := map[string]bool{}
	for _, path := range []string{
		"../../.github/workflows/ci.yml",
		"../../.github/workflows/build-release.yml",
		"../../.github/workflows/security-watch.yml",
		"../../CONTRIBUTING.md",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range install.FindAllStringSubmatch(string(body), -1) {
			tools[strings.SplitN(m[2], "@", 2)[0]] = true
			if !strings.Contains(m[1], `GOTOOLCHAIN="$(go env GOVERSION)"`) {
				t.Errorf("%s builds %s with whatever toolchain go install picks, not the one go.mod names", path, m[2])
			}
		}
	}
	if len(tools) != 3 {
		t.Errorf("found %d of the three analysis tools being installed: %v", len(tools), tools)
	}
}

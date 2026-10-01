package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every flag this service accepts, beside what it does.
//
// -open and -without-password were each one line in main.go, and each turned
// proof of control off for whoever started the service with it. They were
// removed in v0.25.1 (N9). This list is what stops the next one arriving the
// same way: a flag that is not here fails the test, so adding one means adding
// it here too, in the open, under the rule that nothing on this list may
// weaken the proof. Choosing which proof is asked for, or asking for a
// stronger one, is fine; skipping it is not a flag this service can have.
var everyServiceFlag = map[string]string{
	"listen":                       "the address the service listens on; anywhere but loopback needs a secret",
	"tls-cert":                     "the certificate chain the service presents",
	"tls-key":                      "the key for that chain",
	"request-timeout":              "the budget for one scan",
	"max-concurrent":               "how many scans run at once",
	"max-connections":              "how many connections may be open at once",
	"burst":                        "how many scans one client may run back to back",
	"refill":                       "how long one rate limit token takes to return",
	"max-tracked-clients":          "how many clients the rate limiter remembers",
	"verification-secret-file":     "the secret every proof record is derived from",
	"verification-requires-dnssec": "accepts only a proof the zone signs: stronger, never weaker",
	"verification-token":           "prints the record a domain must publish, then exits",
	"names-monitor":                "which certificate transparency monitor the inventory asks",
	"names-monitor-url":            "that monitor's address",
	"names-passive":                "which passive DNS register the inventory asks",
	"names-passive-url":            "that register's address",
	"names-read-zone":              "asks a proven domain's servers for the zone",
	"names-walk-proofs":            "follows a proven zone's DNSSEC absence proofs",
	"names-read-certificates":      "reads the certificate each name presents",
	"ask-responder":                "asks a certificate's own authority about revocation",
	"stats-file":                   "where the aggregate counters are kept",
	"results-dir":                  "where this installation keeps its own reports",
	"results-keep":                 "how many reports to keep per target",
	"helo":                         "the name the mail check gives with EHLO",
	"resolver":                     "the resolver for lookups; never the one the proof is read through",
	"access-file":                  "the password that closes the installation",
	"version":                      "prints the release, then exits",
}

// A name that says it gets round the proof fails even when it is listed: the
// list is reviewed, and this is the line a reviewer should not have to catch.
var soundsLikeABypass = regexp.MustCompile(`(?i)(^|-)(open|insecure|unsafe|skip|without|bypass|disable|no-?proof|no-?verif|unverified|allow-any|any-domain)(-|$)`)

func TestNoServiceFlagTurnsProofOff(t *testing.T) {
	defined := flagsDefinedIn(t, ".")
	if len(defined) == 0 {
		t.Fatal("no flags were found, so this test checks nothing")
	}
	for name := range defined {
		if _, ok := everyServiceFlag[name]; !ok {
			t.Errorf("-%s is a flag this list does not name: add it, with what it does, and only if it leaves proof of control as it is", name)
		}
		if soundsLikeABypass.MatchString(name) {
			t.Errorf("-%s reads as a way round proof of control, which this service does not have", name)
		}
	}
	for name := range everyServiceFlag {
		if !defined[name] {
			t.Errorf("-%s is listed and no longer defined: take it off the list", name)
		}
	}

	// The two that were removed are names the pattern catches, or it is not
	// the pattern this test needs.
	for _, removed := range []string{"open", "without-password"} {
		if !soundsLikeABypass.MatchString(removed) {
			t.Errorf("-%s, which turned proof or the password off, does not read as a bypass to this test", removed)
		}
	}
}

// The functions in package flag that register one. flag.Lookup and the rest
// name a flag without making one.
var definesAFlag = map[string]bool{
	"Bool": true, "BoolVar": true, "BoolFunc": true, "Func": true,
	"String": true, "StringVar": true, "Int": true, "IntVar": true,
	"Int64": true, "Int64Var": true, "Uint": true, "UintVar": true,
	"Uint64": true, "Uint64Var": true, "Float64": true, "Float64Var": true,
	"Duration": true, "DurationVar": true, "Var": true, "TextVar": true,
}

// flagsDefinedIn reads the package's own source for every flag it registers,
// rather than running it: a flag defined behind a branch that a test does not
// take is still a flag somebody can pass.
func flagsDefinedIn(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// A flag set of its own would register flags this test does not see.
		if strings.Contains(string(src), "flag.NewFlagSet") {
			t.Fatalf("%s makes a flag set of its own; teach this test to read it", path)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" || !definesAFlag[sel.Sel.Name] {
				return true
			}
			// flag.Bool("name", …) and flag.BoolVar(&v, "name", …), and the
			// same for every other kind.
			at := 0
			if strings.HasSuffix(sel.Sel.Name, "Var") {
				at = 1
			}
			if len(call.Args) <= at {
				return true
			}
			lit, ok := call.Args[at].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if name, err := strconv.Unquote(lit.Value); err == nil {
				names[name] = true
			}
			return true
		})
	}
	return names
}

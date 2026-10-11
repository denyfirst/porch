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

// Every flag the command line accepts, beside what it does.
//
// The command line asked for no proof at all until v0.25.1: every release
// before it checked whatever name was typed in (N9). It asks now, and this
// list is what keeps a flag from quietly undoing that: one that is not here
// fails the test, so adding a flag means adding it here too, in the open, under
// the rule that nothing on this list may weaken the proof. The same rule and
// the same reader as cmd/porchd's list.
var everyCommandLineFlag = map[string]string{
	"json":                     "the report as JSON",
	"timeout":                  "the budget for one target",
	"allow-private":            "permits private addresses; a name still has to be proven",
	"check":                    "which check runs",
	"passive":                  "which passive DNS register the inventory asks",
	"passive-url":              "that register's address",
	"ranges":                   "address ranges the operator owns, read for their names",
	"read-zone":                "asks a proven domain's servers for the zone",
	"walk-proofs":              "follows a proven zone's DNSSEC absence proofs",
	"read-certificates":        "reads the certificate each name presents",
	"names":                    "names the operator already has",
	"names-file":               "a file of names the operator already has",
	"resolver":                 "the resolver for CAA records; never the one the proof is read through",
	"results-dir":              "where the operator's own reports are kept",
	"results-keep":             "how many reports to keep per target",
	"helo":                     "the name the mail check gives with EHLO",
	"dkim-selector":            "the selectors DKIM keys are looked for under",
	"dkim-common":              "also looks under the selectors providers document",
	"history":                  "prints what was kept, then exits; connects to nothing",
	"verification-secret-file": "the secret every proof record is derived from",
	"verification-token":       "prints the records a domain must publish, then exits",
	"limits":                   "prints the method's limits, then exits",
	"version":                  "prints the release, then exits",
}

// A name that says it gets round the proof fails even when it is listed: the
// list is reviewed, and this is the line a reviewer should not have to catch.
var soundsLikeABypass = regexp.MustCompile(`(?i)(^|-)(open|insecure|unsafe|skip|without|bypass|disable|no-?proof|no-?verif|unverified|allow-any|any-domain)(-|$)`)

func TestNoCommandLineFlagTurnsProofOff(t *testing.T) {
	defined := flagsDefinedIn(t, ".")
	if len(defined) == 0 {
		t.Fatal("no flags were found, so this test checks nothing")
	}
	for name := range defined {
		if _, ok := everyCommandLineFlag[name]; !ok {
			t.Errorf("-%s is a flag this list does not name: add it, with what it does, and only if it leaves proof of control as it is", name)
		}
		if soundsLikeABypass.MatchString(name) {
			t.Errorf("-%s reads as a way round proof of control, which the command line does not have", name)
		}
	}
	for name := range everyCommandLineFlag {
		if !defined[name] {
			t.Errorf("-%s is listed and no longer defined: take it off the list", name)
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

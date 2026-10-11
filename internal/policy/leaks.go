package policy

import (
	"fmt"
	"strings"
)

// Files a site serves that should never be public, graded.
//
// Graded, unlike most of what this check reports, because the line is drawn
// by a document and no correct configuration crosses it: each kind is a named
// weakness in MITRE's CWE, and a Git repository or an environment file in the
// web root is a leak whatever the site meant (R21). What decides the verdict
// is what the file gives away — the source and its history, or passwords and
// keys, are insecure; a page describing the server, or a list of the files
// beside it, is weak.

var (
	cwe527 = Reference{"CWE-527 — Exposure of Version-Control Repository to an Unauthorized Control Sphere", "https://cwe.mitre.org/data/definitions/527.html"}
	cwe538 = Reference{"CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory", "https://cwe.mitre.org/data/definitions/538.html"}
	cwe497 = Reference{"CWE-497 — Exposure of Sensitive System Information to an Unauthorized Control Sphere", "https://cwe.mitre.org/data/definitions/497.html"}
	cwe548 = Reference{"CWE-548 — Exposure of Information Through Directory Listing", "https://cwe.mitre.org/data/definitions/548.html"}
)

// ServedFile is one file the site served that it should not have.
type ServedFile struct {
	Path string
	What string

	// Kind is "source", "secrets", "diagnostics" or "listing".
	Kind string
}

// GradeLeaks grades the files served, one finding per kind.
func GradeLeaks(files []ServedFile) WebResult {
	var out WebResult
	by := map[string][]ServedFile{}
	for _, f := range files {
		by[f.Kind] = append(by[f.Kind], f)
	}
	for _, rule := range []struct {
		kind, id string
		verdict  Verdict
		title    string
		why      string
		ref      Reference
	}{
		{"source", "web.exposed-source", Insecure, "The site's source repository is served",
			"hands anybody the site's code and its history, often with passwords committed to it long ago", cwe527},
		{"secrets", "web.exposed-secrets", Insecure, "A file of passwords or keys is served",
			"hands anybody the credentials the site runs with", cwe538},
		{"diagnostics", "web.exposed-diagnostics", Weak, "A page describing the server is served",
			"tells anybody what software runs here, how it is set up, and who is using it", cwe497},
		{"listing", "web.exposed-listing", Weak, "A listing of the server's files is served",
			"names files nobody was meant to find", cwe548},
	} {
		got := by[rule.kind]
		if len(got) == 0 {
			continue
		}
		var named []string
		for _, f := range got {
			named = append(named, f.Path+" ("+f.What+")")
		}
		out.add(Finding{
			RuleID:     rule.id,
			Verdict:    rule.verdict,
			Title:      rule.title,
			Rationale:  fmt.Sprintf("%s %s; it %s. Remove it from the web root, or deny it in the server's configuration.", list(named), servedVerb(len(got)), rule.why),
			References: []Reference{rule.ref},
		})
	}
	return out
}

func servedVerb(n int) string {
	if n == 1 {
		return "is served to anybody who asks for it by name"
	}
	return "are served to anybody who asks for them by name"
}

// LeaksLabel is the row the answer is shown under.
const LeaksLabel = "Files that should not be public"

// LeaksLine says what was found, in one line.
func LeaksLine(asked bool, paths, unanswered int, served []ServedFile, reason string) string {
	switch {
	case !asked:
		return ""
	case reason != "":
		return "not established: " + reason
	case len(served) == 0 && unanswered == 0:
		return fmt.Sprintf("none of the %d checked is served", paths)
	case len(served) == 0:
		return fmt.Sprintf("none of the %d checked is served; %d could not be asked", paths-unanswered, unanswered)
	}
	var named []string
	for _, f := range served {
		named = append(named, f.Path)
	}
	verb := " is served"
	if len(named) > 1 {
		verb = " are served"
	}
	return strings.TrimSpace(list(named) + verb)
}

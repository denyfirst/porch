package web

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/webprobe"
)

// flatten collapses the whitespace a template wraps its prose with, so an
// assertion is about what a reader sees rather than about where a line broke.
func flatten(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// checksDoc is docs/checks.md, which reports and the command line link to.
func checksDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/checks.md")
	if err != nil {
		t.Fatal(err)
	}
	return flatten(string(raw))
}

// The addresses the method pages had still lead somewhere: user agents,
// command-line output and shared reports carry them.
func TestTheOldMethodAddressesLeadToTheChecksDocument(t *testing.T) {
	for path, want := range map[string]string{
		"/docs":         DocsURL,
		"/method":       ChecksURL + "#tls",
		"/tls/method":   ChecksURL + "#tls",
		"/web/method":   ChecksURL + "#web",
		"/mail/method":  ChecksURL + "#mail",
		"/dns/method":   ChecksURL + "#dns",
		"/names/method": ChecksURL + "#names",
	} {
		w := get(t, path)
		if w.Code != 301 || w.Header().Get("Location") != want {
			t.Errorf("GET %s: %d to %q, want 301 to %q", path, w.Code, w.Header().Get("Location"), want)
		}
	}
	for _, heading := range []string{"## TLS", "## Web", "## Mail", "## DNS", "## Names", "### Obsolete suites"} {
		if !strings.Contains(checksDoc(t), heading) {
			t.Errorf("docs/checks.md has no %q, so a link to its anchor lands nowhere", heading)
		}
	}
}

// Why the obsolete suites are asked by hand is said in the checks document,
// and the report says only how to read a row and links there.
func TestTheObsoleteSuitesAreExplainedInTheChecksDocument(t *testing.T) {
	src := script(t)
	if strings.Contains(src, "Go cannot offer") {
		t.Error("the report still explains the library it is built with")
	}
	for _, want := range []string{
		`"Refused means the server accepted none of them. "`,
		`why.href = CHECKS_DOC + "#obsolete-suites";`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the obsolete-suite section no longer contains %s", want)
		}
	}

	// Every row the report draws is a term the document defines, in the same
	// words, so a reader who follows the link finds the row they came from.
	doc := checksDoc(t)
	rows := regexp.MustCompile(`answer\("([^"]+)", l\.`).FindAllStringSubmatch(src, -1)
	if len(rows) != 4 {
		t.Fatalf("the report draws %d family rows, want 4", len(rows))
	}
	labels := []string{"Downgrade signal"}
	for _, r := range rows {
		labels = append(labels, r[1])
	}
	for _, l := range labels {
		if !strings.Contains(doc, "**"+l+":**") {
			t.Errorf("docs/checks.md does not define %q, which the report draws", l)
		}
	}
}

// The mail check's document answers the question its reports raise most.
func TestTheMailCheckIsDocumented(t *testing.T) {
	doc := checksDoc(t)
	for _, want := range []string{"## Mail", "reverse DNS name", "`-helo`"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/checks.md does not say %q", want)
		}
	}
}

// What the web check calls itself is in the checks document, not under every
// report.
func TestTheUserAgentIsDocumentedAndNotInTheReport(t *testing.T) {
	if !strings.Contains(checksDoc(t), "`"+webprobe.DefaultUserAgent+"`") {
		t.Error("docs/checks.md does not say what the web check calls itself")
	}
	src := script(t)
	if strings.Contains(src, "Requested as") || strings.Contains(src, "observed.userAgent") {
		t.Error("the Reach report still draws the user agent")
	}
}

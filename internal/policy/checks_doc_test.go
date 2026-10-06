package policy

import (
	"os"
	"strings"
	"testing"
)

// Reports link to docs/checks.md for the limits that are true of every scan,
// so that document carries each one, in the words the command line prints.
func TestEveryStandingLimitIsInTheChecksDocument(t *testing.T) {
	raw, err := os.ReadFile("../../docs/checks.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(raw)), " ")
	for _, set := range [][]StandingLimit{StandingLimits(), WebStandingLimits(), MailStandingLimits(), DNSStandingLimits()} {
		for _, l := range set {
			if want := "**" + l.Title + ".** " + l.Text; !strings.Contains(doc, want) {
				t.Errorf("docs/checks.md does not carry the limit %s as the program states it", l.ID)
			}
		}
	}
}

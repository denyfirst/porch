package mailscan

import (
	"context"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/announce"
	"github.com/denyfirst/porch/internal/smtptls"
)

// What an exchanger's greeting named reaches the report: the row in the words
// both faces print, and one sentence where a version came with it.
//
// Dropped on the way, every report would say the greeting named nothing this
// check knows, about servers announcing their patch level to anybody.
func TestWhatAGreetingNamedReachesTheReport(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	x := &fixedExchangers{answer: func(host string) smtptls.Result {
		return smtptls.Result{Host: host, Connected: true, Measured: true,
			Software: []announce.Software{{Name: "Exim", Where: announce.Greeting, Versioned: true}}}
	}}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Observed.Exchangers) != 1 {
		t.Fatalf("exchangers reported as %+v", got.Observed.Exchangers)
	}
	if line := got.Observed.Exchangers[0].SoftwareLine; line != "names Exim, with its version" {
		t.Errorf("the row reads %q", line)
	}

	var said bool
	for _, n := range got.Notes {
		said = said || strings.Contains(n.Text, "the version of Exim (mx1.example.net)")
	}
	if !said {
		t.Errorf("no sentence names the version announced: %+v", got.Notes)
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Title, "version") {
			t.Errorf("a version was graded: %+v", f)
		}
	}
}

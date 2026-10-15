package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/liveness"
)

// The names page reads the state and the field the API sends for a name a
// hosting service says nobody has claimed, and lists it under Findings.
//
// Misspelled on either side, the name would be drawn as one more state in the
// table and never reach the part of the page an operator acts on.
func TestTheNamesPageListsANameNobodyClaimedAsAFinding(t *testing.T) {
	raw, err := json.Marshal(liveness.Name{Name: "docs.example.test", Status: liveness.Unclaimed,
		Alias: "someone.github.io", Provider: "GitHub Pages"})
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["status"] != "unclaimed" || sent["provider"] != "GitHub Pages" {
		t.Fatalf("the API sends %s", raw)
	}

	source := script(t)
	for _, want := range []string{
		`const unclaimed = hosts.filter((n) => status(n) === "unclaimed");`,
		`case now.status === "unclaimed":`,
		`for (const n of unclaimed) {`,
		`n.now.provider`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("app.js no longer has %s", want)
		}
	}
}

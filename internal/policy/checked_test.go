package policy

import (
	"strings"
	"testing"
)

// Every item a check asked for is named, in the order asked, with what came
// back, and nothing is said more strongly than it was measured.
func TestEveryItemAskedIsNamedWithWhatCameBack(t *testing.T) {
	files := LeaksChecked([]FileAsked{
		{Path: "/.git/HEAD", What: "a Git repository", Answered: true},
		{Path: "/.env", What: "an environment file", Answered: true, Served: true},
		{Path: "/.svn/wc.db", What: "a Subversion working copy"},
	})
	want := []Checked{
		{Item: "/.git/HEAD", What: "a Git repository", State: "not served"},
		{Item: "/.env", What: "an environment file", State: "served", Found: true},
		{Item: "/.svn/wc.db", What: "a Subversion working copy", State: "no answer"},
	}
	if len(files) != len(want) {
		t.Fatalf("got %d items, want %d", len(files), len(want))
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("item %d is %+v, want %+v", i, files[i], want[i])
		}
	}

	ports := ExposureChecked([]ServiceAsked{
		{Port: "445", Name: "SMB"},
		{Port: "6379", Name: "Redis", AnsweredAt: []string{"192.0.2.1", "2001:db8::1"}},
	})
	if ports[0].State != "no answer from here" || ports[0].Found {
		t.Errorf("a silent port reads %+v", ports[0])
	}
	if ports[1].State != "answers at 192.0.2.1 and 2001:db8::1" || !ports[1].Found {
		t.Errorf("an open port reads %+v", ports[1])
	}

	// A silent port is never said to be closed: a firewall, a network on the
	// way, or a provider blocking the port outbound all look the same here.
	for _, c := range append(files, ports...) {
		if strings.Contains(c.State, "closed") || strings.Contains(c.State, "safe") {
			t.Errorf("%s reads %q, which claims more than was measured", c.Item, c.State)
		}
	}
}

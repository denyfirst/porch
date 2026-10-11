package webscan

import (
	"testing"

	"github.com/denyfirst/porch/internal/hstspreload"
	"github.com/denyfirst/porch/internal/policy"
)

// The preload list's answer sits beside the header it is about, in the
// declared rows both faces already draw, and says which entry covers the host.
func TestThePreloadListSitsBesideTheHeader(t *testing.T) {
	declared := []policy.Declaration{
		{Label: "Strict-Transport-Security", Says: "max-age=63072000; includeSubDomains; preload"},
		{Label: "X-Content-Type-Options", Says: "nosniff"},
	}
	got := withPreload(declared, "www.example.test",
		hstspreload.Status{Asked: true, State: "preloaded", PreloadedDomain: "example.test"})
	if len(got) != 3 || got[1].Label != policy.PreloadLabel ||
		got[1].Says != "on the list browsers build in, through example.test" {
		t.Errorf("the rows read %+v", got)
	}
	if got[2].Label != "X-Content-Type-Options" {
		t.Errorf("a row after the header was lost: %+v", got)
	}

	for state, says := range map[string]string{
		"unknown":  "not on the list browsers build in",
		"pending":  "submitted, and waiting to be added",
		"rejected": "submitted, and rejected",
	} {
		rows := withPreload(nil, "example.test", hstspreload.Status{Asked: true, State: state})
		if len(rows) != 1 || rows[0].Says != says {
			t.Errorf("%s reads %+v", state, rows)
		}
	}
	if rows := withPreload(nil, "example.test", hstspreload.Status{Asked: true, Reason: "the preload list did not answer"}); len(rows) != 1 || rows[0].Says != "not established: the preload list did not answer" {
		t.Errorf("a failed answer reads %+v", rows)
	}
	if rows := withPreload(declared, "example.test", hstspreload.Status{}); len(rows) != 2 {
		t.Errorf("a list nobody asked added a row: %+v", rows)
	}
}

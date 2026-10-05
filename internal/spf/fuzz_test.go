package spf

import (
	"context"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/display/displaytest"
)

// fuzzZone answers TXT questions from a fixed map.
type fuzzZone map[string][]string

func (z fuzzZone) LookupTXT(_ context.Context, name string) ([]string, bool, error) {
	v, ok := z[strings.ToLower(strings.TrimSuffix(name, "."))]
	return v, ok, nil
}

// A sender policy is whatever the domain publishes, and so is every policy it
// includes (audit 2026-10-05, F5). The walk must end, and nothing it returns
// may act on a display.
func FuzzSPFWalk(f *testing.F) {
	for _, seed := range [][2]string{
		{"v=spf1 include:a.example.test redirect=b.example.test -all", "v=spf1 include:example.test ~all"},
		{"v=spf1 include:%{ir}.%{v}._spf.example.test ptr -all", "v=spf1 a mx ip4:192.0.2.0/24 ?all"},
		{"v=spf1 include:a\x1b[2J.example.test -all", "v=spf1 include:a\u202e.example.test"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, top, below string) {
		zone := fuzzZone{
			"example.test":   {top},
			"a.example.test": {below},
			"b.example.test": {below, top},
		}
		displaytest.Clean(t, Check(context.Background(), zone, "example.test"))
	})
}

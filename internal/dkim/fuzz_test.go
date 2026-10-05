package dkim

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

// A key record is whatever the domain publishes under a selector (audit
// 2026-10-05, F5). Read without panicking, and nothing returned may act on a
// display.
func FuzzDKIMRecord(f *testing.F) {
	for _, seed := range []string{
		"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA; t=y:s",
		"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		"v=DKIM1; k=rsa\x1b[2J; p=; n=\u202enote",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, record string) {
		zone := fuzzZone{"mail._domainkey.example.test": {record}}
		displaytest.Clean(t, Check(context.Background(), zone, "example.test", []Selector{{Name: "mail"}}))
	})
}

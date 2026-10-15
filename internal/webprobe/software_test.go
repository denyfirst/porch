package webprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What a response named about its software is kept as names, and the headers
// that carried the versions are not kept at all.
func TestTheSoftwareNamedIsKeptWithoutItsVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.3.1")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/", anywhere())
	hop := c.Final()
	if hop == nil || len(hop.Software) != 2 || hop.Software[0].Name != "nginx" || !hop.Software[0].Versioned ||
		hop.Software[1].Name != "PHP" || !hop.Software[1].Versioned {
		t.Fatalf("the software named was read as %+v", hop)
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"1.25.3", "8.3.1"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("the version %s reached the report: %s", leaked, raw)
		}
	}
}

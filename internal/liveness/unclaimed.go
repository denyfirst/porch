package liveness

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// UserAgent is what the one request this package makes says it is.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// maxUnclaimedBody bounds what is read of the answer. Each service's sentence
// for a name nobody has claimed is near the top of a short page.
const maxUnclaimedBody = 16 << 10

// provider is a service that hands a name to whoever asks for it first, and
// what it answers, with 404, for a name nobody has claimed there.
//
// A fixed list of services whose answer is documented, and short on purpose:
// an entry that matched the wrong page would tell an operator that somebody
// can take a name over when nobody can, and one whose sentence changed would
// fall silent rather than say so. Each answer is matched exactly, and only on
// a 404.
type provider struct {
	name   string
	serves func(alias string) bool
	answer string
}

var providers = []provider{
	{"GitHub Pages", under("github.io"), "There isn't a GitHub Pages site here."},
	{"Amazon S3", isS3, "NoSuchBucket"},
	{"Pantheon", under("pantheonsite.io"), "The gods are wise, but do not know of the site which you seek."},
	{"Surge", under("surge.sh"), "project not found"},
}

// under matches a name strictly below a suffix.
func under(suffix string) func(string) bool {
	return func(alias string) bool { return strings.HasSuffix(alias, "."+suffix) }
}

// isS3 matches the names Amazon gives buckets: under amazonaws.com, with a
// label naming S3 — "bucket.s3.amazonaws.com",
// "bucket.s3-website-us-east-1.amazonaws.com",
// "bucket.s3.eu-west-1.amazonaws.com".
func isS3(alias string) bool {
	if !strings.HasSuffix(alias, ".amazonaws.com") {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(alias, ".amazonaws.com"), ".")
	for _, l := range labels[1:] {
		if l == "s3" || strings.HasPrefix(l, "s3-") {
			return true
		}
	}
	return false
}

// providerOf is the service any alias in a chain points at, if it is one on
// the list.
func providerOf(aliases []string) *provider {
	for _, a := range aliases {
		a = strings.ToLower(strings.TrimSuffix(a, "."))
		for i := range providers {
			if providers[i].serves(a) {
				return &providers[i]
			}
		}
	}
	return nil
}

// unclaimed asks the name once, over plain HTTP at the address already
// resolved, and reports whether the service answered as it does for a name
// nobody has claimed.
//
// Nothing is followed and nothing is kept. The dial goes through the same
// dialler as every other connection here, so an address nothing may dial is
// still never dialled.
func (c *Checker) unclaimed(ctx context.Context, name string, addr netip.Addr, p *provider) bool {
	dial := c.dial()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dial(ctx, network, net.JoinHostPort(addr.String(), "80"))
			},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: maxUnclaimedBody,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+name+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUnclaimedBody))
	if err != nil {
		return false
	}
	return bytes.Contains(body, []byte(p.answer))
}

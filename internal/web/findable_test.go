package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// A crawler is told what to do, and the answer differs by deployment: the
// demonstration wants to be found and lists its pages; an installation
// somebody runs asks not to be indexed at all, because its addresses are one
// company's instrument rather than anything to search for.
func TestACrawlerIsToldWhatThisDeploymentIs(t *testing.T) {
	robots := get(t, "/robots.txt")
	if robots.Code != 200 || !strings.HasPrefix(robots.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("robots.txt: %d %s", robots.Code, robots.Header().Get("Content-Type"))
	}
	body := robots.Body.String()

	sitemap := get(t, "/sitemap.xml")
	if !demo.Enabled {
		if !strings.Contains(body, "Disallow: /") || strings.Contains(body, "Sitemap:") {
			t.Errorf("an installation somebody runs asks to be indexed: %q", body)
		}
		if sitemap.Code != 404 {
			t.Errorf("an installation somebody runs publishes a sitemap: %d", sitemap.Code)
		}
		return
	}

	// Two names since 2026-10-05, and each offers itself and lists the pages
	// it serves. Between them every page is listed once, at the address it
	// states as its own, and each listed address answers without a redirect.
	listedAll := 0
	for _, crawler := range []struct{ host, base string }{
		{organisationHost, SiteURL},
		{porchHost, PorchURL},
	} {
		robots := getOn(t, "GET", crawler.host, "/robots.txt").Body.String()
		if !strings.Contains(robots, "Allow: /") || !strings.Contains(robots, "Sitemap: "+crawler.base+"/sitemap.xml") {
			t.Errorf("%s does not offer itself: %q", crawler.host, robots)
		}
		sitemap := getOn(t, "GET", crawler.host, "/sitemap.xml")
		if sitemap.Code != 200 || !strings.Contains(sitemap.Header().Get("Content-Type"), "xml") {
			t.Fatalf("%s sitemap: %d %s", crawler.host, sitemap.Code, sitemap.Header().Get("Content-Type"))
		}
		for _, loc := range regexp.MustCompile(`<loc>([^<]+)</loc>`).FindAllStringSubmatch(sitemap.Body.String(), -1) {
			listedAll++
			if !strings.HasPrefix(loc[1], crawler.base+"/") {
				t.Errorf("%s's sitemap lists %s, on the other name", crawler.host, loc[1])
				continue
			}
			if w := getOn(t, "GET", crawler.host, strings.TrimPrefix(loc[1], crawler.base)); w.Code != 200 {
				t.Errorf("%s's sitemap lists %s, which answers %d", crawler.host, loc[1], w.Code)
			}
		}
	}
	for path := range rendered {
		home := porchHost
		if p := pages[path]; p != nil && p.Organisation {
			home = organisationHost
		}
		if !strings.Contains(getOn(t, "GET", home, "/sitemap.xml").Body.String(), "<loc>"+statedAddress(path)+"</loc>") {
			t.Errorf("the sitemaps leave out %s", path)
		}
	}
	if listedAll != len(rendered) {
		t.Errorf("the sitemaps list %d addresses and the site has %d", listedAll, len(rendered))
	}
}

// statedAddress is the address a demonstration page states as its own,
// written out here rather than taken from canonicalURL, so that a mistake
// there is not repeated in what checks it: the organisation's two pages on
// its name, Porch's page at the root of Porch's, and every other on Porch's.
func statedAddress(path string) string {
	switch path {
	case "/":
		return SiteURL + "/"
	case "/organisation":
		return SiteURL + "/privacy"
	case "/porch":
		return PorchURL + "/"
	}
	return PorchURL + path
}

// Every page on the demonstration says which address it is and repeats its
// own title in the tags a link preview reads. An installation somebody runs
// says neither: its pages are its own, and a canonical address here would
// tell a search engine they are copies of ours.
func TestEveryPageSaysWhichAddressItIs(t *testing.T) {
	for path, p := range pages {
		body := get(t, path).Body.String()
		if !demo.Enabled {
			// SiteURL itself is not forbidden: the page that explains what the
			// web check sends quotes its own user agent, which names it.
			for _, never := range []string{"rel=\"canonical\"", "og:title", "og:url"} {
				if strings.Contains(body, never) {
					t.Errorf("%s: an installation somebody runs carries %s", path, never)
				}
			}
			continue
		}
		for _, want := range []string{
			`<link rel="canonical" href="` + statedAddress(path) + `">`,
			`<meta property="og:url" content="` + statedAddress(path) + `">`,
			`<meta property="og:title" content="` + p.Title + `">`,
			`<meta property="og:site_name" content="denyfirst">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not carry %s", path, want)
			}
		}
	}
}

// What a search result says this is. The product has a name, the maker has a
// name, and a page that carries neither leaves a search engine with whatever
// it indexed months ago — which for this project is a TLS checker called
// denyfirst that no longer describes it.
func TestTheDemonstrationTitlesNameTheToolAndTheMaker(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation somebody runs is not a site to find")
	}
	for path, p := range pages {
		if !strings.Contains(strings.ToLower(p.Title), "denyfirst") {
			t.Errorf("%s: the title does not name the maker: %q", path, p.Title)
		}
		if len(p.Description) < 50 || len(p.Description) > 320 {
			t.Errorf("%s: the description is %d characters: %q", path, len(p.Description), p.Description)
		}
	}
	for _, path := range []string{"/tls", "/web", "/porch", "/privacy"} {
		if !strings.Contains(pages[path].Title, "Porch") {
			t.Errorf("%s: a page about the tool does not name it: %q", path, pages[path].Title)
		}
	}
	if !strings.Contains(pages["/"].Title, "security and privacy") {
		t.Errorf("the front page does not say what this is: %q", pages["/"].Title)
	}
}

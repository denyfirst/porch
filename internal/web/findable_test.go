package web

import (
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

	if !strings.Contains(body, "Allow: /") || !strings.Contains(body, "Sitemap: "+SiteURL+"/sitemap.xml") {
		t.Errorf("the demonstration does not offer itself: %q", body)
	}
	if sitemap.Code != 200 || !strings.Contains(sitemap.Header().Get("Content-Type"), "xml") {
		t.Fatalf("sitemap: %d %s", sitemap.Code, sitemap.Header().Get("Content-Type"))
	}
	listed := sitemap.Body.String()
	for path := range rendered {
		if !strings.Contains(listed, "<loc>"+SiteURL+path+"</loc>") {
			t.Errorf("the sitemap leaves out %s", path)
		}
	}
	if strings.Count(listed, "<loc>") != len(rendered) {
		t.Errorf("the sitemap lists %d addresses and the site has %d", strings.Count(listed, "<loc>"), len(rendered))
	}
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
			`<link rel="canonical" href="` + SiteURL + path + `">`,
			`<meta property="og:url" content="` + SiteURL + path + `">`,
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
	for _, path := range []string{"/tls", "/web", "/porch", "/docs"} {
		if !strings.Contains(pages[path].Title, "Porch") {
			t.Errorf("%s: a page about the tool does not name it: %q", path, pages[path].Title)
		}
	}
	if !strings.Contains(pages["/"].Title, "security and privacy") {
		t.Errorf("the front page does not say what this is: %q", pages["/"].Title)
	}
}

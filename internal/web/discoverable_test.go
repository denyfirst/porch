package web

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// Each of the demonstration's names says what it is to a program that asks
// at /llms.txt, from the table the pages and the sitemap come from: every
// page its sitemap lists is in it, every address it gives on its own name
// answers there without a redirect, and each points at the other's. An
// installation somebody runs says nothing, as it asks robots not to index it.
func TestEachNameTellsAnAssistantWhatItIs(t *testing.T) {
	if !demo.Enabled {
		if w := get(t, "/llms.txt"); w.Code != http.StatusNotFound {
			t.Errorf("an installation somebody runs serves llms.txt: %d", w.Code)
		}
		return
	}

	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, name := range []struct {
		host, base, other, heading string
	}{
		{organisationHost, SiteURL, PorchURL, "# denyfirst\n"},
		{porchHost, PorchURL, SiteURL, "# Porch\n"},
	} {
		w := getOn(t, http.MethodGet, name.host, "/llms.txt")
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("%s/llms.txt: %d %s", name.host, w.Code, w.Header().Get("Content-Type"))
		}
		body := w.Body.String()

		// The shape the proposal gives: a heading with the name, then the
		// summary as a quotation, then sections of links.
		if !strings.HasPrefix(body, name.heading+"\n> ") {
			t.Errorf("%s/llms.txt does not open with its name and a summary: %.80q", name.host, body)
		}
		if strings.Contains(body, "{{") || strings.Contains(body, "<no value>") || strings.Contains(body, "\n\n\n") {
			t.Errorf("%s/llms.txt carries what its template left behind", name.host)
		}

		sitemap := getOn(t, http.MethodGet, name.host, "/sitemap.xml").Body.String()
		for _, loc := range regexp.MustCompile(`<loc>([^<]+)</loc>`).FindAllStringSubmatch(sitemap, -1) {
			if !strings.Contains(body, "]("+loc[1]+")") {
				t.Errorf("%s/llms.txt leaves out %s, which its sitemap lists", name.host, loc[1])
			}
		}

		for _, m := range link.FindAllStringSubmatch(body, -1) {
			target := m[1]
			switch {
			case strings.HasPrefix(target, name.base+"/"):
				if w := getOn(t, http.MethodGet, name.host, strings.TrimPrefix(target, name.base)); w.Code != http.StatusOK {
					t.Errorf("%s/llms.txt links %s, which answers %d", name.host, target, w.Code)
				}
			case target == name.other+"/" || target == name.other+"/llms.txt":
			case strings.HasPrefix(target, "https://github.com/denyfirst/porch"):
			default:
				t.Errorf("%s/llms.txt links %s, which is neither its own nor this project's", name.host, target)
			}
		}
		if !strings.Contains(body, "]("+name.other+"/llms.txt)") {
			t.Errorf("%s/llms.txt does not point at the other name's", name.host)
		}
	}

	porch := getOn(t, http.MethodGet, porchHost, "/llms.txt").Body.String()
	for _, c := range consoleChecks() {
		if !strings.Contains(porch, "- "+c.Label+": "+c.Says+"\n") {
			t.Errorf("Porch's llms.txt does not list the %s check as the console offers it", c.Label)
		}
	}
}

// The release a demonstration was built from is named in its llms.txt, as on
// its page, and nothing is named when the build carries none.
func TestPorchsLLMsTxtNamesTheReleaseOnlyWhenItHasOne(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation serves no llms.txt")
	}
	saved := releaseTag
	defer func() {
		releaseTag = saved
		buildLLMs()
	}()

	for _, tc := range []struct{ tag, want string }{
		{"", ""},
		{"not a release", ""},
		{"v0.32.2", "- Current release: [v0.32.2](https://github.com/denyfirst/porch/releases/tag/v0.32.2)\n"},
	} {
		releaseTag = tc.tag
		buildLLMs()
		body := getOn(t, http.MethodGet, porchHost, "/llms.txt").Body.String()
		if got := strings.Contains(body, "Current release"); got != (tc.want != "") || !strings.Contains(body, tc.want) {
			t.Errorf("built from %q, the file says: %q", tc.tag, body)
		}
	}
}

// What the organisation's llms.txt states about this site holds on every
// address either name answers with a page or a crawler file: no cookie, and
// a policy that lets a browser load nothing from another server.
func TestWhatTheOrganisationsLLMsTxtStatesIsSo(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation serves no llms.txt")
	}
	body := getOn(t, http.MethodGet, organisationHost, "/llms.txt").Body.String()
	if !strings.Contains(body, "This site sets no cookie, loads nothing from another server, and carries no tracker.") {
		t.Fatal("the sentence this test holds to is gone; hold its replacement")
	}
	for _, host := range []string{organisationHost, porchHost} {
		paths := []string{"/robots.txt", "/sitemap.xml", "/llms.txt", "/", "/privacy"}
		for path := range rendered {
			paths = append(paths, path)
		}
		for _, path := range paths {
			w := getOn(t, http.MethodGet, host, path)
			if w.Header().Get("Set-Cookie") != "" {
				t.Errorf("%s%s sets a cookie", host, path)
			}
			for _, directive := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
				if strings.Contains(directive, "http") || strings.Contains(directive, "*") {
					t.Errorf("%s%s lets a browser load from elsewhere: %s", host, path, directive)
				}
			}
		}
	}
}

// Every page on the demonstration shows its name's card in a link preview,
// at the size the page states, from its own name; the card is a PNG and
// carries nothing but its picture. An installation shows none and serves
// none.
func TestEachPageShowsItsNamesCard(t *testing.T) {
	if !demo.Enabled {
		for path := range pages {
			if body := get(t, path).Body.String(); strings.Contains(body, "og:image") || strings.Contains(body, "twitter:card") {
				t.Errorf("%s: an installation somebody runs carries a link preview", path)
			}
		}
		for card := range socialCards {
			if w := get(t, card); w.Code != http.StatusNotFound {
				t.Errorf("an installation somebody runs serves %s: %d", card, w.Code)
			}
		}
		return
	}

	meta := func(page, property string) string {
		m := regexp.MustCompile(`<meta (?:property|name)="`+regexp.QuoteMeta(property)+`" content="([^"]*)">`).FindAllStringSubmatch(page, -1)
		if len(m) != 1 {
			t.Errorf("a page states %s %d times", property, len(m))
			return ""
		}
		return m[0][1]
	}
	for path, p := range pages {
		host, base, card := porchHost, PorchURL, "/og-porch.png"
		if p.Organisation {
			host, base, card = organisationHost, SiteURL, "/og-denyfirst.png"
		}
		page := get(t, path).Body.String()
		if got := meta(page, "og:image"); got != base+card {
			t.Errorf("%s shows %q, not its name's card %q", path, got, base+card)
			continue
		}
		if meta(page, "twitter:card") != "summary_large_image" || meta(page, "og:image:type") != "image/png" || meta(page, "og:image:alt") == "" {
			t.Errorf("%s does not say the card is a large PNG with a description", path)
		}

		w := getOn(t, http.MethodGet, host, card)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("%s%s: %d %s", host, card, w.Code, w.Header().Get("Content-Type"))
		}
		picture, err := png.DecodeConfig(bytes.NewReader(w.Body.Bytes()))
		if err != nil {
			t.Fatalf("%s is not a PNG: %v", card, err)
		}
		if strconv.Itoa(picture.Width) != meta(page, "og:image:width") || strconv.Itoa(picture.Height) != meta(page, "og:image:height") {
			t.Errorf("%s is %dx%d, and %s says otherwise", card, picture.Width, picture.Height, path)
		}
		if picture.Width != 1200 || picture.Height != 630 {
			t.Errorf("%s is %dx%d, not the 1200x630 a large preview asks for", card, picture.Width, picture.Height)
		}
		if extra := pngChunksBeyondThePicture(w.Body.Bytes()); len(extra) != 0 {
			t.Errorf("%s carries %v beside its picture", card, extra)
		}
	}
}

// pngChunksBeyondThePicture lists every chunk a PNG carries other than the
// ones a picture is drawn from: text, dates, profiles and anything else a
// tool that wrote it might have left.
func pngChunksBeyondThePicture(file []byte) []string {
	picture := map[string]bool{"IHDR": true, "PLTE": true, "tRNS": true, "IDAT": true, "IEND": true}
	var extra []string
	for i := 8; i+8 <= len(file); {
		length := int(binary.BigEndian.Uint32(file[i : i+4]))
		kind := string(file[i+4 : i+8])
		if !picture[kind] {
			extra = append(extra, kind)
		}
		i += 12 + length
	}
	return extra
}

// The two front pages say who and what they are to a search engine in
// schema.org microdata, on what they already show, and in nothing a browser
// runs. Each value is one the page states in its own words too, and nothing
// is claimed that nobody gave: no rating, no review.
func TestTheFrontPagesSayWhoAndWhatTheyAre(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation somebody runs is not a site to find")
	}
	prop := func(page, name string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`itemprop="`+name+`"(?: (?:content|href)="([^"]*)")?`).FindAllStringSubmatch(page, -1) {
			out = append(out, m[1])
		}
		return out
	}

	home := getOn(t, http.MethodGet, organisationHost, "/").Body.String()
	if strings.Count(home, `itemtype="https://schema.org/Organization"`) != 1 {
		t.Error("the front page does not say once that it is an organisation's")
	}
	for name, want := range map[string]string{"name": "denyfirst", "url": SiteURL + "/", "sameAs": "https://github.com/denyfirst"} {
		if got := prop(home, name); len(got) != 1 || got[0] != want {
			t.Errorf("the organisation's %s is %q, want %q", name, got, want)
		}
	}
	if logo := prop(home, "logo"); len(logo) != 1 || !strings.HasPrefix(logo[0], SiteURL+"/") {
		t.Errorf("the organisation's logo is %q", logo)
	} else if w := getOn(t, http.MethodGet, organisationHost, strings.TrimPrefix(logo[0], SiteURL)); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" {
		t.Errorf("the organisation's logo %s answers %d %s", logo[0], w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(home, `<p class="band-prose" itemprop="description">denyfirst is an independent team`) {
		t.Error("the organisation is not described by the sentence the page says it in")
	}

	porch := getOn(t, http.MethodGet, porchHost, "/").Body.String()
	if strings.Count(porch, `itemtype="https://schema.org/SoftwareApplication"`) != 1 {
		t.Error("Porch's page does not say once that it is a program's")
	}
	// Its maker is the organisation above, under the name and address it
	// gives itself; taken out here so its name is not counted as Porch's.
	publisher := regexp.MustCompile(`<div hidden itemprop="publisher" itemscope itemtype="https://schema.org/Organization">(.*?)</div>`)
	if m := publisher.FindAllStringSubmatch(porch, -1); len(m) != 1 ||
		!strings.Contains(m[0][1], `<meta itemprop="name" content="denyfirst">`) || !strings.Contains(m[0][1], `<link itemprop="url" href="`+SiteURL+`/">`) {
		t.Errorf("Porch's maker is %q", m)
	}
	porch = publisher.ReplaceAllString(porch, "")
	for name, want := range map[string]string{
		"name": "Porch", "url": PorchURL + "/", "applicationCategory": "SecurityApplication",
		"license": "https://github.com/denyfirst/porch/blob/main/LICENSE", "price": "0",
	} {
		if got := prop(porch, name); len(got) != 1 || got[0] != want {
			t.Errorf("Porch's %s is %q, want %q", name, got, want)
		}
	}
	// What the values rest on, said on the page in words.
	for _, said := range []string{
		`<a href="https://github.com/denyfirst/porch/blob/main/LICENSE">LICENSE</a>`,
		"Free and open source",
		"No paid tier",
	} {
		if !strings.Contains(porch, said) {
			t.Errorf("Porch's microdata rests on %q, which the page no longer says", said)
		}
	}
	if got := prop(porch, "softwareVersion"); pageRelease() == "" && len(got) != 0 || pageRelease() != "" && (len(got) != 1 || got[0] != pageRelease()) {
		t.Errorf("Porch's version is %q, and this build is %q", got, pageRelease())
	}
	if !strings.Contains(porch, `<p class="lede" itemprop="description">Porch checks what your servers show the outside world:`) {
		t.Error("Porch is not described by the sentence the page says it in")
	}

	for path := range pages {
		page := get(t, path).Body.String()
		for _, never := range []string{"application/ld+json", "aggregateRating", "itemprop=\"review", "ratingValue"} {
			if strings.Contains(page, never) {
				t.Errorf("%s carries %s", path, never)
			}
		}
	}
}

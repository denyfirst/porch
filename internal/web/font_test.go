package web

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// fontSHA256 is the typeface as it was chosen: Schibsted Grotesk, the variable
// Latin subset from @fontsource-variable/schibsted-grotesk 5.3.0, whose npm
// tarball matched the registry's published integrity when it was taken.
//
// A font is a program a reader's browser parses, and font parsers have been
// attacked through the files they were handed. So the file is pinned: a
// different one is a decision somebody makes and writes down here, never a
// side effect of something else.
const fontSHA256 = "4c8b93f431d462c696e12b9d6a033feb3394d36e66e781357c496b95d8a75e05"

// The typeface is the file that was chosen, it carries its licence, and it is
// served from here and from nowhere else.
func TestTheTypefaceIsServedFromHereAndIsTheOneChosen(t *testing.T) {
	body, err := assets.ReadFile("assets/schibsted-grotesk.woff2")
	if err != nil {
		t.Fatalf("reading the typeface: %v", err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != fontSHA256 {
		t.Errorf("the typeface is not the file that was chosen: sha256 %x", sum)
	}

	// The SIL Open Font License asks that the licence go with the font.
	licence, err := assets.ReadFile("assets/schibsted-grotesk-OFL.txt")
	if err != nil {
		t.Fatalf("the typeface's licence is not beside it: %v", err)
	}
	for _, want := range []string{"SIL OPEN FONT LICENSE Version 1.1", "Copyright 2023 The Schibsted-Grotesk Project Authors"} {
		if !strings.Contains(string(licence), want) {
			t.Errorf("the typeface's licence does not say %q", want)
		}
	}

	res := get(t, FontPath)
	if res.Code != 200 || res.Header().Get("Content-Type") != "font/woff2" || res.Body.String() != string(body) {
		t.Errorf("%s is served as %d %q, not as the font", FontPath, res.Code, res.Header().Get("Content-Type"))
	}

	// One face, from this server. The stylesheet loads nothing else at all.
	sheet := stylesheet(t)
	if n := strings.Count(sheet, "@font-face"); n != 1 {
		t.Errorf("the stylesheet declares %d faces, not one", n)
	}
	urls := regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(sheet, -1)
	if len(urls) != 1 || urls[0][1] != `"`+FontPath+`"` {
		t.Errorf("the stylesheet loads %v, not the typeface from this server alone", urls)
	}

	// The browser holds the page to the same: fonts from this origin only.
	if !strings.Contains(contentSecurityPolicy, "font-src 'self';") || strings.Count(contentSecurityPolicy, "font-src") != 1 {
		t.Errorf("the policy does not limit fonts to this server: %s", contentSecurityPolicy)
	}
}

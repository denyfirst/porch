package web

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// The rail's marks are drawn, not borrowed from the reader's fonts.
//
// They were six symbol characters until 2026-10-06. The typeface has none of
// them, so each came from whatever fonts the reader had and looked different
// on every system; on some, one became a coloured emoji.
func TestTheRailsMarksAreDrawn(t *testing.T) {
	layout, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(layout)
	if strings.ContainsAny(markup, "▦◎⁙◷⚙≡") {
		t.Error("the rail still marks an entry with a character the reader's fonts draw")
	}
	if n := strings.Count(markup, `<svg class="rail-glyph" viewBox="0 0 24 24" aria-hidden="true" focusable="false">`); n != 6 {
		t.Errorf("the rail draws %d marks, and it has six entries", n)
	}
	if rule := cssRule(t, stylesheet(t), ".rail-glyph"); !strings.Contains(rule, "stroke: currentColor") || !strings.Contains(rule, "fill: none") {
		t.Errorf("the rail's marks do not take their colour from the entry:\n%s", rule)
	}
}

// Each site's tab icon is its mark's first letter and stop, drawn as shapes
// and nothing else.
//
// An SVG can carry a script, a link or a reference to a file elsewhere, and a
// tab icon is fetched by every browser and by search engines. These were cut
// from the typeface's outlines and hold a square, a letter and a stop.
func TestTheTabIconsAreTheMarksAndOnlyShapes(t *testing.T) {
	for _, icon := range []struct{ file, name, stop string }{
		{"assets/favicon.svg", "denyfirst", "#ed4552"},
		{"assets/porch-icon.svg", "porch", "#9b7bf0"},
	} {
		raw, err := assets.ReadFile(icon.file)
		if err != nil {
			t.Fatal(err)
		}
		svg := strings.ToLower(string(raw))
		for _, banned := range []string{"<script", "href", "<image", "<use", "<foreignobject", "<style", "url(", "javascript:", " on"} {
			if strings.Contains(svg, banned) {
				t.Errorf("%s contains %q", icon.file, banned)
			}
		}
		if !strings.Contains(svg, `aria-label="`+icon.name+`"`) || !strings.Contains(svg, `fill="`+icon.stop+`"`) {
			t.Errorf("%s is not %s's mark with its stop", icon.file, icon.name)
		}
		if n := strings.Count(svg, "<path"); n != 2 {
			t.Errorf("%s draws %d paths, not a letter and a stop", icon.file, n)
		}
	}
}

// Each mark is also an .ico and a square PNG, for what reads no SVG, and the
// files carry the picture and nothing else.
//
// Safari and search engines ask for /favicon.ico or a PNG, and until
// 2026-10-07 both answered 404 here. They are cut from the same SVGs, and a
// PNG is checked down to its chunks: a text or time chunk in a file every
// visitor's browser fetches would be something said about whoever made it.
func TestTheFallbackIconsAreTheMarks(t *testing.T) {
	for _, name := range []string{"assets/denyfirst.ico", "assets/porch.ico"} {
		raw, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 6 || binary.LittleEndian.Uint16(raw[0:]) != 0 || binary.LittleEndian.Uint16(raw[2:]) != 1 {
			t.Fatalf("%s is not an icon file", name)
		}
		count := int(binary.LittleEndian.Uint16(raw[4:]))
		var sizes []int
		for i := 0; i < count; i++ {
			entry := raw[6+16*i:]
			size := int(entry[0])
			length := int(binary.LittleEndian.Uint32(entry[8:]))
			offset := int(binary.LittleEndian.Uint32(entry[12:]))
			if offset+length > len(raw) {
				t.Fatalf("%s points past its end", name)
			}
			width, height, _ := pngShape(t, name, raw[offset:offset+length])
			if width != size || height != size {
				t.Errorf("%s says %dx%d and holds %dx%d", name, size, size, width, height)
			}
			sizes = append(sizes, size)
		}
		if fmt.Sprint(sizes) != "[16 32 48]" {
			t.Errorf("%s holds %v, want 16, 32 and 48", name, sizes)
		}
	}

	// A phone puts this on its home screen and rounds the corners itself, so
	// it is square and has nothing to see through.
	for _, name := range []string{"assets/denyfirst-touch.png", "assets/porch-touch.png"} {
		raw, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		width, height, colour := pngShape(t, name, raw)
		if width != 180 || height != 180 || colour != 2 {
			t.Errorf("%s is %dx%d with colour type %d, want an opaque 180x180", name, width, height, colour)
		}
	}
}

// pngShape reads a PNG's size and colour type, and fails on any chunk but the
// four a picture needs.
func pngShape(t *testing.T, name string, raw []byte) (width, height, colour int) {
	t.Helper()
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("%s holds something that is not a PNG", name)
	}
	for at := 8; at+8 <= len(raw); {
		length := int(binary.BigEndian.Uint32(raw[at:]))
		kind := string(raw[at+4 : at+8])
		switch kind {
		case "IHDR":
			width = int(binary.BigEndian.Uint32(raw[at+8:]))
			height = int(binary.BigEndian.Uint32(raw[at+12:]))
			colour = int(raw[at+17])
		case "PLTE", "tRNS", "IDAT", "IEND":
		default:
			t.Errorf("%s carries a %s chunk, which is not part of the picture", name, kind)
		}
		at += 12 + length
	}
	return width, height, colour
}

// Pages link the marks at their new addresses, and each name answers the
// addresses a browser asks for unprompted with its own mark.
func TestEachNameLinksAndServesItsOwnMark(t *testing.T) {
	layout, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	head := string(layout)
	for _, want := range []string{
		`<link rel="icon" href="/denyfirst.ico" sizes="16x16 32x32 48x48">`,
		`<link rel="icon" href="/icon-denyfirst.svg" type="image/svg+xml">`,
		`<link rel="apple-touch-icon" href="/denyfirst-touch.png">`,
		`<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">`,
		`<link rel="icon" href="/icon-porch.svg" type="image/svg+xml">`,
		`<link rel="apple-touch-icon" href="/apple-touch-icon.png">`,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("the layout does not link %s", want)
		}
	}
	// The old addresses still answer, and nothing links them: a browser that
	// kept the earlier mark under one would go on showing it.
	for _, old := range []string{`href="/favicon.svg"`, `href="/porch-icon.svg"`} {
		if strings.Contains(head, old) {
			t.Errorf("the layout still links %s", old)
		}
	}

	if !demo.Enabled {
		return
	}
	for _, c := range []struct{ host, path, file string }{
		{organisationHost, "/favicon.ico", "assets/denyfirst.ico"},
		{organisationHost, "/apple-touch-icon.png", "assets/denyfirst-touch.png"},
		{porchHost, "/favicon.ico", "assets/porch.ico"},
		{porchHost, "/apple-touch-icon.png", "assets/porch-touch.png"},
	} {
		want, err := assets.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		w := getOn(t, http.MethodGet, c.host, c.path)
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("%s%s answers %d with something other than %s", c.host, c.path, w.Code, c.file)
		}
	}
}

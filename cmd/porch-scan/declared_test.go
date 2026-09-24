package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/webscan"
)

// What the site sends is drawn, and drawn whether or not it sent anything.
//
// Thirteen headers were recorded by the probe on every scan. Two of them are
// graded and none of them was shown, so a report of a site that declares a
// content policy read exactly like a report of one that declares nothing — and
// the second is what an operator came to find out. A report that showed only
// what is wrong showed almost nothing about a site that is right.
func TestWhatTheSiteDeclaresIsDrawnInBothFaces(t *testing.T) {
	var buf bytes.Buffer
	printWebReport(&buf, webResult{
		Host: "example.com",
		Result: &webscan.Result{
			Host: "example.com", Policy: policy.WebVersion,
			Declared: []policy.Declaration{
				{Label: "Served over", Says: "HTTP/2.0"},
				{Label: "Strict-Transport-Security", Says: "max-age=63072000"},
				{Label: "X-Frame-Options", Says: "none"},
				{Label: "Cookies", Says: "2 set; 2 Secure, 1 HttpOnly, 2 with SameSite"},
				{Label: "The page", Says: "read, nothing on it arrives in the clear"},
				{Label: "Security contact", Says: "published, 1 contact; expires 2027-01-31"},
			},
		},
	})
	text := buf.String()

	if !strings.Contains(text, "What the site sends") {
		t.Errorf("the report has no block for what the site said:\n%s", text)
	}
	for _, want := range []string{
		"Served over                HTTP/2.0",
		"Strict-Transport-Security  max-age=63072000",
		"X-Frame-Options            none",
		"Cookies                    2 set; 2 Secure, 1 HttpOnly, 2 with SameSite",
		"The page                   read, nothing on it arrives in the clear",
		"Security contact           published, 1 contact; expires 2027-01-31",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}

	// A response nobody reached declares nothing, and the block says nothing
	// rather than listing every header as absent: an empty list here means the
	// question was never put (R4), which the notes carry.
	buf.Reset()
	printWebReport(&buf, webResult{
		Host:   "example.com",
		Result: &webscan.Result{Host: "example.com", Policy: policy.WebVersion},
	})
	if strings.Contains(buf.String(), "What the site sends") {
		t.Errorf("a site nothing answered from was described as declaring things:\n%s", buf.String())
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`frag.appendChild(declared(data.declared));`,
		`sectionTitle("What the site sends")`,
		`tr.appendChild(el("td", null, row.says));`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}
}

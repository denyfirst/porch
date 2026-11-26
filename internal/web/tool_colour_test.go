package web

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The colours a reader can tell apart, in CIE76 ΔE, below which two colours
// are taken for one. Twenty is generous: the closest pair this sheet has
// accepted is 33, light links against the strong green as a tritanope sees
// them; the pair that made the test necessary was 0.
const distinguishable = 20

// Machado, Oliveira and Fernandes (2009), severity 1.0: how a reader with each
// common colour vision deficiency sees a colour, in linear RGB. The identity
// is ordinary vision.
var visions = map[string][3][3]float64{
	"ordinary vision": {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}},
	"deuteranopia":    {{0.367322, 0.860646, -0.227968}, {0.280085, 0.672501, 0.047413}, {-0.011820, 0.042940, 0.968881}},
	"protanopia":      {{0.152286, 1.052583, -0.204868}, {0.114503, 0.786281, 0.099216}, {-0.003882, -0.048116, 1.051998}},
	"tritanopia":      {{1.255528, -0.076749, -0.178779}, {-0.078411, 0.930809, 0.147602}, {0.004733, 0.691367, 0.303900}},
}

// lab is the CIE L*a*b* of a hex colour as the given vision sees it.
func lab(hex string, vision [3][3]float64) [3]float64 {
	hex = strings.TrimPrefix(hex, "#")
	var lin [3]float64
	for i := range lin {
		v, _ := strconv.ParseInt(hex[2*i:2*i+2], 16, 32)
		c := float64(v) / 255
		if c <= 0.04045 {
			lin[i] = c / 12.92
		} else {
			lin[i] = math.Pow((c+0.055)/1.055, 2.4)
		}
	}
	var rgb [3]float64
	for i := range rgb {
		rgb[i] = math.Min(1, math.Max(0, vision[i][0]*lin[0]+vision[i][1]*lin[1]+vision[i][2]*lin[2]))
	}
	x := (0.4124*rgb[0] + 0.3576*rgb[1] + 0.1805*rgb[2]) / 0.95047
	y := 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
	z := (0.0193*rgb[0] + 0.1192*rgb[1] + 0.9505*rgb[2]) / 1.08883
	f := func(t float64) float64 {
		if t > 0.008856 {
			return math.Cbrt(t)
		}
		return 7.787*t + 16.0/116
	}
	return [3]float64{116*f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))}
}

func deltaE(a, b string, vision [3][3]float64) float64 {
	la, lb := lab(a, vision), lab(b, vision)
	return math.Sqrt((la[0]-lb[0])*(la[0]-lb[0]) + (la[1]-lb[1])*(la[1]-lb[1]) + (la[2]-lb[2])*(la[2]-lb[2]))
}

// Porch draws no control in a verdict's colour.
//
// Red, amber and green say how a host fared, and a report is the one page
// whose job is to make them mean that. Until 2026-10-05 Porch's buttons, links
// and chosen tab were the brand red, and measured in Chromium the button and
// an insecure verdict were the same rgb(179, 32, 46): a reader looking for the
// one word that matters found it in every link. Violet since, and held apart
// from each verdict colour for ordinary vision and for the three common colour
// vision deficiencies, in both schemes — for whoever changes it next.
func TestPorchsColourIsNeverAVerdictsColour(t *testing.T) {
	tables := schemes(t, stylesheet(t))
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for _, control := range []string{"tool", "accent", "accent-hover", "link"} {
			for _, verdict := range []string{"strong", "weak", "insecure"} {
				c, v := tokens[control], tokens[verdict]
				if c == "" || v == "" {
					t.Fatalf("%s: --%s or --%s is not defined", scheme, control, verdict)
				}
				for name, vision := range visions {
					if d := deltaE(c, v, vision); d < distinguishable {
						t.Errorf("%s: --%s (%s) and the %s verdict's --%s (%s) are ΔE %.1f apart in %s, "+
							"below %d: a control reads as a verdict", scheme, control, c, verdict, verdict, v, d, name, distinguishable)
					}
				}
			}
		}
	}
}

// The brand red is the wordmark's and nothing else's.
//
// Any other rule reaching for --brand would put the red back on a control on
// Porch's pages, which is what the test above exists to stop and cannot see,
// because it reads tokens and not the rules that use them. Until v0.37.0 the
// organisation's pages kept the red for their links and buttons as well,
// through tokens of their own; they are denyfirst/site's now, and so is that.
func TestTheBrandRedIsTheWordmarksAlone(t *testing.T) {
	sheet := stylesheet(t)
	allowed := map[string]bool{
		".wordmark-deny, .wordmark-stop": true,
	}
	rule := regexp.MustCompile(`(?m)^([^{}\n/][^{}\n]*?)\s*\{([^}]*)\}`)
	found := map[string]bool{}
	for _, m := range rule.FindAllStringSubmatch(sheet, -1) {
		if !strings.Contains(m[2], "var(--brand)") {
			continue
		}
		selector := strings.TrimSpace(m[1])
		found[selector] = true
		if !allowed[selector] {
			t.Errorf("%s is drawn in the brand red; on Porch's pages a control is --tool", selector)
		}
	}
	for selector := range allowed {
		if !found[selector] {
			t.Errorf("%s no longer takes the brand red", selector)
		}
	}
	for _, gone := range []string{"--brand-link", "--brand-accent", `data-owner="organisation"`} {
		if strings.Contains(sheet, gone) {
			t.Errorf("the stylesheet still carries %s, which only the organisation's pages used", gone)
		}
	}

	// A button's white label is legible on Porch's accent, in both schemes.
	// The contrast test reads only the colours rules set text in directly,
	// and these reach a button through the token.
	tables := schemes(t, sheet)
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for _, face := range []string{"accent", "accent-hover"} {
			if got := contrast("#ffffff", tokens[face]); got < readableContrast {
				t.Errorf("%s: a button's white label on --%s is %.2f:1, below %.1f:1", scheme, face, got, readableContrast)
			}
		}
	}
}

// No page here is the organisation's. denyfirst.dev's pages, which kept the
// brand red for their controls, are denyfirst/site's since v0.37.0, and every
// page this program serves is Porch's, on every build.
func TestNoPageHereIsMarkedAsTheOrganisations(t *testing.T) {
	for path := range pages {
		if strings.Contains(get(t, path).Body.String(), `data-owner="organisation"`) {
			t.Errorf("%s is marked as the organisation's", path)
		}
	}
}

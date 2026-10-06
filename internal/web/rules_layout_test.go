package web

import (
	"regexp"
	"strings"
	"testing"
)

// The front page's rules share the product card's columns, so the red edge of
// each check falls on the same line as the violet edges of the card's list.
//
// The two are written in different rules of the stylesheet, and the line
// they make only holds while the columns, the gap and the inset agree, on a
// wide screen and on a phone. Measured in a browser at 1280 and 390 pixels
// when it was built; this keeps the numbers that made it true together.
func TestTheRulesLineUpWithTheProductCard(t *testing.T) {
	sheet := stylesheet(t)
	card := cssRule(t, sheet, ".product-feature")
	rules := cssRule(t, sheet, ".rules > li")

	declared := func(rule, property string) string {
		m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(property) + `:\s*([^;]+);`).FindStringSubmatch(rule)
		if m == nil {
			return ""
		}
		return strings.TrimSpace(m[1])
	}

	if a, b := declared(card, "grid-template-columns"), declared(rules, "grid-template-columns"); a == "" || a != b {
		t.Errorf("the rules have columns %q, the card %q", b, a)
	}
	gap := strings.Fields(declared(card, "gap"))
	if len(gap) != 2 || declared(rules, "column-gap") != gap[1] {
		t.Errorf("the rules' column gap %q is not the card's %v", declared(rules, "column-gap"), gap)
	}
	// The card is inset by its padding inside a one-pixel border; a rule has
	// no border at its sides, so its inset is the two together.
	if declared(card, "padding") != "2rem" || !strings.HasSuffix(declared(rules, "padding"), " calc(2rem + 1px)") {
		t.Errorf("the rules are inset by %q, the card by %q", declared(rules, "padding"), declared(card, "padding"))
	}

	// On a phone both fall to one column, and the card's inset narrows.
	_, phone, ok := strings.Cut(sheet, "@media (max-width: 52rem) {\n  .product-feature {")
	if !ok {
		t.Fatal("the stylesheet no longer narrows the product card on a phone")
	}
	phone, _, _ = strings.Cut(phone, "\n}")
	if !strings.Contains(phone, " grid-template-columns: 1fr; padding: 1.5rem; }") ||
		!strings.Contains(phone, ".rules > li { grid-template-columns: 1fr; padding: 1.4rem calc(1.5rem + 1px); }") {
		t.Errorf("on a phone the rules and the card are not inset alike:\n%s", phone)
	}
}

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/webscan"
)

// What a line counted is on both faces: the page folds a list under the line
// and the terminal prints the same items, grouped by what came back (R16).
func TestWhatALineCountedIsOnBothFaces(t *testing.T) {
	body, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, want := range []string{
		"const list = checkedList(row.checked);",
		`fact("Exposed services", report.exposureLine, report.exposureChecked);`,
		`details.appendChild(el("summary", null, items.length + " checked"));`,
		`name.appendChild(el("code", null, item.item));`,
		`cell.appendChild(el("span", "checked-state", item.state || ""));`,
		`const PRINTED_OPEN = "details.checked-list, details.notes-section";`,
		`document.querySelectorAll(PRINTED_OPEN)`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s", want)
		}
	}
	// The list is built from text alone: nothing in it is parsed as markup.
	start := strings.Index(script, "function checkedList(items) {")
	end := strings.Index(script[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("app.js has no checkedList")
	}
	for _, never := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "href"} {
		if strings.Contains(script[start:start+end], never) {
			t.Errorf("checkedList uses %s", never)
		}
	}

	var buf bytes.Buffer
	printDeclared(&buf, webResult{Result: &webscan.Result{Declared: []policy.Declaration{{
		Label: policy.LeaksLabel, Says: "/.env is served",
		Checked: policy.LeaksChecked([]policy.FileAsked{
			{Path: "/.git/HEAD", Answered: true},
			{Path: "/.env", Answered: true, Served: true},
			{Path: "/.git/config", Answered: true},
			{Path: "/.htpasswd"},
		}),
	}}}})
	for _, want := range []string{
		"      not served: /.git/HEAD, /.git/config",
		"      served: /.env",
		"      no answer: /.htpasswd",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the terminal does not print %q:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	printReport(&buf, result{Result: &scan.Result{
		Target:       "example.com:443",
		ExposureLine: "Redis (6379) answers to anybody on the internet",
		ExposureChecked: policy.ExposureChecked([]policy.ServiceAsked{
			{Port: "21", Name: "FTP"},
			{Port: "6379", Name: "Redis", AnsweredAt: []string{"192.0.2.1"}},
			{Port: "445", Name: "SMB"},
		}),
	}})
	for _, want := range []string{
		"no answer from here: 21 FTP, 445 SMB",
		"answers at 192.0.2.1: 6379 Redis",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the terminal does not print %q:\n%s", want, buf.String())
		}
	}

	// A report from before the list existed prints only its line.
	buf.Reset()
	printReport(&buf, result{Result: &scan.Result{Target: "example.com:443", ExposureLine: "none of the 21 services checked answers"}})
	if strings.Contains(buf.String(), "no answer from here") {
		t.Errorf("a report without a list printed one:\n%s", buf.String())
	}
}

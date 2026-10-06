package web

import (
	"html"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/ociimage"
)

// The demonstration keeps no copy of a report and counts nothing for its
// visitor.
//
// A report of our own domain is ours, so the download is offered only by an
// installation somebody runs, where the report is theirs. The scan counter is
// a figure about this deployment, not about the visitor's check, and
// /api/v1/stats still publishes it. Read from the source, as the other script
// tests are.
func TestTheDemonstrationOffersNoDownloadAndNoCounter(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`const DEMO_SITE = document.body.dataset.site === "demo";`,
		// The download and the print button together, behind one condition: a
		// report on the demonstration is about this project's own domain, and a
		// visitor has no use for a copy of it.
		"  if (!DEMO_SITE) {\n" +
			"    const actions = el(\"p\", \"summary-actions\");\n" +
			"    actions.appendChild(downloadLink(data));\n" +
			"    actions.appendChild(printButton());",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer contains %q", want)
		}
	}
	// Nothing on a page asks for the counters, so nothing can draw them.
	if strings.Contains(src, "/api/v1/stats") {
		t.Error("app.js asks for the counters, which no page draws")
	}
	if n := strings.Count(src, "appendChild(downloadLink("); n != 1 {
		t.Errorf("app.js offers the download in %d places; the one above is the only one gated", n)
	}
}

// The three steps on the Porch page are the guide's own commands.
//
// The guide is the reference and says why each step is there; a command on
// the page that the guide no longer gives is one nobody is maintaining.
func TestThePorchStepsAreTheGuidesCommands(t *testing.T) {
	page, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile("../../docs/self-host.md")
	if err != nil {
		t.Fatal(err)
	}
	// Whole lines: "docker compose up -d" is inside the guide's
	// "docker compose up -d --build" and is not the same command.
	given := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(string(guide), "\r\n", "\n"), "\n") {
		given[strings.TrimSpace(line)] = true
	}
	// Each carries the id its Copy button names, so the id is allowed and
	// nothing else is.
	blocks := regexp.MustCompile(`(?s)<pre><code(?: id="command-[a-z]+")?>(.*?)</code></pre>`).FindAllStringSubmatch(string(page), -1)
	if len(blocks) != 3 {
		t.Fatalf("the Porch page has %d command blocks, want 3", len(blocks))
	}
	for _, b := range blocks {
		// The text a reader sees and Copy writes: the colours are spans, and
		// the prompt is drawn by CSS, so neither is in it.
		for _, line := range strings.Split(shownText(b[1]), "\n") {
			if !given[line] {
				t.Errorf("the Porch page gives %q, which docs/self-host.md does not", line)
			}
		}
	}
}

// shownText is what a block of markup puts on the screen and in the
// clipboard: its text, without the tags that colour it.
func shownText(markup string) string {
	return html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(markup, ""))
}

// The commands are drawn as the terminal they are typed into, and the prompt
// is drawn by CSS: on the screen, never in what Copy writes. A "$ " in the
// text would be pasted into a shell, where it is a command that does not exist.
func TestThePorchCommandsAreATerminalWhosePromptIsNotCopied(t *testing.T) {
	page, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)<code id="command-[a-z]+">(.*?)</code>`).FindAllStringSubmatch(string(page), -1)
	if len(blocks) != 3 {
		t.Fatalf("%d command blocks, want 3", len(blocks))
	}
	for _, b := range blocks {
		text := shownText(b[1])
		if strings.HasPrefix(text, "$") || strings.Contains(text, "\n$") {
			t.Errorf("a prompt is in the text Copy writes: %q", text)
		}
		if lines, drawn := strings.Count(text, "\n")+1, strings.Count(b[1], `<span class="ln">`); lines != drawn {
			t.Errorf("%d lines and %d prompts", lines, drawn)
		}
	}

	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".terminal .ln::before {\n  content: \"$ \";") {
		t.Error("the prompt is not drawn by the stylesheet")
	}
	// And each says where it runs, which is the question a reader has.
	for _, where := range []string{"on the server", "on your computer"} {
		if !strings.Contains(string(page), `<span class="terminal-where">`+where+`</span>`) {
			t.Errorf("no command says it runs %s", where)
		}
	}
}

// The compose file on the Porch page is the one the release ships, line for
// line without its comments, and it is offered to be read, not copied: the
// copy that runs is the signed one.
func TestThePorchPageShowsTheComposeFileThatShips(t *testing.T) {
	raw, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}

	// Rendered with a digest, as the demonstration build is: the page has to
	// show the compose file the release ships, which is the template with
	// this release's image digest written in.
	const digest = "sha256:4559d2b5f26e9bce3f00a8fc63947addee3992a9d2837e1512df258602c4466b"
	body, err := render(&page{Title: "t", Fragment: "assets/porch.html",
		Data: porchPage{Hosts: []demo.Host{{Host: "one.test", Shows: "a"}}, Checks: consoleChecks(), ImageDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	shown := regexp.MustCompile(`(?s)<code id="compose-file">(.*?)</code>`).FindStringSubmatch(string(body))
	if shown == nil {
		t.Fatal("the Porch page does not show the compose file")
	}
	shipped, err := ociimage.Compose(string(template), ociimage.Repository, digest)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(strings.ReplaceAll(shipped, "\r\n", "\n"), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			want = append(want, line)
		}
	}
	got := strings.Split(shownText(shown[1]), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the page shows a compose file the release does not ship:\n%s\nwant:\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// A build that was not told the digest says so with the placeholder,
	// rather than showing one it does not know.
	if pageImageDigest() != ociimage.Placeholder && imageDigest == "" {
		t.Error("a build with no image digest shows something other than the placeholder")
	}

	if strings.Contains(string(raw), `data-copy="compose-file"`) {
		t.Error("the compose file is offered to the clipboard; the one to run is the signed one")
	}
	// One way in, and the page says which. Somebody used to pasting a compose
	// file looks for it here, and the answer is that step 1's paste is the one
	// that puts this file on the server, checked: said in both places, so
	// nobody goes looking for a second way that skips the signature.
	said := strings.Join(strings.Fields(shownText(string(raw))), " ")
	for _, sentence := range []string{
		"Downloads the compose file shown below and checks its signature.",
		"Read it before you run it. Step 1 downloads and checks the real file.",
	} {
		if !strings.Contains(said, sentence) {
			t.Errorf("the Porch page no longer says %q", sentence)
		}
	}
	// Open, so it is read before it is run rather than behind a click.
	if !strings.Contains(string(raw), `<section class="compose-view"`) || strings.Contains(string(raw), `<details class="compose-view"`) {
		t.Error("the compose file is folded away, or no longer on the page")
	}
	// The page is for running the service. The command line is in the guide.
	if strings.Contains(string(raw), "docker compose run --rm scan") {
		t.Error("the Porch page offers the command line, which belongs to docs/self-host.md")
	}
	// And nothing on it builds an image or picks a binary: the compose file
	// names the published one.
	for _, gone := range []string{"--build", "uname -m", "porchd_${V}", "Dockerfile"} {
		if strings.Contains(shownText(string(raw)), gone) {
			t.Errorf("the Porch page still gives %q, which the release image replaced", gone)
		}
	}
}

// One host is shown, and more than one is a menu.
//
// Rendered with made-up hosts rather than read from the page, because the
// build carries one host today and the branch for two would otherwise go
// untested until the day it is needed.
func TestThePorchPageShowsOneHostAndOffersSeveral(t *testing.T) {
	for _, hosts := range [][]demo.Host{
		{{Host: "one.test", Shows: "a"}},
		{{Host: "one.test", Shows: "a"}, {Host: "two.test", Shows: "b"}},
	} {
		body, err := render(&page{Title: "t", Fragment: "assets/porch.html", Data: porchPage{Hosts: hosts, Checks: consoleChecks()}})
		if err != nil {
			t.Fatal(err)
		}
		out := string(body)
		menu := strings.Contains(out, `<select class="field" id="porch-target"`)
		fixed := strings.Contains(out, `<input type="hidden" id="porch-target" name="target" value="one.test">`)
		if menu != (len(hosts) > 1) || fixed != (len(hosts) == 1) {
			t.Errorf("%d hosts: menu %v, fixed field %v", len(hosts), menu, fixed)
		}
		for _, h := range hosts {
			if !strings.Contains(out, h.Host) {
				t.Errorf("%d hosts: %s is not on the page", len(hosts), h.Host)
			}
		}
	}
}

// The front page says what denyfirst makes, the about section who makes it,
// and the footer only the promise.
//
// Each phrase once, where it belongs: the footer carried "Independent
// security and privacy tools" beside the promise while the hero said "team",
// and the section about the team was headed only "denyfirst". Its label is
// short, "The team", because the long one broke over two lines on a phone;
// the paragraph under it says what kind of team.
func TestEachDenyfirstPhraseIsSaidOnceWhereItBelongs(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	home := get(t, "/").Body.String()
	for _, want := range []string{
		`<p class="eyebrow eyebrow-dot">Independent security and privacy tools</p>`,
		`<p class="eyebrow">03 / The team</p>`,
		`<p class="colophon-line">Cites everything. Records nothing.</p>`,
	} {
		if !strings.Contains(home, want) {
			t.Errorf("the front page does not carry %s", want)
		}
	}
	if n := strings.Count(home, "Independent security and privacy tools"); n != 1 {
		t.Errorf("the front page says what denyfirst makes %d times, want once", n)
	}
}

// The page says how to take an installation away again, in one line, and the
// guide says the rest: what the directory held, and the DNS record, which
// stays public after everything else is gone and says the domain was checked
// with Porch. Long explanations are the guide's; the page names the command.
func TestThePorchPageSaysHowToRemoveIt(t *testing.T) {
	page, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile("../../docs/self-host.md")
	if err != nil {
		t.Fatal(err)
	}
	said := strings.Join(strings.Fields(shownText(string(page))), " ")
	if !strings.Contains(said, "To remove it, docker compose down --rmi all, then delete the directory and the DNS record.") {
		t.Error("the Porch page no longer says how to remove an installation")
	}
	removing := regexp.MustCompile(`(?s)### Removing it\n(.*?)\n### `).FindStringSubmatch(string(guide))
	if removing == nil {
		t.Fatal("docs/self-host.md has no section on removing an installation")
	}
	for _, step := range []string{"docker compose down --rmi all", "sudo rm -rf porch", "_porch-challenge", "porch-data"} {
		if !strings.Contains(removing[1], step) {
			t.Errorf("removing an installation no longer covers %q", step)
		}
	}
}

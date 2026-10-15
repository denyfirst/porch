package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// installCommand renders the Porch page for one release and returns the text
// its first Copy button copies.
func installCommand(t *testing.T, release string) string {
	t.Helper()
	body, err := render(&page{Title: "t", Fragment: "assets/porch.html",
		Data: porchPage{Hosts: []demo.Host{{Host: "one.test", Shows: "a"}}, Checks: consoleChecks(),
			ImageDigest: pageImageDigest(), Release: release}})
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<code id="command-get">(.*?)</code>`).FindStringSubmatch(string(body))
	if m == nil {
		t.Fatal("the Porch page has no install command")
	}
	return shownText(m[1])
}

// The release on denyfirst.dev hands a new installation itself, by name, and
// the commands refuse a signed list that is another release's: a signature
// says who made a release, not that it is the newest, so a redirect moved to
// an older one would otherwise pass.
func TestTheInstallFetchesTheReleaseThatServesThePage(t *testing.T) {
	got := installCommand(t, "v1.2.3")
	for _, want := range []string{
		`curl -fsSLO "https://github.com/denyfirst/porch/releases/download/v1.2.3/${f}"`,
		`< SHA256SUMS && grep -qF "_v1.2.3_" SHA256SUMS && sha256sum --ignore-missing -c SHA256SUMS || { rm -f docker-compose.yml;`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the install does not carry %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "latest") {
		t.Errorf("a release's own page still sends the install to GitHub's latest:\n%s", got)
	}

	// A build that is not a release does not invent one.
	plain := installCommand(t, "")
	if !strings.Contains(plain, "releases/latest/download/${f}") || strings.Contains(plain, "grep") {
		t.Errorf("a build that is no release names one:\n%s", plain)
	}
}

// The tag is compiled in, and read as a release name or not at all: nothing
// else reaches a command a visitor pastes into a root shell.
func TestOnlyAReleaseNameIsWrittenIntoTheInstall(t *testing.T) {
	was := releaseTag
	t.Cleanup(func() { releaseTag = was })
	for tag, want := range map[string]string{
		"v0.28.0":                    "v0.28.0",
		"":                           "",
		"v0.28.0'; rm -rf ~; echo '": "",
		"v0.28.0\n":                  "",
		"0.28.0":                     "",
		"v0.28.0-rc1":                "",
		"latest":                     "",
	} {
		releaseTag = tag
		if got := pageRelease(); got != want {
			t.Errorf("tag %q was read as %q, want %q", tag, got, want)
		}
	}
}

// New check's banner says when the release it names was found, and where to
// look again: loading the page asks GitHub nothing, so a newer one may exist.
func TestTheBannerSaysWhenItsReleaseWasFound(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "function showUpdateBanner(")
	end := strings.Index(src, "const updateBanner = ")
	if start < 0 || end < start {
		t.Fatal("showUpdateBanner was not found")
	}
	banner := src[start:end]
	for _, want := range []string{`" Found by the check" + (state.checked ? " at " + state.checked : "")`, `again.href = "/installation#updates";`} {
		if !strings.Contains(banner, want) {
			t.Errorf("the banner no longer has %s", want)
		}
	}
}

// asGuide writes the page's release the way the guide does, as ${V}, so the
// two can be held to the same commands line for line.
func asGuide(page string) string {
	page = strings.ReplaceAll(page, "{{if .Release}}download/{{.Release}}{{else}}latest/download{{end}}", "download/${V}")
	return strings.ReplaceAll(page, `{{if .Release}}<span class="t-c">grep</span> <span class="t-f">-qF</span> <span class="t-s">"_{{.Release}}_"</span> SHA256SUMS <span class="t-o">&amp;&amp;</span> {{end}}`,
		`<span class="t-c">grep</span> <span class="t-f">-qF</span> <span class="t-s">"_${V}_"</span> SHA256SUMS <span class="t-o">&amp;&amp;</span> `)
}

//go:build !demo

package web

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/updates"
)

// jsConst reads one string constant from app.js.
func jsConst(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^const ` + name + ` = "([^"\\]*)";$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("app.js has no constant %s", name)
	}
	return m[1]
}

// The commands the banner shows check a release with the key strangers use:
// the line in .allowed_signers, the key porchd verifies the list with, and
// the fingerprint the page prints beside it, all one key. A page that wrote
// a second key into the commands would have the server trust whoever held
// it, and nothing else would notice.
func TestTheUpdateCommandsCarryTheReleaseKey(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	signers, err := os.ReadFile(filepath.Join("..", "..", ".allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	var line []string
	for _, l := range strings.Split(string(signers), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "releases@denyfirst.dev" {
			line = f[:3]
		}
	}
	if line == nil {
		t.Fatal(".allowed_signers names no release key")
	}

	if got, want := jsConst(t, src, "RELEASE_SIGNER"), strings.Join(line, " "); got != want {
		t.Errorf("the commands write %q to allowed_signers; .allowed_signers says %q", got, want)
	}
	if line[2] != updates.ReleaseKey {
		t.Error("porchd verifies with a key that is not the one in .allowed_signers")
	}

	blob, err := base64.StdEncoding.DecodeString(line[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	if got, want := jsConst(t, src, "RELEASE_FINGERPRINT"), "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("the page prints the release key as %s; it is %s", got, want)
	}
}

// The version is the one thing the page takes from the answer, and it is
// used only once it reads as a release name: the commands are not built for
// anything else, and the banner shows them only for a version so read.
func TestTheBannerUsesOnlyAVersionThatIsAReleaseName(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`const RELEASE_NAME = /^v\d{1,4}\.\d{1,4}\.\d{1,4}$/;`,
		"if (!RELEASE_NAME.test(version)) return null;",
		`const latest = typeof d.latest === "string" && RELEASE_NAME.test(d.latest) ? d.latest : "";`,
		"const lines = state.newer ? updateCommands(state.latest) : null;",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer has %s", want)
		}
	}

	// Each line runs whether or not the one before it worked, so the compose
	// file in use is replaced only on the line that verifies first, and the
	// files are fetched into a folder of their own, never beside it.
	cmds := src[strings.Index(src, "function updateCommands("):strings.Index(src, "function drawCommands(")]
	if strings.Count(cmds, `C("cp"), " " + dir + "/docker-compose.yml docker-compose.yml "`) != 1 ||
		!strings.Contains(cmds, `[C("if"), " ", C("ssh-keygen")`) {
		t.Error("the compose file in use can be replaced outside the line that verifies it")
	}
	if !strings.Contains(cmds, `S("\"" + dir + "/${f}\"")`) || strings.Contains(cmds, `"-fsSLO"`) {
		t.Error("the download writes beside the compose file in use rather than into its own folder")
	}
	if !strings.Contains(cmds, `C("grep"), " ", F("-qF"), " ", S("'_" + version + "_'")`) {
		t.Error("the commands do not check the signed list is this version's, so an older signed release could be installed")
	}
}

// New check carries the banner, hidden until the script has a reason to
// show it, and This installation carries the Updates part, with the daily
// check off until the page has read the choice, and says how an update is
// installed while there is none to install.
func TestTheUpdatePartsAreOnTheirPages(t *testing.T) {
	console := consoleAs(t)
	for _, want := range []string{`id="update-banner" role="status" hidden`, `id="update-commands"`, `data-copy="update-commands"`} {
		if !strings.Contains(console, want) {
			t.Errorf("New check has no %s", want)
		}
	}

	installation := workspaceWith(t, "/installation")
	for _, want := range []string{`id="updates-check"`, `id="updates-daily" disabled`, `<script src="/app.js"></script>`, "Asked of GitHub", "<dt>Installing</dt>", "Never by itself."} {
		if !strings.Contains(installation, want) {
			t.Errorf("This installation has no %s", want)
		}
	}
}

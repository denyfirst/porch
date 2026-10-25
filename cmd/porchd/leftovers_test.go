package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/ociimage"
)

// An installation's directory holds the compose file and the data, and
// nothing the install or an update fetched to check them.
//
// Found on a test server on 2026-10-23: after one install and two updates its
// directory still held the key, the signed list and its signature from the
// install, each update's folder of downloads, the compose file each update
// replaced, and on the server the image each update replaced. Nothing read
// any of them again. The guide's own lines are run here, with the network,
// the signature check and Docker stood in for, and the directory read after.

// standIns are the commands the guide's lines reach beyond the directory
// with. Each is a few lines of sh, first on PATH, so a line run here never
// reaches GitHub, the release key or a real Docker.
var standIns = map[string]string{
	// Writes what -o names, or the URL's last part for -O, with a signed
	// list that names the release the URL does.
	"curl": `out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
[ -n "$out" ] || out="${url##*/}"
v=$(printf '%s\n' "$url" | sed -n 's#.*/download/\([^/]*\)/.*#\1#p')
case "$url" in
  */SHA256SUMS) printf 'aa  porchd_%s_linux_amd64\nbb  docker-compose.yml\n' "$v" > "$out" ;;
  *) printf 'served %s %s\n' "$v" "${url##*/}" > "$out" ;;
esac`,
	"ssh-keygen": `[ "$PORCH_TEST_SIGNATURE" = good ] && { echo 'Good "file" signature'; exit 0; }
echo 'Could not verify signature.' >&2
exit 255`,
	"sha256sum": `[ -f docker-compose.yml ] && { echo 'docker-compose.yml: OK'; exit 0; }
exit 1`,
	"sudo": `exec "$@"`,
	"docker": `echo "docker $*" >> "$PORCH_TEST_DOCKER"
[ "$*" = "compose up -d" ] && [ "$PORCH_TEST_UP" = fails ] && exit 1
exit 0`,
}

type guideRun struct {
	signature string // "good" or anything else
	up        string // "fails", or anything else for a start that works
}

// run runs lines in dir as a pasted block runs: one after another, each
// whether or not the one before it worked. It returns what Docker was asked.
func (g guideRun) run(t *testing.T, dir, lines string) []string {
	t.Helper()
	bin := t.TempDir()
	for name, body := range standIns {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dockerLog := filepath.Join(t.TempDir(), "docker")
	cmd := exec.Command("sh", "-c", lines)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"HOME=" + dir,
		"PORCH_TEST_SIGNATURE=" + g.signature,
		"PORCH_TEST_UP=" + g.up,
		"PORCH_TEST_DOCKER=" + dockerLog,
	}
	out, _ := cmd.CombinedOutput()
	t.Logf("%s", out)
	asked, err := os.ReadFile(dockerLog)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(asked)), "\n")
}

// guideBlock is the guide's sh block holding marker, each line as pasted.
func guideBlock(t *testing.T, marker string) string {
	t.Helper()
	var block []string
	in := false
	for _, line := range strings.Split(repoFile(t, "docs/self-host.md"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !in && trimmed == "```sh":
			in, block = true, nil
		case in && trimmed == "```":
			in = false
			if body := strings.Join(block, "\n"); strings.Contains(body, marker) {
				return body
			}
		case in:
			block = append(block, trimmed)
		}
	}
	t.Fatalf("docs/self-host.md has no sh block holding %q", marker)
	return ""
}

// named sets the release the guide's lines leave as V=vX.Y.Z.
func named(t *testing.T, block, version string) string {
	t.Helper()
	if !strings.HasPrefix(block, "V=vX.Y.Z\n") {
		t.Fatalf("the block does not start by naming the release:\n%s", block)
	}
	return "V=" + version + strings.TrimPrefix(block, "V=vX.Y.Z")
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func needSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the guide's lines are sh, run on the server")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh to run the guide's lines with")
	}
}

// The prune names every Porch image by the label the image is built with:
// the same words, or a prune that matches nothing and says nothing.
func pruneLine() string {
	label := ociimage.Porch("v0.0.0", "amd64", nil, nil).Labels["org.opencontainers.image.source"]
	return "docker image prune -a -f --filter label=org.opencontainers.image.source=" + label
}

func TestTheInstallKeepsOnlyTheComposeFile(t *testing.T) {
	needSh(t)
	install := named(t, guideBlock(t, "mkdir -p porch && cd porch"), "v9.9.9")

	for _, c := range []struct {
		signature string
		want      []string
	}{
		{"good", []string{"docker-compose.yml"}},
		// Nothing for the next step to start, and nothing else either.
		{"bad", nil},
	} {
		root := t.TempDir()
		if asked := (guideRun{signature: c.signature}).run(t, root, install); asked[0] != "" {
			t.Errorf("signature %s: the install asked Docker %q before its own step", c.signature, asked)
		}
		if got := entries(t, filepath.Join(root, "porch")); !slices.Equal(got, c.want) {
			t.Errorf("signature %s: the installation's directory holds %q, want %q", c.signature, got, c.want)
		}
	}
}

func TestAnUpdateLeavesOnlyTheComposeFileAndTheData(t *testing.T) {
	needSh(t)
	update := named(t, guideBlock(t, `mkdir -p "update-${V}"`), "v9.9.9")
	const inUse = "the compose file in use\n"
	installation := func(t *testing.T) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(inUse), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "porch-data"), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	compose := func(t *testing.T, dir string) string {
		b, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("verified and started", func(t *testing.T) {
		dir := installation(t)
		asked := guideRun{signature: "good"}.run(t, dir, update)
		if got := compose(t, dir); got != "served v9.9.9 docker-compose.yml\n" {
			t.Errorf("the compose file in use is %q, want v9.9.9's", got)
		}
		if got, want := entries(t, dir), []string{"docker-compose.yml", "porch-data"}; !slices.Equal(got, want) {
			t.Errorf("after the update the directory holds %q, want %q", got, want)
		}
		// The images go only once the new one runs, so the one in use is
		// never among them.
		if want := []string{"docker compose up -d", pruneLine()}; !slices.Equal(asked, want) {
			t.Errorf("Docker was asked %q, want %q", asked, want)
		}
	})

	t.Run("not verified", func(t *testing.T) {
		dir := installation(t)
		asked := guideRun{signature: "bad"}.run(t, dir, update)
		if got := compose(t, dir); got != inUse {
			t.Errorf("a release that did not verify replaced the compose file in use with %q", got)
		}
		if got, want := entries(t, dir), []string{"docker-compose.yml", "porch-data"}; !slices.Equal(got, want) {
			t.Errorf("a download that did not verify left %q, want %q", got, want)
		}
		if asked[0] != "" {
			t.Errorf("a release that did not verify asked Docker %q", asked)
		}
	})

	// A start that fails removes nothing: the folder stays for the lines to be
	// run again, and no image goes while the new one has not started.
	t.Run("verified and not started", func(t *testing.T) {
		dir := installation(t)
		asked := guideRun{signature: "good", up: "fails"}.run(t, dir, update)
		if got, want := entries(t, dir), []string{"docker-compose.yml", "porch-data", "update-v9.9.9"}; !slices.Equal(got, want) {
			t.Errorf("after a start that failed the directory holds %q, want %q", got, want)
		}
		if want := []string{"docker compose up -d"}; !slices.Equal(asked, want) {
			t.Errorf("after a start that failed Docker was asked %q, want only %q", asked, want)
		}
	})

	t.Run("run somewhere else", func(t *testing.T) {
		dir := t.TempDir()
		asked := guideRun{signature: "good"}.run(t, dir, update)
		if got := entries(t, dir); len(got) != 0 {
			t.Errorf("run where there is no compose file, the lines wrote %q", got)
		}
		if asked[0] != "" {
			t.Errorf("run where there is no compose file, the lines asked Docker %q", asked)
		}
	})
}

// What earlier versions of the lines left is removed by the guide's own
// lines, and nothing beside it.
func TestWhatEarlierLinesLeftIsRemoved(t *testing.T) {
	needSh(t)
	tidy := guideBlock(t, "docker-compose.yml.before-v*")
	dir := t.TempDir()
	for _, name := range []string{
		"docker-compose.yml", "docker-compose.yml.before-v0.30.1", "docker-compose.yml.before-v0.31.0",
		"allowed_signers", "SHA256SUMS", "SHA256SUMS.sig", "update-v0.31.0/SHA256SUMS", "porch-data/secret",
		"docker-compose.override.yml",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asked := guideRun{}.run(t, dir, tidy)
	if got, want := entries(t, dir), []string{"docker-compose.override.yml", "docker-compose.yml", "porch-data"}; !slices.Equal(got, want) {
		t.Errorf("after the tidy the directory holds %q, want %q", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "porch-data", "secret")); err != nil || string(b) != "porch-data/secret" {
		t.Errorf("the tidy touched the data directory: %q %v", b, err)
	}
	if want := []string{pruneLine()}; !slices.Equal(asked, want) {
		t.Errorf("Docker was asked %q, want %q", asked, want)
	}
}

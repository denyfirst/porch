package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The procedure that decides what people download has to be in the
// repository.
//
// Until 2026-08-22 it was in a chat window: three workflow files and a
// PowerShell script each held a piece, and the order, the dry run and the two
// repository settings it rests on were written nowhere. For a project whose
// argument is that everything here can be checked, that was the one thing a
// reader could not check — and a maintainer who lost the window would have
// had to reconstruct it.
func TestTheReleaseProcedureIsWrittenDown(t *testing.T) {
	body, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatalf("reading docs/releasing.md: %v", err)
	}
	page := string(body)

	// Each of these is a step that cannot be inferred from the workflows, and
	// each has already gone wrong once.
	for _, required := range []struct {
		text string
		why  string
	}{
		{"dry run", "the dry run is the step that keeps a first mistake off a release evening"},
		{"release.ps1", "the signing step"},
		{"build-release.yml", "how to restart the build when the tag did not trigger it"},
		{"--draft=false", "publishing, which is what starts the reproduction"},
		{"docs/policy-changes.md", "what an upgrader has to be told"},
		{"cannot be deleted or moved", "the tag ruleset the signature's meaning depends on"},
		{"Squash and rebase merging are disabled", "the merge setting S6 records"},

		// Each of the four below is a mistake that has been made, in order.
		{"gh pr list --state open", "a release must not begin while a green pull request is unmerged: that is how v0.3.1 shipped, signed and reproduced, without the one fix it existed to carry"},
		{"--json databaseId", "a run has to be named, or gh opens a picker and the wrong run is watched"},
		{"git status --short", "reading the index before staging and again after is what keeps unrelated files out of a commit"},
		{"gh pr merge --merge", "auto-merge is off here, so merging is a step somebody has to take and four pull requests were left green and unmerged in one day"},
		{"name the tag about to be cut", "a rule set's section is written before the tag exists, so it reads Unreleased until somebody comes back for it — denyfirst-v4 said so on the page five releases after v0.4.0 shipped it"},
		{"STOP: not on the branch, nothing applied", "the branch check has to be the condition the patch is applied under: printed on its own line it went past twice, and both times the commit landed on main"},
		{"STOP: not on the branch, nothing committed", "a patch applied by hand after a failed switch reaches the same place, so the commit is guarded too"},
		{"carries the reason for the change, and nothing else", "a commit message is published and permanent, and an identifier in one cannot be taken back without rewriting main"},
		{"-Pattern 'Unreleased' -CaseSensitive", "Select-String ignores case, and a sentence of history saying \"were unreleased\" is printed as an alarm that has to be read past"},
		{"--workflow=reproduce.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId'", "the newest reproduction run may be the previous release's, already green: on 2026-10-01 it was watched in place of the release's own and reported success"},
	} {
		if !strings.Contains(page, required.text) {
			t.Errorf("docs/releasing.md no longer covers %q — %s", required.text, required.why)
		}
	}

	// Every jq expression survives Windows PowerShell 5.1, which strips the
	// double quotes inside an argument handed to a program: a filter naming
	// the tag in quotes failed to parse there on 2026-10-01. And none takes the
	// first element, which prints null before a run exists and ends a wait on
	// a run that is not there.
	for _, m := range regexp.MustCompile(`--jq '([^']*)'`).FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], `"`) {
			t.Errorf("docs/releasing.md hands jq %q, whose quotes PowerShell 5.1 strips", m[1])
		}
		if strings.Contains(m[1], ".[0]") {
			t.Errorf("docs/releasing.md hands jq %q, which prints null where no run exists yet", m[1])
		}
	}

	// The notes go on before the release is published: the draft's own text
	// says it is unsigned, and v0.24.0 and v0.25.0 were both published saying so.
	notes := strings.Index(page, "gh release edit v0.2.0 --notes-file NOTES.md")
	publish := strings.Index(page, "gh release edit v0.2.0 --draft=false")
	if notes < 0 || publish < 0 || notes > publish {
		t.Error("docs/releasing.md publishes the release before its notes replace the draft's")
	}
}

// A procedure's first instruction has to work.
//
// `.\scripts\release.ps1 -Tag v0.1.0` was the documented invocation in the
// script's own help and in the workflow's closing message, and on a default
// Windows installation PowerShell refuses to run a script file at all. So the
// release procedure's entry point failed before the script started, on the
// single kind of machine it exists to run on — the same class of defect as
// the build recipe in docs/verify.md that named a linker symbol this program
// did not define.
//
// Every place that spells out how to invoke it has to spell out one that
// runs. Prose mentioning the bare path is fine and is how the failure is
// explained; a line handing it a tag is an instruction.
func TestTheDocumentedInvocationIsTheOneThatWorks(t *testing.T) {
	for _, path := range []string{
		"../../docs/releasing.md",
		"../../scripts/release.ps1",
		"../../.github/workflows/build-release.yml",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		for n, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "release.ps1 -Tag") {
				continue
			}
			if !strings.Contains(line, "-ExecutionPolicy Bypass") {
				t.Errorf("%s:%d hands release.ps1 a tag without a way to run it:\n  %s",
					path, n+1, strings.TrimSpace(line))
			}
		}
	}
}

// A command in a procedure is an instruction, and an instruction that opens a
// menu is one somebody answers wrongly at two in the morning.
//
// `gh run watch` and `gh run view --log` with no run named list every recent
// run and wait for a choice. On 2026-08-23 the CI run was chosen instead of
// the build, the draft release was taken to exist, and the next command
// answered `release not found` on the one procedure that must never be
// guessed at.
//
// Only lines that are commands are checked. Prose naming the bare form is how
// the failure gets explained, and this test would otherwise forbid explaining
// it.
func TestEveryRunCommandNamesItsRun(t *testing.T) {
	for _, path := range []string{
		"../../docs/releasing.md",
		"../../docs/verify.md",
		"../../README.md",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		for n, line := range strings.Split(string(body), "\n") {
			command := strings.TrimSpace(line)
			rest, isWatch := strings.CutPrefix(command, "gh run watch")
			if !isWatch {
				var isView bool
				rest, isView = strings.CutPrefix(command, "gh run view")
				if !isView || !strings.Contains(rest, "--log") {
					continue
				}
			}

			// What has to be there is a run to act on: an id, a variable
			// holding one, or the query that produces one. A flag is not one.
			named := false
			for _, field := range strings.Fields(rest) {
				if strings.HasPrefix(field, "-") {
					break
				}
				named = true
				break
			}
			if !named {
				t.Errorf("%s:%d names no run, so it opens a picker:\n  %s", path, n+1, command)
			}
		}
	}
}

// A release is bytes anybody can verify. A deploy is the separate claim that
// those bytes are what answers on port 443, and it is made by a person typing
// commands into a server a few times a year.
//
// Until 2026-09-01 that sequence was written nowhere. The release page said
// "then deploy" and gave one command, which does not exist on the machine it
// was written for — so the whole of S1 to S14 ended at the point where its
// conclusion had to be carried to production by memory.
//
// Each entry below is a step whose absence is not visible from the result. A
// deploy that skipped every one of them still leaves a service answering
// correctly, which is why they are written down rather than noticed.
func TestTheDeployProcedureIsWrittenDown(t *testing.T) {
	body, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatalf("reading docs/releasing.md: %v", err)
	}
	page := string(body)

	for _, required := range []struct {
		text string
		why  string
	}{
		{"--workflow=reproduce.yml --limit 1",
			"a build that was signed but not reproduced is one a single laptop vouches for"},
		{"ssh-keygen -Y verify",
			"the signature is checked on the machine that will run the file, not only on the one that downloaded it"},
		{"raw.githubusercontent.com/denyfirst/porch/main/.allowed_signers",
			"the key comes from the repository; a key shipped beside the file it vouches for establishes nothing"},
		{"install -o root -g root -m 0755",
			"owner and mode are set as the file is written, so there is no interval with the wrong ownership on the live path"},
		{"porchd.rollback-pre-${V}",
			"a rollback carries the release that replaced it; a .bak from 2026-08-18 is what the alternative looks like"},
		{"sudo systemctl restart porchd",
			"the unit is porchd.service since 2026-09-20; before that the page named a path the machine did not have, and the v0.16.0 deploy stopped at its first line"},
		{"|| { echo 'STOP: not the demonstration build'; exit 1; }",
			"the downloaded file proves it is the demonstration build before it reaches the live path, and the block stops if it does not"},
		{"getcap /opt/porch/porchd",
			"the binary must carry no file capability — the unit grants the port to one process instead"},
		{"AmbientCapabilities",
			"where the capability actually comes from"},
		{"MainPID",
			"the running process is identified through /proc/<pid>/exe: a failed restart leaves the old inode serving while the new file looks correct"},
		{"set -euo pipefail",
			"the deploy block stops at the first failure: pasted as loose lines, three 404s let it carry on and copy the running binary over itself as a rollback of the version already running"},
		{`git rev-parse "v0.2.0^{commit}"`,
			"the tag has to be on the commit just read, and quoted, or PowerShell hands git the tag's first parent — which on a merge commit is the previous tip and looks exactly like the failure this check is for"},
		{"An existing tag means either that",
			"an existing tag is a stop: on 2026-09-01 the release carried on past `fatal: tag already exists` and shipped, signed and deployed the commit before the change it was for"},
		{"noexec",
			"why the download goes under the deploying user's home rather than /tmp"},
	} {
		if !strings.Contains(page, required.text) {
			t.Errorf("docs/releasing.md no longer covers %q — %s", required.text, required.why)
		}
	}

	// And nothing addresses the names the machine no longer has. The unit was
	// renamed on 2026-09-20; what kept the old name is the account, the state
	// directory and the alerting around it, none of which this page gives a
	// command for. The one sentence saying what the page used to say is the
	// only place an old path may appear.
	for _, never := range []string{"systemctl restart denyfirstd", "--value denyfirstd", "/opt/denyfirst/"} {
		if strings.Count(page, never) > strings.Count(page, "said `"+never) {
			t.Errorf("docs/releasing.md still gives %q, which names a unit or path the server no longer has", never)
		}
	}
}

// The service is named by the path it is at.
//
// `porchd` is not on PATH on the server, and on 2026-09-01 the one deploy
// instruction this repository contained was `porchd -version`. It answered
// `porchd: command not found` the first time anybody followed it.
//
// This is the same defect as the release script's own example failing on
// Windows: a document naming a command nobody had run. Prose mentioning the
// bare name is how the failure gets explained; a line handing it a flag is an
// instruction, and an instruction has to work.
func TestTheServiceIsNamedByThePathItIsAt(t *testing.T) {
	for _, path := range []string{
		"../../docs/releasing.md",
		"../../docs/verify.md",
		"../../README.md",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		for n, line := range strings.Split(string(body), "\n") {
			command := strings.TrimSpace(line)
			command = strings.TrimPrefix(command, "sudo ")
			rest, bare := strings.CutPrefix(command, "porchd")
			if !bare {
				rest, bare = strings.CutPrefix(command, "denyfirstd")
			}
			if !bare || !strings.HasPrefix(rest, " -") {
				continue
			}
			t.Errorf("%s:%d invokes the service by a name that is not on PATH there:\n  %s",
				path, n+1, strings.TrimSpace(line))
		}
	}
}

// A clone is followed by the directory it made.
//
// The repository was renamed from denyfirst to porch on 2026-09-18, and git
// names the directory after the repository. Every guide that clones and then
// changes into the old name is a first step that fails.
func TestEveryCloneIsFollowedByTheDirectoryItMade(t *testing.T) {
	for _, path := range []string{
		"../../README.md",
		"../../docs/self-host.md",
		"../../docs/verify.md",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
		clones := 0
		for i, line := range lines {
			_, repo, ok := strings.Cut(line, "git clone https://github.com/denyfirst/")
			if !ok {
				continue
			}
			clones++
			repo = strings.TrimSpace(repo)
			if i+1 >= len(lines) || strings.TrimSpace(lines[i+1]) != "cd "+repo {
				t.Errorf("%s:%d clones %s and is not followed by cd %s", path, i+1, repo, repo)
			}
		}
		if clones == 0 {
			t.Errorf("%s no longer clones the repository, so this test checks nothing there", path)
		}
	}
}

// The signature uploaded is the one release.ps1 made for that tag, and no
// other.
//
// On 2026-10-01 v0.26.0 was published with the signature the v0.26.0-rc1 dry
// run had left behind. The upload read dist\SHA256SUMS.sig whatever the tag,
// release.ps1 had not run for v0.26.0, and so the file the dry run signed was
// the file that went out. reproduce.yml said so within the minute and every
// installation that checked refused, but a release was published with nothing
// that verified it.
//
// So the path carries the tag, the script empties dist before anything can
// stop it, and a signature it did not make, or could not verify, is not left
// where the upload looks.
func TestTheSignatureUploadedIsTheOneMadeForThatTag(t *testing.T) {
	body, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatalf("reading docs/releasing.md: %v", err)
	}
	uploads := regexp.MustCompile(`(?m)^gh release upload (\S+) (\S+)`).FindAllStringSubmatch(string(body), -1)
	if len(uploads) == 0 {
		t.Fatal("docs/releasing.md no longer uploads a signature, so this test checks nothing there")
	}
	for _, m := range uploads {
		if want := `dist\` + m[1] + `\SHA256SUMS.sig`; m[2] != want {
			t.Errorf("docs/releasing.md uploads %s for %s, where only %s is the signature made for that tag", m[2], m[1], want)
		}
	}

	raw, err := os.ReadFile("../../scripts/release.ps1")
	if err != nil {
		t.Fatalf("reading scripts/release.ps1: %v", err)
	}
	script := string(raw)

	if !strings.Contains(script, `gh release upload $Tag dist\$Tag\SHA256SUMS.sig --clobber`) {
		t.Error("release.ps1 prints an upload that does not name the tag's own signature")
	}
	if !regexp.MustCompile(`(?m)^\s*\$dist = Join-Path \$distRoot \$Tag\s*$`).MatchString(script) {
		t.Error("release.ps1 no longer keeps each tag's files in a directory of its own")
	}

	// Emptied before the first statement that can stop the script, or a run
	// that stops early leaves the last run's signature in place.
	clear := strings.Index(script, "Remove-Item -Recurse -Force $distRoot")
	first := regexp.MustCompile(`(?m)^\s*throw\b`).FindStringIndex(script)
	if clear < 0 || first == nil || clear > first[0] {
		t.Error("release.ps1 can stop before it empties dist, leaving an earlier signature to be uploaded")
	}

	// The signature the release already carries is downloaded with
	// everything else; it is gone before signing, so a run that stops there
	// cannot leave it to be uploaded again.
	download := strings.Index(script, "gh release download $Tag")
	removed := strings.Index(script, "Remove-Item -Force $published")
	sign := strings.Index(script, "ssh-keygen -Y sign")
	if download < 0 || sign < 0 || removed < download || removed > sign {
		t.Error("release.ps1 keeps the downloaded signature until it signs, so a run that stops leaves it to be uploaded")
	}

	// Every way out after signing, other than success, removes the signature.
	signed := strings.Index(script, `"`+"`nSigned.")
	if signed < sign {
		t.Fatal("release.ps1 no longer says when it has signed, so this test cannot find the end of signing")
	}
	exits := strings.Split(script[sign:signed], "throw ")
	for _, before := range exits[:len(exits)-1] {
		if !strings.Contains(before, `Remove-Item -Force "$checksums.sig"`) {
			t.Error("release.ps1 stops after signing without removing a signature it could not stand behind")
		}
	}
	if len(exits) < 3 {
		t.Error("release.ps1 no longer refuses both a failed signing and a signature that does not verify")
	}
}

// A comparison that finds a difference signs nothing.
//
// S17 says release.ps1 -Compare signs only if every byte matches, and until
// 2026-10-01 that was a description of the maintainer rather than of the
// script: it printed "n identical, m different" and went straight on to the
// passphrase prompt. The image's digest is trusted because this comparison
// holds it, so a difference is a refusal, in both directions: a file built
// here that is not the release's, and a file the list names that was not
// built here.
func TestADifferenceInTheComparisonSignsNothing(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/release.ps1")
	if err != nil {
		t.Fatalf("reading scripts/release.ps1: %v", err)
	}
	script := string(raw)

	compare := strings.Index(script, "if ($Compare) {")
	sign := strings.Index(script, "ssh-keygen -Y sign")
	if compare < 0 || sign < compare {
		t.Fatal("release.ps1 no longer compares before it signs, so this test checks nothing")
	}
	region := script[compare:sign]

	for _, counted := range []string{"(not in the release)", "(not rebuilt here)"} {
		if !strings.Contains(region, counted) {
			t.Errorf("release.ps1 no longer counts a file %s as a difference", counted)
		}
	}
	if !strings.Contains(region, "$name -ne 'BUILD' -and $rebuilt -notcontains $name") {
		t.Error("release.ps1 no longer requires every listed file but BUILD to have been rebuilt")
	}

	refusal := regexp.MustCompile(`if \(\$different\.Count -gt 0\) \{\s*throw `).FindStringIndex(region)
	if refusal == nil {
		t.Fatal("release.ps1 signs past a difference it has counted")
	}
	if last := strings.LastIndex(region, "$different +="); last > refusal[0] {
		t.Error("release.ps1 refuses before every difference has been counted")
	}
}

// No guide sends a reader to a binary that is no longer offered.
//
// Every release before v0.25.1 checked names nobody had proven, and on
// 2026-10-01 their binaries were withdrawn: the tag, SHA256SUMS, its signature
// and BUILD stay, the binaries do not (N9). docs/verify.md's examples still
// downloaded v0.1.0's command line that day, which would now be a 404 in the
// one guide whose every step has to work, and a pointer to the kind of release
// this project no longer distributes. A list and its signature from an old
// release are still fine to fetch; a binary is not.
func TestNoGuideDownloadsAWithdrawnBinary(t *testing.T) {
	download := regexp.MustCompile(`releases/download/v(\d+)\.(\d+)\.(\d+)[^/\s]*/([A-Za-z0-9_.\-]+)`)
	var guides []string
	for _, pattern := range []string{"../../docs/*.md", "../../*.md", "../../internal/web/assets/*.html"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		guides = append(guides, found...)
	}
	if len(guides) == 0 {
		t.Fatal("no guides were found, so this test checks nothing")
	}
	for _, path := range guides {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range download.FindAllStringSubmatch(string(body), -1) {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			patch, _ := strconv.Atoi(m[3])
			withdrawn := major == 0 && (minor < 25 || minor == 25 && patch < 1)
			record := m[4] == "SHA256SUMS" || m[4] == "SHA256SUMS.sig" || m[4] == "BUILD"
			if withdrawn && !record {
				t.Errorf("%s downloads %s, a binary withdrawn with every release before v0.25.1", path, m[0])
			}
		}
	}
}

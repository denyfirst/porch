# Cutting a release

This is the maintainer's procedure. It lived in a chat window and in nobody's
repository, which for a project whose argument is that everything here can be
checked is the wrong place for the one procedure that decides what people
download.

Two parties make a release and neither can do it alone. A workflow builds from
the tagged source on a machine the maintainer does not control, in a log
anyone can read, and cannot sign. The maintainer signs on their own machine
and does not build. Compromising either alone yields nothing, which is the
reason the steps are split and the reason not to collapse them when one of
them is inconvenient.

---

## Landing a change

Most days there is no release, only a change. These are here because each one
has already gone wrong, and each costs less to do than the mistake cost to
find.

**The branch is a condition, not a line to read.** `git switch -c` fails if
the branch already exists, and a failed switch leaves you where you were —
which on 2026-08-23 was `main`, where the commit then landed. It happened
again on 2026-09-01, in a block that printed the current branch one line
before applying a patch to it: the word `main` went past on the way to the
next command, the patch applied to `main`, and the commit landed there.

Printing a fact and acting on it are different things. The patch is applied
inside the check, so on the failure path nothing is applied and there is
nothing to commit:

```powershell
$branch = 'topic/thing-2026-01-01'
git switch -c $branch main

if ((git branch --show-current) -eq $branch) {
  git apply "$env:USERPROFILE\Downloads\thing.patch"
} else {
  Write-Host 'STOP: not on the branch, nothing applied' -ForegroundColor Red
}
```

The commit is guarded the same way, because a patch applied by hand after a
failed switch reaches the same place:

```powershell
if ((git branch --show-current) -eq $branch) {
  git commit -S -m "scope: what changed" -m "why"
} else {
  Write-Host 'STOP: not on the branch, nothing committed' -ForegroundColor Red
}
```

**Read the index before staging, and again after.** `git add -A` takes
everything in the directory, including whatever was left there while working
out what was wrong. On 2026-08-31 it took two saved workflow logs into a
commit that reached `main`. Nothing in those was sensitive; that was luck
rather than a property, and the second look is what turns it into one.

Stage the paths the change touches, by name. `git add -A` was in this place
until 2026-09-01, when it swept a downloaded patch file into the commit that
applied it — the same shape as the logs, in the procedure written to prevent
them. Reading the index afterwards showed the extra file and did not stop it,
because nothing was asked to.

```powershell
git status --short
git add docs/releasing.md internal/policy/note.go
git status --short
```

**A commit message carries the reason for the change, and nothing else.** No
attribution trailers, no session, tool or account identifiers, no link a
reader of this repository cannot follow. A message is published, permanent,
and correctable only by rewriting `main` — which S6 and S12 forbid for far
better reasons than a trailer is worth.

The rule is here because one reached `main` on 2026-09-02 before it existed:
`468341e` carries a `Claude-Session:` URL. Nobody but its owner can open it,
so it tells a reader nothing; what it does carry is an identifier that links
this repository's history to a session on a third-party service, in a public
record, permanently. It stays where it is — force-pushing the default branch
to remove one line would cost more than the line does — and it is not
repeated.

**Write diagnostic output somewhere other than the repository.** `gh run view
--log` writes into the current directory, and the current directory is usually
this one. `*.log` is ignored now, which catches that shape and not the next
file with a different extension.

```powershell
gh run view $id --log | Out-File -Encoding utf8 "$env:TEMP\run.log"
```

**Merge as soon as the checks are green.** Auto-merge is disabled here and
that is the right setting: it lands a change without anybody looking at the
result. The cost is that merging is a step somebody has to take, and on
2026-08-23 four pull requests were left green and unmerged, each discovered
only when the next patch failed to apply on top of it. One of them was the
only reason v0.3.1 existed.

```powershell
gh pr checks --watch
gh pr merge --merge
```

**Give the checks a moment to register first.** `gh pr checks --watch` run in
the same breath as `gh pr create` reports that no checks exist and exits
immediately, because none has been queued yet. The merge then fails for a
reason that reads like a policy block — required checks not satisfied — and the
obvious next move is to go looking at branch protection, which is working
correctly. Wait a few seconds, or run `gh pr checks` once on its own and watch
only when it lists something.

---

## Before the first time

**A signing key**, separate from the key that pushes to GitHub, at
`%USERPROFILE%\.ssh\id_ed25519_denyfirst_release` or wherever `-SigningKey`
points. Its public half is in `.allowed_signers`. If it lived in GitHub's
secrets, whoever took the account could sign a release, and the signature
would confirm only that they had access.

**`gh`**, authenticated as somebody who can edit releases.

**The image's package, public.** The release workflow publishes the container
image to `ghcr.io/denyfirst/porch` with its own token, and the first time it
does, GitHub may create the package private. The workflow then reads the image
back anonymously, as an installation will, and fails before staging the
draft: an image nobody can fetch must not be named by a release. Make the
package public under its settings — and link it to this repository if GitHub
has not — and run the workflow again for the same tag. It is pushed by digest
and with no tag; nothing about that changes when it is made public.

**`bash`**, for `-Compare`. Git for Windows ships one and puts only its `cmd\`
directory on the path, so the script also looks in `C:\Program Files\Git\bin\`.

**A way to run the script at all.** On a default Windows installation
PowerShell refuses to run any script file, and `.\scripts\release.ps1` fails
before it starts:

```
File ...\release.ps1 cannot be loaded because running scripts is disabled
on this system.
```

Run it in a child process that is allowed to, which changes nothing outside
that one process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

Do not change the machine's policy to make this go away. The execution policy
is not a security boundary — Microsoft says so, and `-ExecutionPolicy Bypass`
is a documented flag rather than a trick — so relaxing it permanently buys no
safety and loses the accident it does prevent. What protects this step is that
the script is in this repository and has been read.

---

## The dry run

Do this once, on a tag you are not releasing, before the first real release
and after any change to `release.ps1` or `build.sh`. Signing is the one place
where a mistake is expensive and, until 2026-08-22, the one place that had
never been exercised end to end.

```powershell
git checkout main
git pull
git tag -s v0.2.0-rc1 -m "Dry run of the release procedure. Not a release."
git push origin v0.2.0-rc1
do { Start-Sleep 5; $id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0-rc1 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
```

Then the maintainer's half, without publishing anything:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0-rc1 -Compare
```

Stop there. Do not upload the signature and do not publish: `reproduce.yml`
runs on publication, and a release candidate is not the thing to point it at.
The signature it made stays in `dist\v0.2.0-rc1` until the script next runs,
and the real release's upload names its own tag, so it cannot pick that one up.

**The tag stays.** Tags here cannot be deleted or moved, which is what makes a
signature over one mean anything, so a dry run leaves a signed tag behind for
ever. That is the correct trade, and the reason to name release candidates as
such rather than reusing the real number.

Delete the draft release when you are finished with it. Do not pass
`--cleanup-tag`: it will fail on the tag, which is the rule working.

```powershell
gh release delete v0.2.0-rc1 --yes
```

---

## The release

```powershell
git checkout main
git pull

# Nothing may be waiting. A green pull request that was never merged is not in
# this tag, and on 2026-08-23 that produced v0.3.1: released, signed,
# reproduced and deployed without the one fix it existed to carry.
#
# Read this output rather than running the next line. On 2026-09-28 the whole
# block below was typed out while one pull request was still green and open,
# because the list of steps was written before it merged: v0.23.2 was cut one
# merge early, and the two `rev-parse` lines agreed with each other because
# both were read before main moved. A tag matching main proves nothing if main
# is not finished.
#
# And on 2026-10-01: this list showed the pull request the release existed for,
# still open, and the block was run on regardless. v0.25.0 is the commit
# v0.24.1 was cut from, under a new number, signed and published; what it was
# meant to carry shipped as v0.25.1. The list printing anything is a stop.
gh pr list --state open

git log --oneline -1              # the commit this will release

# If the rule set moved in this release, the newest section of
# docs/policy-changes.md has to name the tag about to be cut. That section is
# written before the tag exists, so it says "Unreleased" until somebody comes
# back for it — and on 2026-09-01 nobody had: `denyfirst-v4` was still marked
# unreleased on the page five releases after v0.4.0 shipped it. Any output
# here is a stop while the rule set is the one being released.
#
# Case-sensitive, because Select-String is not by default, and the page says
# "were unreleased" in a sentence of history: on 2026-10-01 that line was
# printed, read as a false alarm, and the next line run — which is the habit
# this check cannot afford to teach.
Select-String -Path docs\policy-changes.md -Pattern 'Unreleased' -CaseSensitive

git tag -s v0.2.0 -m "porch v0.2.0"

# The tag has to be new, and it has to be on the commit just read.
#
# On 2026-09-01 `git tag -s` answered `fatal: tag already exists` and the
# release went on regardless: the tag had been cut before the last pull
# request merged, so v0.6.0 was built, signed, reproduced and deployed from
# the commit before the change it was for. An existing tag means either that
# this version is already released or that something older than you think is
# about to be published. Both are a stop.
#
# It happened again on 2026-09-28, and this is what it costs now: the tag was
# pushed, the ruleset "Released tags are immutable" refused to delete it, and
# the version number was abandoned. There is no v0.23.2. The draft it produced
# was deleted before anything was signed, so nothing was ever downloadable
# under it — a mis-cut tag is a wasted number rather than a wrong release, and
# that is the ruleset working rather than getting in the way. Do not turn the
# rule off to tidy up after this; cut the next number.
#
# Quote the argument. Unquoted, PowerShell takes {commit} for a script block
# and git is handed `v0.7.0^` — the tag's first parent, which on a merge
# commit is the previous tip and looks exactly like the failure this check is
# for.
git rev-parse "v0.2.0^{commit}"
git rev-parse main

git push origin v0.2.0
do { Start-Sleep 5; $id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
```

`gh run watch` with no argument lists every recent run and waits for one to be
chosen. On 2026-08-23 the CI run was picked instead of the build, the draft
was assumed to exist, and the next command answered `release not found`. A
procedure is a set of instructions; an instruction that opens a menu is one
somebody answers wrongly at two in the morning.

The workflow builds every artifact, runs `go vet`, `go test` and `govulncheck`
against the tagged source, writes `SHA256SUMS` and `BUILD`, and leaves a
**draft** release. A draft is invisible to anyone but you, so the binaries
wait there unsigned without being downloadable.

If it did not start, or you are rebuilding after a failure:

```powershell
gh workflow run build-release.yml -f tag=v0.2.0
```

Check the log before going further. Both gate steps have to have run: a
release built from source that does not pass its own tests is a release nobody
gated.

```powershell
$id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId'
gh run view $id --log | Select-String "Refuse to stage"
```

### Sign

`-Compare` needs the tag checked out. Otherwise it compares the release
against whatever is in the working tree and reports a difference count for the
wrong source.

```powershell
git checkout v0.2.0
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

**Expect every artifact to match, on Windows too.** This page used to say the
opposite — that a cross-compile from Windows puts a different `GOROOT` into
the runtime package and the comparison could only mean something on Linux.
Measured on 2026-08-23 against v0.3.0: ten artifacts, ten identical, from
Windows. The toolchain came from the module cache rather than from an
installed `GOROOT`, and `-trimpath` does normalise module cache paths.

That holds whenever the `go` directive in `go.mod` names a version other than
the Go on your PATH, which is the ordinary case here. If they happen to be the
same version, the build uses the installed `GOROOT` and the bytes will differ
by that path — so read the `goroot` line in `BUILD` before treating a
difference as anything else.

A mismatch is now worth stopping for. Telling a verifier that mismatches are
normal on their platform is the one lesson this check must never teach, and it
was being taught in four places.

**And the script stops for it.** Until 2026-10-01 it printed the difference
count and went straight on to the passphrase prompt, so a difference was one
keystroke from being signed. Now any file built here that is not the
release's, and any file the list names that was not built here, refuses the
signature: the image's digest in particular is trusted because this comparison
holds it (S17). `BUILD` is the one exception, because it is a record rather
than a build, and the script reads it field by field before anything else.

Anything the script refuses to sign, it says why and signs nothing. Do not
work around it.

### Publish

The notes go on before the release is published. The draft's own text says it
has no signature yet, and a release published without new notes says that
in public for as long as nobody comes back for it — v0.24.0 and v0.25.0 both
did. Write them to `NOTES.md` outside the commit (see *Afterwards* for what
they say), then:

```powershell
gh release upload v0.2.0 dist\v0.2.0\SHA256SUMS.sig --clobber
gh release edit v0.2.0 --notes-file NOTES.md
gh release edit v0.2.0 --draft=false
Remove-Item NOTES.md
```

The signature is read from a directory named for the tag, which `release.ps1`
makes, and only `release.ps1` writes into. On 2026-10-01 the path was
`dist\SHA256SUMS.sig` for every tag. The script had not run for v0.26.0, the
directory still held what the v0.26.0-rc1 dry run had signed, and the upload
sent that: v0.26.0 was published with a signature over another release's list.
`reproduce.yml` reported it within the minute and every installation that
checked refused, so nothing false was believed, but the release could not be
verified until it was signed again. Now a signature not made for this tag is
not at the path this line reads, and the script empties `dist` before its
first check, so a run that stops early leaves nothing behind to upload.

Publication starts `reproduce.yml`, which verifies the signature, checks that
the tag and the default branch trust the same keys, rebuilds every artifact on
a runner and compares. Watch the run for this tag, not the newest run:
published a second ago, it may not be registered yet, and the newest is then
the previous release's, already green. On 2026-10-01 that is what was watched,
and it reported success for a run that had nothing to do with the release.

```powershell
do { Start-Sleep 5; $id = gh run list --workflow=reproduce.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
```

Every run is found the same way, by `--branch` and the tag, which is what a
run started by a tag or a release carries as its branch. Not by a `jq` filter
naming the tag: Windows PowerShell 5.1 strips the double quotes inside an
argument it hands to a program, so `select(.headBranch == "v0.2.0")` reached
`jq` with the tag unquoted and failed to parse — on 2026-10-01, the evening it
was first written down. And `.[].databaseId` rather than `.[0].databaseId`,
because before the run exists the second prints `null`, which ends the wait
on a run that is not there.

A red mark there is public, which is the point. It is also the only thing that
demonstrates the property this whole arrangement exists for, so it is worth
watching rather than assuming.

### Afterwards

Write the release notes so somebody upgrading knows what moved.
`docs/policy-changes.md` records what a new rule set grades differently, and a
verdict from one policy version is not comparable with a verdict from another
— link it rather than restating it.

The notes are edited with `gh release edit vX.Y.Z --notes-file NOTES.md`, and
`--notes-file` is read relative to the current directory. On 2026-09-01 it was
not, the command failed, and the published release kept a draft sentence
saying it had no signature yet — an actively false statement on a release that
was signed. Check what the page says after editing it, not that the command
was typed.

Then deploy, which the section below describes.

---

## Deploying

A release is a set of bytes anybody can verify. A deploy is the separate claim
that those exact bytes are what now answers at denyfirst.dev, and nothing above
establishes it.

The commands are kept with the rest of what describes that machine, in the
maintainers' private notes. A public page listing a server's paths, accounts
and monitoring is a map for whoever would attack it, and nobody verifying a
release needs any of it. What every deploy does is public, because it is what
anybody relying on the demonstration is entitled to know:

- **Nothing is deployed that was not reproduced.** `reproduce.yml` has passed
  for the tag, so the bytes are not one laptop's word.
- **The server checks the signature itself**, with the commands
  `docs/verify.md` gives a stranger and the key from this repository, before
  the file goes anywhere near the live path.
- **Only the demonstration build runs there** (N6), and the file has to say so
  before it is installed. The ordinary binary on that machine would be a
  scanner for anybody's estate, with nothing in its configuration to show it.
- **The previous binary is kept, named for the release that replaced it**, so
  going back is one rename.
- **The running process is checked, not the file**, and the binary carries no
  file capability: the service is granted the port it needs and nothing else.

Until 2026-10-01 the commands were on this page, and with them the binary's
path, the service's account, its state directory and the monitoring around it.

---

## What each step is for

| Step | What it establishes |
|---|---|
| Signed tag | Which commit is being released, and by whom |
| Public build | The binaries correspond to that commit, in a log anyone can read |
| Gates in the workflow | That commit passes its own tests and carries no known reachable vulnerability |
| `release.ps1` checks | The build record names this tag, this commit, and a build script that exists in this history |
| The signature | The list of hashes came from the key in `.allowed_signers` |
| `reproduce.yml` | Someone other than the maintainer can rebuild the same bytes, and the release is signed |

No single one of those is the answer. The signature without the public build
says a compromised laptop signed something; the public build without the
signature says anyone who takes the account can ship; the reproduction without
either says only that the bytes are self-consistent.

---

## Repository settings this depends on

Neither can be asserted by a test from inside a checkout, which is why they
are written down.

**Merge commits only.** Squash and rebase merging are disabled. A rebase merge
cannot preserve a commit signature — the signature covers the parent hash —
and GitHub does not re-sign, so rebase-merged commits arrive on `main`
unsigned, after every check has already gone green. S6 has the history.

**Tags cannot be deleted or moved.** A tag that can be moved is a tag whose
signature says nothing about what was released: the bytes people verified
against would stay valid while the tag pointed somewhere else. Both
restrictions belong on, and the cost is that a dry run's tag is permanent.

# Cutting a release

The maintainer's procedure. Two parties make a release and neither can do it
alone: a workflow builds from the tagged source on a machine the maintainer
does not control, in a public log, and cannot sign; the maintainer signs on
their own machine and does not build. Do not collapse the two because one is
inconvenient.

Every step below is here because skipping it has already gone wrong once.

---

## Landing a change

**Act inside the branch check, not after printing it.** A failed
`git switch -c` leaves you on `main`:

```powershell
$branch = 'topic/thing-2026-01-01'
git switch -c $branch main

if ((git branch --show-current) -eq $branch) {
  git apply "$env:USERPROFILE\Downloads\thing.patch"
} else {
  Write-Host 'STOP: not on the branch, nothing applied' -ForegroundColor Red
}
```

```powershell
if ((git branch --show-current) -eq $branch) {
  git commit -S -m "scope: what changed" -m "why"
} else {
  Write-Host 'STOP: not on the branch, nothing committed' -ForegroundColor Red
}
```

**Stage by name, and read the index before and after.** `git add -A` has
swept logs and a patch file into commits on `main`.

```powershell
git status --short
git add docs/releasing.md internal/policy/note.go
git status --short
```

**A commit message carries the reason for the change, and nothing else.** No
attribution trailers, no session, tool or account identifiers, no link a
reader of this repository cannot follow. A message is public and permanent.

**So are a branch's name and a pull request's description.** Name the branch
for the change and its date, as `$branch` above; the name is written into the
merge commit for ever. A description carries no session link and no link a
reader cannot follow. Forty-six merges before 2026-10-21 name a tool's working
branch, and 38 commits from 2026-10-02 to 2026-10-07 carry attribution
trailers. They are in signed releases, so they stay.

**Write diagnostic output outside the repository:**

```powershell
gh run view $id --log | Out-File -Encoding utf8 "$env:TEMP\run.log"
```

**Merge as soon as the checks are green.** Auto-merge is off on purpose.

```powershell
gh pr checks --watch
gh pr merge --merge
```

Straight after `gh pr create`, `gh pr checks --watch` reports that
no checks exist and exits, because none is queued yet. Wait a few seconds.

---

## Before the first time

- **A signing key**, separate from the key that pushes to GitHub, at
  `%USERPROFILE%\.ssh\id_ed25519_denyfirst_release` or wherever `-SigningKey`
  points. Its public half is in `.allowed_signers`. It is never a GitHub
  secret.
- **`gh`**, signed in as somebody who can edit releases.
- **The image's package, public.** The workflow pushes
  `ghcr.io/denyfirst/porch` by digest and reads it back anonymously; if GitHub
  created the package private, make it public, link it to this repository,
  and run the workflow again for the same tag.
- **`bash`**, for `-Compare`. Git for Windows ships one.
- **A way to run the script.** Windows refuses script files by default. Run it
  in a child process instead of changing the machine's policy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

---

## The dry run

Once, on a tag you are not releasing, before the first release and after any
change to `release.ps1` or `build.sh`:

```powershell
git checkout main
git pull
git tag -s v0.2.0-rc1 -m "Dry run of the release procedure. Not a release."
git push origin v0.2.0-rc1
do { Start-Sleep 5; $id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0-rc1 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0-rc1 -Compare
```

Stop there: do not upload or publish. Tags cannot be deleted or moved, so the
`-rc1` tag stays for ever; that is the rule working. Delete the draft, without
`--cleanup-tag`:

```powershell
gh release delete v0.2.0-rc1 --yes
```

---

## The release

```powershell
git checkout main
git pull

# Nothing may be waiting. Any output here is a stop: a release has three times
# been cut one merge early. The build workflow refuses such a tag as well, but
# by then the tag exists for ever and the cure is the next number.
gh pr list --state open

git log --oneline -1              # the commit this will release

# If the rule set moved, the newest section of docs/policy-changes.md has to
# name the tag about to be cut. Any output here is a stop.
Select-String -Path docs\policy-changes.md -Pattern 'Unreleased' -CaseSensitive

git tag -s v0.2.0 -m "porch v0.2.0"

# The tag has to be new, and on the commit just read.
# An existing tag means either that this version is already released or that
# something older than you think is about to be published. Both are a stop:
# cut the next number.
# Quoted, or PowerShell eats {commit}.
git rev-parse "v0.2.0^{commit}"
git rev-parse main

git push origin v0.2.0
do { Start-Sleep 5; $id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
```

Always give `gh run watch` the run's id; without one it opens a menu.

The workflow builds every artifact, runs `go vet`, `go test` and
`govulncheck` against the tagged source, writes `SHA256SUMS` and `BUILD`, and
leaves a **draft** release nobody else can see. To rebuild after a failure:

```powershell
gh workflow run build-release.yml -f tag=v0.2.0
```

Check that both gate steps ran:

```powershell
$id = gh run list --workflow=build-release.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId'
gh run view $id --log | Select-String "Refuse to stage"
```

### Sign

```powershell
git checkout v0.2.0
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

`-Compare` rebuilds every artifact from the checked-out tag and compares.
**Expect every artifact to match, on Windows too.** If the Go on your PATH is
the version `go.mod` names, the build uses the installed `GOROOT`; read the
`goroot` line in `BUILD` before treating a difference as anything else.

Any difference refuses the signature, and so does anything else the script
does not accept. It says why and signs nothing. Do not work around it.

### Publish

The notes go on before the release is published, or the draft's "not signed
yet" text goes public. Write them to `NOTES.md` outside the commit, then:

```powershell
$sig = 'dist\v0.2.0\SHA256SUMS.sig'; $got = Join-Path $env:TEMP ('sig-' + [guid]::NewGuid())
if (-not (Test-Path NOTES.md)) { Write-Host 'STOP: NOTES.md does not exist; nothing was uploaded' } elseif (Test-Path $sig) {
gh release upload v0.2.0 dist\v0.2.0\SHA256SUMS.sig --clobber
gh release edit v0.2.0 --notes-file NOTES.md
$body = (gh release view v0.2.0 --json body --jq .body) -join "`n"
$noted = ($body.Length -gt 0) -and ($body -notmatch 'no signature yet')
gh release download v0.2.0 --pattern SHA256SUMS.sig --dir $got
$ok = (Test-Path "$got\SHA256SUMS.sig") -and ((Get-FileHash "$got\SHA256SUMS.sig").Hash -eq (Get-FileHash $sig).Hash)
Remove-Item -Recurse -Force $got -ErrorAction SilentlyContinue
if ($ok -and $noted) {
gh release edit v0.2.0 --draft=false
Remove-Item NOTES.md
} elseif (-not $noted) { Write-Host 'STOP: the notes are not on the release; it stays a draft' } else { Write-Host 'STOP: the release does not carry the signature release.ps1 made; it stays a draft' }
} else { Write-Host "STOP: $sig does not exist, so release.ps1 signed nothing; nothing was uploaded" }
```

The signature comes from the directory named for the tag, which only
`release.ps1` writes, so a signature made for another tag cannot be uploaded.

The block is one statement. PowerShell reads it to the last brace before it
runs any of it, so no step that fails can be followed by the publish, and the
release is published only once the signature downloaded back from it is the
one `release.ps1` wrote. That holds only while every `elseif` and `else` sits
on the line its brace closes: pasted into a PowerShell window, an `if` runs as
soon as its brace closes at the end of a line, and an `elseif` on the next
line is a command of its own that does not exist. On 2026-10-23 the block for
v0.30.1 stopped there, having uploaded nothing. On 2026-10-16 these were four lines: `release.ps1`
had signed nothing, the upload failed, and the next lines published v0.29.1
unsigned. `reproduce.yml` failed within minutes, and the release went back to
draft until it was signed.

It is published only once the notes read back from it are not the draft's
either. On 2026-10-21 `NOTES.md` had not been written, `gh release edit` said
so, and the block went on to publish v0.30.0, signed, under "This draft has no
signature yet". The notes went on afterwards.

Publication starts `reproduce.yml`: it verifies the signature, checks the tag
and the default branch trust the same keys, rebuilds on a runner and compares.
Watch the run for this tag, not the newest run:

```powershell
do { Start-Sleep 5; $id = gh run list --workflow=reproduce.yml --limit 1 --branch v0.2.0 --json databaseId --jq '.[].databaseId' } until ($id)
gh run watch $id
```

Runs are found by `--branch` and the tag, never by a `jq` filter with quotes
in it, which Windows PowerShell 5.1 strips. `.[].databaseId`, not
`.[0].databaseId`, which prints `null` before the run exists.

### Afterwards

Release notes say what an upgrader has to be told, and link
`docs/policy-changes.md` when a rule set moved. `--notes-file` is read from the
current directory; check the published page, not that the command ran.

---

## Deploying

A deploy is the separate claim that those exact bytes now answer at
denyfirst.dev and porch.denyfirst.dev. The commands live in the maintainers'
private notes, because a public map of a server's paths and accounts helps
only an attacker. What every deploy does is public:

- **Nothing is deployed that was not reproduced.** `reproduce.yml` has passed
  for the tag.
- **The server checks the signature itself**, with the commands
  `docs/verify.md` gives a stranger and the key from this repository.
- **Only the demonstration build runs there** (N6), and the file has to say so
  before it is installed.
- **The previous binary is kept, named for the release that replaced it**, so
  going back is one rename.
- **The running process is checked, not the file**, and the binary carries no
  file capability.

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

No one of these is enough alone.

---

## Repository settings this depends on

- **Merge commits only.** Squash and rebase merging are disabled: a rebase
  cannot keep a commit signature, and GitHub does not re-sign.
- **Tags cannot be deleted or moved.** Otherwise a signature over a tag says
  nothing about what was released.

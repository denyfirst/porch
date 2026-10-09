# Contributing to porch

These are the rules the code does not show. Each guard, where it is enforced
and the tests behind it are in [`docs/invariants.md`](docs/invariants.md); the
reasons are in those tests' comments. Read the invariant before changing what
it guards.

---

## What this is

A scanner that measures how a host is reached and grades what it finds, with
four checks: TLS and certificates (`porch-tls-v7`), how a website is reached
(`porch-web-v3`), what a domain's DNS says about its mail (`porch-mail-v3`),
and how the domain itself is served (`porch-dns-v2`). Each rule set has its
own version, and a report names the one that graded it.

**The tool is what you run. The site is a demonstration of it.** The public
deployment connects only to hosts this project owns, and that is compiled in
(N6).

**No third-party dependencies.** `go.mod` has no `require` block, and it stays
that way.

---

## The three priorities, in order

Security, privacy, anonymity: of this project and of whatever it scans. A
change that improves one at the cost of another is argued before it is
written.

- **Record nothing that is not needed.** Not the hostname, not the client
  address, not a time beyond a date.
- **Never echo the input back in an error** (I3, I6).
- **A guard goes where the connection is made**, not in the handler that calls
  it today.
- **Say what was measured, never what it implies** (R17). **Nothing measured
  is not passing** (R4).

---

## Rules for a change

- **Sabotage what you wrote, in both directions.** Break the new behaviour and
  check a test fails; break it the other way and check again. A sabotage that
  escapes gets a test, or a comment saying why the code is right.
- **A verdict change is a rule-set version change.** Bump the rule set and add
  a section to `docs/policy-changes.md` marked `Unreleased`.
- **Where no document sets a threshold, report rather than grade** (R21).
- **Every invariant cites tests that exist.** CI fails otherwise.
- **Error strings are lowercase, one line, no trailing punctuation**
  (staticcheck ST1005).

---

## Rules for git

- **Commit messages carry the reason for the change and nothing else.** No
  attribution trailers, no session, tool or account identifiers, no link a
  reader of this repository cannot follow.
- **Check the branch before committing.** A failed `git switch -c` leaves you
  on `main`:

  ```sh
  git switch -c topic/thing-2026-01-01 main
  [ "$(git branch --show-current)" = topic/thing-2026-01-01 ] || exit 1
  ```

- **Stage by name, never `git add -A`,** and read the index before and after.
- **Merge commits only.** A rebase cannot keep a commit signature.
- **Never `gh pr merge --admin` or `--auto`.** A person looks at the result.
- `gh pr checks --watch` straight after `gh pr create` reports no checks and
  exits. Wait a few seconds.

---

## Running the gates

```sh
gofmt -l internal cmd
go vet ./...
go test ./...

# every platform the release ships, not only this one
for os in linux darwin windows; do GOOS="$os" go vet ./... || break; done

# what CI's "Static analysis" job runs, at the versions it pins: staticcheck
# v0.8.1 built against golang.org/x/tools v0.51.0, which reads Go 1.27.2's
# export data (see the job in ci.yml for why)
toolchain="$(go env GOVERSION)"
bin="$(go env GOPATH)/bin"
(
  export GOTOOLCHAIN="${toolchain:?the toolchain go.mod names could not be fetched}"
  cd "$(mktemp -d)" && go mod init staticcheck-build >/dev/null 2>&1 &&
    go get honnef.co/go/tools/cmd/staticcheck@v0.8.1 golang.org/x/tools@v0.51.0 &&
    go build -o "${bin}/staticcheck" honnef.co/go/tools/cmd/staticcheck
)
"${bin}/staticcheck" ./...

# what CI's "Security linter" job runs, at the versions it pins, once per
# platform: gosec v2.28.0 built against golang.org/x/tools v0.51.0, for the
# same reason
toolchain="$(go env GOVERSION)"
bin="$(go env GOPATH)/bin"
(
  export GOTOOLCHAIN="${toolchain:?the toolchain go.mod names could not be fetched}"
  cd "$(mktemp -d)" && go mod init gosec-build >/dev/null 2>&1 &&
    go get github.com/securego/gosec/v2/cmd/gosec@v2.28.0 golang.org/x/tools@v0.51.0 &&
    go build -o "${bin}/gosec" github.com/securego/gosec/v2/cmd/gosec
)
for os in linux darwin windows; do
  GOOS="$os" "${bin}/gosec" -severity medium -confidence medium ./... || break
done
```

- `go vet` per platform matters: a file behind another platform's build tag is
  never compiled here, so a mistake in `resolver_windows.go` would otherwise
  surface only in a release build.
- Each tool is built with the toolchain `go.mod` names, read on its own line so
  a failed fetch stops the step instead of building with an older Go.
- `-race` needs cgo; CI runs it on Linux.

**The demonstration build** is a build tag, and nothing above exercises it:

```sh
go build -tags demo ./...
go vet -tags demo ./...
go test -tags demo ./internal/demo/ ./internal/scan/ ./internal/webscan/ ./internal/mailscan/ ./internal/web/
go test -tags demo -run Demonstration ./cmd/porch-scan/
```

`go vet` is there because `go build` does not compile tests. Most
`internal/httpapi` tests, and two `cmd/porchd` tests that describe a
self-hosted copy, fail under the tag by design: compare against the same run
on `main`, not against zero.

**The citation gate:**

```sh
grep -ohE '`(Test|Fuzz)[A-Za-z0-9_]+`' docs/invariants.md | tr -d '`' | sort -u > /tmp/cited
grep -rhoE '^func (Test|Fuzz)[A-Za-z0-9_]+' --include='*_test.go' . | sed -E 's/^func //' | sort -u > /tmp/defined
comm -23 /tmp/cited /tmp/defined     # must be empty
```

---

## What is not automated, and stays that way

- **Signing a release.** A workflow builds on a machine the maintainer does
  not control and cannot sign; the maintainer signs and does not build.
  Compromising either alone yields nothing.
- **Publishing and deploying**, by [`docs/releasing.md`](docs/releasing.md).
- **Merging.** A person looks at the result.

---

## Where things are

| | |
|---|---|
| `internal/tlsprobe`, `internal/certinfo` | the TLS measurement |
| `internal/rawhello` | a ClientHello Go cannot send: SSL 3.0, export and NULL suites, the downgrade probe |
| `internal/webprobe` | the HTTP measurement: one `GET` of `/`, the other form of the name, IPv6 (N7) |
| `internal/markup` | reads a page; keeps hosts and booleans, never markup (N7) |
| `internal/securitytxt` | reads what a site publishes about reporting a fault in it, and keeps a count and a date (N7) |
| `internal/wellknown` | every address under `/.well-known` this project asks for or serves, each beside its document (N7) |
| `internal/dnsnames` | the names a domain's own MX, sender policy and delegation already name (N12) |
| `internal/liveness` | whether a name answers now: resolves, answers, is internal, is gone, or dangles (N12) |
| `internal/inventory` | one list of names out of every source that named them, each name carrying which ones did (N12) |
| `internal/ptrnames` | the names the addresses in a range the operator names answer to; command line only, never a service (N12) |
| `internal/certnames` | the names the hosts themselves present, read off the certificate each one serves; off unless asked for (N12) |
| `internal/passivedns` | what a register observed under a domain — the only source that sees behind a wildcard, off unless an operator names one (N12) |
| `internal/zonenames` | the names a zone hands over when asked for itself; the only complete source, read only for an estate the asker owns (N12) |
| `internal/nsecnames` | the names a signed zone lists through its own DNSSEC absence proofs; works where a transfer is refused, read only for an estate the asker owns (N12) |
| `internal/knownnames` | the names the operator already has, taken as given and never invented; the only source that reads nothing (N12) |
| `internal/policy` | every rule, versioned, each citing the document it rests on |
| `internal/display` | makes a string somebody else chose safe to put in front of a person (R10) |
| `internal/scan`, `internal/webscan`, `internal/mailscan`, `internal/dnsscan` | a check: measure, then grade |
| `internal/budget` | ends the questions asked after a measurement short of the request's deadline, so a slow third party cannot cost the report (N4) |
| `internal/spf` | walks a sender policy and counts what evaluating it costs |
| `internal/dkim` | reads signing keys under selectors somebody named |
| `internal/mtasts` | fetches the MTA-STS policy a zone announces, behind proof (N13) |
| `internal/smtptls` | asks each MX for STARTTLS on port 25, and a domain's own MX whether it relays; no message is ever composed (N3, N13) |
| `internal/dane` | checks an exchanger's DANE records against the certificate it presented, as RFC 7672 has a sender do (N13) |
| `internal/dmarcreports` | where a DMARC record asks for its reports, and whether the places outside the domain agreed to receive them, as RFC 7489 §7.1 has a receiver check (N13) |
| `internal/ociimage` | the release's container image, byte for byte the same wherever it is built, pushed and checked by digest (S17) |
| `internal/demo` | which hosts this deployment may reach, compiled in |
| `internal/verify` | which domains a deployment has been shown control of (N9) |
| `internal/challenge` | fetches the file half of that proof, and nothing else |
| `internal/exclusion` | names no deployment scans, whoever asks (N8) |
| `internal/safedial` | refuses private, loopback and reserved destinations |
| `internal/truststore` | which store decides the word "trusted", for both checks (R7) |
| `internal/rootstores` | Mozilla's, Chrome's, Microsoft's and Apple's root stores, carried and named beside the verdict (R7) |
| `internal/crl` | reads the revocation list a certificate names (N11) |
| `internal/ocsp` | reads a stapled status response and says whether it means anything |
| `internal/ocspquery` | asks a certificate's own responder, only behind `porch-scan -ask-responder` (R3a) |
| `internal/ctsearch` | finds certificates a public log holds for a name (N12) |
| `internal/ctlogs` | Google's signed CT log list, carried; checks each transparency receipt against it (R3c) |
| `internal/dnsclient` | the resolver; CAA, TXT, and the walk up the tree (N5) |
| `internal/httpapi` | the service; the only package that sees untrusted input |
| `internal/access` | closes an installation to whoever cannot sign in, and holds the key its kept data is encrypted with |
| `internal/vault` | the reports an installation keeps, encrypted under the key that password seals |
| `internal/results` | a deployment's own scans, kept only where it is told to, and never beside `-access-file` |
| `internal/web` | the pages |
| `internal/promises` | what denyfirst undertakes, and what each product adds (N14) |
| `docs/invariants.md` | every guard above, where it is enforced, and its tests |
| `docs/scope.md` | who may scan what, and where that is decided |

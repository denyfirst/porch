# porch

A scanner that reads what a server already shows to anyone who asks, cites its
sources for every verdict, and keeps no records it was not told to keep.

The name is the scope. A porch is the part of a building you can walk up to
without going inside, and that is the whole of what this reads: the handshake a
server offers, the page it serves to every visitor, and the records its domain
publishes. It guesses at nothing, sends nothing malformed, and changes nothing.

Published by **denyfirst**.

Four checks, each with its own rule set. The TLS check opens a real handshake
at every TLS version, works out which cipher suites the server will actually
accept, and reads the certificate chain it presents. The web check reads how a
site is reached over HTTP; the mail check, what a domain's DNS says about its
mail; the DNS check, how the domain itself is served, down to its DNSSEC chain.
Every verdict comes from a written rule set with the document behind it
attached, and every report states what it could not measure.

Nothing about a scan is recorded unless whoever runs the tool says where to
keep it. Not the hostname, not your address, not the result.

---

## Why another one

There are several TLS scanners and they work. Three things here are
deliberately different.

**Every verdict names its source.** A finding that says a suite is insecure
links to RFC 9325, to RFC 8446, to the CVE. Disagree with a grade and you are
disagreeing with the document, not with us. The rules live in
[`internal/policy`](internal/policy) and are versioned, so the same server
graded by the same policy version gives the same answer next year.

**Every report says what it did not check.** Go's TLS stack implements
roughly twenty-seven of the three hundred suites in the IANA registry, and
gives a client no way to choose among TLS 1.3 suites, so those are asked with
a hand-written hello, one registry suite at a time. Revocation is read from
what the server stapled and from the list the certificate names, and the
certificate's own responder is asked only where an operator says so. All of
that is printed alongside the findings, because a short list of problems can
mean a well-configured server or a scan that could not see very far, and a
reader deserves to know which.

**Nothing is recorded unless you say where.** There is no log of what was
scanned, by whom, or when. The demonstration keeps a count of scans, which is
published on the site precisely because it identifies nobody. A copy you run
yourself keeps results only where you tell it to: `-results-dir` on your own
disk, or, behind a password, a history sealed under a key only that password
opens. Nobody else's data is on your machine, and none of yours is on ours.

---

## Using it

### The command line

Every release carries `porch-scan` for Linux, macOS and Windows, so nothing
needs Go: download it with `SHA256SUMS` and `SHA256SUMS.sig`, check it as
[`docs/verify.md`](docs/verify.md) says, and run it.
[`docs/self-host.md`](docs/self-host.md) has the commands. Or build it:

```sh
go build ./cmd/porch-scan
./porch-scan -verification-token example.com   # the TXT record to publish, once
./porch-scan example.com
```

```
porch-scan example.com
porch-scan example.com:8443 www.example.com
porch-scan -json example.com
porch-scan -allow-private intranet.example.com
```

It checks only domains proven to it, as the service does. The first run makes
a secret for you under your configuration directory; `-verification-token`
prints the `_porch-challenge` TXT record a domain publishes to be checked from
your machine, and a record at a domain covers every name under it. A target
that is not proven is refused with the record that would prove it. On a
server running the service, `docker compose run --rm scan example.com` runs it
in the service's container with the service's secret, so the record the page
asked for covers both.

The exit status is the worst verdict found, so it can gate a pipeline: `0`
when everything is strong, `1` on a weak finding, `2` on an insecure one, and
`3` when the scan could not be completed.

The command line accepts any port, and with `-allow-private` a name that
resolves to a private address. It does not accept a bare address, because no
record can prove one: name the host by a domain you have proven. The reasons
the hosted service is narrower still are in
[`internal/scan/scan.go`](internal/scan/scan.go).

### The service

```sh
go build ./cmd/porchd
./porchd -listen 127.0.0.1:8080
```

Then open `http://127.0.0.1:8080`. It listens on loopback by default so that
an accidental start is not immediately public. Over plain HTTP it answers only
to an address or to `localhost`, so a page on another site cannot point its own
name at your machine and use the service through your browser.

Anywhere else it needs two things, and refuses to start without them: a
password in front of everything it serves, and proof of control of each domain
before it checks one.

```sh
./porchd \
  -listen :443 \
  -tls-cert /etc/ssl/porch.pem \
  -tls-key /etc/ssl/porch.key \
  -verification-secret-file /var/lib/porch/secret \
  -access-file /var/lib/porch/access
```

Both files are created on the first start. The password is printed once;
sign in and change it. Each domain is then checked only once it publishes the
TXT record the page shows for it, and for as long as the record is there.
[`docs/self-host.md`](docs/self-host.md) has the whole procedure.

`porchd -h` lists every limit and its default.

---

## Running your own

**This is the tool. denyfirst.dev is a demonstration of it.**

That deployment reaches only hosts this project owns. It used to reach
anything anybody typed, which put this project in the worst position available
to it: ours was the address in the scanned party's logs, and we had
deliberately made ourselves unable to say who had asked, because recording
that is the one thing this project undertakes not to do. Either start keeping
records, which is not available, or stop connecting to third parties. So the
scan runs on your machine, from your address.

The hosted service says it records nothing and you have to believe it. Here
there is nothing to believe: this project is not in the path.

The restrictions that exist to stop a stranger using somebody else's server
through ours do not apply to your own network — private addresses and any
port. One does, everywhere: a domain is checked only once it has been proven
to the copy checking it, because this is a tool for your own estate.

**[`docs/self-host.md`](docs/self-host.md)** has the procedure: verifying a
release before running it, the command line, the service, and a container
image with no base system, named by its digest under the release's
signature, whose trust store comes from your machine rather than from the
image.

```sh
git clone https://github.com/denyfirst/porch
cd porch
go build ./cmd/porchd
```

There are no third-party dependencies. `go.mod` has no `require` block, so
`go build` fetches nothing beyond the standard library and there is no supply
chain to audit here beyond Go itself.

The service is licensed under AGPL-3.0. If you run a modified version and
offer it to others, the modifications have to be available to them. That is
the point of the licence for a tool whose value rests on being checkable.

---

## What it does not do

Named rather than left to be discovered.

**No exploits.** No malformed packets, no Heartbleed probe, no ROBOT oracle,
no padding oracle. Only a standard client hello at each version. Everything
reported is what any client receives on connecting.

**No path is invented.** The TLS check makes no HTTP request: the connection is
closed as soon as the handshake finishes. The web check sends one `GET` of `/`
over each scheme and follows only the addresses a `Location` header names; the
only paths anything here constructs are the published `/.well-known` addresses
a check exists to read. `docs/invariants.md` N7 lists every one.

**No certificate authority is asked which certificate you are looking at,
unless you say so.** Asking a responder whether a serial is still valid tells
it which certificate somebody is examining, so that question is behind
`-ask-responder` and needs proof of control on a service. The revocation list a
certificate names is fetched, because one list covers thousands of certificates
and asking for it names none of them.

What the server sends can include a stapled status response, and that is read.
Until 2026-08-22 it was not: this reported that some bytes had arrived, which
a reader takes to mean revocation was checked, and a server can staple an
empty file, a year-old response, a response about a different certificate or
one signed by nobody. A status is now reported only when the response
describes this certificate by issuer and serial, has not expired, and carries
the issuing authority's signature — otherwise the report says it establishes
nothing. A revoked certificate is graded insecure.

A missing staple is still a fact rather than a fault — certificate authorities
are no longer required to run OCSP and several have stopped — so it is still
not graded. A certificate that demands stapling under RFC 7633 and receives no
*valid* response is, because that breaks the connection for every client that
honours the extension.

What is still not checked is the responder certificate's own revocation
status, which would need a second request over the network, and a chain with
no revocation channel at all: `docs/invariants.md` says so under R3b.

**No port scanning.** The TLS check dials only ports that speak TLS from the
first byte: 443, 8443, 465, 636, 990, 993, 995 and 5061. The web check dials 80
and 443, and the mail check port 25 on the exchangers a domain's own MX records
name — never a port it chose.

**No private addresses.** The dialler refuses private, loopback, link-local,
multicast and reserved ranges, resolves each name once per connection, and
connects to the address it inspected rather than to the name. The command line
has `-allow-private` for your own network; the service has no such switch.

---

## How it is put together

```
cmd/porch-scan     the command line tool
cmd/porchd         the service

internal/safedial      a dialler that refuses non-public addresses
internal/tlsprobe      handshakes: versions, cipher suites, the chain
internal/certinfo      what the certificate says, and whether it verifies
internal/policy        the rules, and the documents behind them
internal/scan          the TLS check; webscan, mailscan and dnsscan the others
internal/verify        which domains an installation has been shown control of
internal/access        the password in front of an installation
internal/vault         what an installation keeps, sealed under that password
internal/httpapi       the HTTP surface and its limits
internal/web           the pages
```

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the whole map, one row per package, and CI fails
when it misses one.

Two principles run through it.

**Measurement and judgement are separate.** `tlsprobe` and `certinfo` gather
facts; `policy` decides what they mean. That is why an upstream library
changing its opinion about a cipher suite does not silently change ours.

**Guards sit where the action happens, not where the request arrives.** The
port list is enforced in `internal/scan`, not in the HTTP handler, so it
survives a caller that does not exist yet.

---

## Verifying and contributing

- [`/.well-known/security.txt`](https://denyfirst.dev/.well-known/security.txt)
  — the machine-readable contact, in the RFC 9116 format
- [`docs/invariants.md`](docs/invariants.md) — what the project guarantees,
  where each guarantee is enforced, and which test protects it
- [`docs/verify.md`](docs/verify.md) — checking a release against its signature,
  and rebuilding it yourself
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability

Findings are welcome. This used to point readers at input parsing, on the
grounds that every bug so far had been found there; the first outside review
found more in the release procedure, the rate limits and the instrumentation
than in any parser, so that guidance was wrong and is withdrawn rather than
quietly reworded.

Documents are in scope too, and not as a courtesy. Several of those findings
were pages that no longer described the code — including one that told anyone
rebuilding a release to pass a linker flag naming a symbol this program does
not define, which changes the build ID and therefore the hash. The instructions
for proving a release untampered produced, for every honest reader who followed
them, the exact signature of tampering.

```sh
go test ./...                                                    # everything
go test ./internal/scan -run '^$' -fuzz FuzzSplitTarget           # one target
```

---

## Licence

AGPL-3.0. See [`LICENSE`](LICENSE).
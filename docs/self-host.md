# Running it yourself

This is the tool. The site is a demonstration of it.

Until 2026-09-03 anybody could point denyfirst.dev at any host on the internet
and that server opened the connections. It put this project in the worst
position available to it: ours was the address in the scanned party's logs,
and we had deliberately made ourselves unable to say who had asked, because
recording that is the one thing this project undertakes not to do. There were
two ways out — start keeping records, which is not available, or stop
connecting to third parties. This is the second.

So the scan runs on your machine, from your address, under your
responsibility. The public deployment reaches only hosts this project owns.

What that buys you is not only ours to give up.

**The promise becomes a fact.** The hosted service says it records nothing and
you have to believe it. Here there is nothing to believe: this project is not
in the path. *I don't even have the data to begin with* is a stronger
statement than any policy.

**The restrictions that exist for a public service do not apply to you.** They
are there so that a stranger cannot use somebody else's server through ours,
and you are not a stranger to your own network:

| | hosted | yours |
|---|---|---|
| private and loopback addresses | refused | `-allow-private` |
| ports | eight implicit-TLS ports | any |
| bare IP addresses | refused | accepted |
| which hosts | the ones this project owns | whichever you point it at |

### The last row is the one to read twice

`porchd` listens on `127.0.0.1:8080` by default, and on that address the row
above is exactly right: the only person who can reach it is you.

**Bind it to an interface a stranger can reach, without
`-verification-secret-file`, and you have built an open scanner.** Anyone who
can reach the port can point it at any public host on the internet, and it is
*your* address in that host's logs. That is the arrangement this project
dismantled for its own public deployment — see `docs/scope.md` — rebuilt inside
your network.

A default is a mitigation rather than a boundary: it is the thing somebody
changes on the afternoon they need the service reachable, without changing
anything else. The boundary is proof of control, it is one flag, and
`docs/verify.md` is how to set it up:

```sh
porchd -listen 0.0.0.0:8443 -verification-secret-file /etc/porch/secret
```

The file is created on the first start if it is not there. Without it, `porchd`
does not start — on loopback or anywhere else — and no flag changes that.

`porchd -version` says which of the two you have, so a deploy can read it
rather than trust a filename:

```
scans whatever it is pointed at              # no proof required
scans only domains it has been shown control of
```

This is written here rather than only in `docs/scope.md` because this is the
page somebody follows while setting the service up, and a warning they meet
after they have finished is a warning about something they have already done.

---

## Keeping your own results

Nothing is kept unless you say where to keep it. That is the default and it
does not change.

What changes on a machine you run yourself is whose data it is. The public
deployment holds nothing because it is the visible party in somebody else's
logs and cannot say who asked — a repository worth seizing. None of that
reasoning survives the move to your own machine: these are your scans, of your
own estate, because you asked for them.

```sh
porch-scan -results-dir /var/lib/porch/results denyfirst.dev
porch-scan -results-dir /var/lib/porch/results -history denyfirst.dev
```

```
denyfirst.dev
=============

  DATE         VERDICT    FINDINGS
  2026-08-14   weak       hsts.absent
  2026-09-12   strong     none

  All graded by porch-tls-v7
```

`porchd` takes the same two flags, for a service that runs on this machine's
loopback with no password — a schedule, say — and writes to the same store, so
it and a person at a terminal build one history rather than two.

**Behind a password, History is the history.** The compose file starts
`porchd` with `-access-file`, and then every report is kept whole and encrypted
under **History**, to open again or delete; see *One password, and what it
seals* below. `-results-dir` beside a password is refused at start, because it
would keep a second copy in the clear, under each checked name, of what the
password is there to seal.

**The plain store is never served over HTTP.** A browsable history of an
estate's weaknesses is a thing worth attacking, so a service with no password
does not offer one. Reading it back is `porch-scan -history`, which runs on
the machine, makes no connection and resolves nothing.

**Nothing is kept that a report does not already carry**: the date, the check,
the rule set, the verdict, and which rules were raised. No time of day, no
client address, no markup, no cookie value. Writing a report down does not
relax what a report may contain.

**The rule set is kept beside each verdict**, and `-history` says where in a
history it changed. A server that went from strong to weak because a rule got
stricter has not changed at all, and a table that showed those two rows side by
side without saying so would send somebody looking for a change that never
happened.

**No retention period is invented.** `-results-keep N` bounds a target's
history and drops the oldest first; unset keeps everything. A number this
project chose would be a threshold nobody can argue with, applied to your disk.

---

## Get a binary, and check it before you run it


Every release carries `SHA256SUMS` and an OpenSSH signature over it, and a
workflow rebuilds each release on a machine the maintainer does not control.

**[`docs/verify.md`](verify.md) has the procedure.** It is not repeated here,
because two copies of a verification procedure drift and the copy nobody is
reading is the one that goes wrong. Do that first; everything below assumes a
binary you have checked.

Nothing needs Go. The command line for this machine's system and processor,
with the list and its signature to check it against:

```sh
V=$(basename "$(curl -fsSLo /dev/null -w '%{url_effective}' https://github.com/denyfirst/porch/releases/latest)")
OS=$(uname -s | tr '[:upper:]' '[:lower:]'); A=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
for f in "porch-scan_${V}_${OS}_${A}" SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/download/${V}/${f}"; done
```

Then check them as `docs/verify.md` says, and only then name it and make it
runnable:

```sh
mv "porch-scan_${V}_${OS}_${A}" porch-scan && chmod +x porch-scan
```

On Windows, `porch-scan_<version>_windows_amd64.exe` from the release page,
checked with `Get-FileHash` as `docs/verify.md` shows. The service is the
same: its binary is in the release, and a server runs it in a container
without Go (see *In a container*).

Building from source is the other answer, and needs nothing but Go:

```sh
git clone https://github.com/denyfirst/porch
cd porch
go build ./cmd/porch-scan ./cmd/porchd
```

`go.mod` has no `require` block. Nothing is fetched beyond the standard
library, so there is no third-party supply chain to audit here.

---

## The command line

```sh
./porch-scan -verification-token example.com   # the TXT record to publish, once
./porch-scan example.com
./porch-scan -json example.com
./porch-scan -allow-private intranet.example.com
```

**Every domain is proven first**, as on the service. The first run makes a
secret under your configuration directory (`-verification-secret-file` names
another), and every record you publish is derived from it:
`-verification-token` prints the `_porch-challenge` TXT records for a name and
each domain above it, and any one of them proves the name. The record is read
from the zone's own servers, reached from the root over TCP port 53, so it
counts as soon as they serve it and no resolver on this machine is asked. The
web check also takes the file at `/.well-known/porch-challenge`, as the
service does.

An address is refused, because no record can prove one; so is a single label
such as `intranet`. A host on a private address is checked with
`-allow-private` and named by a domain proven in public DNS. The secret is
yours: another user on the machine has their own, and proving a domain to them
proves nothing to you.

On a server running the service, use the command line that runs beside it
instead (*The command line, on the server*, below): it has the service's
secret, so the record the page asked for is the only one there is.

The exit status is the worst verdict found — `0` strong, `1` weak, `2`
insecure, `3` the scan could not be completed — so it gates a pipeline without
anything having to parse the output.

### Four checks

`-check` selects which one runs, and the default is the one that has always
run. A default that quietly started running a second check would change the
exit status of a pipeline nobody touched.

```sh
./porch-scan example.com                 # the transport and its certificates
./porch-scan -check web example.com      # how the site is reached over HTTP
./porch-scan -check mail example.com     # what its DNS says about its mail
./porch-scan -check dns example.com      # how the domain itself is served
```

The DNS check connects to nothing at all: it asks the resolver for what the
domain publishes about itself — its addresses, its name servers and their
addresses, the record at the top of its zone, and the two ends of its DNSSEC
chain — and grades the few things a standard requires. Its own digest of the
zone's keys is compared with the one the parent holds, so a key rotated
without the registrar being told is found before a validating resolver finds
it for you.

### If the Issuance line says "not checked"

That row is the CAA record set: which authorities the domain allows to issue a
certificate for it. Reading it needs a resolver, and the resolver is this
machine's own — read from `/etc/resolv.conf` on unix, assembled from the
registry on Windows. Every one the machine has configured is tried in order,
because the second is there for exactly the case where the first does not
answer.

If it still says *not checked*, name one:

```sh
./porch-scan -resolver 192.168.1.1:53 example.com
```

Any resolver you would ordinarily use. There is deliberately no default: a
public resolver chosen by this program would quietly decide who learns which
names you are looking at, and that is your decision rather than ours.

The web check answers what a TLS report cannot: whether the site is *also*
served in the clear, whether the plaintext address sends a visitor to the
secure one, and whether anything tells a browser to come back over TLS. A host
can negotiate TLS 1.3 with an immaculate certificate and still hand every
visitor's first request to whoever is on the path.

It sends **one `GET` of `/`** over each scheme, reads the headers, closes the
body unread, and follows only the addresses a `Location` header names. It
never requests a path of its own choosing. `docs/invariants.md` N7 has the
whole discipline.

The four rule sets are separate and never comparable with each other:
`porch-tls-v7` grades a handshake, `porch-web-v3` grades an HTTP response,
`porch-mail-v3` grades what a domain's DNS says about its mail, and
`porch-dns-v2` grades how the domain itself is served — its name servers and
its DNSSEC chain. `-version` prints them all, and every report names the one
that produced it.

```sh
./porch-scan -check web -limits          # what a header check cannot establish
```

## The service

```sh
./porchd -listen 127.0.0.1:8080
```

Loopback by default, so an accidental start is not immediately public.
`porchd -h` lists every limit and its default.

**Over plain HTTP it answers only to an address or to `localhost`.** Open it as
`http://127.0.0.1:8080` or `http://localhost:8080`; a name such as
`http://scanner.corp:8080` is refused. The reason is the loopback copy with no
password: it trusts whoever reaches it as its operator, and a page on another
site can point its own name at your machine and call the service through your
browser, as the same origin, reading every answer. The name that page sends is
the one thing it cannot change, so a name is refused. Over HTTPS the
certificate settles it and any name you serve it under is answered.

The service takes `-resolver` too, for the lookups it makes itself — CAA, the
mail records and the proof-of-control challenge — and for the same reason as
above. It has to be an address and a port, not a name:

```sh
./porchd -listen 127.0.0.1:8080 -resolver 192.168.1.1:53
```

The addresses a scan connects to are still resolved by the machine.

Where the mail check asks each exchanger on port 25, it introduces itself with
EHLO. Unless told otherwise that name is this machine's fully qualified host
name or, failing that, its address — behind NAT, a private one — and the
exchanger's operator reads it. `-helo` sets it instead, on the service as on
the command line, and a name that could not be sent stops the service at start
rather than being quietly replaced by the machine's own:

```sh
./porchd -listen 127.0.0.1:8080 -helo scanner.example.com
```

Some providers refuse an EHLO that names no real host. A name that resolves to
the address the scan leaves from is the one least likely to be turned away.

**Your own exchangers are also asked whether they relay.** An exchanger inside
the domain being checked — `mail.example.com` under `example.com` — is asked
whether it forwards mail for a domain it does not serve, which is what an open
relay does and what gets a domain's mail refused everywhere once somebody
finds it. It is three lines that cannot deliver anything: an empty sender, a
recipient at a name RFC 2606 reserves so that it cannot exist, and a reset
before any message. An exchanger run by a provider — `aspmx` anything — is
never asked, because a relay probe in somebody else's logs reads as a spam
probe and the address it came from is the one that gets listed. There is no
flag that widens this.

---

## In a container

The image has **no base system**: no package manager, no shell, no libc.
There is nothing in it to update and nothing in it to take. It is the
release's two Linux binaries and nothing else, built for `amd64` and `arm64`
by `internal/ociimage` rather than by Docker, so that it comes out byte for
byte the same wherever it is built. The release workflow publishes it to
`ghcr.io/denyfirst/porch`, the maintainer rebuilds it and signs only when the
digest matches, and the release's `docker-compose.yml` names it **by that
digest**. A registry cannot answer a digest with any other bytes, and Docker
refuses them if it tries, so the only file a server needs to check is the
compose file.

### On a server, step by step

1. Get the compose file and the signed list that covers it, and check them.
   On the server, in a directory of its own. Nothing is built there, so the
   server needs Docker and nothing else: no Go, no source, no binaries.

   ```sh
   mkdir -p porch && cd porch
   for f in docker-compose.yml SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/latest/download/${f}"; done
   curl -fsSL https://raw.githubusercontent.com/denyfirst/porch/main/.allowed_signers -o allowed_signers
   ssh-keygen -Y verify -f allowed_signers -I releases@denyfirst.dev -n file -s SHA256SUMS.sig < SHA256SUMS && sha256sum --ignore-missing -c SHA256SUMS
   ```

   The last line has to print `Good "file" signature for
   releases@denyfirst.dev with ED25519 key SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y` and
   `docker-compose.yml: OK`. Anything else is a stop. The key file comes from
   the repository, and the Porch page on denyfirst.dev prints the same
   fingerprint from a server GitHub does not run: a key changed on GitHub
   alone prints one that does not match. [`docs/verify.md`](verify.md) says
   what each part proves, and why the key comes from the repository rather
   than from the release.

   Building the image yourself instead: the `Dockerfile` in the repository
   builds the same contents from binaries you built, as *Get a binary* above
   says. Its digest will not be the release's — a Docker build stamps times —
   so name it in the compose file in place of the `ghcr.io` line, with
   `pull_policy: never`.

2. Make the data directory for the user the container runs as, and start it.
   There is no shell in the image to make the directory from inside:

   ```sh
   mkdir -p porch-data && sudo chown 65534:65534 porch-data
   docker compose up -d
   docker compose logs
   ```

   Docker pulls the image the compose file names, anonymously, from
   `ghcr.io`. If this machine has signed in to `ghcr.io` with `docker login`,
   the pull is made as that account, and GitHub learns which account installed
   it; `docker logout ghcr.io` first if that matters.

   The first start writes a verification secret to `porch-data/secret` and
   says so. Keep that file: it is what every domain's record is derived from,
   and a new one means every domain publishing its record again.

   It also prints this installation's password, once, in the log. The program
   writes it nowhere else, but Docker keeps the log until the container is
   recreated, which is one reason to change the password straight away.

3. Open it. The example publishes the service on the server's own loopback,
   so nothing is reachable from outside. From your computer:

   ```sh
   ssh -L 8080:127.0.0.1:8080 you@your-server
   ```

   and open `http://localhost:8080`.

4. Sign in with the password from the log, then change it under **This
   installation**. Everything the installation serves, pages and API alike,
   is behind it.

5. Check a name. The first time, the page shows a TXT record to add at your
   DNS provider — `_porch-challenge.<domain>` and its value — and a button to
   check again once it is published. After that the checks run, and they run
   for every name under that domain without asking again, for as long as the
   record is there. Delete the record and the domain is refused again.

### Upgrading

Step 1 again, in the same directory, and then `docker compose up -d`. The
data directory stays, so does the password, and so does every record you
published. Docker pulls the new digest and replaces the container.

An installation from v0.25.1 or before built its image on the server. Once the
new compose file is in place, the binaries, `Dockerfile` and
`Dockerfile.dockerignore` in its directory can go, and what its old builds
left in Docker's cache should too:

```sh
docker image rm porch
sudo docker builder prune -a -f
```

The first removes the image those versions built, and the second what the
builds left in Docker's cache. Before v0.25.1 that cache could hold a copy of
`porch-data`, the secret and the sealed password with it, because the build
was sent the whole directory.

### Removing it

In the installation's directory:

```sh
docker compose down --rmi all
cd .. && sudo rm -rf porch
```

The first stops the container and removes it with the image it ran. The
second deletes the directory, and with it `porch-data`: the verification
secret, the sealed password and every report the installation kept. Nothing
else on the server holds any of them. `sudo`, because the data directory
belongs to the user the container ran as.

Then delete the `_porch-challenge` TXT record at your DNS provider. With the
secret gone it proves nothing to anybody, but it stays public, and it tells
whoever looks that the domain was checked with Porch.

The command line run on its own, outside the container, keeps its secret in
the user configuration directory: `~/.config/porch` on Linux,
`~/Library/Application Support/porch` on macOS and `%AppData%\porch` on
Windows. Delete that directory and the binary.

### The command line, on the server

The image carries `porch-scan` beside the service, and the compose file runs
it with this installation's secret. The record that proves a domain to the
page proves it here, and nothing else proves anything:

```sh
docker compose run --rm scan example.com
docker compose run --rm scan -check mail example.com
```

It checks, prints and exits, and its exit status is the worst verdict, so a
job on the server can gate on it. It runs in the same sandbox as the service —
no capability, nothing writable — and sees the data directory read-only: it
reads the secret and can change nothing there, not the secret, not the
password, not a kept report. Start the service once first, because the first
start is what makes the secret. A domain not proven to this installation is
refused with the record to publish, which is the record the page shows.

### Where the record goes at your provider

Every provider asks for the type, `TXT`; the name; and the value, pasted as it
is. Most add your domain to the name themselves, so type only the part before
it — for `_porch-challenge.www.example.com` in the zone `example.com`, that is
`_porch-challenge.www`. If the record reads back with your domain on it twice,
type the shorter form.

| Provider | The name goes in |
|---|---|
| Cloudflare | Name |
| Amazon Route 53 | Record name, with the value inside double quotes |
| Google Cloud DNS | DNS name |
| Azure DNS | Name |
| GoDaddy | Name |
| Namecheap | Host |
| Hetzner | Name |
| DigitalOcean | Hostname |
| A zone file | The whole name with a final dot, the value inside double quotes, then a reload |

The same table is beside the record in the console and on the Domains page.
It is help with a form and nothing else. The record is read from whichever
servers the zone names, reached from the root, whoever runs them; pinning the
check to a provider picked from a list would prove less, because control of
the zone is what is being proven and a zone moved to another provider is still
its owner's. A provider missing from the table works exactly as well.

### Proof of control is on, and has to be

A container listens beyond loopback by construction, and `porchd` refuses to
do that while scanning whatever it is given: it will not start without
`-verification-secret-file`. The image and the compose file both turn proof on.
A password is the same: beyond loopback `porchd` wants `-access-file`, and the
image and the compose file give it. Neither can be turned off — `-open` and
`-without-password` did that until 2026-09-29, and an installation started with
either is now told they were removed. Nothing checks a name nobody has
proven: `porch-scan` asks for the same record, and on this server it asks
with this installation's secret.

**Why showing the record is safe.** The value is derived from this
installation's secret and the one domain. It proves something only once it is
published in that domain's DNS, which only whoever runs the domain can do.
Copied to another domain it is the wrong value, because that domain's value is
different; copied into another installation it is the wrong value, because
that installation's secret is different. Somebody who sees your record in
public DNS learns nothing that lets them scan anything with your installation
or theirs.

**What it does not prove** is who owns the addresses a name points at. Whoever
runs a zone can point a name at anything. That is DNS, not this record, and it
is bounded by the rest of this page: private and reserved addresses are
refused, each host has a budget, and a scan sends what a browser or a mail
server would.

**It is asked every time.** Nothing remembers that a domain was proven: every
check asks the zone's own servers again, so taking the record out ends the
proof as soon as those servers stop serving it — no resolver's cache stands in
between. A lookup that fails is not taken as proof, and the check is refused
with a sentence saying the record could not be looked up.

**Starting over.** Every record is derived from the secret in
`porch-data/secret`. Delete it and restart, and a new one is made: every
record published so far stops proving anything, and each domain has to publish
its new value, which Domains shows.

**Where the record is read.** From the zone's own servers, not from a
resolver. porchd walks from the root servers, whose addresses it carries, down
to the servers that hold the domain, and asks them; a resolver on this machine,
or the one `-resolver` names, is not asked for the record at all, so a resolver
that lies cannot prove a domain. The walk leaves over TCP port 53 to name
servers anywhere on the internet: a firewall that allows the server only its
own resolver refuses every proof, with a sentence saying the record could not
be looked up.

**Signed or not.** Domains says whether the resolver reported the record
DNSSEC-signed. That is the resolver's word, not porch's own check, and it is
worth what the resolver is worth: from a validating resolver on this machine, a
great deal; from one across the internet over plain DNS, no more than the
record itself, because whoever could forge one could forge the other. With a
resolver you trust, `-verification-requires-dnssec` accepts only signed
records, and no challenge file. A domain whose zone is not signed can then
not be proven at all.

**What proof buys you, beyond being allowed to scan.** Two questions are only
asked about an estate an installation has been shown control of, because both
say a name out loud to somebody else:

- **The transparency logs are searched**, with no switch to turn on. Every
  certificate for your names is already published to anybody who looks, so the
  search discloses nothing new about the domain — what it discloses is that
  somebody is looking, and with proof of control that somebody is you. It finds
  certificates for your names that are valid today and are not the one your
  server presented, which is the only way a scan can show a certificate
  somebody else obtained.
- **`-ask-responder` asks each certificate's own authority whether it has been
  revoked.** Off by default, and refused without a verification secret: the
  question tells that authority which certificate is being looked at, from this
  address and when. For your own estate that is a disclosure you may find worth
  making, and a revoked certificate is the most serious thing a scan can find.
  Without it the report says revocation was not checked, rather than implying it
  passed.

### One password, and what it seals

The compose file starts the service with `-access-file /data/access`, and
nothing it serves is reachable without signing in: not the pages, not the API,
not the history. There is one password, for whoever runs the installation.

**The password is never written down.** `porch-data/access` holds a random key,
sealed with AES-256-GCM under a key derived from the password with
PBKDF2-SHA256 at 600,000 iterations. Opening the seal is the password check.
What the installation keeps is encrypted under that key, so a copy of the disk,
or of a backup, holds nothing readable without the password.

**Every check is kept, and can be deleted.** Behind the password each report is
kept whole in `porch-data/history`, one file per report under a random name,
sealed with that key. A report is kept as it was drawn, so it carries the
name checked and the time it was measured; the list shows only the date.
**History** lists them, opens any of them as it was drawn, and deletes one for good. At most a thousand that
the password opens are kept, the oldest dropped first. A file in the history it
does not open — kept under an earlier password, or damaged — is never dropped
by that bound; History says how many there are and how much space they take.

A report opened from History is set beside the one kept before it for the same
check against the same host: the findings, by rule, that are in one and not the
other, and the two verdicts. The verdicts are compared only when both were
graded under the same rule set, since a verdict from one means nothing under
another; and no finding is compared when either report measured nothing,
because a finding that was not looked for has not gone away. The earlier report
is read when you open the later one, through the same sign-in, and nothing about
the comparison is kept.

**The domains you add are kept too**, in `porch-data/domains.sealed`, sealed the
same way: the names and the date each was added. Whether each is proven is not
kept. **Domains** asks DNS again every time it opens, so a record taken out of a
zone reads as unproven straight away.

**So a lost password cannot be recovered**, by anyone. Move
`porch-data/access` aside — to `porch-data/access.lost`, say — and restart: a
new password is printed and a new key made. Before it is made, the history and
the domain list kept under the old key are moved, not deleted, to
`porch-data/retired-<date>/`, and the log says where. The new password starts
with an empty history and an empty list of domains. What was moved opens only
with the old access file and its password: if the password comes back to you,
stop the service, put `access.lost` back as `access` and the contents of the
retired folder back in `porch-data`, and start it again. Otherwise delete the
folder once you are sure nobody needs it; porchd never does.

**A session is a cookie** that no script can read and no other site can send,
and it ends when you sign out, after twelve hours, or when the service
restarts. Changing the password ends every other session. Guessing is slowed
per address and one guess is checked at a time. A password is taken only over HTTPS
or through the SSH tunnel to `localhost`; sent in plain HTTP to any other
address it is refused before it is read.

### A public address, with a certificate

`porchd` reads a certificate from disk and reloads it when it is renewed. With
one from Let's Encrypt for `scan.example.com`:

```yaml
    command:
      - "-listen"
      - "0.0.0.0:8443"
      - "-verification-secret-file"
      - "/data/secret"
      - "-access-file"
      - "/data/access"
      - "-tls-cert"
      - "/certs/live/scan.example.com/fullchain.pem"
      - "-tls-key"
      - "/certs/live/scan.example.com/privkey.pem"
    ports:
      - "443:8443"
    volumes:
      - /etc/ssl/certs:/etc/ssl/certs:ro
      - ./porch-data:/data
      - /etc/letsencrypt:/certs:ro
```

A `command` replaces the one in the compose file, it is not added to it, so
every argument has to be there: drop `-access-file` and the password goes, and
`porchd` then refuses to start on a public address, because it will not serve
anyone beyond loopback without a password.

The key has to be readable by user 65534. Nothing listens on port 80 — see
`docs/invariants.md`, P5 — so obtain the certificate with a DNS challenge, or
with `certbot certonly --standalone` while this service is stopped.

### The trust store comes from your machine

`docker-compose.yml` mounts `/etc/ssl/certs` read-only into the container and
points `SSL_CERT_DIR` at it.

This is not a convenience. Every verdict about a certificate chain is a
verdict *against some trust store*, and a report should reflect yours rather
than one baked in by whoever built an image. The standing limits already say
that a scan consults one trust store; this is where you choose which.

**An empty store does not fail — it reports every certificate as untrusted.**
The chains still verify, they verify to nothing, and every report says the
scanned server does not reach a trusted root: a finding about your container
printed as a finding about somebody else's server. So the service
refuses to start when it cannot find a store, rather than producing
confident nonsense.

### What the compose file takes away

`read_only: true`, `no-new-privileges:true`, `cap_drop: ALL`, and an
unprivileged user. The container binds a port above 1024 and the host
publishes it, so nothing inside needs the capability to bind a privileged port.
The data directory is the only writable path.

---

## What is yours now

The scan leaves your machine and your address is in the logs of whatever you
point it at. That is the arrangement working as intended, and it is also a
responsibility that used to be ours.

Scan what you own, what you administer, or what you have permission to scan.
This tool sends nothing malformed and nothing a browser or a mail server would
not send — standard client hellos, one `GET` of `/` over each scheme, the
`/.well-known` files a check exists to read, and on port 25 a greeting that
never becomes a message — but a scan is still a connection somebody else pays
for, and thirteen to fifty of them is still thirteen to fifty.

The licence is AGPL-3.0. Run a modified version and offer it to others, and
the modifications have to be available to them. That is the point of the
licence for a tool whose value rests on being checkable.

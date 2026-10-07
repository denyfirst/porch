# Running it yourself

Porch runs on your machine, from your address. The public site at
[porch.denyfirst.dev](https://porch.denyfirst.dev) is a demonstration that
scans only hosts this project owns; this page is the tool.

Nothing here is sent to this project. There is no account, no telemetry and no
update check: *we don't have the data to begin with*.

---

## On a server, with Docker

The server needs Docker and nothing else: no Go, no source, no binaries. The
image has no base system — no shell, no package manager, no libc — only the
release's two Linux binaries, built byte for byte the same wherever they are
built. The release's `docker-compose.yml` names the image **by digest**, so
the compose file is the only thing a server has to check.

1. Get the compose file and the signed list that covers it, and check them:

   ```sh
   mkdir -p porch && cd porch
   for f in docker-compose.yml SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/latest/download/${f}"; done
   echo 'releases@denyfirst.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR' > allowed_signers
   ssh-keygen -Y verify -f allowed_signers -I releases@denyfirst.dev -n file -s SHA256SUMS.sig < SHA256SUMS && sha256sum --ignore-missing -c SHA256SUMS || { rm -f docker-compose.yml; echo 'STOP: docker-compose.yml did not verify and was removed'; }
   ```

   It has to print `Good "file" signature for releases@denyfirst.dev with
   ED25519 key SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y` and
   `docker-compose.yml: OK`. Otherwise it prints `STOP` and removes the
   compose file, so the next step has nothing to start.

   The key is written out rather than fetched: a key fetched from GitHub comes
   from the same place as the release, and whoever could replace one could
   replace the other. [`verify.md`](verify.md) says what each part proves.

2. Make the data directory for the user the container runs as, and start it.
   The image has no shell to do this from inside:

   ```sh
   mkdir -p porch-data && sudo chown 65534:65534 porch-data
   docker compose up -d
   docker compose logs
   ```

   The pull from `ghcr.io` is anonymous unless this machine ran `docker login`
   there; then GitHub learns which account installed it. `docker logout
   ghcr.io` first if that matters.

   The first start writes the verification secret to `porch-data/secret`.
   Keep it: every domain's record is derived from it. It also prints the
   installation's password once, in the log. Docker keeps that log until the
   container is recreated, so change the password straight away.

3. Open it. The compose file publishes the service on the server's own
   loopback only. From your computer:

   ```sh
   ssh -L 8080:127.0.0.1:8080 you@your-server
   ```

   and open `http://localhost:8080`.

4. Sign in with the password from the log and change it under **This
   installation**. Every page and the API are behind it.

5. Add a domain. The page shows a TXT record, `_porch-challenge.<domain>`, to
   publish at your DNS provider. Once it is there, every name under that
   domain can be checked. Delete the record and the domain is refused again.

### Where the record goes at your provider

Type `TXT`, the name, and the value pasted as it is. Most providers add your
domain to the name, so type only the part before it: for
`_porch-challenge.www.example.com` in `example.com`, that is
`_porch-challenge.www`.

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

A provider missing from the table works exactly as well: the record is read
from whichever servers the zone names.

### Upgrading

Step 1 again in the same directory, then `docker compose up -d`. The data
directory, the password and every published record stay.

An installation from v0.25.1 or before built its image on the server, and the
build cache could hold a copy of `porch-data`. Remove both:

```sh
docker image rm porch
sudo docker builder prune -a -f
```

### Removing it

In the installation's directory:

```sh
docker compose down --rmi all
cd .. && sudo rm -rf porch
```

That removes the container, the image and `porch-data`: the secret, the sealed
password and every kept report. Nothing else on the server holds them.

Then delete the `_porch-challenge` TXT record. It proves nothing once the
secret is gone, but it stays public and says the domain was checked with
Porch.

### A public address, with a certificate

`porchd` reads a certificate from disk and reloads it when it is renewed:

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

A `command` replaces the compose file's, so every argument has to be there.
Without `-access-file` there is no password, and `porchd` refuses to start on
a public address. The key has to be readable by user 65534. Nothing listens on
port 80, so get the certificate with a DNS challenge, or with `certbot certonly
--standalone` while the service is stopped.

---

## Proof of control

A scanner anyone can reach and point anywhere is an **open scanner**, and it
is *your* address in every scanned host's logs. So `porchd` will not start
without `-verification-secret-file`, on loopback or anywhere else, and no flag
turns that off. The compose file sets it. `porchd -version` says which you
have:

```
scans only domains it has been shown control of
```

- **The record is safe to show.** Its value is derived from this
  installation's secret and the one domain. Copied to another domain or
  another installation it is the wrong value.
- **It is asked every time.** Nothing remembers a proof. Remove the record and
  the next check is refused. A lookup that fails is never taken as proof.
- **It is read from the zone's own servers**, walked from the root over TCP
  port 53, not from a resolver. A resolver that lies cannot prove a domain. A
  firewall that allows the server only its own resolver refuses every proof.
- **Signed only.** With a validating resolver you trust,
  `-verification-requires-dnssec` accepts only DNSSEC-signed records.
- **Starting over.** Delete `porch-data/secret` and restart. Every record
  published so far stops proving anything.
- **What it does not prove** is who owns the addresses a name points at.
  Private and reserved addresses are refused, and each host has a budget.

Two checks run only for proven domains, because both tell somebody else what
is being looked at: the certificate transparency search, which finds
certificates for your names that your server did not present, and
`-ask-responder`, off by default, which asks each certificate's authority
whether it was revoked.

---

## The password, and what it seals

There is one password, for whoever runs the installation.

- **It is never written down.** `porch-data/access` holds a random key sealed
  with AES-256-GCM under PBKDF2-SHA256 at 600,000 iterations. Everything the
  installation keeps is encrypted under that key, so a copy of the disk holds
  nothing readable without the password.
- **History** keeps each report whole in `porch-data/history`, one sealed file
  per report under a random name, at most a thousand, oldest dropped first.
  Any report can be deleted for good. Opening one sets it beside the previous
  report for the same check and host.
- **Domains** are kept in `porch-data/domains.sealed`: the names and the date
  each was added. Whether each is proven is asked again every time.
- **A lost password cannot be recovered**, by anyone. Move
  `porch-data/access` aside and restart: a new password is printed, and the
  old history and domain list are moved to `porch-data/retired-<date>/`, never
  deleted. They open only with the old access file and its password.
- **A session** is a cookie no script can read and no other site can send. It
  ends on sign-out, after twelve hours, or on restart; changing the password
  ends every other session. Guesses are slowed per address. A password sent in
  plain HTTP to anything but `localhost` is refused before it is read.

---

## The container

`docker-compose.yml` runs the service with `read_only: true`,
`no-new-privileges:true`, `cap_drop: ALL` and user `65534:65534`. The data
directory is the only writable path.

**The trust store is yours.** The compose file mounts `/etc/ssl/certs`
read-only, because every verdict on a certificate chain is a verdict against
some trust store. An empty store does not fail: it reports every certificate
as untrusted, a fault of this machine printed as a fault of somebody else's
server. So the service refuses to start when it finds none.

To build the image yourself, the `Dockerfile` builds the same contents from
binaries you built. Its digest will differ, so name it in the compose file in
place of the `ghcr.io` line, with `pull_policy: never`.

---

## Network

- **Plain HTTP answers only to an address or `localhost`**, so a page on
  another site cannot point its own name at your machine and call the service
  through your browser. Over HTTPS any name is answered.
- **`-resolver 192.168.1.1:53`** names the resolver for CAA, the mail records
  and the DNSSEC bit `-verification-requires-dnssec` asks for. There is no
  default public resolver: which one learns the names you look at is your
  decision.
- **`-helo scanner.example.com`** sets the name the mail check sends on port
  25. Otherwise it is this machine's host name or address, and the
  exchanger's operator reads it.
- **Port 25 is blocked by many cloud providers.** The mail report then says the
  exchangers could not be reached from here, after eight seconds an address.
  If you open it, open it only for the account the service runs as.
- **Your own exchangers are asked whether they relay** — three commands that
  cannot deliver anything, to a recipient at a name that cannot exist. An
  exchanger run by a provider is never asked.

---

## The command line

On a server running the service, use the copy inside the container. It has the
installation's secret, so the same record proves a domain to both, and it sees
the data directory read-only:

```sh
docker compose run --rm scan example.com
docker compose run --rm scan -check mail example.com
```

Anywhere else, download `porch-scan` for your system with the list and its
signature, check them as [`verify.md`](verify.md) says, then make it runnable:

```sh
V=$(basename "$(curl -fsSLo /dev/null -w '%{url_effective}' https://github.com/denyfirst/porch/releases/latest)")
OS=$(uname -s | tr '[:upper:]' '[:lower:]'); A=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
for f in "porch-scan_${V}_${OS}_${A}" SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/download/${V}/${f}"; done
mv "porch-scan_${V}_${OS}_${A}" porch-scan && chmod +x porch-scan
```

Or build it from source. `go.mod` has no `require` block, so nothing is
fetched beyond the standard library:

```sh
git clone https://github.com/denyfirst/porch
cd porch
go build -o . ./cmd/porch-scan ./cmd/porchd
```

Then:

```sh
./porch-scan -verification-token example.com   # the TXT record to publish, once
./porch-scan example.com                        # TLS and certificates
./porch-scan -check web example.com
./porch-scan -check mail example.com
./porch-scan -check dns example.com
```

Its secret is made on the first run under your configuration directory:
`~/.config/porch`, `~/Library/Application Support/porch` or `%AppData%\porch`.
Addresses and single labels are refused, because no record can prove them; a
host on a private address is checked with `-allow-private` under a proven
domain. The exit status is the worst verdict: `0` strong, `1` weak, `2`
insecure, `3` not completed. `-limits` prints what a check cannot establish.

### Keeping results

Nothing is kept unless you say where:

```sh
porch-scan -results-dir /var/lib/porch/results example.com
porch-scan -results-dir /var/lib/porch/results -history example.com
```

A kept result holds only what the report carries: the date, the check, the
rule set, the verdict and the rules raised. `-history` marks where the rule
set changed, so a stricter rule is not mistaken for a changed server.
`-results-keep N` keeps the newest N per target; there is no retention period
of ours.

The plain store is **never served over HTTP**: a browsable list of an estate's
weaknesses is worth attacking. `porch-scan -history` reads it on the machine
and connects to nothing. `porchd` takes the same flags for a loopback service
with no password; behind a password, **History** is the store, and
`-results-dir` is refused because it would keep a second copy in the clear.

---

## What is yours now

Your address is in the logs of whatever you scan. Scan what you own, what you
administer, or what you have permission to scan. Porch sends nothing malformed
and nothing a browser or a mail server would not send, but every connection is
one somebody else pays for.

The licence is AGPL-3.0: run a modified version for others, and they are owed
its source.

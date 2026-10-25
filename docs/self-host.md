# Running it yourself

Porch runs on your machine, from your address. The public site at
[porch.denyfirst.dev](https://porch.denyfirst.dev) is a demonstration that
scans only hosts this project owns; this page is the tool.

Nothing here is sent to this project. There is no account, no telemetry,
nothing that reports back: *we don't have the data to begin with*. The one thing a copy asks about
itself, whether a newer signed release exists, it asks GitHub, and only when
you tell it to ([Upgrading](#upgrading)).

---

## On a server, with Docker

The server needs Docker and nothing else: no Go, no source, no binaries. The
image has no base system — no shell, no package manager, no libc — only the
release's two Linux binaries, built byte for byte the same wherever they are
built. The release's `docker-compose.yml` names the image **by digest**, so
the compose file is the only thing a server has to check.

1. Install Docker. On Debian 13, from Debian's own packages: the engine, the
   `docker` command and Compose, updated with the rest of the system:

   ```sh
   sudo apt-get update
   sudo apt-get install -y docker.io docker-cli docker-compose
   sudo docker compose version
   ```

   The last line has to print a version. `docker-cli` is named because
   `docker.io` holds only the engine, and a system set not to install
   recommended packages, as many cloud images are, otherwise has a running
   engine and no `docker` command (seen on a cloud provider's Debian 13
   image on 2026-10-20). On another system, follow
   [Docker's guide](https://docs.docker.com/engine/install/).

   Every `docker` command in this guide runs with `sudo`. Without it the
   socket refuses (`permission denied while trying to connect to the Docker
   daemon socket`), and the other way past that, adding yourself to the
   `docker` group, is root without a password: anyone with your login could
   start a container that mounts `/`.

2. Get the compose file and the signed list that covers it, and check them.
   Set `V` to the release to install: the one
   [porch.denyfirst.dev](https://porch.denyfirst.dev) names, whose page shows
   these lines with it filled in, or the newest on the releases page.

   ```sh
   V=vX.Y.Z
   mkdir -p porch && cd porch
   for f in docker-compose.yml SHA256SUMS SHA256SUMS.sig; do curl -fsSLO "https://github.com/denyfirst/porch/releases/download/${V}/${f}"; done
   echo 'releases@denyfirst.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR' > allowed_signers
   ssh-keygen -Y verify -f allowed_signers -I releases@denyfirst.dev -n file -s SHA256SUMS.sig < SHA256SUMS && grep -qF "_${V}_" SHA256SUMS && sha256sum --ignore-missing -c SHA256SUMS || { rm -f docker-compose.yml; echo 'STOP: docker-compose.yml did not verify and was removed'; }
   rm -f allowed_signers SHA256SUMS SHA256SUMS.sig
   ```

   It has to print `Good "file" signature for releases@denyfirst.dev with
   ED25519 key SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y` and
   `docker-compose.yml: OK`. Otherwise it prints `STOP` and removes the
   compose file, so the next step has nothing to start. The last line
   removes the key and the signed list, which only the check needs.

   The key is written out rather than fetched: a key fetched from GitHub comes
   from the same place as the release, and whoever could replace one could
   replace the other. The release is named rather than taken from GitHub's
   *latest* for the same reason: a signature says who made a release, not
   that it is the newest, so a redirect moved to an older release would pass
   it. The `grep` checks that the signed list is `V`'s.
   [`verify.md`](verify.md) says what each part proves.

3. Make the data directory for the user the container runs as, and start it.
   The image has no shell to do this from inside:

   ```sh
   mkdir -p porch-data && sudo chown 65534:65534 porch-data
   sudo docker compose up -d
   sudo docker compose logs porch 2>&1 | grep -A2 "password is"
   ```

   The pull from `ghcr.io` is anonymous unless root on this machine ran
   `sudo docker login` there; then GitHub learns which account installed it.
   `sudo docker logout ghcr.io` first if that matters.

   The first start writes the verification secret to `porch-data/secret`.
   Keep it: every domain's record is derived from it. It also prints the
   installation's password once, in the log. Docker keeps that log until the
   container is recreated, so change the password straight away.

   The password is on standard error, which Docker keeps apart from standard
   output: without `2>&1`, `grep` sees nothing and the whole log goes past it
   to the screen. If the last line prints nothing, the service is still
   starting; run it again a moment later.

4. Open it. The compose file publishes the service on the server's own
   loopback only. From your computer:

   ```sh
   ssh -L 8080:127.0.0.1:8080 you@your-server
   ```

   and open `http://localhost:8080`.

   A server whose SSH refuses forwarding (`AllowTcpForwarding no`) answers
   `administratively prohibited`. Allow this one address and nothing else, in
   a file read before the one that forbids it, since the first value read is
   the one used:

   ```sh
   printf 'AllowTcpForwarding local\nPermitOpen 127.0.0.1:8080\n' | sudo tee /etc/ssh/sshd_config.d/00-0-porch.conf
   sudo sshd -t && sudo systemctl reload ssh
   ```

5. Sign in with the password from the log and change it under **This
   installation**. Every page and the API are behind it.

6. Add a domain. The page shows a TXT record, `_porch-challenge.<domain>`, to
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

Under **This installation**, **Check now** asks GitHub for the latest
release's signed list and checks it with the release key built into this
copy; the daily check, off until you turn it on, asks once a day. The request
carries no cookie, no version and nothing about the installation; GitHub sees
the server's address. The choice is kept in `porch-data/updates.json`, not
sealed: it says only whether the daily check is on. Nothing is installed:
when a newer release verifies, **New check** shows the commands for it, with
a Copy button.

A signature says who made the list, not that it is the newest. Whoever could
change what GitHub serves could keep a newer release from being shown, but not
make an older one install: the commands check that the signed list is the
named release's.

By hand, with `V` set to the release you are moving to:

```sh
V=vX.Y.Z
test -f docker-compose.yml && mkdir -p "update-${V}"
for f in docker-compose.yml SHA256SUMS SHA256SUMS.sig; do curl -fsSL -o "update-${V}/${f}" "https://github.com/denyfirst/porch/releases/download/${V}/${f}"; done
echo 'releases@denyfirst.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR' > "update-${V}/allowed_signers"
if ssh-keygen -Y verify -f "update-${V}/allowed_signers" -I releases@denyfirst.dev -n file -s "update-${V}/SHA256SUMS.sig" < "update-${V}/SHA256SUMS" && grep -qF "_${V}_" "update-${V}/SHA256SUMS" && (cd "update-${V}" && sha256sum --ignore-missing -c SHA256SUMS); then cp "update-${V}/docker-compose.yml" docker-compose.yml && sudo docker compose up -d && rm -r "update-${V}" && sudo docker image prune -a -f --filter label=org.opencontainers.image.source=https://github.com/denyfirst/porch; else rm -rf "update-${V}"; echo "STOP: ${V} did not verify; its download was removed and nothing was changed"; fi
```

Run in the installation's directory, they fetch into a folder of their own,
check the signature, that the signed list is `V`'s and not an older release's,
and the compose file's digest. Only then is the new compose file put in place
of the one in use. Each line is safe on its own: a pasted line runs whether or
not the one before it worked, and nothing beside the compose file in use is
written until the last one has verified. If anything does not verify, the last
line removes the folder and prints `STOP`. The data directory, the password
and every published record stay.

Once the new version has started, the same line removes the folder and every
Porch image no container uses: the one just replaced, and any an interrupted
update left. It picks them by the label every Porch image carries, so no other
image on the server is touched. Nothing else is kept either: to go back, run
the same lines with `V` set to the release you left, which checks it the same
way and pulls its image again.

Earlier versions of these lines kept `docker-compose.yml.before-V` and the
`update-V` folder, and the install kept `allowed_signers`, `SHA256SUMS` and
`SHA256SUMS.sig`. None of them is needed. In the installation's directory:

```sh
test -f docker-compose.yml && rm -rf update-v* docker-compose.yml.before-v* allowed_signers SHA256SUMS SHA256SUMS.sig
sudo docker image prune -a -f --filter label=org.opencontainers.image.source=https://github.com/denyfirst/porch
```

Changes of your own belong in `docker-compose.override.yml`, which Docker
Compose reads beside the compose file and an update leaves alone.

An installation from v0.25.1 or before built its image on the server, and the
build cache could hold a copy of `porch-data`. Remove both:

```sh
sudo docker image rm porch
sudo docker builder prune -a -f
```

### Removing it

In the installation's directory:

```sh
sudo docker compose down --rmi all
cd .. && sudo rm -rf porch
```

That removes the container, the image and `porch-data`: the secret, the sealed
password and every kept report. Nothing else on the server holds them.

Then delete the `_porch-challenge` TXT record. It proves nothing once the
secret is gone, but it stays public and says the domain was checked with
Porch.

### A public address, with a certificate

`porchd` reads a certificate from disk and reloads it when it is renewed. Put
this in `docker-compose.override.yml`, beside the compose file:

```yaml
services:
  porch:
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
      - /etc/letsencrypt:/certs:ro
```

A `command` there replaces the compose file's, so every argument has to be
there. Ports and volumes are added to the compose file's: its loopback port
stays published, with nothing listening behind it. Without `-access-file`
there is no password, and `porchd` refuses to start, on loopback or anywhere
else. The key has to be readable by user 65534. Nothing listens on port 80,
so get the certificate with a DNS challenge, or with `certbot certonly
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

Two questions go to the source that holds the answer, directly from your
server, and only about proven domains: Cert Spotter, for certificates logged
for your names that your server did not present, and each certificate's own
authority, for whether it was revoked. Cert Spotter answers about ten
requests an hour per address without a key; set `CERTSPOTTER_TOKEN` to an
SSLMate API key for more.

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
- **The container reaches the internet through the host's forward chain.** A
  firewall that drops forwarded traffic, as hardening guides set it
  (`policy drop` on an nftables `forward` chain), drops everything the
  container sends: every proof says the record could not be looked up, and
  every check waits and fails. Accept what leaves Docker's bridges and the
  replies to it, in that chain:

  ```
  iifname "br-*" accept
  oifname "br-*" ct state established,related accept
  ```

  `br-*` is the network Compose makes for the installation; `docker0` is the
  one plain `docker run` uses.

---

## The command line

On a server running the service, use the copy inside the container. It has the
installation's secret, so the same record proves a domain to both, and it sees
the data directory read-only:

```sh
sudo docker compose run --rm scan example.com
sudo docker compose run --rm scan -check mail example.com
```

Anywhere else, download `porch-scan` for your system with the list and its
signature, check them as [`verify.md`](verify.md) says, then make it runnable.
`V` is the release, named as in step 2 rather than read from GitHub's
*latest*; the file's name carries it, so a list for another release does not
cover it:

```sh
V=vX.Y.Z
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

### Nothing is kept

`porch-scan` writes nothing to disk but its own verification secret. A
report is printed, or written as JSON with `-json`, and kept only if you keep
it. `porchd` keeps every report under **History**, sealed under its
password; nothing this project writes keeps a result in the clear.

---

## What is yours now

Your address is in the logs of whatever you scan. Scan what you own, what you
administer, or what you have permission to scan. Porch sends nothing malformed
and nothing a browser or a mail server would not send, but every connection is
one somebody else pays for.

The licence is AGPL-3.0: run a modified version for others, and they are owed
its source.

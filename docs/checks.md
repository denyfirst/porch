# How the checks work

Porch has four graded checks and one inventory. Each reads what a server already
shows to anyone. Nothing is guessed, no exploit is sent, no login is tried, and
private, loopback, link-local and reserved addresses are refused.

Where an answer is held somewhere else, Porch asks the source that holds it,
directly from the machine it runs on, and only about a domain it was shown
control of: Cert Spotter for logged certificates, a certificate's own
authority for revocation. No service in between learns what is checked.

## Reading a report

- **Findings** are graded. Each names a rule and the standard behind it. The
  worst finding sets the verdict.
- **Observed** facts are not graded, because no standard sets a line.
- **Not established** is what this scan could not settle. It never means
  "nothing was there".
- A host that answered nothing is *ungraded*, not *weak*. *Strong* needs a
  complete scan.
- **Limits** below are true of every scan of a check, so reports link here
  instead of repeating them.

## TLS

**Sends:** TLS handshakes at each version and for each accepted cipher suite,
each closed when the handshake ends. No HTTP request.

**Connects to:** twenty-one ports of services that should never face the
internet — FTP, Telnet, NetBIOS, SMB, rsync, Microsoft SQL Server, Oracle,
NFS, the Docker API, etcd, MySQL, Remote Desktop, PostgreSQL, VNC, CouchDB,
WinRM, Redis, Elasticsearch, the Kubernetes kubelet, Memcached and MongoDB — at
the first IPv4 and first IPv6 address the handshakes reached. One connection
each, closed as soon as it opens; nothing is sent. Each port is listed in the
report with what came back. One that refuses or stays silent is listed as *no
answer from here*, never as closed: a firewall that drops is doing its job,
and a network between here and the host may have dropped it instead. A host's
own intrusion detection may notice twenty-one connections in two seconds.

**Also asks:** the certificate authority for its revocation list, and its
responder whether this certificate was revoked where the certificate names
one; and Cert Spotter which certificates are logged for the name. Set
`CERTSPOTTER_TOKEN` to an SSLMate API key for more than the anonymous rate.

**Grades:** protocol versions, cipher suites, the certificate and its chain,
revocation, and certificate transparency.

### Obsolete suites

Go cannot offer these, so each family is offered in a hello Porch writes
itself. *Refused* means the server accepted none of them.

- **Export-grade:** 40- and 56-bit keys from 1990s export rules (FREAK, Logjam).
- **NULL, no encryption:** the server is authenticated, nothing is encrypted.
- **Finite-field DHE:** classic Diffie-Hellman; RFC 10015 prohibits these in
  TLS 1.2.
- **Anonymous, no certificate:** anyone on the path can pose as the server.
- **Downgrade signal:** a hello with `TLS_FALLBACK_SCSV` (RFC 7507).
  *Honoured* means the server refused to be pushed to an older version.

SSL 3.0 is asked the same way and shown in the version table.

### Limits

- **Only the first hop was measured.** The endpoint that answered was measured; behind a CDN, proxy or load balancer, the server behind it is not visible. A name with several addresses was measured at one, with one handshake to each other.
- **Only the suites this client can offer were offered.** Suites were enumerated among those Go's TLS stack implements. SSL 3.0 and the export-grade, NULL, finite-field DHE and anonymous families were asked with a hand-written hello, which shows whether any suite of a family is accepted, not every one. SSLv2 is not covered, and a refused version may only share no suite with this client.
- **TLS 1.3 suites are asked from the registry.** Each TLS 1.3 suite in the IANA registry is asked with a hand-written hello, because Go cannot choose among them; suites outside the registry are not asked. Where that hello is answered differently, only the negotiated suite is listed and the report says so.
- **The verdict rests on one root store.** Trust is checked against one root store, and the verdict rests on that store: on Linux and other unix systems, the store of the machine that ran this scan; on Windows and macOS, the copy of Microsoft's or Apple's store this build carries. Mozilla, Chrome, Microsoft and Apple are compared from dated copies of their stores: which roots they include and Mozilla's distrust dates are applied, and other conditions are named, not applied.
- **Revocation is what the authority publishes.** A stapled response is read, the authority's revocation list is fetched, and its responder is asked where the certificate names one. A certificate that names neither a list nor a responder cannot be checked for revocation by anyone.
- **Transparency receipts are checked against one browser's log list.** Receipts are checked against Chrome's log list as of the date in the report, and counted as Chrome's policy counts them. A receipt from a log the list does not name cannot be checked, and other browsers count by rules of their own.

## Web

Every request carries the user agent `porch/1 (+https://porch.denyfirst.dev/privacy#stopping)`.

**Sends:**

- `GET /` over HTTPS and over HTTP, following up to five redirects your server
  names. A redirect to another scheme, or to a host the copy may not reach, is
  not followed.
- The last page reached over HTTPS once more, with
  `Origin: https://porch-cors-check.invalid` and nothing else changed, to see
  whether it trusts a site it cannot know (CORS). Its answer is not followed and
  its body is not read.
- `GET /.well-known/security.txt` (RFC 9116).
- `GET /` on the other form of the name, with or without `www.`. Its answer is
  not followed.
- One TLS handshake to the site's IPv6 address, if it publishes one, with no
  request over it.

Ports 80 and 443 only. No other path or name is tried.

**Also asks for** eleven files that should never be served, each one GET over
HTTPS with no redirect followed and at most 4 KB read: `/.git/HEAD`,
`/.git/config`, `/.svn/wc.db`, `/.env`, `/.aws/credentials`,
`/wp-config.php.bak`, `/.htpasswd`, `/server-status`, `/phpinfo.php`,
`/actuator/env` and `/.DS_Store`. A file counts as served only if what comes
back is what that file looks like, so a site that answers every path with a
page of its own has nothing exposed. What a file held is never kept: the
report names the path and what it is.

**Also asks:** hstspreload.org whether the host is on the HSTS preload list
that Chrome keeps and other browsers build from. Reported, not graded.

**Reads the page** only of a domain proven to the copy asking (or for its own
operator), once, up to one megabyte. From it, only whether a content policy is
declared and the host names of anything loaded over HTTP or from another site
are kept. Only graded headers are kept. Cookies are kept by name and
attributes, never by value. From `Server`, `X-Powered-By`, `X-AspNet-Version`
and `X-AspNetMvc-Version`, only the software's name and whether a version came
with it are kept, never the version; reported, not graded.

**Grades:** how the site is reached over HTTPS, redirects, HSTS, cookies, mixed
content, a few headers, a page that trusts any origin with credentials, and any
of the files above that is served. The HSTS policy graded is the one from the last
HTTPS hop.

### Limits

- **Only the root was asked.** Only the root of the site was requested. Another page may send different headers and load different things.
- **No browser ran here.** Nothing was executed: what a page loads was read from its markup, so anything a script fetches later was not seen, and whether a declared policy is enforced only a browser can tell.
- **One answer, from one machine, at one moment.** A name served by several machines can answer the next visitor differently. This is what one address said once.

## Mail

**Reads, through the resolver:** SPF and everything it includes, DMARC, MX,
MTA-STS, TLS-RPT, DANE for each mail server, and DKIM keys. A DKIM key lives at
`<selector>._domainkey`, and DNS cannot list what is under a name, so only the
selectors you name and those common providers document are read. Your selector
is the `s=` tag in the `DKIM-Signature` header of any mail you sent. Up to
sixteen. And whether each mail server (up to eight) has an IPv6 address, which
is reported and not graded.

**Connects to:** the MTA-STS policy file, if announced, and each mail server
(up to eight) on port 25, asked whether it offers STARTTLS. A server that
negotiates TLS 1.2 or 1.3 is asked once more, in a second short conversation,
whether it still accepts TLS 1.1 or older: one hello offering nothing newer,
the first record of the answer read, no handshake completed. Only for a domain
proven to the copy asking, or where only its operator can use it. From each
greeting, only which mail server it names, from a fixed list, and whether a
version came with it are kept; the greeting itself is not.

**Grades** only what a standard calls an error: two SPF records, more than ten
SPF lookups, `+all`, two DMARC records, an unusable MTA-STS policy, and a mail
server still speaking TLS 1.0 or 1.1, which RFC 8996 retired (weak where it
also speaks TLS 1.2 or 1.3, because a sender refused there falls back to plain
text; insecure where it speaks nothing newer). `~all`, `p=none` and the choice
of MTA-STS or DANE are observed, not graded.

Many mail servers refuse an address with no reverse DNS name. Give yours one
and pass it with `-helo`. A blocked outbound port 25 is reported as such.

### Limits

- **No message was sent.** No message was sent: there is no DATA, so nothing is delivered or queued. An exchanger inside the domain is asked whether it would relay for a domain it does not serve, with an address that cannot exist (RFC 2606), and reset before any message; an exchanger run by somebody else is never asked. DANE is checked only against presented certificates, DNSSEC is the resolver's word, and DKIM is read only under the selectors given.

## DNS

**Reads, through the resolver:** `A`, `AAAA`, `CNAME`, `NS` and their
addresses, `SOA`, `TXT`, `DS` and `DNSKEY`. Whether the name and its name
servers have IPv6 addresses is said in one line, and not graded: RFC 3901 asks
only that a zone stay reachable over IPv4.

**Grades** only what stops a resolver: fewer than two name servers or all on
one network, a name server that resolves to nothing, a parent that hands out
different servers or stale glue, a broken DNSSEC chain, a signature at the
top of the zone that does not verify with the zone's own keys or has expired,
and an alias at the top of a zone. Serial, timers, the signing
algorithm and an open zone transfer are reported, not graded.

If the name is an alias whose target no longer exists, whoever claims the
target next can answer for your name. This is reported, not graded.

**Also asks:** the registry that holds the domain, over RDAP (RFC 9083), for
its registration: the registrar, when it runs out, and whether it is locked
against transfer. Which registry that is comes from IANA's list, read whole,
so IANA learns no domain. The registry is asked about the registered domain
first and a longer name only if it holds no shorter one. Reported, not graded.

**And asks** RIPEstat, run by RIPE NCC, whether the routes to the name's
addresses and its name servers' are signed with RPKI (RFC 6811): valid,
invalid, or not signed. Up to eight addresses. Reported, not graded: the
route is the hosting provider's to sign.

### Limits

- **Everything here came from one resolver.** Most answers came from this installation's resolver. Four questions go directly to name servers over TCP port 53: whether each answers for the zone, whether each allows a zone transfer, whether a server inside the domain (never a provider's) answers for other domains, and which servers a parent server hands out. The transfer is closed before any record is read. The DNSSEC chain is checked by comparing key digests with the parent's, and the signatures over the zone's keys and over the record at the top of the zone are verified here with those keys; signatures on other records are the resolver's word. Where the resolver fails those three questions, they are asked once more with checking disabled, so what is wrong can be said.

## Names

Lists the names under a domain and where each was found. Nothing is graded.

**Sources:** public certificates (Cert Spotter), the domain's MX, SPF and
NS records, and, if configured, a passive DNS register, the hosts' own
certificates, the reverse DNS of address ranges you name (up to a /20 or /116,
4,096 addresses in total), and names you already have (up to 1,000).

An inventory is made only for a domain proven to the copy asking.

It cannot show hosts with no public certificate, hosts behind a wildcard
certificate (unless a register was read), or hosts your DNS has no reason to
name.

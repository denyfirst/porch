# How the checks work

Porch has four graded checks and one inventory. Each reads what a server already
shows to anyone. Nothing is guessed, no exploit is sent, no login is tried, and
private, loopback, link-local and reserved addresses are refused.

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

**Also asks:** the certificate authority for its revocation list (it names no
certificate), and crt.sh for the certificates logged for the name (only for a
domain proven to the copy asking).

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

- **Only the first hop was measured.** The endpoint that answered was measured. Behind a CDN, proxy or load balancer, the link to the server behind it is not visible and may differ. A name with several addresses was measured at one of them; each other address gets one handshake.
- **Only the suites this client can offer were offered.** Suites were enumerated among those Go's TLS stack implements. SSL 3.0 and the export-grade, NULL, finite-field DHE and anonymous families were asked with a hand-written hello, which shows whether any suite of a family is accepted, not every one. SSLv2 and other suites are not covered. A version refused here may only share no suite with this client.
- **TLS 1.3 suites are asked from the registry.** Each TLS 1.3 suite in the IANA registry is asked with a hand-written hello, because Go cannot choose among them. Suites outside the registry are not asked. Where that hello is not answered like the scan's own handshake, only the negotiated suite is listed and the report says so.
- **The verdict rests on one root store.** Trust is checked against one root store, and the verdict rests on that store: on Linux and other unix systems, the store of the machine that ran this scan; on Windows and macOS, the copy of Microsoft's or Apple's store this build carries. What Mozilla, Chrome, Microsoft and Apple make of the chain comes from copies of their stores dated in the report. Only which roots they include, and Mozilla's distrust dates, are applied; other conditions are named, not applied.
- **No authority is asked about this certificate.** No certificate authority is asked about this certificate, because the question carries its serial number and tells the authority which certificate is being looked at. -ask-responder turns that on, only for a domain a service has been shown control of, and the report then says so. A response the server stapled is read, and a revocation list the certificate names is fetched, because one list names no single certificate. Without either, a trusted, in-date chain may still have been withdrawn.
- **Transparency receipts are checked against one browser's log list.** Receipts are checked against Chrome's log list as it stood on the date in the report. A receipt from a log the list does not name cannot be checked, and nothing here decides how many receipts a browser requires.

## Web

Every request carries the user agent `porch/1 (+https://porch.denyfirst.dev/privacy#stopping)`.

**Sends:**

- `GET /` over HTTPS and over HTTP, following up to five redirects your server
  names. A redirect to another scheme, or to a host the copy may not reach, is
  not followed.
- `GET /.well-known/security.txt` (RFC 9116).
- `GET /` on the other form of the name, with or without `www.`. Its answer is
  not followed.
- One TLS handshake to the site's IPv6 address, if it publishes one, with no
  request over it.

Ports 80 and 443 only. No other path or name is tried.

**Reads the page** only of a domain proven to the copy asking (or for its own
operator), once, up to one megabyte. From it, only whether a content policy is
declared and the host names of anything loaded over HTTP or from another site
are kept. Only graded headers are kept. Cookies are kept by name and
attributes, never by value.

**Grades:** how the site is reached over HTTPS, redirects, HSTS, cookies, mixed
content and a few headers. The HSTS policy graded is the one from the last
HTTPS hop.

### Limits

- **Only the root was asked.** Only the root of the site was requested. Another page may send different headers and load different things.
- **No browser ran here.** Nothing was executed. Where the page was read, what it loads was read from its markup, so anything a script fetches later was not seen. Whether a declared policy is enforced is visible only to a browser.
- **One answer, from one machine, at one moment.** A name served by several machines can answer the next visitor differently. This is what one address said once.

## Mail

**Reads, through the resolver:** SPF and everything it includes, DMARC, MX,
MTA-STS, TLS-RPT, DANE for each mail server, and DKIM keys. A DKIM key lives at
`<selector>._domainkey`, and DNS cannot list what is under a name, so only the
selectors you name and those common providers document are read. Your selector
is the `s=` tag in the `DKIM-Signature` header of any mail you sent. Up to
sixteen.

**Connects to:** the MTA-STS policy file, if announced, and each mail server
(up to eight) on port 25, asked only whether it offers STARTTLS. Only for a
domain proven to the copy asking, or where only its operator can use it.

**Grades** only what a standard calls an error: two SPF records, more than ten
SPF lookups, `+all`, two DMARC records, an unusable MTA-STS policy. `~all`,
`p=none` and the choice of MTA-STS or DANE are observed, not graded.

Many mail servers refuse an address with no reverse DNS name. Give yours one
and pass it with `-helo`. A blocked outbound port 25 is reported as such.

### Limits

- **No message was sent.** No message was sent: there is no DATA, so nothing is delivered or queued. An exchanger inside the domain is asked whether it would relay for a domain it does not serve, with an address that cannot exist (RFC 2606), and reset before any message; an exchanger run by somebody else is never asked. DANE is checked only against presented certificates, DNSSEC is the resolver's word, and DKIM is read only under the selectors given.

## DNS

**Reads, through the resolver:** `A`, `AAAA`, `CNAME`, `NS` and their
addresses, `SOA`, `TXT`, `DS` and `DNSKEY`.

**Grades** only what stops a resolver: fewer than two name servers or all on
one network, a name server that resolves to nothing, a parent that hands out
different servers or stale glue, a broken DNSSEC chain or an expired
signature, and an alias at the top of a zone. Serial, timers, the signing
algorithm and an open zone transfer are reported, not graded.

If the name is an alias whose target no longer exists, whoever claims the
target next can answer for your name. This is reported, not graded.

### Limits

- **Everything here came from one resolver.** Most answers came from this installation's resolver. Four questions go directly to name servers over TCP port 53: whether each answers for the zone, whether each allows a zone transfer, whether a server inside the domain (never a provider's) answers for other domains, and which servers a parent server hands out. The transfer is closed before any record is read. The DNSSEC chain is checked by comparing key digests with the parent's; whether every signature verifies is the resolver's word.

## Names

Lists the names under a domain and where each was found. Nothing is graded.

**Sources:** public certificates (crt.sh or SSLMate), the domain's MX, SPF and
NS records, and, if configured, a passive DNS register, the hosts' own
certificates, the reverse DNS of address ranges you name (up to a /20 or /116,
4,096 addresses in total), and names you already have (up to 1,000).

The monitor learns that somebody is looking at the domain, so an inventory is
made only for a domain proven to the copy asking.

It cannot show hosts with no public certificate, hosts behind a wildcard
certificate (unless a register was read), or hosts your DNS has no reason to
name.

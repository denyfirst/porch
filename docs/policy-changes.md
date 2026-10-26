# Rule set changes

Every verdict names the rule set that graded it. The ones in force are
`porch-tls-v9`, `porch-web-v6`, `porch-mail-v6` and `porch-dns-v5`. Reports
from two rule sets are not comparable: a server graded `strong` under one and
`weak` under the next may not have changed at all. This page says what moved,
so a pipeline can tell a configuration that got worse from a rule that got
stricter.

Rule identifiers are stable across releases. Track or suppress a finding by
its identifier, never by its wording.

Rule sets were named `denyfirst-…` until v0.16.0, when the tool was renamed
Porch. The numbers did not reset, and older sections keep the names they
shipped under, because those are the names in the reports.

Newest first.

---

## `porch-dns-v4` → `porch-dns-v5`

Released in v0.32.0, 2026-10.

- **A zone is not strong where a question that a graded rule reads went
  unanswered.** A server the zone names that was asked directly and did not
  answer, or a zone above it that did not answer, leaves the rules about
  servers that do not answer for the zone, that recurse, and about the parent
  handing out other servers silent, and silence is not passing. The report
  says which server did not answer and why; it said nothing.
- **Nor where a server's addresses could not be read.** The rules about a
  server that resolves to nothing and about servers on one network read them.
  `dns.name-servers-one-network` is no longer raised from a count that left a
  server out.
- **Nor is a zone strong where its registration was asked about and not
  read.** `dns.registration-expired` reads it, and it was strong when the
  registry timed out. A top-level domain whose registry publishes no RDAP
  service is different: no scan can ask it, so the report says so, names the
  registrar as where the date is, and the verdict is not withheld.
- A note that a zone transfer was not established is filed as not
  established. It was filed among what the scan measured.

---

## `porch-mail-v5` → `porch-mail-v6`

Released in v0.32.0, 2026-10.

- **Strong needs every record a graded rule reads.** A domain whose MTA-STS
  record could not be read, whose announced MTA-STS policy was not read, or
  whose DMARC reports go to an outside destination whose consent could not be
  read is not strong. The rules about each fall silent where nothing was read,
  and silence is not passing. The same reading v5 gave exchangers that were
  not measured.
- An MTA-STS or TLS-RPT record that could not be read is reported as not
  established. It was reported as absent.

---

## `porch-tls-v8` → `porch-tls-v9`

Released in v0.31.0, 2026-10.

- **Added `version.no-tls13`, weak.** The server accepts an older version and
  declined TLS 1.3 (RFC 9325, NIST SP 800-52 Rev. 2). A TLS 1.3 handshake that
  timed out or was reset is not a refusal: it is not graded, and the transport
  is then not strong, with a note saying why.
- **A server answering a TLS 1.3 hello in TLS 1.2 now reads as refusing TLS
  1.3.** That is how most servers without TLS 1.3 answer. It was reported as a
  version this build of Go did not offer.
- **Added `exposure.service-open`, weak.** One of the services on the exposure
  list (a database, remote desktop, a file share, an administration port)
  accepts a connection from the internet (CISA's performance goals, NIST SP
  800-41). One finding names every service that answered.
- An address where every port on the list accepts a connection is graded for
  none of them, and its services are not named. Something there completes
  every connection whatever is behind it, such as a SYN proxy or a tarpit, so
  which services answer is not established, and a note says so.
- **Strong needs a graded certificate.** A scan whose certificate was not
  graded is not strong.

---

## `porch-web-v5` → `porch-web-v6`

Released in v0.31.0, 2026-10.

- **Added `hsts.short-max-age`, weak.** The policy lasts less than six months
  (15768000 seconds), the minimum in Mozilla's web security guidelines. It used
  to be described and not graded, on the reading that no document sets a
  floor. A short `max-age` is still the right way to begin a rollout, and the
  finding says so.

---

## `porch-mail-v4` → `porch-mail-v5`

Released in v0.31.0, 2026-10.

- **Strong now needs something to grade.** A domain publishing no mail record
  at all, and one whose exchangers were never reached, both came back strong.
- **Added `mail.dmarc-absent`, weak.** No DMARC record covers the domain, so
  anyone can send in its name (RFC 7489, NIST SP 800-177 Rev. 1). A domain that
  sends no mail says so with `p=reject`, `v=spf1 -all` and a null MX (RFC 7505).
- **Added `mail.dmarc-not-enforcing`, weak.** The policy is `p=none`, the
  monitoring step, under which failing mail is delivered.
- **`mail.dmarc-no-policy` also fires for a `p=` naming no policy RFC 7489
  defines.** `p=rejet` came back strong.
- **DMARC is read up the tree, as receivers read it** (RFC 7489, 6.6.3). A
  name with no record of its own is covered by the nearest name above it that
  has one, under that record's `sp=` where it sets one and its `p=` where it
  does not. The walk stops before the top-level domain and asks at most five
  names. A lookup that failed stops the walk and is reported as not
  established, not as absent.
- **Added `mail.exchanger-no-starttls`, weak.** An exchanger that was reached
  offers no STARTTLS, so mail to it crosses the network unencrypted (RFC 3207,
  NIST SP 800-177 Rev. 1).
- **A domain whose exchangers were not all measured is not strong.** Examples:
  one not contacted, one beyond the eight asked, or one that offered STARTTLS
  and did not complete it.

---

## `porch-dns-v3` → `porch-dns-v4`

Released in v0.31.0, 2026-10.

- **A zone whose delegation could not be read is not strong.** Every rule
  about name servers fell silent, and silence read as passing. The same holds
  where signing could not be established, or where a signed zone's link or
  signatures could not be checked.
- **A delegation signer that could not be asked for no longer reads as an
  unsigned zone.** It is reported as not established.
- **Added `dns.unsigned`, weak.** The parent holds no delegation signer, so
  nothing lets a resolver tell the zone's answers from forged ones (RFC 9364,
  NIST SP 800-81-2). It used to be described as a choice.
- **Added `dns.registration-expired`, insecure.** The registry records the
  registration as ended. Once the grace periods end, anybody can register the
  name. A registration about to run out is still described and not graded,
  because automatic renewal does not show from outside.

---

## `porch-tls-v7` → `porch-tls-v8`

Released in v0.30.0, 2026-10.

- **`cert.validity-too-long` counts the last second.** A certificate's lifetime
  runs from `notBefore` through `notAfter` inclusive (RFC 5280, 4.1.2.5), as the
  Baseline Requirements count it. Before, the seconds were dropped, so a
  certificate issued one second past its limit read as exactly the limit and
  passed; it is now weak.
- The lifetime both faces print moves with it: a Let's Encrypt certificate,
  written as 90 days less a second, now reads 90 days rather than 89.

---

## `porch-web-v4` → `porch-web-v5`

Released in v0.29.0, 2026-10.

- **Added `headers.cors-trusts-any-origin`, insecure.** Asked from
  `https://porch-cors-check.invalid`, a name that cannot exist (RFC 6761), the
  page a visitor lands on named it back in `Access-Control-Allow-Origin` and
  allowed credentials. A browser then lets any site read that page with the
  visitor's cookies.
- It is asked in one more `GET` of that same page, with an `Origin` header and
  nothing else changed. The answer is not followed and its body is not read.
  The header values are compared exactly, as a browser compares them, and are
  not kept.
- **Reported, not graded:** the origin named back without credentials, which
  shares only what anyone can fetch.
- **Reported, not graded:** the software the response names in `Server`,
  `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version`, and whether a
  version came with it, with the setting that turns the version off. The
  version itself is not kept. The mail report says the same of each
  exchanger's greeting, from a fixed list of mail servers.

---

## `porch-mail-v3` → `porch-mail-v4`

Released in v0.27.1, 2026-10.

- **Added `mail.exchanger-only-legacy-tls`, insecure.** An exchanger offered
  nothing newer than TLS 1.1 to a client offering TLS 1.3 (RFC 8996).
- **Added `mail.exchanger-legacy-tls`, weak.** An exchanger that negotiates TLS
  1.2 or 1.3 still chose TLS 1.1 or older for a sender that offered nothing
  newer. Weak rather than insecure because a mail sender refused there falls
  back to plain text unless MTA-STS or DANE is enforced (RFC 7435).
- The second case is asked in a second, short conversation with each
  exchanger that negotiated TLS 1.2 or 1.3: greeting, EHLO, STARTTLS, one hello
  offering nothing newer than TLS 1.1, and the first record of the answer. No
  handshake is completed and the connection is closed there. An exchanger that
  closes without answering is reported as not established, not as refusing.
- **Reported, not graded:** whether each exchanger has an IPv6 address.

---

## `porch-dns-v2` → `porch-dns-v3`

Released in v0.27.1, 2026-10.

- **Added `dns.dnssec-signature-invalid`, insecure.** The parent's digest
  matches a key, but the signatures at the top of the zone do not hold when
  checked with the zone's own keys: the key the digest names does not sign the
  key set, or no key in the set signs the record at the top of the zone, or the
  signature is outside its validity period (RFC 4035 §5.3). Until now this was
  the resolver's word. A signature is found wanting only where its key was
  read and its algorithm is one Porch verifies; anything else is reported as
  not checked.
- Where the resolver fails the zone's own records, which is what a validating
  resolver does with a zone whose signatures do not hold, the top of the zone,
  the digest and the keys are asked for once more with checking disabled
  (RFC 4035 §3.2.2). Such a zone used to be reported as a name inside another
  zone, with nothing graded.
- **Reported, not graded:** whether the resolver rejected the zone, and why the
  signatures were not checked where they were not.

---

## `porch-web-v3` → `porch-web-v4`

Released in v0.27.1, 2026-10.

- **Added `web.exposed-source`, insecure.** A Git or Subversion repository is
  served from the web root, which hands over the site's code and history
  (CWE-527).
- **Added `web.exposed-secrets`, insecure.** A file of passwords or keys is
  served: an environment file, cloud credentials, a backup of WordPress's
  settings, a password file, or a Spring Boot application's settings
  (CWE-538).
- **Added `web.exposed-diagnostics`, weak.** Apache's status page or PHP's
  configuration page is served (CWE-497).
- **Added `web.exposed-listing`, weak.** A macOS folder index naming the files
  beside it is served (CWE-548).
- Each is asked for by one GET of a fixed path, and counts only if what comes
  back is what that file looks like; a site that answers every path with its
  own page has nothing exposed. What a file held is never kept.
- **Reported, not graded:** whether the host is on the HSTS preload list.

---

## `porch-mail-v2` → `porch-mail-v3`

Released in v0.24.0, 2026-09.

- **Added `mail.dmarc-reports-unauthorised`, weak.** The DMARC record sends
  reports to another domain that has not published the authorisation record
  RFC 7489 §7.1 requires, so every receiver discards them. A destination under
  the domain itself counts as inside it. Where the authorisation record could
  not be read, nothing is graded.
- **Narrowed `mail.open-relay`.** An exchanger whose name is a CNAME is no
  longer asked whether it relays, because an alias usually points at a
  provider's machine. It is still graded weak under
  `mail.exchanger-is-an-alias`.
- **Reported, not graded:** where DMARC reports go; which policies a void
  lookup came from; an `sp=` that asks less than `p=`; and, for a proven
  domain, the SPF, DMARC and TLS-RPT records as published.

---

## `porch-mail-v1` → `porch-mail-v2`

Released in v0.19.0, 2026-09.

- **Added `mail.exchanger-is-an-alias`, weak.** An MX target that is a CNAME,
  which RFC 2181 forbids. Senders disagree about it, so some mail arrives and
  some does not.
- **Added `mail.open-relay`, insecure.** An exchanger inside the domain accepts
  mail for a domain it does not serve (RFC 2505). It is asked with an empty
  sender, a recipient under `.invalid` and `RSET`. `DATA` is never sent.
  Exchangers run by a provider are never asked. An exchanger not asked, one
  that refused the empty sender, and one that ended early are reported as
  such and not graded.

---

## `porch-dns-v1` → `porch-dns-v2`

Released in v0.20.0, 2026-09.

- **Added `dns.signature-expired`, insecure.** The zone's DNSSEC signatures
  have run out (RFC 4035 §5.3.1), so every validating resolver fails it.
- **Added `dns.glue-does-not-match`, weak.** The parent hands out an address
  for an in-zone name server that the zone does not publish (RFC 1912 §2.3).
- **Reported, not graded:** when the signatures expire; whether the servers
  hold the same serial; whether anybody can transfer the zone.

---

## `porch-dns-v1` — a new rule set

Released in v0.19.0, 2026-09.

The fourth check: how a domain itself is served. No TLS, web or mail verdict
moved. Most facts come from the machine's own resolver. Name servers are asked
directly over TCP port 53, through the guard that refuses private addresses. A
zone transfer is asked for and never taken.

| rule | verdict | when |
|---|---|---|
| `dns.one-name-server` | weak | fewer than two name servers (RFC 1034, RFC 2182) |
| `dns.name-servers-one-network` | weak | every server in one network, judged by address prefix |
| `dns.name-server-without-address` | weak | a server the zone names resolves to nothing (RFC 1912) |
| `dns.name-server-not-authoritative` | weak | a delegated server does not answer for the zone (RFC 1912) |
| `dns.name-server-offers-recursion` | weak | a server inside the domain answers for other domains (RFC 5358) |
| `dns.parent-and-zone-disagree` | weak | the parent's server list differs from the zone's (RFC 1912) |
| `dns.name-server-is-an-alias` | weak | a delegated name is a CNAME (RFC 2181) |
| `dns.alias-at-zone-apex` | insecure | a CNAME at the top of the zone (RFC 1034, RFC 2181) |
| `dns.dnssec-no-keys` | insecure | the parent anchors DNSSEC and the zone publishes no matching key |
| `dns.dnssec-chain-broken` | insecure | no published key matches the parent's digest |
| `dns.dnssec-sha1-digest` | weak | the chain works over a SHA-1 digest (RFC 8624) |
| `dns.dnssec-retired-algorithm` | insecure | signed with an algorithm RFC 8624 says must not be used |
| `dns.dnssec-weak-algorithm` | weak | signed with an algorithm RFC 8624 no longer recommends |
| `dns.nsec3-iterations` | weak | NSEC3 hashes more than once (RFC 9276) |

The DS digest is computed here from the zone's keys, not taken from the
resolver's AD bit. **Reported, not graded:** serial format and timers, which
RFC 1912 only recommends; NSEC versus NSEC3; an alias whose target does not
exist.

---

## `porch-mail-v1` — a new rule set

Released in v0.16.0, 2026-09.

The third check: what a domain's DNS says about its mail. No TLS or web
verdict moved. The MTA-STS policy file and a short conversation with each
exchanger happen only where the command line runs them or the domain is
proven. No message is ever composed. An address may be given; the part before
the `@` is discarded before anything can see it.

| rule | verdict | when |
|---|---|---|
| `mail.spf-duplicate` | insecure | more than one SPF record (RFC 7208) |
| `mail.spf-lookup-limit` | insecure | the policy needs more than ten DNS lookups (RFC 7208) |
| `mail.spf-allows-everybody` | insecure | the policy ends in `+all` |
| `mail.spf-void-lookups` | weak | more than two lookups return nothing (RFC 7208) |
| `mail.dmarc-duplicate` | weak | more than one DMARC record (RFC 7489) |
| `mail.dmarc-no-policy` | weak | a DMARC record with no `p=` (RFC 7489) |
| `mail.dkim-weak-key` | weak | an RSA signing key below 1024 bits (RFC 8301) |
| `mail.mta-sts-policy-invalid` | weak | the policy file breaks RFC 8461 |
| `mail.mta-sts-uncovered-exchanger` | weak | an enforcing policy matches none of the exchangers |
| `mail.mta-sts-exchanger-fails-policy` | weak | an exchanger an enforcing policy covers has no STARTTLS or a certificate that fails |
| `mail.dane-exchanger-fails-binding` | weak | a validated DANE record does not hold for the exchanger's certificate (RFC 7672) |

The MTA-STS and DANE failures are weak rather than insecure because they fail
closed: mail stops rather than travelling unprotected.

**Reported, not graded:** no SPF record; `~all`, `?all` or no `all`; a lookup
count under ten; `p=none` and `pct=` below 100; no `rua=` and no TLS-RPT;
`ptr`; a null MX; MTA-STS and DANE presence; `testing` and `none` modes and
`max_age`; STARTTLS and certificates where no policy requires them. A domain
whose records could not be read is ungraded, not strong. DKIM keys are read
only under the selectors the operator names and the ones providers document,
and the report lists every selector it tried.

---

## `denyfirst-tls-v6` → `porch-tls-v7`

Released in v0.16.0, 2026-09.

Verdicts that can now appear where they could not before. In each case nothing
about the server changed; what it accepts became visible.

- **SSL 3.0, export and NULL suites are asked about**, with hand-written
  hellos. `version.ssl3`, `cipher.export` and `cipher.null` could not fire
  through Go's client. A server accepting any is now insecure.
- **Finite-field DHE and anonymous suites are asked about.** `cipher.ffdhe`
  and `cipher.anonymous` can now fire.
- **TLS 1.3 suites are asked one at a time**, so an integrity-only suite
  (RFC 9150) raises `cipher.no-encryption`. The answers are used only when the
  suite Go negotiated is confirmed among them.
- **Revocation lists are read.** One can raise `cert.revoked` after it is
  fetched from an address the certificate names, size-capped, verified against
  the issuer and found in date. A list that does not cover the certificate is
  "not checked". The demonstration never fetches one.
- **`porch-scan -ask-responder`**, off by default, asks the certificate's OCSP
  responder; a verified answer can raise `cert.revoked` or
  `cert.revocation-unknown`.
- **A scan whose suite list did not finish stays ungraded**, even beside a
  sound certificate.
- **On Windows and macOS, trust is decided by the carried copy of the
  platform's root store**, not by the platform verifier, which fetched
  missing intermediates outside the private-address guard.

**Reported, not graded:** what Mozilla, Chrome, Microsoft and Apple make of the
chain; transparency receipts, now verified offline against Google's signed log
list; whether a downgraded hello with `TLS_FALLBACK_SCSV` is refused; the same
leaf over a different intermediate.

---

## `denyfirst-web-v2` → `porch-web-v3`

Released in v0.16.0, 2026-09.

| rule | verdict | when |
|---|---|---|
| `cookie.no-secure-over-tls` | insecure | a cookie set over TLS without `Secure` is also sent in the clear |
| `cookie.host-prefix-broken` | weak | a `__Host-` cookie breaks the prefix, so browsers reject it |
| `cookie.secure-prefix-broken` | weak | a `__Secure-` cookie without `Secure`, so browsers reject it |
| `cookie.samesite-none-without-secure` | weak | `SameSite=None` without `Secure`, so browsers reject it |
| `headers.cors-wildcard-with-credentials` | weak | `Access-Control-Allow-Origin: *` with credentials, which browsers refuse |
| `content.form-posts-in-the-clear` | insecure | a form on a secure page posts to `http://` |
| `content.mixed-blocked` | weak | a secure page loads a script, stylesheet, frame or plugin over `http://` |

**The page itself is now read**, where the deployment reads pages: one GET of
the final response, up to one megabyte, streamed, and nothing kept but a few
booleans and host names. A `Content-Security-Policy` declared in markup is
now seen.

**Corrected readings:** an HSTS header that repeats a directive is
unparseable; only the graded host's own HSTS policy counts; a redirect not
followed is said rather than graded `reach.never-reaches-tls`; character
references, `<base>`, `srcset` and `formaction` are read as a browser reads
them.

**Reported, not graded:** missing `HttpOnly`, missing `SameSite`, a `Domain`
attribute; security headers not sent; images and media over `http://`; scripts
from elsewhere without `integrity`; forms posting to another origin over TLS.

---

## `denyfirst-web-v1` → `denyfirst-web-v2`

Released in v0.16.0, 2026-09, already superseded there by `porch-web-v3`. It
was tagged v0.15.1, which was never published.

- **A correctly reached site is `strong`, not `ungraded`.** v1 reported a sound
  redirect and a sound policy as an absence.
- **A host that answered nothing over TLS no longer raises `hsts.absent`.** It
  is said as not established.

---

## `denyfirst-web-v1` — a new rule set

Released in v0.15.0, 2026-09.

The second check: how a name answers on each scheme. No TLS verdict moved.

| rule | verdict | when |
|---|---|---|
| `reach.plaintext-served` | insecure | port 80 returns a page instead of redirecting |
| `reach.never-reaches-tls` | insecure | the redirects from port 80 end on plaintext |
| `reach.downgrades-to-plaintext` | insecure | the https address ends on an http one |
| `reach.plaintext-not-redirected` | weak | port 80 answers and does not send the visitor to TLS |
| `reach.redirect-via-plaintext` | weak | TLS is reached only after a second cleartext request |
| `hsts.absent` | weak | no `Strict-Transport-Security` on the secure response |
| `hsts.plaintext-only` | weak | the header is sent only where RFC 6797 has a browser ignore it |
| `hsts.unparseable` | weak | no `max-age` a browser can read |
| `hsts.disabled` | weak | `max-age=0` |
| `hsts.preload-ineffective` | weak | `preload` without the year and `includeSubDomains` the list requires |

**Not graded:** the length of `max-age`, a missing `includeSubDomains`, a
temporary redirect.

---

## `denyfirst-v6` → `denyfirst-tls-v6`

Released in v0.13.0, 2026-09. **No rule changed.** The name now carries the
check as well as the number, because a second check was coming.

---

## `denyfirst-v5` → `denyfirst-v6`

Released in v0.11.0, 2026-09. **The rest of the chain is graded**, not only
the leaf. A forged intermediate can issue for any name.

| rule | verdict | when |
|---|---|---|
| `chain.signature-sha1` | insecure | an issuer carries a SHA-1 signature |
| `chain.signature-md5` | insecure | an issuer carries an MD5 or MD2 signature |
| `chain.signature-algorithm-unrecognised` | weak | an issuer's signature algorithm is unknown |
| `chain.roca` | insecure | an issuer's RSA modulus carries the RSALib fingerprint |
| `chain.rsa-key-too-small` | insecure | an issuer's RSA key is below 2048 bits |
| `chain.ec-key-too-small` | insecure | an issuer's curve is below P-256 |
| `chain.key-algorithm-unrecognised` | weak | an issuer's key type cannot be sized |
| `chain.expired` | insecure | an issuer's validity has ended |
| `chain.not-yet-valid` | insecure | an issuer's validity has not begun |
| `chain.expiring-soon` | weak | an issuer expires within 30 days |
| `chain.critical-extension-unrecognised` | weak | an issuer marks an unknown extension critical |

New identifiers rather than widened `cert.` ones, so a filter on a leaf rule
does not start receiving findings about another certificate. Roots are not
graded: no client checks a root's own signature.

---

## `denyfirst-v4` → `denyfirst-v5`

Released in v0.8.0, 2026-09. Four rules on what a certificate says about
itself, all read from bytes the scan already had.

| rule | verdict | when |
|---|---|---|
| `cert.leaf-is-ca` | insecure | the served certificate says `cA:TRUE` |
| `cert.key-usage-cert-sign` | insecure | `keyCertSign` without `cA:TRUE` |
| `cert.no-digital-signature` | weak | key usage is listed and `digitalSignature` is not in it |
| `cert.critical-extension-unrecognised` | weak | a critical extension this checker does not recognise |

---

## `denyfirst-v3` → `denyfirst-v4`

Released in v0.4.0, 2026-08.

| rule | verdict | when |
|---|---|---|
| `cert.roca` | insecure | the RSA modulus carries the RSALib fingerprint (CVE-2017-15361) |
| `cert.no-server-auth` | insecure | extended key usage is listed and server authentication is not in it |
| `cert.wildcard-shape` | weak | a `*` anywhere but as the whole leftmost label (RFC 9525) |
| `cert.cn-not-in-san` | weak | the common name holds a hostname the SAN does not |
| `cert.serial-entropy` | weak | on a publicly trusted chain, a serial too small to hold 64 random bits |

**Reported, not graded:** an RSA exponent below 65537; how many names a
certificate covers; whether the server accepts X25519MLKEM768, which costs one
extra handshake where TLS 1.3 is spoken.

**API change:** `notes` became an array of `{"kind", "text"}`, and
`assurances` was replaced by `coverage`. Notes are grouped as Observed, Not
established for this host, and Limits of this method.

---

## `denyfirst-v2` → `denyfirst-v3`

Released in v0.3.0, 2026-08. **The stapled OCSP response is parsed and
verified**: it must describe this certificate by issuer and serial, be in
date, and be signed by the issuer or its delegated responder.

| rule | verdict | when |
|---|---|---|
| `cert.revoked` | insecure | a verified response says the certificate was withdrawn |
| `cert.revocation-unknown` | weak | a verified response says the authority does not know the serial |
| `cert.staple-unverifiable` | weak | stapled bytes establish nothing |

`cert.must-staple-not-stapled` now fires unless a response arrives and
verifies. A missing staple is still not graded.

---

## `denyfirst-v1` → `denyfirst-v2`

Released in v0.2.0, 2026-08.

| rule | was | is | why |
|---|---|---|---|
| `cipher.ffdhe` | no rule | insecure | RFC 10015 moved finite-field DHE in TLS 1.2 to MUST NOT |
| `cipher.no-forward-secrecy` | no rule | insecure | static RSA, DH and ECDH key exchange |
| `cipher.no-encryption` | no rule | insecure | RFC 9150 integrity-only suites |
| `cipher.unrecognised` | strong | weak | an unreadable answer is not a pass |
| `cert.signature-algorithm-unrecognised` | strong | weak | the same, for a signature algorithm |
| `cert.key-algorithm-unrecognised` | strong | weak | the same, for a key algorithm |

A cipher enumeration that stopped early is **ungraded**, not strong. An
expired and untrusted chain is reported not trusted. A CAA search that stopped
early is not established either way. A certificate served only at an older
version is graded too, and the worse one sets the verdict. RFC 8446 is cited
as RFC 9846.

---

## What did not change

Grading is worst case: one insecure option makes a configuration insecure,
because an attacker chooses what to negotiate. Refusing an obsolete version is
not graded. Issuance policy (CAA) is reported and not graded.

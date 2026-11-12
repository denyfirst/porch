"use strict";

/*
  What each part of a report means, for a reader who does not already know.

  A report keeps its own words: every label is the one the terminal prints
  (R16), and every value is what was measured. Under a label, app.js adds the
  short line `about` here gives, and beside it a button that opens `what`,
  `good`, `how` and the source in a panel. Nothing here changes a value, and
  nothing here grades: a row the rules leave ungraded is explained, not judged.

  Keyed by the label exactly as drawn. "Section › Label" is the same label
  where one section means something else by it, and wins there.

  The object below is JSON, read as such by explain_test.go, which fails when
  a report draws a label or a section title that has no entry here. A new row
  is therefore explained when it is added, and not later by someone who
  noticed. Sources are the standards bodies only, linked and never fetched:
  nothing is asked of any other site to show this.
*/
const EXPLAIN = Object.freeze({
  "Protocol versions": {
    "what": "Which versions of TLS, the protocol that encrypts HTTPS, the server agrees to speak. Each version is tried on its own.",
    "good": "TLS 1.3 and TLS 1.2 only. TLS 1.1, TLS 1.0 and SSL 3.0 are retired.",
    "src": ["RFC 8996", "https://www.rfc-editor.org/rfc/rfc8996"]
  },
  "Cipher suites accepted": {
    "what": "The combinations of key exchange, encryption and integrity check the server accepted, one handshake each.",
    "good": "AEAD suites only, such as AES-GCM and ChaCha20-Poly1305, with forward secrecy.",
    "src": ["RFC 9325", "https://www.rfc-editor.org/rfc/rfc9325"]
  },
  "Obsolete suites, asked for directly": {
    "what": "Old families of suites, such as export, RC4, 3DES and NULL, each offered in a hello of its own to see whether the server still takes any of them.",
    "good": "Every family refused.",
    "src": ["RFC 9325", "https://www.rfc-editor.org/rfc/rfc9325"]
  },
  "Each address, asked on its own": {
    "what": "Every address the name points to, asked separately. Behind one name there can be several servers, and each can be set up differently.",
    "good": "Every address gives the same answer."
  },
  "Certificate": {
    "what": "The certificate the server presented: whom it was issued to, who issued it, how long it lasts, and whether browsers trust it.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Coverage": {
    "about": "How much of the picture this scan reached",
    "what": "What this scan was able to measure. The verdict rests only on what was reached, and anything not reached is said, never assumed to be fine."
  },
  "Subject": {
    "about": "Whom the certificate was issued to",
    "what": "The name in the certificate's subject field. Browsers match the host against the Names below, not against this field.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Issuer": {
    "about": "The authority that signed it",
    "what": "The certificate authority, or its intermediate, that signed this certificate.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Validation": {
    "about": "What the issuer checked before issuing",
    "what": "Domain validation (DV) checks only that the requester controls the name. Organisation (OV) and extended (EV) validation also check who the requester is.",
    "good": "DV is what most sites use, and it is enough for encryption.",
    "src": ["CA/Browser Forum Baseline Requirements", "https://cabforum.org/working-groups/server/baseline-requirements/"]
  },
  "Valid": {
    "about": "When it may be used, and the days left",
    "what": "The first and last day the certificate is valid. After the last day every browser refuses it.",
    "good": "Renewed automatically, well before it runs out."
  },
  "Lifetime": {
    "about": "Its total length, against the current limit",
    "what": "How long the certificate was issued for, compared with the longest the CA/Browser Forum allowed on the day it was issued. The limit is being shortened in steps.",
    "good": "90 days or less, renewed automatically.",
    "src": ["CA/Browser Forum Baseline Requirements", "https://cabforum.org/working-groups/server/baseline-requirements/"]
  },
  "Key": {
    "about": "The type and size of its key",
    "what": "The algorithm and size of the public key in the certificate, which the server proves it holds in every handshake.",
    "good": "ECDSA P-256, or RSA of 2048 bits or more.",
    "src": ["RFC 9325", "https://www.rfc-editor.org/rfc/rfc9325"]
  },
  "Signature": {
    "about": "How the issuer signed it",
    "what": "The algorithm the issuer used to sign this certificate.",
    "good": "SHA-256 or stronger, such as ecdsa-with-SHA256 or sha256WithRSAEncryption.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Names": {
    "about": "The names it is valid for",
    "what": "The DNS names the certificate covers, its subject alternative names. A browser accepts it only for a host in this list.",
    "src": ["RFC 9525", "https://www.rfc-editor.org/rfc/rfc9525"]
  },
  "Certificate › Addresses": {
    "about": "IP addresses it is valid for",
    "what": "IP addresses written into the certificate. Public certificates for websites rarely carry any.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Name match": {
    "about": "Whether its names cover this host",
    "what": "Whether one of the certificate's names matches the host that was checked. Without a match, browsers show an error.",
    "src": ["RFC 9525", "https://www.rfc-editor.org/rfc/rfc9525"]
  },
  "Chain": {
    "about": "The certificates up to a trusted root",
    "what": "The certificates the server sent, from this one up toward a root certificate, and whether they lead to a root that browsers trust.",
    "good": "Trusted, with every intermediate sent by the server.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "Stores": {
    "about": "What the four browser root stores make of it",
    "what": "Whether the chain ends at a root that Mozilla, Chrome, Microsoft and Apple trust, from copies of their lists that Porch carries."
  },
  "Revocation": {
    "about": "How a withdrawn certificate would be noticed",
    "what": "Whether the certificate names a way to check that it has not been revoked, a CRL or OCSP, and whether the server stapled a fresh OCSP answer to the handshake.",
    "good": "A CRL address, or a stapled OCSP answer where the issuer still runs OCSP.",
    "src": ["RFC 6960", "https://www.rfc-editor.org/rfc/rfc6960"]
  },
  "Issuance": {
    "about": "Who may issue certificates for this name",
    "what": "CAA records in DNS name the certificate authorities allowed to issue for the domain. Without them, any public authority may.",
    "good": "A CAA record naming the authority you use.",
    "how": "example.com.  CAA 0 issue \"letsencrypt.org\"",
    "src": ["RFC 8659", "https://www.rfc-editor.org/rfc/rfc8659"]
  },
  "Transparency": {
    "about": "Whether it was publicly logged",
    "what": "Certificate Transparency is a set of public logs that every trusted certificate has to appear in. The certificate carries signed proof of being logged.",
    "src": ["RFC 6962", "https://www.rfc-editor.org/rfc/rfc6962"]
  },
  "Logged": {
    "about": "Other certificates the logs hold for this name",
    "what": "Certificates for this name that the public logs hold, other than the one presented. One you did not ask for is worth looking into.",
    "src": ["RFC 6962", "https://www.rfc-editor.org/rfc/rfc6962"]
  },
  "Serial": {
    "about": "Its number, unique for its issuer",
    "what": "The serial number the issuer gave this certificate. With the issuer, it identifies the certificate in revocation lists and in the logs.",
    "src": ["RFC 5280", "https://www.rfc-editor.org/rfc/rfc5280"]
  },
  "SHA-256": {
    "about": "Fingerprint of this exact certificate",
    "what": "A hash of the whole certificate. Two certificates with the same fingerprint are the same certificate."
  },
  "Cipher order": {
    "about": "Who picks the cipher: server or visitor",
    "what": "Whether the server applies its own order of preference when it chooses a suite, or follows the order the visitor's browser offered.",
    "good": "Either is fine when every accepted suite is strong."
  },
  "Key exchange": {
    "about": "How the session key was agreed",
    "what": "The group used to agree the key that encrypts the session, and whether a post-quantum hybrid such as X25519MLKEM768 was offered and accepted.",
    "src": ["RFC 8446", "https://www.rfc-editor.org/rfc/rfc8446"]
  },
  "Exposed services": {
    "about": "Other ports answering on this host",
    "what": "Ports of services that are usually kept private, such as databases, remote desktop and admin panels, asked on this host.",
    "good": "None open to the internet unless they have to be public."
  },

  "What the site sends": {
    "what": "Headers the site's response carries. Most ask browsers to follow a rule. No document requires them, so Porch reports them and does not grade them.",
    "src": ["RFC 9110", "https://www.rfc-editor.org/rfc/rfc9110"]
  },
  "Served over": {
    "about": "Which version of HTTP carried the page",
    "what": "The version of HTTP the server chose for this visit, agreed during the TLS handshake.",
    "good": "HTTP/2 or HTTP/3. HTTP/1.1 also works.",
    "src": ["RFC 9113", "https://www.rfc-editor.org/rfc/rfc9113"]
  },
  "Software named": {
    "about": "What the server says it runs",
    "what": "The software the response names in headers such as Server and X-Powered-By. Porch shows the name and never the version.",
    "good": "No version number, which only helps someone look up its flaws."
  },
  "Strict-Transport-Security": {
    "about": "Tells browsers to always use HTTPS here",
    "what": "HSTS: browsers that have seen it use HTTPS for this site for the time it gives, and never start on plain HTTP.",
    "good": "max-age of a year or more, sent only over HTTPS.",
    "how": "add_header Strict-Transport-Security \"max-age=31536000\" always;",
    "src": ["RFC 6797", "https://www.rfc-editor.org/rfc/rfc6797"]
  },
  "X-Content-Type-Options": {
    "about": "Stops browsers guessing what a file is",
    "what": "With nosniff, a browser uses a file only as the type the server declared, so a text file is never run as a script.",
    "good": "nosniff",
    "how": "add_header X-Content-Type-Options nosniff always;",
    "src": ["Fetch Standard", "https://fetch.spec.whatwg.org/#x-content-type-options-header"]
  },
  "X-Frame-Options": {
    "about": "Whether other sites may show it in a frame",
    "what": "Stops other sites from placing this page inside theirs, which is how clickjacking works.",
    "good": "DENY, or SAMEORIGIN when the site frames its own pages.",
    "how": "add_header X-Frame-Options SAMEORIGIN always;",
    "src": ["RFC 7034", "https://www.rfc-editor.org/rfc/rfc7034"]
  },
  "Referrer-Policy": {
    "about": "How much of this address other sites see",
    "what": "Decides how much of this page's address is passed on when a visitor follows a link to another site.",
    "good": "strict-origin-when-cross-origin, or no-referrer for more privacy.",
    "how": "add_header Referrer-Policy strict-origin-when-cross-origin always;",
    "src": ["W3C Referrer Policy", "https://www.w3.org/TR/referrer-policy/"]
  },
  "Permissions-Policy": {
    "about": "Browser features the page turns off",
    "what": "Turns off features the site does not use, such as the camera or location, so a script embedded in the page cannot ask for them.",
    "good": "Every feature the site does not use set to ().",
    "how": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
    "src": ["W3C Permissions Policy", "https://www.w3.org/TR/permissions-policy-1/"]
  },
  "Cross-Origin-Opener-Policy": {
    "about": "Separates it from windows other sites open",
    "what": "Keeps this page in a browsing context of its own, so a window another site opened cannot reach it.",
    "good": "same-origin",
    "how": "add_header Cross-Origin-Opener-Policy same-origin always;",
    "src": ["HTML Standard", "https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies"]
  },
  "Cross-Origin-Embedder-Policy": {
    "about": "What it may load from other sites",
    "what": "Lets the page load content from other sites only where that content agrees to it. With COOP it makes the page cross-origin isolated.",
    "good": "Sent only where the site needs isolation. Not sending it is common.",
    "src": ["HTML Standard", "https://html.spec.whatwg.org/multipage/browsers.html#coep"]
  },
  "Cross-Origin-Resource-Policy": {
    "about": "Which sites may load its files",
    "what": "Says which sites may load this response, an image or a script, into their own pages.",
    "good": "same-origin or same-site for anything private.",
    "src": ["Fetch Standard", "https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header"]
  },
  "Access-Control-Allow-Origin": {
    "about": "Which other sites may read its answers",
    "what": "CORS: lets the sites it names read this site's responses from inside a visitor's browser.",
    "good": "Not sent, unless an API needs it, and never * on anything private.",
    "src": ["Fetch Standard", "https://fetch.spec.whatwg.org/#http-access-control-allow-origin"]
  },
  "Content-Security-Policy": {
    "about": "Where scripts and content may load from",
    "what": "Lists the places the page may load scripts, styles and images from. It limits what a script injected into the page can do.",
    "good": "A policy starting from default-src 'self', with only what the site needs added.",
    "how": "add_header Content-Security-Policy \"default-src 'self'\" always;",
    "src": ["W3C Content Security Policy", "https://www.w3.org/TR/CSP3/"]
  },
  "Cookies": {
    "about": "How the site's cookies are protected",
    "what": "Whether each cookie is sent only over HTTPS (Secure), hidden from scripts (HttpOnly) and held back from other sites (SameSite).",
    "good": "Secure; HttpOnly; SameSite=Lax or Strict",
    "src": ["RFC 6265", "https://www.rfc-editor.org/rfc/rfc6265"]
  },
  "The page": {
    "about": "Whether what the page loads is protected",
    "what": "Porch reads the page itself: whether anything on it loads or submits over plain HTTP, and whether code it runs from other sites carries an integrity check.",
    "good": "Nothing in the clear, and an integrity attribute on scripts from other sites.",
    "src": ["W3C Subresource Integrity", "https://www.w3.org/TR/SRI/"]
  },
  "Asked from another site": {
    "about": "The answer to a site it cannot know",
    "what": "Porch asks again as if from a site the page cannot know. A page that names that site back with credentials allowed lets any site read what a signed-in visitor sees.",
    "good": "The unknown site is not named back.",
    "src": ["Fetch Standard", "https://fetch.spec.whatwg.org/#http-cors-protocol"]
  },
  "The other form": {
    "about": "The name with or without www",
    "what": "The same site under the other form of its name, with www or without it, and whether it leads to the same place over HTTPS."
  },
  "Over IPv6": {
    "about": "Whether the site answers over IPv6",
    "what": "Whether the name has an IPv6 address and the site answers on it, as it does on IPv4."
  },
  "Security contact": {
    "about": "Where to report a security problem",
    "what": "security.txt, a small file at /.well-known/security.txt that tells a researcher whom to contact about a vulnerability.",
    "good": "A Contact line and an Expires date within a year.",
    "src": ["RFC 9116", "https://www.rfc-editor.org/rfc/rfc9116"]
  },
  "Reached over HTTPS": {
    "what": "Each redirect a browser follows from the https:// address, hop by hop, until a page answers.",
    "src": ["RFC 9110", "https://www.rfc-editor.org/rfc/rfc9110"]
  },
  "Reached over plaintext": {
    "what": "The same, starting from http:// on port 80. Every hop here travels unencrypted until one reaches HTTPS. A 301 redirect is permanent; a 302 or 307 is temporary, and a browser asks again each time.",
    "good": "A permanent redirect straight to HTTPS, with HSTS sent there.",
    "src": ["RFC 9110", "https://www.rfc-editor.org/rfc/rfc9110"]
  },

  "What the name publishes": {
    "what": "The DNS records this name answers with today, read from the internet as any visitor would read them.",
    "src": ["RFC 1035", "https://www.rfc-editor.org/rfc/rfc1035"]
  },
  "IPv4 (A)": {
    "about": "Its IPv4 addresses",
    "what": "The A records: the IPv4 addresses a visitor connects to.",
    "src": ["RFC 1035", "https://www.rfc-editor.org/rfc/rfc1035"]
  },
  "IPv6 (AAAA)": {
    "about": "Its IPv6 addresses",
    "what": "The AAAA records: the IPv6 addresses a visitor connects to.",
    "src": ["RFC 3596", "https://www.rfc-editor.org/rfc/rfc3596"]
  },
  "IPv6": {
    "about": "Whether it and its name servers use IPv6",
    "what": "Whether the name, and the servers that answer for its zone, can be reached over IPv6."
  },
  "Addresses": {
    "about": "Its IP addresses",
    "what": "The addresses this name points to."
  },
  "Alias (CNAME)": {
    "about": "Another name this one points to",
    "what": "A CNAME makes this name an alias of another. An alias to a name that does not exist can be taken over by whoever registers that name.",
    "good": "None, or an alias to a name you control.",
    "src": ["RFC 1034", "https://www.rfc-editor.org/rfc/rfc1034"]
  },
  "Zone (SOA)": {
    "about": "Where its DNS zone begins",
    "what": "The SOA record marks the top of a zone and carries its serial number, which changes whenever the zone does.",
    "src": ["RFC 1035", "https://www.rfc-editor.org/rfc/rfc1035"]
  },
  "Primary": {
    "about": "The zone's primary name server",
    "what": "The name server the SOA record names as the original source of the zone."
  },
  "Timers (SOA)": {
    "about": "How often copies of the zone refresh",
    "what": "The SOA timers: how often secondary servers check for changes, how long they keep an old copy, and how long a missing answer is remembered.",
    "src": ["RFC 1912", "https://www.rfc-editor.org/rfc/rfc1912"]
  },
  "Mailbox (SOA)": {
    "about": "The address responsible for the zone",
    "what": "The mailbox the SOA record names for whoever runs the zone, written with its @ as a dot."
  },
  "Text records (TXT)": {
    "about": "Free text the name publishes",
    "what": "TXT records carry text. Domains use them for SPF, for proofs to other services, and for notes.",
    "src": ["RFC 1035", "https://www.rfc-editor.org/rfc/rfc1035"]
  },
  "Text records, as published": {
    "what": "The TXT records exactly as the domain publishes them. They are written by whoever runs the domain, not by Porch, and are shortened where long."
  },
  "DNSSEC (DS)": {
    "about": "Whether its answers are signed",
    "what": "DNSSEC signs a zone's answers so they cannot be forged on the way. The parent zone holds a DS record that links to the zone's key.",
    "good": "Signed, with the parent's DS matching a key and the signatures verifying.",
    "src": ["RFC 4033", "https://www.rfc-editor.org/rfc/rfc4033"]
  },
  "Registration": {
    "about": "When the domain runs out, and its lock",
    "what": "What the registry holds about the domain: when its registration expires and whether it is locked against transfer.",
    "good": "Expiry well ahead, renewing automatically, and a transfer lock.",
    "src": ["RFC 9083", "https://www.rfc-editor.org/rfc/rfc9083"]
  },
  "Routes (RPKI)": {
    "about": "Whether the routes to its addresses are signed",
    "what": "RPKI lets a network sign which networks may announce its addresses, so a route announced by anyone else can be rejected.",
    "good": "Every route valid.",
    "src": ["RFC 6811", "https://www.rfc-editor.org/rfc/rfc6811"]
  },
  "Signed with (DNSKEY)": {
    "about": "The algorithm the zone is signed with",
    "what": "The signing algorithm of the zone's DNSSEC keys.",
    "good": "ECDSA P-256 (13) or Ed25519 (15).",
    "src": ["RFC 8624", "https://www.rfc-editor.org/rfc/rfc8624"]
  },
  "Keys (DNSKEY)": {
    "about": "The keys that sign the zone",
    "what": "The zone's DNSSEC keys by their tag, and what each signs.",
    "src": ["RFC 4034", "https://www.rfc-editor.org/rfc/rfc4034"]
  },
  "Digests (DS)": {
    "about": "What the parent zone holds for its keys",
    "what": "The DS records in the parent zone: a digest of the key that the chain of trust goes through.",
    "src": ["RFC 4034", "https://www.rfc-editor.org/rfc/rfc4034"]
  },
  "Signature (RRSIG)": {
    "about": "When the zone's signature runs out",
    "what": "A signature's dates. After the last one, validating resolvers reject the zone's answers until it is signed again.",
    "good": "Re-signed automatically, well before it runs out.",
    "src": ["RFC 4034", "https://www.rfc-editor.org/rfc/rfc4034"]
  },
  "Absent names (NSEC3)": {
    "about": "How it proves a name does not exist",
    "what": "A signed zone proves that a name does not exist with NSEC, which names its neighbours plainly, or with NSEC3, which hashes them.",
    "good": "NSEC3 with no extra iterations, or NSEC where listing the zone does not matter.",
    "src": ["RFC 9276", "https://www.rfc-editor.org/rfc/rfc9276"]
  },
  "Where the zone is answered": {
    "what": "The name servers the zone is delegated to, the addresses of each, and whether each answers for the zone with the same serial.",
    "good": "Two or more servers, in different networks, all answering with the same serial.",
    "src": ["RFC 2182", "https://www.rfc-editor.org/rfc/rfc2182"]
  },

  "What the zone says": {
    "what": "The records that decide who may send mail as this domain, what a receiver does with mail that fails, and how mail reaches the domain safely."
  },
  "SPF": {
    "about": "Which servers may send its mail",
    "what": "An SPF record lists the servers allowed to send mail as this domain, and what to do with mail from any other.",
    "good": "Ends in -all, or ~all while it is being tested.",
    "how": "example.com.  TXT \"v=spf1 mx -all\"",
    "src": ["RFC 7208", "https://www.rfc-editor.org/rfc/rfc7208"]
  },
  "Lookups": {
    "about": "DNS lookups its SPF costs a receiver",
    "what": "A receiver may make at most ten DNS lookups to evaluate an SPF record. Over ten, the record fails for everyone.",
    "good": "Comfortably under ten.",
    "src": ["RFC 7208", "https://www.rfc-editor.org/rfc/rfc7208"]
  },
  "Void lookups": {
    "about": "SPF lookups that find nothing",
    "what": "Names in the SPF record that answer nothing. A receiver allows two before the record fails.",
    "good": "None.",
    "src": ["RFC 7208", "https://www.rfc-editor.org/rfc/rfc7208"]
  },
  "Record": {
    "about": "The record above, exactly as published",
    "what": "The text of the record named in the row above, exactly as the domain publishes it."
  },
  "DMARC": {
    "about": "What receivers do with mail that fails",
    "what": "A DMARC record tells receivers what to do with mail that claims to be from this domain and fails SPF and DKIM, and where to send reports.",
    "good": "p=reject, or p=quarantine on the way there.",
    "how": "_dmarc.example.com.  TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"",
    "src": ["RFC 7489", "https://www.rfc-editor.org/rfc/rfc7489"]
  },
  "Reports to": {
    "about": "Where DMARC reports go",
    "what": "The addresses the DMARC record asks receivers to send aggregate reports to. An address at another domain has to agree, in its own DNS, to receive them.",
    "src": ["RFC 7489", "https://www.rfc-editor.org/rfc/rfc7489"]
  },
  "TLS-RPT": {
    "about": "Where failed encryption is reported",
    "what": "A TLS-RPT record asks senders to report when they could not deliver mail to this domain over an encrypted connection.",
    "how": "_smtp._tls.example.com.  TXT \"v=TLSRPTv1; rua=mailto:tls@example.com\"",
    "src": ["RFC 8460", "https://www.rfc-editor.org/rfc/rfc8460"]
  },
  "DKIM": {
    "about": "Keys that sign its outgoing mail",
    "what": "DKIM keys, published under a selector, let receivers check that a message was signed by the domain and not changed. DNS cannot list selectors, so only the ones named were looked at.",
    "good": "A key at each selector your mail services use, RSA of 2048 bits or Ed25519.",
    "src": ["RFC 6376", "https://www.rfc-editor.org/rfc/rfc6376"]
  },
  "MX": {
    "about": "The servers that receive its mail",
    "what": "MX records name the servers that accept mail for the domain. A null MX says the domain accepts no mail at all.",
    "src": ["RFC 5321", "https://www.rfc-editor.org/rfc/rfc5321"]
  },
  "MX alias": {
    "about": "A mail server named by an alias",
    "what": "An MX record has to name a host that has an address, not an alias. Some senders refuse to deliver to an alias.",
    "good": "Every MX names a host with its own A or AAAA record.",
    "src": ["RFC 2181", "https://www.rfc-editor.org/rfc/rfc2181"]
  },
  "MX IPv6": {
    "about": "Whether its mail servers use IPv6",
    "what": "Whether the mail servers can be reached over IPv6."
  },
  "MTA-STS": {
    "about": "Requires encryption for mail to it",
    "what": "MTA-STS publishes a policy that tells senders to deliver mail to this domain only over TLS, to servers with valid certificates.",
    "good": "mode: enforce, with every MX host listed.",
    "src": ["RFC 8461", "https://www.rfc-editor.org/rfc/rfc8461"]
  },
  "DANE": {
    "about": "Mail server certificates pinned in DNSSEC",
    "what": "TLSA records, signed with DNSSEC, tell senders which certificate each mail server must present, so a forged one is refused.",
    "good": "TLSA 3 1 1 records matching each server, in a signed zone.",
    "src": ["RFC 7672", "https://www.rfc-editor.org/rfc/rfc7672"]
  },
  "STARTTLS": {
    "about": "Whether each mail server offers encryption",
    "what": "Whether each mail server, asked on port 25, offers to encrypt the connection, and with what.",
    "good": "Offered, TLS 1.2 or 1.3, with a valid certificate.",
    "src": ["RFC 3207", "https://www.rfc-editor.org/rfc/rfc3207"]
  },
  "RELAY": {
    "about": "Whether it forwards mail for strangers",
    "what": "Whether a mail server accepts mail for a domain it does not serve. An open relay is used to send spam under the server's name.",
    "good": "Refuses.",
    "src": ["RFC 5321", "https://www.rfc-editor.org/rfc/rfc5321"]
  },
  "LEGACY": {
    "about": "Whether it still speaks old TLS",
    "what": "Whether a mail server still accepts TLS 1.1 or older from a sender that offers nothing newer.",
    "good": "Refuses TLS 1.1 and older.",
    "src": ["RFC 8996", "https://www.rfc-editor.org/rfc/rfc8996"]
  },
  "SOFTWARE": {
    "about": "What each mail server says it runs",
    "what": "The software a mail server names in its greeting. Porch shows the name and never the version.",
    "good": "No version number."
  },

  "Names under this domain": {
    "what": "Every name found under the domain, from every source at once, and what each one does now."
  },
  "Wildcards, which name no host": {
    "what": "Wildcard records answer for any name under them. They show that a pattern exists, not that a host by any one name does.",
    "src": ["RFC 4592", "https://www.rfc-editor.org/rfc/rfc4592"]
  },
  "What this does not show": {
    "what": "What none of the sources can see. DNS cannot be listed, so a name nobody has published, logged or resolved stays unknown."
  },
  "Found": {
    "about": "How many names were found",
    "what": "The number of distinct names found, from every source together."
  },
  "Produced": {
    "about": "When this list was made",
    "what": "When the list was made. Names change, so an older list may miss new ones."
  },
  "The zone": {
    "about": "What the zone itself gave up",
    "what": "Whether the zone's own servers handed out the whole zone, which lists every name in it.",
    "src": ["RFC 5936", "https://www.rfc-editor.org/rfc/rfc5936"]
  },
  "Its proofs": {
    "about": "Names its DNSSEC proofs reveal",
    "what": "A signed zone using NSEC names its neighbours when it proves a name does not exist, so walking those proofs lists the zone.",
    "src": ["RFC 4034", "https://www.rfc-editor.org/rfc/rfc4034"]
  },
  "Certificates": {
    "about": "Names found in the certificate logs",
    "what": "Names that appear in certificates in the public Certificate Transparency logs.",
    "src": ["RFC 6962", "https://www.rfc-editor.org/rfc/rfc6962"]
  },
  "Records": {
    "about": "Names its own records point to",
    "what": "Names that the domain's own records mention, such as its MX hosts, name servers and aliases."
  },
  "Passive DNS": {
    "about": "Names others have seen resolved",
    "what": "Names that a passive DNS register has seen asked about on the internet."
  },
  "The hosts": {
    "about": "Names its servers present",
    "what": "Names that the domain's own servers present in their certificates."
  },
  "Reverse DNS": {
    "about": "Names its addresses point back to",
    "what": "The names that the domain's IP addresses resolve back to in reverse DNS."
  },
  "Your list": {
    "about": "Names you added yourself",
    "what": "Names this installation was told about, checked like any other."
  },
  "Wildcards": {
    "about": "Patterns that match any name below",
    "what": "Wildcard records found. Each covers hosts it does not name.",
    "src": ["RFC 4592", "https://www.rfc-editor.org/rfc/rfc4592"]
  },
  "Other names": {
    "about": "Names outside this domain",
    "what": "Names that were found but are not under this domain, such as a provider's hosts."
  },
  "Cut": {
    "about": "Not every name is listed",
    "what": "More names were found than the list shows."
  }
});

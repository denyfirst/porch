# Who may scan what

A scanner opens connections to somebody else's server. Two facts decide
everything about it: **whose address is in that server's logs**, and **whether
anybody can say who asked**. This project keeps no record of who asked, so it
must never be the visible party for a scan it cannot account for. Until
2026-09-03 the public site was exactly that. Now it scans only hosts this
project owns, and everything else runs on the machine of whoever wants it.

[`invariants.md`](invariants.md) has each guard and its tests. This page says
how they fit together.

---

## Three deployments

| | who runs it | who chooses the target | what stops it |
|---|---|---|---|
| **the demonstration** | this project | a stranger | a list of our own hosts, compiled in (N6) |
| **`porchd`** | an organisation | whoever holds its password | proof of control of each domain, and the password beyond loopback |
| **`porch-scan`** | one person | that person | proof of control of each domain, from a secret of their own |

Proof of control is on in every build and no flag turns it off. A default is
a mitigation, not a boundary: a service bound to an interface without it is
an open scanner for a careless colleague, a compromised CI job or an SSRF,
and it is the operator's address in the logs.

---

## The boundary

**A deployment scans only domains it has been shown control of.** The proof is
a `TXT` record at `_porch-challenge.<domain>`, or a file at
`/.well-known/porch-challenge`.

- **It is asked where the scan is decided**, in `Scanner.Scan` beside the
  demonstration's own check, not where a request arrives. A guard at one entry
  point disappears when a second is added.
- **It is re-read every time.** A domain changes hands, a contract ends, and a
  remembered proof would outlive it. Deleting the record is the revocation.
- **The two proofs grant different things.** A `TXT` record proves the zone. A
  file proves one host's HTTP surface: it authorises that hostname only, never
  the zone, and never a check that does not read HTTP. The mail and DNS checks
  need the zone.
- **The record is read from the zone's own servers**, walked from the root,
  with no walk up the tree. A record at `example.com` does not prove a name
  delegated to somebody else.
- **A verified zone is not a list of hosts you control.** `shop.example.com`
  may be a shop platform and `mail.example.com` a mail provider. There is no
  honest automatic answer, so the tool says what it is about to reach and the
  operator decides. An exchanger behind an alias is never asked whether it
  relays.
- **It does not travel down a redirect.** A `Location` header names whatever
  the server chose, so the scope is asked again before each hop (N10).
- **It does not make an address scannable.** There is no zone to put a record
  in for `10.0.0.5`. A name that resolves to a private address can be proven
  and then checked with `-allow-private`.
- **It is visible.** `_porch-challenge.example.com` is public and says the
  domain is checked with Porch.

---

## Where it may look, never how

```
          unverified          verified
              │                  │
        public scope        owned scope
              │                  │
              └───── same ───────┘
                   methodology:
             read and observe only,
         no exploit, no fuzzing, no guessing,
               minimal retention
```

Verification changes **where** the tool may look. It never changes **how** it
looks. So a verified deployment is never called *full*, *deep* or *active*:
each of those words quietly authorises something this project refuses.

| | unverified | verified |
|---|---|---|
| which hosts | what the build may reach | the estate proven |
| private, loopback, reserved | refused | the operator's choice, off by default |
| ports | the implicit-TLS list | the operator's choice, off by default |
| how a host is examined | identical | identical |
| what is kept | identical | identical |

Verification changes who is responsible, not what the tool does. A verified
deployment can still be reached by an SSRF or driven by a compromised job, so
none of these is ever relaxed by it: the private-address refusal, the port
list, the rate and concurrency limits, the per-target budget, and N7.

---

## Not doing, on any deployment

**Exploitation, credential guessing, fuzzing somebody else's service, state
change, port sweeps, scanning at scale, or CVE guesses matched from a version
string.** Nothing malformed is ever sent.

- A tool that sends broken input is a weapon in whoever's hands it ends up
  in. This one is installed by a company to check itself, and the worst a
  careless colleague can do with it should be to read a page.
- Several such probes can take down what they are aimed at.
- The class is often wrong in both directions, and this project's answers are
  meant to be checkable line by line.

Completeness comes from more that can be read, not from pushing harder.

---

## Sources, and who learns what

Privacy here means one thing: **no service in between learns what you check.**
An online scanner is that service — it sees every domain everyone checks, and
keeps them. Porch runs on your own machine, so nobody does.

Some answers are held somewhere else, and Porch asks the source that holds
them, directly, and only about a domain it may scan. Avoiding those sources
would make the report worse and protect nobody: they hold the answer whether
or not anybody asks.

- **A revocation list** covers thousands of certificates. It is read on every
  build.
- **The certificate's own responder** is asked whether this certificate was
  revoked, where the certificate names one. The authority that issued it
  learns its owner looked.
- **Cert Spotter** is asked which certificates are logged for a name, and
  which names under a domain they cover. It learns that somebody looked at a
  domain whose certificates are already public. It was crt.sh until
  2026-10-10, which fell a day behind the logs.
- **The names inventory** reads registers that exist to be read: logs, the
  domain's own records, a zone that hands itself over, a passive register the
  operator names and pays for, and names the operator lists. It invents no
  name. It grades nothing, and says every time that it is not a complete
  inventory.

---

## Reading a page

A page body can hold a key in a comment, a token in a script, a name in a
template, and a report is something people paste into issue trackers. So the
web check reads the page only where it belongs to whoever reads the report:
the command line, a proven domain, or the demonstration's own pages. It reads
it once, up to one megabyte, and keeps nothing of it but host names and
yes-or-no facts. `markup.Facts` has no
field that could hold markup. Nothing in the page is followed or executed.

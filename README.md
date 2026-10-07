<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/porch-dark.svg">
    <img alt="porch." src="docs/assets/porch-light.svg" width="220">
  </picture>
</h1>

**Porch** checks what your servers show the outside world — TLS, the website,
mail and DNS — and grades it against published standards. It is open source,
runs on your own server, and keeps nothing it was not told to keep.

Made by [denyfirst](https://denyfirst.dev), an independent security and
privacy team. Try it on our own domain at
[porch.denyfirst.dev](https://porch.denyfirst.dev).

## What it checks

| Check | What it reads |
|---|---|
| TLS | every protocol version, the cipher suites actually accepted, the certificate chain, revocation, certificate transparency, CAA |
| Web | HTTPS redirects, HSTS, cookies, security headers, mixed content |
| Mail | SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, STARTTLS on the mail servers |
| DNS | name servers, delegation, DNSSEC, zone transfers |
| Names | the names under a domain, from certificate logs and DNS |

Every finding links the RFC or guideline it rests on, and every report says
what it could not measure. [`docs/checks.md`](docs/checks.md) lists every
connection a scan makes.

## Principles

- **Your data stays with you.** There is no log of who checked what. Results
  are kept only where you say: a directory, or a history encrypted under your
  password.
- **Only your own domains.** A copy checks a domain only after the domain
  publishes a TXT record proving control.
- **Nothing intrusive.** No exploits, no malformed packets, no port scanning,
  no private addresses.
- **Nothing to trust blindly.** Go's standard library only, no third-party
  code. Releases are signed and can be rebuilt byte for byte.

## Get started

- **The service**, with Docker: [`docs/self-host.md`](docs/self-host.md).
- **The command line**, for Linux, macOS and Windows: download `porch-scan`
  from the [releases](https://github.com/denyfirst/porch/releases),
  [verify it](docs/verify.md), then:

```sh
porch-scan -verification-token example.com   # the TXT record to publish, once
porch-scan example.com
```

The exit status is the worst verdict found, so it can gate a pipeline: `0`
strong, `1` weak, `2` insecure, `3` when the scan could not be completed.

Or build both from source, with nothing but Go:

```sh
git clone https://github.com/denyfirst/porch
cd porch
go build -o . ./cmd/porch-scan ./cmd/porchd
```

## Documentation

- [`docs/`](docs/README.md) — every document, in one list
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how the code is laid out, and the checks a change must pass

## Licence

AGPL-3.0. See [`LICENSE`](LICENSE).

```text
  +-- H O S T A G E ------------------------------------+
  | DNS  -->  PROVIDER EVIDENCE  -->  VERDICT          |
  | A missing record is not proof of takeover.        |
  +---------------------------------------- LEVIATHAN X
```

# HostageLVX

**Evidence-backed dangling DNS classification for authorized infrastructure.**

HostageLVX is a standalone Go tool in the **Leviathan X** tooling suite. It evaluates DNS and service responses, applies provider fingerprints, and reports potential dangling configurations with context for human verification.

[![CI](https://github.com/cyeezy08/HostageLVX/actions/workflows/ci.yml/badge.svg)](https://github.com/cyeezy08/HostageLVX/actions/workflows/ci.yml)
[Releases](https://github.com/cyeezy08/HostageLVX/releases) | [Security policy](SECURITY.md) | [MIT license](LICENSE)

> Only test infrastructure you own or are explicitly authorized to assess. A matching provider fingerprint does not establish that a takeover is possible.

`hostage` resolves a list of targets, fingerprints the HTTP surface, and highlights takeover-prone endpoints with low false-positive noise. It is designed for reusable recon workflows, operator tooling, and CI-friendly scanning.

---

## What it does

- Checks dangling DNS and takeover-prone subdomains
- Fingerprints common takeover services (GitHub Pages, AWS S3, Azure, Heroku, Fastly, CloudFront, Vercel, etc.)
- Uses wildcard-DNS canaries to reduce false positives
- Supports JSONL output for automation and SIEM pipelines
- Runs on Linux, macOS, and Windows

---

## Real offline CLI demonstration

Run `bash scripts/live-demo.sh` to build the current source and display **actual** version and fingerprint catalogue output. If `asciinema` is installed, it also records a terminal session as `demo.cast`. This path does not scan any internet host. Do not present the catalogue as confirmed vulnerabilities or a live scan.

The existing demo script previously referenced a CLI flag that did not exist. This corrected path is also exercised in CI.

---

## Install

### Via Homebrew (macOS & Linux)

```bash
brew install cyeezy08/tap/hostage
hostage --help
```

### Installer script

The repository includes [install.sh](install.sh). Review its contents before running it, or prefer the documented Go install and published release artifacts.

### Prebuilt binary

Download from the [Releases](../../releases) page:

- Windows x64
- Linux x64
- Linux arm64
- macOS amd64
- macOS arm64

### Go install

```bash
go install github.com/leviathan-offsec/HostageLVX@latest
```

Requires Go 1.22+.

### Docker

```bash
docker pull ghcr.io/cyeezy08/hostagelvx:latest
```

---

## Quick usage

```bash
# basic scan from a file
hostage @subs.txt

# stdin input
cat subs.txt | hostage -

# JSONL output
hostage -json -o findings.jsonl @subs.txt

# silent mode: only print TAKEOVER / LIKELY results
hostage -silent @subs.txt

# use a custom resolver
hostage -dns-server 1.1.1.1:53 @subs.txt

# print the fingerprint database
hostage -fingerprints
```

### Common flags

| Flag | Default | Description |
|---|---|---|
| `-t` | `50` | Concurrent worker count |
| `-timeout` | `8.0` | DNS + HTTP timeout (seconds) |
| `-resolver` | `doh` | `doh` or `system` |
| `-dns-server` | empty | Custom resolver, e.g. `1.1.1.1:53` |
| `-json` | `false` | Emit JSONL |
| `-silent` | `false` | Only print confirmed takeovers |
| `-o` | stdout | Output file |
| `-fingerprints` | `false` | Show all fingerprints |
| `-no-wildcard-check` | `false` | Skip wildcard detection |
| `-V` | — | Print version |

---

## Output examples

### Text mode

```text
[X] TAKEOVER   legacy.example.com
        CNAME   legacy-example-com.herokuapp.com
        service Heroku
        note    claim by creating a Heroku app with the matching name

[+] ALIVE       api.example.com -> 104.26.14.225
        server  cloudflare
        status  200 OK
        tech    Cloudflare, nginx
```

### JSONL mode

```json
{"host":"legacy.example.com","verdict":"takeover","cname":"legacy-example-com.herokuapp.com","service":"Heroku","status":404,"note":"claim by creating a Heroku app with the matching name"}
{"host":"api.example.com","verdict":"alive","ip":"104.26.14.225","server":"cloudflare","status":200,"tech":["Cloudflare","nginx"]}
```

### Exit codes

- `0` — no takeover candidates found
- `1` — at least one takeover candidate found
- `2` — usage or I/O error

---

## Fingerprints

`hostage` includes a built-in fingerprint set for common services including:

- GitHub Pages
- AWS S3
- Azure Web Apps
- Heroku
- Fastly
- Shopify
- Tumblr
- Zendesk
- Bitbucket Cloud
- Surge.sh
- Readme.io
- Pantheon
- Ghost
- Helpjuice
- CloudFront
- Netlify
- Vercel
- Google Cloud Storage
- DigitalOcean Spaces
- Firebase Hosting
- Webflow

Use `hostage -fingerprints` to print the full database.

---

## Wildcard DNS detection

Hostage LVX can detect wildcard DNS zones and suppress parking-page noise before it becomes a false positive. This is useful when many subdomains resolve to the same placeholder response.

---

## Developer environment

```bash
make build       # build hostage binary
make build-all   # cross-compile all platforms
test
go test ./...   # run tests
make vet         # go vet
make lint        # golangci-lint
make docker      # build docker image
```

## Evidence and limitations

HostageLVX reports classification signals, not guaranteed exploitation. DNS wildcards, provider defaults, rate limits, inaccessible responses, untested services and stale provider fingerprints can affect outcomes. Confirm any flagged condition against your documented scope and the applicable provider before reporting it as a finding.

This repo is a tool, not the Leviathan X hosted platform. It does not claim to run a continuous production monitoring service.

---

## Legal / usage

If you cannot produce written authorization for a target, do not scan it.

See [DISCLAIMER.md](./DISCLAIMER.md) for the full policy text.

---

## Contributing

PRs are welcome for new fingerprints, bug fixes, and platform improvements. Keep dependencies minimal and avoid submitting real target data.

---

## License

MIT, see [LICENSE](./LICENSE).

---

**Leviathan X tooling:** [FenrirLVX](https://github.com/cyeezy08/FenrirLVX) for WordPress advisory correlation and [surfacediff](https://github.com/cyeezy08/surfacediff) for historical asset changes. The tools remain standalone; a unified API is not claimed as shipped here.

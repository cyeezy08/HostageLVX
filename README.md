<div align="center">

<p>
  <a href="https://codespaces.new/cyeezy08/HostageLVX?quickstart=1">
    <img src="https://github.com/codespaces/badge.svg" alt="Open in Codespaces" width="180" height="32" />
  </a>
  <a href="../../actions/workflows/ci.yml">
    <img src="https://img.shields.io/badge/CI-live-cyan?style=for-the-badge&logo=githubactions&logoColor=black" alt="CI status" width="120" height="32" />
  </a>
  <a href="../../releases/latest">
    <img src="https://img.shields.io/badge/Release-v0.3.0-00d9ff?style=for-the-badge&logo=github&logoColor=black" alt="Current release" width="150" height="32" />
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-111111?style=for-the-badge" alt="MIT License" width="120" height="32" />
  </a>
</p>

</div>

<div align="center">

# HOSTAGE LVX

## LEVIATHAN.AC // OFFSEC.LEVIATHAN.AC

</div>

> BRUTALIST RECON. CLEAN TAKEOVERS. ZERO NOISE.

<p align="center">
  <a href="./scripts/live-demo.sh">
    <img src="https://img.shields.io/badge/Live%20TUI-Demo-00d9ff?style=for-the-badge&logo=terminal&logoColor=black" alt="Live TUI demo" width="180" height="36" />
  </a>
  <a href="https://github.com/cyeezy08/HostageLVX/releases/latest">
    <img src="https://img.shields.io/badge/Download-Binary-111111?style=for-the-badge&logo=github&logoColor=white" alt="Download binary" width="180" height="36" />
  </a>
</p>

`hostage` is a blunt, fast, scope-aware dangling-DNS and takeover engine built for real operators. It resolves a list of targets, fingerprints the HTTP surface, and highlights takeover-prone endpoints without the usual cloud dependency garbage. No backend. No API key. No soft assumptions. Just exposure mapping, fast enough to run in the terminal and sharp enough to move in a workflow.

## Live TUI demo

```text
$ ./scripts/live-demo.sh

    __  ______  ______________   ____________
   / / / / __ \/ ___/_  __/   | / ____/ ____/
  / /_/ / / / /\__ \ / / / /| |/ / __/ __/
 / __  / /_/ /___/ // / / ___ / /_/ / /___
/_/ /_/\____//____//_/ /_/  |_|\____/_____/ 

  LEVIATHAN.AC // HOSTAGE LVX
  RAPID TAKEOVER CHECK

  scanned  6   alive  3   takeovers  2   likely  1
  api.example.com             ALIVE      nginx
  admin.example.com          TAKEOVER   Heroku  ↠ live
  legacy.example.com         TAKEOVER   CloudFront
  staging.example.com         LIKELY     generic
  cdn.example.com             NO_DNS
  shop.example.com            ALIVE      Cloudflare

  last event · admin.example.com · takeover · Heroku
  [q] quit
```

This is the same rapid-swarm interface shipped with `hostage -demo` and `./scripts/live-demo.sh`, tuned for a brutalist Leviathan operator console.

This project is built for the same lane as high-end recon tooling, but with a tighter focus on takeovers that matter: noisy results stripped down, valid findings surfaced harder, and the console kept brutal and readable.

- **21 fingerprints** — GitHub Pages, AWS S3, Azure Web Apps, Heroku, Fastly, Shopify, Tumblr, Zendesk, Bitbucket Cloud, Surge.sh, Readme.io, Pantheon, Ghost, Helpjuice, CloudFront, Netlify, Vercel, Google Cloud Storage, DigitalOcean Spaces, Firebase Hosting, Webflow
- **Wildcard DNS canary detection** — kills parking-page noise before it becomes false-positive drag
- **DoH-first resolution** — fast DNS-over-HTTPS by default, with system / custom UDP fallback
- **Multi-label TLD awareness** — handles `co.uk`, `com.au`, `co.jp`, and similar parent-zone edge cases correctly
- **Technology fingerprinting** — extracts `Server`, `X-Powered-By`, Cloudflare, Vercel, CloudFront, and Shopify markers from responses
- **Cross-platform console output** — works cleanly in terminal environments with Windows VT enabling where needed
- **JSONL output** — pipe straight into SIEM, SOAR, or your automation pipeline
- **CI-friendly exit codes** — exit `1` when takeover candidates are found, `0` otherwise
- **Zero telemetry** — no phone-home, no usage tracking, no auto-update nonsense
- **Single static binary** — Windows, Linux, macOS
- **Developer environment ready** — Codespaces-friendly alongside common recon tooling
- **Release-grade packaging** — built for reproducible distribution and operator workflows

```
    __  ______  ______________   ____________
   / / / / __ \/ ___/_  __/   | / ____/ ____/
  / /_/ / / / /\__ \ / / / /| |/ / __/ __/   
 / __  / /_/ /___/ // / / ___ / /_/ / /___   
/_/ /_/\____//____//_/ /_/  |_|\____/_____/   

  LEVIATHAN.AC // HOSTAGE LVX
  v0.3.0 Rapid SubDomain TakeOver Tool
```

---

## 

**If you cannot produce written authorization for a target, do not scan it.**

See [`DISCLAIMER.md`](./DISCLAIMER.md) for the full text.

---

## Install

### Option 1 — one-line installer (curl | sh)

```bash
curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh
```

To a specific dir:

```bash
curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh -s -- -b /usr/local/bin
```

Pinned version:

```bash
curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh -s -- --version v0.3.0
```

The installer verifies the SHA-256 checksum automatically if present in the release.

### Option 2 — prebuilt binary

Download from the [Releases](../../releases) page:

| Platform | File |
|---|---|
| Windows x64 | `hostage-windows-amd64.exe` |
| Linux x64 | `hostage-linux-amd64` |
| Linux arm64 | `hostage-linux-arm64` |
| macOS arm64 (Apple Silicon) | `hostage-darwin-arm64` |
| macOS amd64 (Intel) | `hostage-darwin-amd64` |

### Option 3 — `go install`

```bash
go install github.com/cyeezy08/HostageLVX@latest
```

Requires Go 1.22+.

### Option 4 — Docker

```bash
docker pull ghcr.io/cyeezy08/hostagelvx:latest
echo "sub.example.com" | docker run --rm -i ghcr.io/cyeezy08/hostagelvx - @-
```

### Option 5 — open in Codespaces

[![Open in Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/cyeezy08/HostageLVX?quickstart=1)

Spin up a full Go dev env in your browser with `subfinder` + `httpx` pre-installed.

### Option 6 — build from source

```bash
git clone https://github.com/cyeezy08/HostageLVX.git
cd HostageLVX
make build
```

---

## Usage

`hostage` accepts targets three ways:

1. **Inline arguments** — `hostage a.example.com b.example.com`
2. **`@file` notation** — `hostage @subs.txt`
3. **Stdin pipe** — `cat subs.txt | hostage -`

```bash
# basic — read from file
hostage @subs.txt

# live demo dashboard (simulated rapid swarm + takeover verdicts)
hostage -demo

# recorded demo path
./scripts/live-demo.sh

# leviathan.ac branded operator view
hostage -tui @subs.txt

# fast — 100 concurrent workers
hostage -t 100 @subs.txt

# JSONL output for piping into SIEM / Leviathan
hostage -json -o findings.jsonl @subs.txt

# silent — only print confirmed takeover candidates
hostage -silent @subs.txt

# custom DNS resolver (forces system mode)
hostage -dns-server 1.1.1.1:53 @subs.txt

# print the fingerprint database and exit
hostage -fingerprints
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-t` | `50` | Concurrent resolution workers |
| `-timeout` | `8.0` | Per-request DNS + HTTP timeout (seconds) |
| `-resolver` | `doh` | `doh` (DNS-over-HTTPS, fast) or `system` (OS resolver) |
| `-dns-server` | (empty) | Custom UDP resolver IP `1.2.3.4:53` — forces system mode |
| `-json` | `false` | JSONL output, one finding per line |
| `-silent` | `false` | Only print TAKEOVER / LIKELY hits |
| `-o` | (stdout) | Write findings to file (JSONL with `-json`, text otherwise) |
| `-fingerprints` | `false` | Print the fingerprint database and exit |
| `-no-color` | `false` | Disable colored output (auto-disabled when piping) |
| `-no-wildcard-check` | `false` | Skip wildcard-DNS canary detection (faster, noisier) |
| `-V` | — | Print version and exit |

---

## Output

### Text mode (default)

```
[X] TAKEOVER   legacy.example.com
        CNAME   legacy-example-com.herokuapp.com
        service Heroku
        note    claim by creating a Heroku app with the matching name

[+] ALIVE       api.example.com -> 104.26.14.225
        server  cloudflare
        status  200 OK
        tech    Cloudflare, nginx

[A-] NO_DNS     dev.example.com
        reason  no DNS answer

[=] 4 scanned — 1 ALIVE — 1 NO_DNS — 1 TAKEOVER — 1 LIKELY
```

### JSONL mode (`-json`)

```json
{"host":"legacy.example.com","verdict":"takeover","cname":"legacy-example-com.herokuapp.com","service":"Heroku","status":404,"note":"claim by creating a Heroku app with the matching name"}
{"host":"api.example.com","verdict":"alive","ip":"104.26.14.225","server":"cloudflare","status":200,"tech":["Cloudflare","nginx"]}
{"host":"dev.example.com","verdict":"no_dns"}
```

### Exit codes

- `0` — no takeover candidates found
- `1` — at least one takeover candidate found (useful for CI gates)
- `2` — usage / I/O error

---

## Fingerprints (21)

| # | Service | Detection signal |
|---|---|---|
| 1 | GitHub Pages | `There isn't a GitHub Pages site here.` (HTTP 404) |
| 2 | AWS S3 | `NoSuchBucket` (HTTP 404) — covers `s3.amazonaws.com`, regional buckets, and `s3-website.*` |
| 3 | Azure Web Apps | `404 Web Site not found` on `.azurewebsites.net` |
| 4 | Heroku | `No such app` / `Application error` on Heroku error page |
| 5 | Fastly | `Fastly error: unknown domain` |
| 6 | Shopify | `Sorry, this shop is currently unavailable` |
| 7 | Tumblr | `Whatever you were looking for doesn't currently exist at this address` |
| 8 | Zendesk | `Help Center Closed` / subdomain doesn't exist |
| 9 | Bitbucket Cloud | `Repository not found` on Bitbucket |
| 10 | Surge.sh | `project not found` on Surge |
| 11 | Readme.io | `Project not found` on Readme.io |
| 12 | Pantheon | `The gods are wise, but unforgiving` |
| 13 | Ghost | `404 Not Found` on Ghost Pro |
| 14 | Helpjuice | `404 - Not found` on Helpjuice |
| 15 | CloudFront | `Bad request` on alternate-domain CNAME mismatch |
| 16 | Netlify | `Not Found - Site not found` |
| 17 | Vercel | `DEPLOYMENT_NOT_FOUND` / `Configuration Error` |
| 18 | Google Cloud Storage | `The specified bucket does not exist` (HTTP 404) — covers `*.storage.googleapis.com` and `*.storage.goog` |
| 19 | DigitalOcean Spaces | `The specified bucket does not exist` (HTTP 404) on `*.digitaloceanspaces.com` |
| 20 | Firebase Hosting | `Why am I seeing this?` (HTTP 404) — covers `*.web.app` and `*.firebaseapp.com` |
| 21 | Webflow | `The page you are looking for doesn't exist or has been moved` (HTTP 404) on `*.proxy-ssl.webflow.com` / `*.webflow.io` |

Want one added? Open an issue with the response body + service name.

Run `hostage -fingerprints` to print the full database with regex patterns, dangling-status codes, and remediation notes.

---

## Sample run (scrubbed)

```
$ hostage @subs.txt

    __  ______  ______________   ____________
   / / / / __ \/ ___/_  __/   | / ____/ ____/
  / /_/ / / / /\__ \ / / / /| |/ / __/ __/   
 / __  / /_/ /___/ // / / ___ / /_/ / /___   
/_/ /_/\____//____//_/ /_/  |_\____/_____/   
                                             
  leviathan.ac - rapid dangling-DNS & takeover engine
  v0.3.0 - 21 fingerprints - authorized scope only

  wildcard canaries: 1 zone(s) - parking noise auto-nulled

[X] TAKEOVER   legacy.example.com
        CNAME   legacy-example-com.herokuapp.com
        service Heroku
        note    claim by creating a Heroku app with the matching name

[+] ALIVE       api.example.com -> 104.26.14.225 (cloudflare, HTTP 200)
        tech    Cloudflare, nginx

[A-] NO_DNS     dev.example.com
[?] LIKELY      staging.example.com -> 404 with no matching fingerprint (review manually)

[=] 4 scanned — 1 ALIVE — 1 NO_DNS — 1 TAKEOVER — 1 LIKELY
```

---

## Wildcard DNS detection

Many organizations have wildcard DNS configured at the apex (`*.example.com` → some parking IP), which causes naive scanners to flag every unresolvable subdomain as "alive" because the wildcard answers. `hostage` auto-detects this by:

1. Issuing canary queries for random nonce subdomains (`a1b2c3d4.example.com`)
2. If canaries resolve, registering the zone as wildcard
3. Computing a body-hash fingerprint of the wildcard response
4. Marking subsequent identical responses as parking-noise and nulling them out

This dramatically reduces false positives in real-world scans. Disable with `-no-wildcard-check` if you're confident the zone is clean.

---

## Tech fingerprinting

In addition to takeover detection, every alive host gets a light tech fingerprint pass:

- `Server` header (e.g. `nginx`, `cloudflare`, `Apache`)
- `X-Powered-By` header (e.g. `Express`, `PHP/8.1`, `ASP.NET`)
- CDN markers: `Cf-Ray` / `Cf-Cache-Status` (Cloudflare), `X-Vercel-Id` (Vercel), `X-Amz-Cf-Id` / `X-Amz-Cf-Pop` (CloudFront), `X-Shopify-Stage` (Shopify)

The tech list is appended to each ALIVE finding in both text and JSONL output, so you can pipe it into asset intelligence pipelines.

---

## CI / automation

`hostage` exits `1` when any takeover candidate is found. Wire it into a GitHub Action:

```yaml
name: nightly-takeover-scan
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh -s -- -b /usr/local/bin
          hostage -json -o findings.jsonl @subs.txt
      - uses: actions/upload-artifact@v4
        with:
          name: findings
          path: findings.jsonl
      - if: ${{ failure() }}
        run: echo "::warning::Takeover candidate detected - check findings.jsonl"
```

(Store `subs.txt` in a private repo or as an encrypted secret.)

---

## Dev environment

### Codespaces

[![Open in Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/cyeezy08/HostageLVX?quickstart=1)

One-click Go dev env with `subfinder`, `httpx`, `dig`, `jq` pre-installed.

### Local dev

```bash
make build       # build hostage binary
make build-all   # cross-compile all platforms to dist/
make test        # run tests
make vet         # go vet
make lint        # golangci-lint
make docker      # build docker image
make install-smoke  # install locally + smoke test
```

### Docker compose (local target testing)

```bash
docker compose up -d fake-target
docker compose run --rm hostage @/data/test-subs.txt
```

Spins up a fake vulnerable nginx serving Heroku-style 404s so you can test fingerprint matching without scanning real infrastructure.

---

## Release pipeline

Releases are fully automated via [`.github/workflows/release.yml`](./.github/workflows/release.yml). On `git push origin v0.x.x`:

1. Cross-compiles 5 binaries (linux-amd64, linux-arm64, windows-amd64, darwin-arm64, darwin-amd64)
2. Generates SHA-256 checksum file
3. Generates SBOM (SPDX JSON) via `anchore/sbom-action`
4. Signs every binary with `cosign` keyless signing
5. Creates the GitHub Release with all artifacts attached
6. Builds & pushes Docker image to `ghcr.io/cyeezy08/hostagelvx`
7. Signs the Docker image with `cosign`

To cut a release:

```bash
git tag v0.3.0
git push origin v0.3.0
```

---

## Roadmap

- `v0.4.0` — additional fingerprints (Cargo, Tilda custom domains, Strikingly, Unbounce, Squarespace, WordPress.com)
- `v0.5.0` — optional webhook to Leviathan X defensive console (push findings straight to your exposure queue)
- `v0.6.0` — CNAME chain walker (`dig +short` style) baked in, no more manual piping
- `v0.7.0` — Homebrew tap (`brew install cyeezy08/tap/hostage`)
- `v1.0.0` — fingerprint schema unlocked for user-contributed rules in YAML

---

## Contributing

PRs welcome for new fingerprints, bug fixes, or platform builds. Please:

1. Open an issue first for non-trivial changes
2. Don't commit real target data — use `*.example.com` in any demo / screenshot
3. Run `make vet` and `make test` before submitting
4. Keep dependencies minimal — `hostage` should stay a single static binary

### Adding a fingerprint

Edit `fingerprints.go` (or `fingerprints_extra.go` for newer additions). Each fingerprint is:

```go
{
    Service:        "Service Name",
    Vulnerable:     true,
    CNAMEs:         mustCNAME(`.*\.example\.com`),          // CNAME regex patterns
    Signatures:     []HTTPSignature{{
        Body:   "404 string to match in response body",    // case-insensitive contains
        Status: []int{404},                                // optional status filter
        Header: [][2]string{{"Server", "cloudflare"}},     // optional header contains
    }},
    DanglingStatus: []int{404, 307},                       // statuses considered "dangling"
    Note:           "how to claim / remediation guidance",
},
```

Run `hostage -fingerprints` to verify the new entry shows up.

---

## License

MIT — see [`LICENSE`](./LICENSE).

## Author

Built solo by [@cyeezy08](https://github.com/cyeezy08) — also shipping [Leviathan X](https://leviathan.ac) (defensive attack-surface management) and [OffSec Leviathan](https://offsec.leviathan.ac) (authorized red-team console).

If `hostage` saved you time on an engagement, star the repo. If it found a real takeover on a bug-bounty program, [drop a ticket in the Leviathan Telegram](https://t.me/leviathanxcloud) — happy to feature writeups.

# v0.3.0 — first public release

`hostage` is a rapid dangling-DNS & subdomain takeover scanner built for [Leviathan X](https://leviathan.ac). It resolves a list of subdomains, fingerprints HTTP responses, and flags takeover candidates. Standalone Go binary, no platform dependency, no API key, no backend.

## Highlights

- **17 fingerprints** — GitHub Pages, AWS S3, Azure Web Apps, Heroku, Fastly, Shopify, Tumblr, Zendesk, Bitbucket Cloud, Surge.sh, Readme.io, Pantheon, Ghost, Helpjuice, CloudFront, Netlify, Vercel
- **Wildcard DNS canary detection** — auto-identifies parking-page noise and nulls it, dramatically reducing false positives
- **DoH-first resolver** — DNS-over-HTTPS by default, falls back to system resolver or custom UDP server
- **Multi-label TLD awareness** — correctly resolves parent zones for `co.uk`, `com.au`, `co.jp`, etc.
- **Multi-input** — inline args, `@file` notation, or stdin pipe
- **JSONL output** (`-json`) for piping into SIEM / Leviathan X defensive console
- **CI-friendly exit code** — exits `1` when any takeover candidate is found
- **Single static binary** — Windows x64, Linux x64, macOS arm64
- **Zero phone-home** — no telemetry, no auto-update, no usage stats

## Install

Grab the binary for your platform from the assets below, or:

```bash
go install github.com/leviathan-x/hostage@v0.3.0
```

## Usage

```bash
hostage @subs.txt                           # basic scan
hostage -t 100 @subs.txt                   # 100 concurrent workers
hostage -json -o findings.jsonl @subs.txt   # JSONL output
hostage -silent @subs.txt                  # only print takeovers
hostage -fingerprints                       # print fingerprint DB
```

See the [README](../../blob/v0.3.0/README.md) for the full flag reference and fingerprint table.

## Known limitations

- Fingerprints are signature-string based, not full HTML parse — may produce false positives on edge-case responses; verify takeover candidates manually before reporting
- No built-in CNAME chain walker (planned for `v0.6.0`); pipe `dig +short` output if you want full chain resolution
- Single DoH provider (Cloudflare) — custom DoH endpoints planned for `v0.4.0`

## What's next

- `v0.4.0` — additional fingerprints (Cargo, Webflow, Tilda, Strikingly, Unbounce, Squarespace, WordPress.com)
- `v0.5.0` — optional webhook into the Leviathan X defensive console (push findings to your exposure queue)
- `v0.6.0` — CNAME chain walker baked in
- `v1.0.0` — fingerprint schema unlocked for user-contributed YAML rules

## Disclaimer

Authorized use only. You must own or have written permission to test every hostname you scan. See [DISCLAIMER.md](../../blob/v0.3.0/DISCLAIMER.md).

---

Built solo by [@cyeezy08](https://github.com/cyeezy08). If `hostage` found you a takeover on a bug-bounty program, ping the [Leviathan Telegram](https://t.me/leviathanxcloud) — happy to feature the writeup.

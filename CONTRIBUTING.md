# Contributing

Thanks for looking. This is a small project maintained by one person, so here
is what is actually useful and what will go unanswered.

## What gets a fast response

**A bug with a reproduction.** A command, the input, what you expected, what
happened. If it needs a live target, say what you are authorised to test and
what the target is. A traceback is usually enough to start.

**A false positive or false negative in the output.** These are the most
valuable reports this project gets, because the whole premise is that the
tool tells you when it does not know something. If it printed a confident
answer it could not support, that is a bug in the thesis, not just the code.
Include the output verbatim.

**A fingerprint or provider that is missing or wrong.** The CNAME pattern, the
provider, and what the HTTP response body actually returned. If you can, include
the resolved CNAME target and the status code, because several providers differ
only by status code.

## What will go unanswered

Feature requests that are really "make this a platform". Issues asking why
something is not on a roadmap. Anything with a paragraph of speculation and no
command output.

## Ground rules

**Passive by default.** If a change makes the tool send traffic somewhere, that
needs to be opt-in per target, behind a flag, and documented. A tool that
contacts a host you did not name is out of scope for this project entirely.

**Authorisation is on you.** Only test domains you own or have written
permission to test. Do not paste data from a third party's infrastructure into
an issue.

**Do not report vulnerabilities in this tool to a third party.** Report them
here first. There is no bug bounty on this org; a public disclosure race helps
nobody.

**Coverage stays honest.** If you add a check, add it to the coverage counters
in the same commit. A new capability that does not increment the denominator is
a capability that will be silently invisible, which is the one thing this
project is against.

## Working on it

Go 1.23 or newer:

```bash
git clone https://github.com/cyeezy08/HostageLVX.git
cd HostageLVX
go test ./... -race -count=1
golangci-lint run
```

Tests that fail CI will fail for you locally too. Please make them pass before
opening the PR, and if you cannot, open the PR anyway and say what is stuck.

### Adding a provider fingerprint

Fingerprints live in one place. A PR that adds one should include the CNAME
pattern, the providers it matches, the status code, and the exact body string
the service returns, plus a test. A fingerprint with no test will be deleted
eventually, because the service will change the string and nobody will notice.

## Commit messages

Say what changed and why. The `why` is the part that matters six months later.
Full sentences, no bullet lists of file names.

## Security reports

Not via a public issue. See [SECURITY.md](SECURITY.md).

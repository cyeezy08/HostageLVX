# Security Policy

## Reporting a vulnerability in this tool

Email **admin@leviathanx.org**. Do not open a public issue.

Please include the version or commit, the command, and the input. If the
vulnerability only triggers against a live target, describe the shape of the
target without needing me to have access to it.

There is no bug bounty on this org and there is no SLA. Realistically you will
get an acknowledgement within a week and a fix or an explanation within a
month. If that is too slow to be useful to you, disclose publicly and say so.

## What I am interested in

- A tool sending traffic to a host that was not named on the command line.
  That breaks the passive-by-default rule and it is the most serious class.
- Credential or API key material ending up in a release artifact, a log line, a
  snapshot file, or a git object.
- A path traversal or arbitrary file read when reading a snapshot, feed, or
  evidence bundle.
- A command injection through a hostname, URL, CNAME, plugin slug, or any other
  value that came from the network rather than from the operator.
- A false claim of completeness. A coverage counter that under-reports what it
  did not check, or a report that says "no findings" when a check silently
  failed.

That last one is unusual and it matters more here than in most projects. The
entire premise of this org is that a scanner should say what it could not
evaluate. A bug that causes it to under-report its own gaps is a bug in the
thesis.

## What is out of scope

- Findings that require you to already control the machine.
- Denial of service by design, including sending a very large input list.
- Missing hardening headers on the documentation site.
- Vulnerabilities in third-party dependencies with no demonstrated path
  through this code. Report those upstream, though I will take a patch.

## Disclosure

I ask for 90 days before public disclosure, and I will publish the writeup
either way. If a fix is not out by then, tell me why before going public and
I will say so in the disclosure.

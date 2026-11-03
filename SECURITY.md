# Security Policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

- Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guiding-contributors-to-report-security-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (Security → Report a vulnerability).
- Alternatively, email `ti@f6.ru`.

Please include the version, the environment variables in use (**never the value
of `TI_API_KEY`**), and the steps to reproduce. We will acknowledge receipt and
keep you updated on the fix.

## Supported versions

The latest released version is supported. Fixes are not backported.

## Scope

This repository is the MCP server only — the client-side process that talks to
the F6 Threat Intelligence API. Vulnerabilities in the TI platform itself are out
of scope here; report those through F6 support.

## Threat model

Points worth understanding before deploying this server. They are properties of
the design, not defects.

**Everything the tools return reaches the model provider.** Query results are
placed in the model's context: compromised credentials and cards, indicators,
threat and threat actor reports, WHOIS data. Give the server a user key whose
account has the narrowest set of collections the task needs, and choose the
model provider accordingly.

**Collection content is attacker-influenced.** Phishing pages, malware
configurations, leaked data and observed domains are written by whoever
produced them. That text arrives in the model's context alongside legitimate
results, so it can carry instructions aimed at the model. The server has no
tool that writes to TI, and `ti_request` refuses the paths that perform actions
on the TI side, so such instructions have nothing to act on through this
server; what the assistant does elsewhere is the client's responsibility.

**The API key goes wherever `TI_BASE_URL` points.** The URL is validated at
startup — https only, no credentials, query or fragment — so the key cannot
travel in the clear or to a malformed address. It is still sent to whatever
host the value names, so treat that variable as part of the credential: a typo
or a lookalike domain discloses the key on the first tool call. Redirects are
not followed for the same reason.

**Proxies and certificates are stated, not inherited.** `HTTP_PROXY`,
`HTTPS_PROXY` and `SSL_CERT_FILE` from the environment are ignored. A proxy is
`TI_PROXY`; a private CA is `TI_CA_BUNDLE`, which replaces the system store
rather than extending it. Certificate verification cannot be turned off: there
is no `verify=False` switch by design.

**Responses are bounded.** A body over 1 MiB, a body that is not JSON, and more
than 512 characters of an error body are not passed to the model, so an HTML
error page or a binary file cannot leak upstream details or flood the context.

## What this server does not do

It makes no network calls other than to `TI_BASE_URL` (through `TI_PROXY` when
set), reads no environment variables beyond the ones documented in the README,
sends no telemetry, and writes no files.

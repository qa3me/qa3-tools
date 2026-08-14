# Header Audit v0.1 Specification

## Problem

Security engineers need a small, reproducible way to inspect response security headers and the verified TLS state of one explicitly supplied HTTPS endpoint without crawling or broad scanning.

## User

A security engineer, system owner, or reviewer auditing an endpoint they are authorized to assess.

## Command

```text
qa3 header-audit [flags] <https-url>
```

### Flags

- `--json`: emit structured JSON.
- `--timeout`: overall request timeout, constrained to 1-30 seconds; default 10 seconds.
- `--max-redirects`: number of HTTPS redirects to follow, constrained to 0-5; default 0.
- `--allow-private`: opt in to loopback and private-network destinations. Link-local and metadata-style address ranges remain blocked.

## Input validation

The command accepts exactly one absolute `https://` URL. It rejects userinfo, fragments, malformed ports, HTTP URLs, and surrounding whitespace.

## Network behavior

- One GET request is made to the supplied URL.
- Redirects are not followed by default.
- When explicitly enabled, each redirect must remain HTTPS and is subject to the same destination checks.
- TLS 1.2 is the minimum accepted protocol version.
- Certificate verification uses the platform trust store.
- HTTP/1.1 and HTTP/2 are supported through Go's standard transport negotiation.
- Response headers are capped at 64 KiB.
- At most eight permitted resolved addresses are attempted, with each connect attempt capped at three seconds or the lower overall timeout.
- Response bodies are not processed.
- No cookies, credentials, authentication headers, crawling, path discovery, port scanning, or retries are performed.

## Findings

v0.1 reports:

- Strict-Transport-Security
- Content-Security-Policy, including obvious `unsafe-inline` / `unsafe-eval` tokens
- X-Content-Type-Options
- clickjacking controls via X-Frame-Options or CSP `frame-ancestors`
- Referrer-Policy
- Permissions-Policy
- negotiated TLS version and cipher suite
- verified leaf-certificate identity and validity window

A warning is an observation requiring review, not a vulnerability claim. Header findings do not change the process exit code.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed, regardless of pass/warn findings. |
| `1` | Unexpected internal or output error. |
| `2` | Invalid command input or flag value. |
| `3` | DNS, connection, timeout, or other network failure. |
| `4` | TLS handshake or certificate verification failure. |

## Explicit non-goals

v0.1 does not crawl, enumerate hosts, discover paths, scan ports, test exploits, submit forms, authenticate, mutate remote state, grade overall website security, or claim compliance with a security standard.

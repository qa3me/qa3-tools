<p align="center">
  <img src="https://raw.githubusercontent.com/qa3me/qa3me/main/assets/qa3-mark.svg" width="64" alt="QA3 mark">
</p>

<h1 align="center">qa3-tools</h1>

<p align="center">
  Small, defensive security tools with explicit scope, safe defaults, and reproducible behavior.
</p>

## Status

Pre-release. The first command, `header-audit`, is under v0.1 validation and has not been published as a release.

## Scope

`qa3-tools` is a compact collection of read-only diagnostic and DFIR utilities. Tools accept explicit user input, avoid uncontrolled discovery, and document their threat boundaries before release.

The initial command is:

```text
qa3 header-audit <https-url>
```

It audits response security headers and verified TLS state for one explicitly supplied HTTPS endpoint. It does not crawl, enumerate hosts, scan ports, submit forms, authenticate, or test exploits.

## Quick Start

Requirements for development:

- Go 1.26.5 is the CI verification runtime.
- The current source uses only the Go standard library at runtime.

Run the command from the repository root:

```bash
go run ./cmd/qa3 header-audit https://example.com
```

JSON output:

```bash
go run ./cmd/qa3 header-audit --json https://example.com
```

Opt in to at most one HTTPS redirect:

```bash
go run ./cmd/qa3 header-audit --max-redirects 1 https://example.com
```

Private and loopback targets are blocked by default. For an authorized internal endpoint:

```bash
go run ./cmd/qa3 header-audit --allow-private https://127.0.0.1:8443
```

Link-local destinations remain blocked even when `--allow-private` is enabled.

## Example Output

```text
Target: https://example.com
HTTP:   200 (HTTP/2.0)
TLS:    TLS 1.3 / TLS_AES_256_GCM_SHA384
Cert:   CN=example.com → 2026-12-31T23:59:59Z

Findings:
  [PASS] strict-transport-security    Strict-Transport-Security is present with max-age of at least one year
  [WARN] permissions-policy           Permissions-Policy is missing
```

Actual results depend on the target at the time of the request.

## Safety & Limitations

- Exactly one HTTPS URL is accepted per invocation.
- Redirects are disabled by default and capped at five when explicitly enabled.
- TLS 1.2 or newer and normal certificate verification are required.
- HTTP/1.1 and HTTP/2 are supported; response headers are capped at 64 KiB and response bodies are not processed.
- Loopback/private destinations require explicit opt-in. Link-local ranges remain blocked.
- Findings are observations, not proof of overall security or compliance.
- Only assess systems you own or are authorized to review.

The detailed behavior contract is in [`docs/header-audit-spec.md`](docs/header-audit-spec.md). The abuse analysis is in [`docs/threat-model.md`](docs/threat-model.md).

## Repository Structure

```text
cmd/qa3/                 CLI entry point
internal/headeraudit/    Header and TLS audit implementation
tools/header-audit/      Tool-specific documentation
docs/                    Specification and threat model
scripts/                 Local verification helpers
.github/workflows/       CI verification
```

## Testing

```bash
gofmt -w .
go vet ./...
go test -race -count=1 ./...
go build ./cmd/qa3
./scripts/secret-scan.sh .
```

CI additionally runs `govulncheck` against the Go vulnerability database. The repository has no third-party runtime module dependencies in v0.1.

## Security Reporting

Use GitHub Private Vulnerability Reporting. See [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

# header-audit

Audits response security headers and verified TLS state for one explicitly supplied HTTPS endpoint.

See [`../../docs/header-audit-spec.md`](../../docs/header-audit-spec.md) for the v0.1 behavior contract and [`../../docs/threat-model.md`](../../docs/threat-model.md) for the safety boundary.

## Example

```bash
go run ./cmd/qa3 header-audit https://example.com
```

Structured output:

```bash
go run ./cmd/qa3 header-audit --json https://example.com
```

Redirects are disabled by default. Private and loopback targets require `--allow-private`; link-local destinations remain blocked.

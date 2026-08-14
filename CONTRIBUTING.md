# Contributing

QA3 tools are intentionally small, defensive, and conservative in scope.

Before proposing a change:

- Keep behavior read-only and target-driven by default.
- Do not add crawling, broad discovery, credential collection, persistence, evasion, or destructive behavior.
- Add or update tests for material behavior changes.
- Run `gofmt`, `go vet ./...`, `go test ./...`, and `./scripts/secret-scan.sh .`.
- Keep dependencies minimal and justify any new dependency in the pull request.
- Do not include real credentials, customer data, private IOCs, or sensitive infrastructure details in fixtures.

Security-sensitive concerns should be reported through GitHub Private Vulnerability Reporting rather than a public contribution.

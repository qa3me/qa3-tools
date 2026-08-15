# Releasing qa3-tools

Releases are intentionally conservative. A tag is created only after the exact commit has passed review and CI.

## Preconditions

- `main` is the intended release commit and CI is green.
- `govulncheck` reports no reachable known vulnerabilities.
- The repository ruleset protecting `main` is active.
- GitHub Private Vulnerability Reporting is enabled.
- The release notes file exists at `docs/releases/vX.Y.Z.md`.
- The working tree and reviewed diff contain no credentials, customer data, private IOCs, or sensitive infrastructure details.
- The release version follows SemVer as `vX.Y.Z`.

## Release

1. Review the release notes for changes, compatibility, breaking changes, security notes, and limitations.
2. Create the SemVer tag on the reviewed commit without moving or reusing an existing tag.
3. Push the tag.
4. The `Release` workflow re-runs tests and `govulncheck` before publishing artifacts.
5. The workflow builds static binaries for Linux, macOS, and Windows on amd64 and arm64, injects the tag version into `qa3 version`, and publishes `SHA256SUMS`.

## Verification

After publication:

- Confirm the GitHub release points to the intended tag and commit.
- Verify the expected artifacts and `SHA256SUMS` are present.
- Download at least one artifact and verify its checksum.
- Run `qa3 version` and a harmless `header-audit` smoke test.
- Confirm no secrets or sensitive values appear in workflow logs.

## Corrections

Published tags are immutable by convention. Do not move or replace a released tag. Fix release defects in a new patch version.

Commit or tag signing is not enabled until a stable, user-controlled signing key and maintenance process are in place.

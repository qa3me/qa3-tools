# Header Audit Threat Model

## Assets and trust boundaries

The tool processes a user-supplied URL and remote response metadata. It must not expose local credentials, silently expand scope, or turn a single-target diagnostic action into a network discovery primitive.

## Abuse and failure cases

| Risk | v0.1 control |
| --- | --- |
| Unsolicited broad scanning | Exactly one explicit URL; no enumeration or crawling. |
| Redirect-based scope expansion | Redirects disabled by default; explicit limit 0-5; redirected URLs are revalidated. |
| SSRF into local services | Loopback/private networks require `--allow-private`; link-local ranges stay blocked. |
| DNS rebinding | The custom dial path resolves, validates, and dials the selected address in one operation. |
| Cloud metadata access | Link-local address space, including common metadata endpoints, remains blocked even with `--allow-private`. |
| Resource exhaustion | 1-30 second overall timeout, at most eight resolved addresses, per-connect cap of three seconds, 64 KiB response-header cap, no response-body processing, no retries. |
| TLS downgrade | HTTPS only; minimum TLS version 1.2; normal certificate verification remains enabled. |
| Credential leakage | URL userinfo rejected; no cookies or authorization headers; output contains response metadata only. |
| Misleading security claims | Findings use pass/warn language and document that they are observations, not proof of security or compliance. |

## Residual risk

A user can intentionally opt into a private target they are not authorized to assess. Authorization remains the operator's responsibility. Remote servers also observe the request source IP and User-Agent, as with any normal HTTPS request.

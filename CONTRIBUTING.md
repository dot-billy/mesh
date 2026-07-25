# Contributing to Mesh

Mesh welcomes focused bug fixes, documentation improvements, tests, and
carefully bounded features.

## Before opening a change

1. Read the [README](README.md), [threat model](docs/threat-model.md), and
   relevant operator documentation.
2. Keep product claims aligned with proof. A process check or heartbeat is not
   packet-level reachability evidence.
3. Do not include credentials, private infrastructure details, production
   captures, or customer data in issues, tests, commits, or screenshots.
4. Discuss large trust-model, storage, identity, routing, installer, or release
   changes before investing in an implementation.

## Development workflow

Create a branch from `main`, keep the diff focused, and run:

```bash
make docs-check
go test ./...
```

For security-sensitive changes, also run the relevant security and smoke gates
described in the README. Some system, packet, installer, and multi-replica
proofs require Linux capabilities, Docker, or dedicated target hosts and exit
with status 77 when their prerequisites are unavailable.

Public operator content lives in `docs/public-guide.json`; generate its HTML
instead of editing `internal/httpapi/web/docs.html`. API contracts live in
`internal/httpapi/openapi.go`; generate `docs/openapi.json` instead of editing
it directly.

## Pull requests

Explain the trust boundary, failure modes, compatibility impact, and evidence
for the change. Call out behavior that remains experimental, platform-limited,
or unproved. Include tests that fail without the change.

By contributing, you agree that your original contributions are licensed under
the repository's MIT License. Third-party code must retain compatible upstream
license and attribution requirements.

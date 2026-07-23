# Mesh repository instructions

## Public documentation

For every final approved change that affects users or operators, use `$update-mesh-docs` before declaring the change complete.

- Treat `docs/public-guide.json` as the canonical public documentation.
- Never edit `internal/httpapi/web/docs.html` directly; run `python3 scripts/generate-public-docs.py`.
- Treat `internal/httpapi/openapi.go` as the typed API route catalog and `docs/openapi.json` as its generated, canonical OpenAPI 3.1 artifact.
- For API behavior, schema, authentication, permission, or route changes, update the typed catalog and run `python3 scripts/generate-api-docs.py`.
- Update prerequisites, safe ordering, permissions, failure modes, and verification evidence affected by the change.
- Run `make docs-check` and `go test ./internal/httpapi`.
- The public and API documentation change gates must pass for user-facing and API-facing code changes.
- Do not publish secrets, private infrastructure details, or unproved behavior.

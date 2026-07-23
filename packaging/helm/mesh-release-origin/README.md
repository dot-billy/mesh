# Mesh release-origin Helm chart

This chart runs the existing digest-verifying `mesh-origin` courier in
Kubernetes. It does not author releases, hold signing keys, or turn the release
origin into a trust root.

The selected PVC must contain one inspected origin generation at its root:

```text
origin-index.json
generation.json
repository/
```

Populate that claim through an authenticated operator workflow before allowing
the Deployment to become ready. The application mounts the claim read-only,
opens only objects listed in the canonical index, and fails readiness if an
opened object changes.

Set an exact image repository and digest, a canonical HTTPS public origin, the
TLS Secret, and either `content.existingClaim` or storage settings for a
chart-owned claim. The TLS Secret must contain the configured certificate,
private-key, and CA-bundle keys. A bounded init operation validates the
projected identity and materializes owner-private regular files into an
`emptyDir`; the non-root origin consumes only that read-only result and does
not have to trust the symlink-based Secret projection. When an ingress proxy
verifies the native TLS backend, configure its backend SNI separately for
`publicHost`.

The bootstrap anchor is deliberately not stored in the PVC or served by this
chart. Transfer it through an independently administered channel.

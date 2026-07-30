# ADR 0003: Initial macOS operator distribution

- Status: accepted for engineering
- Date: 2026-07-23

## Decision

Use notarized direct distribution for the initial Mesh Admin for macOS
application. Keep the application sandbox enabled. Do not add Mac App Store
entitlements or distribution claims in the initial release.

## Consequences

The protected release job uses Developer ID Application signing,
notarization, stapling, Gatekeeper assessment, public re-download, and
digest-bound Mesh release metadata. The Mac App Store remains a separate
future channel because its receipt, entitlement, update, and local-integration
contracts differ.


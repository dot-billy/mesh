# ADR 0004: Darwin architecture artifacts

- Status: accepted for engineering
- Date: 2026-07-23

## Decision

Retain separate `darwin/arm64` and `darwin/amd64` Mesh Node artifacts.

## Consequences

Each artifact preserves its exact Mesh, Nebula, compiler, package-security,
native execution, signing, and notarization evidence. A universal package may
be reconsidered only after a new format binds both thin inputs and their
independent provenance without weakening release-manifest verification.


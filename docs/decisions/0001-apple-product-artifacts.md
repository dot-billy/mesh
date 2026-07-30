# ADR 0001: Apple product artifacts

- Status: accepted for engineering
- Date: 2026-07-23

## Decision

Build Mesh Admin for macOS and Mesh Node for macOS as two independently
installable artifacts released from one source release. Neither installer
invokes, embeds, enrolls, or grants authority to the other. Each can be held
back or revoked independently.

## Consequences

The operator application remains an unprivileged remote client. The node is a
root-managed system package. Release manifests, signing identities, receipts,
installation instructions, support status, and rollback decisions distinguish
the two artifacts. A coordinated release may publish either or both, but never
uses presence of one as evidence for the other.


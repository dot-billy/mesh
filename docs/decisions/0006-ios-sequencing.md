# ADR 0006: iOS delivery sequence

- Status: accepted for engineering
- Date: 2026-07-23

## Decision

Implement and release-qualify Mesh Admin for iPhone and iPad before beginning
the separately gated Packet Tunnel product implementation. A bounded runtime
feasibility spike may follow the operator source gate, but it cannot change
operator entitlements or support language.

## Consequences

Adding `desktop/ios` never configures VPN state, enrolls the device, or claims
node support. Mesh Tunnel has a separate target, entitlement, provisioning
profile, key boundary, release receipt, privacy declaration, and real-device
matrix.


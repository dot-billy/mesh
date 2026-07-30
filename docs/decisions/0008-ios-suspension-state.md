# ADR 0008: iOS suspension evidence

- Status: accepted for schema design
- Date: 2026-07-23

## Decision

Represent operating-system suspension as an explicit, non-healthy,
non-compromised lifecycle condition. It records the last authenticated
extension evidence and server receive time plus a bounded client-declared
transition. It never overloads heartbeat health, revocation, or quarantine.

## Consequences

Only fresh extension evidence can return a node to `tunnel-running`.
Client-supplied foreground/background labels are advisory. Missing evidence
advances through `stale` according to server policy; it cannot assert that
packets flow or that the device is compromised. Older servers and clients
ignore the additive mobile evidence until the mixed-version rollout gate is
passed.


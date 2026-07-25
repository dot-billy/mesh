# Active Probe Policy Gate Design

## Scope

This increment builds the fail-closed, no-I/O planning gate for the first
policy-aware ICMP overlay probe. It does not open a socket, emit a packet,
change runtime-telemetry schemas, or affect lifecycle health.

The gate consumes only a `Bundle` returned by `loadReconciledState`. That seam
has already verified the immutable active bundle, its Mesh signature, the live
host certificate, and the exact activated revision. Callers must not use an
unverified configuration string.

## Output

The gate returns a private plan containing:

- the single verified local IPv4 overlay address;
- at most eight numerically ordered remote lighthouse overlay addresses; and
- no endpoint, certificate, group, policy, or underlay data.

An empty target list is the future `not_eligible` result. A parser or topology
error is distinct: the policy could not be proved and must fail closed without
calling a probe executor.

## Target proof

A candidate target must:

1. appear in the strict signed `lighthouse.hosts` list;
2. appear as a canonical key in the strict signed `static_host_map` mapping;
3. be inside the local host certificate's one verified IPv4 network; and
4. match at least one exact outbound firewall rule that permits ICMP.

The generated static-host-map grammar is parsed narrowly. Duplicate sections,
duplicate keys, aliases, alternate YAML spellings, malformed quoting, invalid
addresses, and unexpected indentation fail closed. Underlay endpoint values
are validated only as the bounded quoted value emitted by Mesh and are never
returned.

## Firewall proof

Only the exact Mesh-rendered outbound firewall grammar is accepted. Rules have
the fixed `port`, `proto`, then selector layout. An ICMP request is eligible
only when:

- `proto` is `icmp` or `any`;
- `port` is `any`; and
- the selector is `host: any`, a canonical `cidr` containing the target, or
  the current quoted `group: "all"` form (with the exact historical unquoted
  `all` spelling retained for signed renderer-v1 compatibility).

Every Mesh-issued node certificate includes the canonical `all` group, so that
one group selector is provable for a Mesh-managed lighthouse. Other group
selectors are conservatively non-matching because the local signed bundle does
not expose the remote certificate's complete group set.

Inbound permission is not required for the echo reply. Nebula v1.10.3 checks
conntrack before the inbound rule table and records the accepted outbound
tuple, so the stateful reply is permitted only after the request itself passes
the proved outbound rule.

## Safety boundary

The planner has no network or process dependency and receives no executor.
Tests therefore prove policy-denied, inbound-only, missing-static-map, and
malformed inputs cannot emit a packet by construction. Linux ping sockets,
nonce/reply validation, deadlines, cancellation, 30-second rate limiting,
versioned result persistence, browser projection, and live packet proofs are
separate follow-on increments.

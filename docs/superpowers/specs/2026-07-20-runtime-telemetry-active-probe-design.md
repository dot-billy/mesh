# Runtime Telemetry Active Probe Design

## Decision

Mesh will add a versioned, policy-aware ICMP-to-lighthouse result beside the
existing passive Nebula observation. It will not embed probe state inside the
observer snapshot, create another control-plane endpoint, or promote the result
to lifecycle health.

The existing no-I/O policy gate remains the only source of targets. Linux gets
the first executor. Unsupported native platforms return an explicit
`unsupported` result and never emulate the contract with a subprocess, raw
socket capability, or loopback service.

## Contract boundary

Passive observation and active probing answer different questions:

- `observation` describes process-local Nebula handshake and authenticated-RX
  aggregates. Its v1/v2 version and process-continuity rules remain unchanged.
- `active_probe` describes one bounded ICMP attempt toward policy-eligible
  remote lighthouses. It has its own version and no process identity.

Keeping these as siblings prevents a probe-schema change from becoming a
Nebula process discontinuity. A higher-heartbeat transition derives process
continuity from `observation` only. An exact same-heartbeat retry must match
both values; changing either is equivocation.

The agent API envelope becomes:

```json
{
  "heartbeat_sequence": 19,
  "observation": { "version": 2, "state": "observed", "snapshot": {} },
  "active_probe": {
    "version": 1,
    "state": "attempted",
    "sample_age_ms": 0,
    "attempted": 2,
    "replied": 2,
    "duration_ms": 14
  }
}
```

`active_probe` uses one fixed object shape. `sample_age_ms` is either a
nonnegative integer or `null`; the three count/duration fields are always
present. This avoids state-dependent omitted-field ambiguity in strict JSON
clients.

Version 1 states and invariants are:

- `not_eligible`: the current signed policy permits no candidate or there is
  no remote lighthouse. `sample_age_ms` is `0`; all other numbers are zero.
- `unsupported`: this platform has no proved implementation.
  `sample_age_ms` is `null`; all numbers are zero.
- `capability_unavailable`: an eligible Linux plan exists, but the existing
  sandbox/host policy denied creation of the unprivileged ping socket.
  `sample_age_ms` is 0 through 30,000; all numbers are zero except bounded
  `duration_ms`.
- `attempted`: at least one and at most eight sends were attempted; `replied`
  is no greater than `attempted`; `duration_ms` is at most 6,000; and
  `sample_age_ms` is 0 through 30,000.
- `unavailable`: signed policy/topology could not be proved, the cadence
  journal was unreadable, the clock regressed, a changed plan is waiting for
  the packet-rate window, entropy failed, or execution had no sound result.
  `sample_age_ms` is `null`; all numbers are zero.

Only `attempted` with fewer replies than attempts is negative evidence. It is
still evidence about bounded ICMP exchange with configured lighthouses, not a
general node, application, handshake, or lifecycle-health result.

## Versioning and migration

The private state document advances to
`mesh-runtime-telemetry-state-v4`. Every v4 record requires `active_probe`.
Canonical state v3 documents migrate strictly by assigning the fixed
`unsupported` value; v1 and v2 retain their existing conservative observation
and continuity migrations and receive the same probe value. PostgreSQL uses a
new exact operation identity, `runtime_telemetry.state.migrate_v4`.

The administrator projection advances to
`mesh-runtime-telemetry-fleet-v4` and exposes the fixed probe object but no
target, local address, plan hash, nonce, packet bytes, socket error, or process
identity. The browser continues to accept exact fleet v2 and v3, mapping both
to `unsupported` legacy probe evidence, and accepts exact fleet v4 with strict
cross-field validation. Older strict fleet-v3 clients reject v4 and therefore
fail closed.

For server-first rolling upgrades, a new server accepts an old agent envelope
that omits `active_probe` and normalizes it to `unsupported` before storage. A
new agent posting the v4 field to an old strict server may lose only the
reconstructible telemetry report; its already accepted lifecycle heartbeat is
unchanged. Production rollout therefore upgrades servers before enabling new
agents.

## Agent data flow

After an accepted lifecycle heartbeat, the agent serially performs:

1. Reload and revalidate the immutable active signed bundle.
2. Take the existing passive observer sample; failure still becomes a fresh
   `unknown` observation.
3. Run the no-I/O probe planner against that same verified bundle.
4. Resolve the platform result and the durable cadence journal.
5. Post passive observation and active-probe result in one separately
   versioned telemetry report bound to the exact heartbeat.

Probe failure never changes the passive observation. Conversely, observer
failure does not prevent an independently sound probe result. Bundle/state or
HTTP failures still return from telemetry reporting without changing lifecycle
state, active configuration, service state, or quarantine policy.

## Durable cadence journal

The 30-second packet limit must survive agent restarts and `--once` execution.
Mesh therefore stores a separate, root-private, crash-durable active-probe
journal adjacent to the agent state. It is not part of the lifecycle state or
control backup. It contains only:

- exact journal schema v1;
- SHA-256 of the local-address/ordered-target plan, never the addresses;
- the UTC instant reserved for the last packet attempt; and
- the last fixed public probe result.

The journal has strict size, canonical JSON, owner/mode, regular-file,
no-symlink, atomic-replace, file-sync, and parent-directory-sync checks matching
the existing private state discipline.

Before opening a socket, the agent durably writes an `unavailable` reservation
with the current plan hash and attempt time. A crash after reservation cannot
cause a restart burst. After execution it durably replaces the reservation
with the result. If the final write fails, the report is `unavailable` while
the reservation continues to suppress packets.

Every lifecycle cycle re-evaluates signed eligibility:

- no targets returns a fresh `not_eligible` without touching the last packet
  reservation;
- unsupported platforms return `unsupported` without touching it;
- an eligible unchanged plan inside 30 seconds reuses a completed cached
  `attempted` or `capability_unavailable` result and increases
  `sample_age_ms`;
- an eligible changed plan inside 30 seconds returns `unavailable`, because an
  old target result is inapplicable and a new packet is not yet allowed;
- at or after 30 seconds, a new durable reservation precedes execution.

An invalid/future journal timestamp or wall-clock regression suppresses packet
I/O and returns `unavailable`; Mesh never solves clock uncertainty by sending
early. Missing journal state is the only create-new case. A corrupt existing
journal is not overwritten implicitly.

## Linux executor

Linux uses one `AF_INET`, `SOCK_DGRAM`, `IPPROTO_ICMP` ping socket bound to the
verified local overlay address. It retains the current empty capability
bounding set. `EACCES` or `EPERM` while creating/binding the socket maps to
`capability_unavailable`; Mesh never adds `CAP_NET_RAW`.

For each of at most eight ordered targets, once per execution:

- generate a fresh 128-bit random nonce;
- encode one ICMP echo request no larger than 64 bytes;
- use a unique bounded sequence number;
- wait at most 750 ms while honoring context cancellation; and
- accept only an echo reply with the exact source address, type, code,
  sequence, and nonce.

Targets are attempted sequentially under one six-second total deadline. A
send attempt increments `attempted` even when the kernel returns a routing or
send error; only a fully validated reply increments `replied`. Unrelated,
duplicate, malformed, late, and wrong-source packets are ignored within the
same target deadline. The implementation uses no shell, external `ping`, TCP,
UDP, HTTP, raw-socket capability, persistent secret, or underlay address.

Darwin and Windows compile a separate executor returning `unsupported` without
opening a socket.

## API and dashboard semantics

The fleet endpoint remains authenticated, query-free, no-store, bounded, and
separate from authoritative health. Its existing heartbeat-sequence binding
and server-time freshness checks apply before either observation is rendered.

The node's observational detail adds one explicit probe sentence:

- `ICMP probe not eligible under the active signed policy.`
- `ICMP probe unsupported on this platform.`
- `ICMP probe capability unavailable under the current host sandbox.`
- `Lighthouse ICMP replied from 2 of 2 attempts; sampled at least 8s ago.`
- `Lighthouse ICMP replied from 0 of 2 attempts; sampled at least 8s ago.`
- `ICMP probe evidence unavailable.`

The attempted labels always say `lighthouse ICMP`; they never say healthy,
reachable, online, connected, failed, or down. Feed, validation, clock, or
rendering errors clear observational evidence only. Health-alert promotion is
out of scope until the complete live failure matrix passes and receives a
separate design.

## Error and privacy rules

- Parser, journal, entropy, socket, send, receive, and protocol errors never
  enter the lifecycle heartbeat or `last_error` fields.
- The server validates every state/count/age combination and rejects malformed
  or equivocated reports with `Cache-Control: no-store`.
- The API, dashboard assets, logs, and audit details omit target/local IPs,
  underlay endpoints, plan hashes, nonces, packet bytes, raw socket errors,
  process identifiers, certificate data, and firewall rules.
- Local root can still spoof observations; the result is operational evidence,
  not an independent attestation.

## Verification

TDD coverage must prove:

- every result-state invariant and exact JSON shape;
- exact same-heartbeat idempotency/equivocation and higher-heartbeat process
  continuity independence;
- strict v1/v2/v3-to-v4 file and PostgreSQL migrations;
- old-agent missing-probe normalization and fleet-v3 browser fallback;
- journal permissions, symlink/nonregular rejection, canonical bytes,
  reservation-before-execution, restart/`--once` rate limiting, plan changes,
  clock regression, interrupted final writes, and cancellation;
- Linux socket error classification, request size, fresh nonces, exact reply
  validation, deadlines, target/cardinality bounds, and no subprocess;
- unsupported non-Linux builds;
- UI wording and continued prohibition on health/reachability claims; and
- races across the agent, telemetry store, and executor seams.

The privileged Linux namespace proof must use the production planner,
cadence journal, socket executor, agent report, server persistence, and fleet
projection. It must demonstrate:

1. signed ICMP denial yields `not_eligible` and an AF_PACKET/TUN capture sees no
   agent probe packet;
2. signed ICMP permission yields a validated lighthouse reply;
3. a second cycle inside 30 seconds emits no packet and preserves the original
   sample age;
4. a changed eligible plan inside the window is `unavailable` with no packet;
5. disallowed ping-socket policy yields `capability_unavailable` without added
   capabilities or subprocesses;
6. observer failure leaves the sound probe result intact and probe failure
   leaves passive observation semantics intact; and
7. cleanup removes all Mesh-owned processes, namespaces, mounts, journals, and
   temporary workspaces.

## Non-goals

This slice does not promote probe results into health, probe members or
application ports, add scheduled server-side probing, expose target identity,
change Nebula firewall policy, add a capability, support unsafe routes, or
claim native Darwin/Windows coverage.

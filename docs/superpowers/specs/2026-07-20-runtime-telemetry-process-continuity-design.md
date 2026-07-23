# Runtime Telemetry Process Continuity Design

## Purpose

Classify whether each accepted aggregate runtime observation continues the same
Nebula observer process, follows a process restart, or lacks enough immediately
prior evidence to decide. Classification must happen before the private process
identity is removed from the administrator projection and must never become a
lifecycle-health or reachability claim.

## Selected boundary

The runtime-telemetry persistence transition compares a new report only with
the currently stored report for that node. It derives and stores one enum:

- `unavailable`: the current observation is `unknown`.
- `unclassified`: the current observation is observed, but the immediately
  previous accepted record is absent or `unknown`.
- `continuous`: both records are observed from the same process instance and
  the new sample advances all monotonic fields.
- `restarted`: both records are observed and their process instance IDs differ.

An `unknown` report continues to replace the previous snapshot. The next
observed report is therefore `unclassified`; Mesh does not retain a hidden
historical snapshot to bridge an evidence gap.

## Alternatives rejected

Browser-side classification is impossible without exposing process identity,
which is outside the aggregate-only administrator contract. Agent-side
classification would trust a reporter-controlled label and would duplicate the
authoritative persistence transition. A separate private continuity-history
anchor could bridge `unknown` reports, but would preserve prior observation
state specifically where the current contract requires replacement with fresh
unknown evidence.

## Transition invariants

Heartbeat sequence remains the outer idempotency boundary:

- a lower heartbeat sequence is replay;
- the same heartbeat sequence accepts only the exact same observation and
  returns the already stored classification and receive time;
- a higher heartbeat sequence evaluates process continuity.

For two observed records with the same `process_instance_id`, the new report is
accepted as `continuous` only when:

- the observation version is unchanged;
- `sample_sequence` strictly increases;
- `process_uptime_ms` does not decrease;
- `handshakes.completed_total` does not decrease; and
- `handshakes.timed_out_total` does not decrease.

A same-process sample-sequence rollback or repeat is replay. Same-process
version, uptime, or counter rollback is a conflict. None replaces the accepted
record. Pending handshakes, current peer/lighthouse counts, and age values are
not monotonic and remain governed by their existing per-snapshot invariants.

When process instance IDs differ, the report is `restarted`; process-local
counters may reset. Mesh does not infer why or exactly when the process changed.

## Persistence and migration

`Record` gains a required `process_continuity` field. The authoritative state
schema advances from `mesh-runtime-telemetry-state-v2` to v3. Canonical v1 and
v2 documents remain accepted only through strict migration:

- migrated unknown observations become `unavailable`;
- migrated observed observations become `unclassified` because a single latest
  record cannot prove its previous transition.

File storage rewrites a migrated document durably on open. PostgreSQL uses a
new immutable migration operation identity and the existing exact-document
update/receipt path. The agent report schema does not gain a continuity field;
the server remains the sole derivation authority.

Memory, file, and PostgreSQL stores use one shared transition function so replay,
equivocation, classification, and rollback decisions cannot drift by backend.

## Administrator projection and browser

The fleet projection advances from v2 to v3 and includes the derived enum on
every record. It still omits `process_instance_id`. A new browser accepts exact
fleet v3 and exact legacy fleet v2:

- legacy observed v2 records are `unclassified`;
- legacy unknown v2 records are `unavailable`;
- old strict clients reject v3 and fail closed.

For a current, fresh observed sample, presentation adds one sentence describing
the enum. `continuous` confirms only monotonic evidence from the previous
accepted sample. `restarted` says the observer process changed and counters were
not compared across the boundary. `unclassified` says no immediately prior
observed sample was available. Labels and detail must not contain `healthy`,
`reachable`, or any process identifier.

## Error handling and security

Continuity failures use the existing replay/conflict HTTP mapping and `no-store`
response policy. Rejected reports do not mutate durable state. An unknown
observation remains valid and does not carry a snapshot or a reporter-supplied
classification.

The projection allowlist exposes only the enum. Tests must continue proving that
process instance IDs, keys, tokens, fingerprints, and local observer errors are
absent from API and browser assets.

## Acceptance evidence

The slice requires fresh proof of:

1. Shared memory/file/PostgreSQL transition parity for first, continuous,
   restarted, unknown-gap, idempotent, replay, version-switch, uptime rollback,
   and counter rollback cases.
2. Canonical v1/v2-to-v3 state migration and durable file/PostgreSQL rewrite.
3. Strict fleet v3 projection, exact v2 browser fallback, and process-identity
   omission.
4. UI wording for every classification without health or reachability claims.
5. Full Go tests, vet, targeted races, browser tests, and both live observer
   namespace proofs.


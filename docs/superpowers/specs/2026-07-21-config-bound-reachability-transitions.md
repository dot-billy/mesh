# Config-bound reachability transition design

Status: implemented and verified on 2026-07-21

## Outcome

The dashboard may explain whether the latest policy-eligible lighthouse ICMP
observation is stable, degraded, or recovered relative to the immediately
previous accepted heartbeat. It must never call that observation lifecycle
health or general end-to-end reachability.

## Binding and privacy boundary

- The control plane already accepts a lifecycle heartbeat only with one exact
  applied signed-configuration SHA-256. Runtime telemetry is authorized only
  for that exact current heartbeat sequence.
- The telemetry handler copies that already authenticated digest into the
  separate private observation record. The agent does not choose or submit a
  second plan identifier.
- The digest is never returned by the fleet telemetry API. The administrator
  projection exposes only the derived transition enum alongside the existing
  aggregate probe counts and explicit `end_to_end_reachability_proven=false`
  policy.
- A changed or missing digest breaks comparison. Equal target counts alone are
  never enough to infer recovery because a different signed lighthouse or
  firewall policy could have produced them.

## Transition semantics

The persisted `probe_transition` value is derived during the same atomic
record replacement as process continuity:

- `unavailable`: the current probe is unsupported, capability-unavailable, or
  unavailable;
- `not_eligible`: the exact signed firewall policy does not permit the probe;
- `unclassified`: the current probe was attempted, but no immediately previous
  heartbeat has an attempted result under the same nonempty configuration
  digest;
- `stable`: the same signed configuration produced the same attempted and
  replied counts;
- `recovered`: the same signed configuration previously had fewer replies than
  attempts and now has replies from every attempted lighthouse;
- `degraded`: the same signed configuration previously had complete replies
  and now has fewer replies than attempts;
- `changed`: the same signed configuration remains partial but its reply count
  changed.

Two attempted samples under one digest must have the same attempted count;
otherwise persistence rejects the report instead of inventing a transition.
Nonconsecutive heartbeat sequences break comparison because persist-before-send
can legitimately leave gaps and the missing heartbeat has no probe evidence.
An exact same-heartbeat retry must match observation, all probe siblings, the
configuration digest, and therefore the derived transition.

## Compatibility

`mesh-runtime-telemetry-state-v7` adds the private
`applied_config_sha256` and public-safe `probe_transition` fields. Canonical
v1 through v6 documents migrate with an empty digest and a transition derived
only from the current probe (`unavailable`, `not_eligible`, or
`unclassified`); migration never fabricates history.

`mesh-runtime-telemetry-fleet-v5` adds only `probe_transition`. Strict browser
clients continue accepting exact v2 through v4 records and derive the same
single-record compatibility value without claiming a cross-heartbeat change.

## Proof

Tests cover every transition, config-change reset, heartbeat-gap reset, attempted-count
conflict, exact retry/equivocation, v6 migration, file and PostgreSQL
round-trips, strict fleet-v5 projection, legacy browser compatibility, stale
presentation, and explicit non-health language. Existing real active-probe
packet tests remain the transport evidence; this slice classifies their
aggregate history and does not broaden what those packets prove.

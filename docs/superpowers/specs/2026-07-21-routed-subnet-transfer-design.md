# Routed-subnet ownership transfer

Status: implemented

## Problem

Nebula unsafe routes are both a routing decision and a certificate authorization.
Changing only the control-plane owner would publish a route through a gateway
whose current certificate may not authorize it, while changing the certificate
first and publishing the route immediately can create an unobserved cutover.

The control plane therefore needs a staged, resumable transfer that preserves one
published owner until the replacement gateway has installed and reported the
required certificate profile.

## Scope and invariants

The first implementation transfers one or more exact IPv4 prefixes between two
distinct active nodes in the same network. Only one transfer may be in flight per
network. ECMP and partial-prefix splitting are out of scope.

- Every prefix is canonical, currently owned by the source, and transferred as an
  exact string; the destination's final prefix set remains canonical,
  non-overlapping, and within the eight-prefix node limit.
- Start is bound to the visible network configuration revision and a 16-128
  character request ID. Repeating the same request is write-free; reusing the ID
  for different input is rejected.
- The source remains the sole published route owner during destination prepare.
- The destination's signed desired config includes the staged prefixes in its
  local firewall expansion and omits those same unsafe routes so it cannot loop
  replacement-LAN traffic back through the source. Every other node still
  receives unsafe routes through the source.
- A separately signed `certificate_profile_renewal_required` flag causes only the
  affected agent to renew early. It is not overloaded onto CA-rotation metadata.
- Promotion is refused until a healthy destination heartbeat proves the exact
  authoritative certificate generation, fingerprint, config revision, and
  config digest.
- Promotion atomically moves durable ownership and advances the signed config
  revision. Peers then route through the destination while the source is forced
  to renew a certificate without the transferred prefixes.
- Completion is refused until the source reports the cleaned certificate and
  current signed config.
- A prepare may be abandoned without cleanup only before the expanded destination
  certificate was issued. Once issued, cancellation itself is a staged cleanup
  and is complete only after the destination reports its original profile.
- CA rotation, firewall rollout, administrator certificate rotation, identity
  replacement, revocation, and archival are fenced for participating nodes or
  networks while a transfer is active.

## State machine

`preparing_target` -> `cleaning_source` -> `completed`

The operator starts the transfer, waits for destination readiness, and advances
it. The second advance completes it after source cleanup convergence. Reads are
always available, so a lost mutation response is recovered by reading the
authoritative transfer.

Cancellation is:

- `preparing_target` -> `cancelled` when no expanded destination certificate was
  issued; or
- `preparing_target` -> `cleaning_target` -> `cancelled` after issuance.

Completed and cancelled receipts are retained on the network until the next
transfer starts. A new start may replace only a terminal receipt.

## API

- `GET /api/v1/networks/{networkID}/route-transfer`
- `POST /api/v1/networks/{networkID}/route-transfer`
- `POST /api/v1/networks/{networkID}/route-transfer/advance`
- `POST /api/v1/networks/{networkID}/route-transfer/cancel`

The start body contains `source_node_id`, `target_node_id`, `routed_subnets`,
`expected_config_revision`, and `request_id`. Advance and cancel contain the
same `request_id` and the caller's `expected_config_revision` so stale dashboard
actions fail closed.

Responses contain no credentials or certificate bodies. They expose phase,
route set, source/target identities, desired certificate generations, current
network revision, convergence facts, and timestamps.

## Failure behavior

An offline destination leaves the source route published indefinitely. An
offline source after promotion leaves the destination route published while the
source cleanup remains visibly incomplete. No timeout silently promotes,
cancels, or completes a transfer. Every transition is audited with actor,
request ID, route set, generations, and revision.

## Verification

Tests prove exact-request replay, stale-revision rejection, route and node
validation, signed early-renewal metadata, prepare rendering, renewal with the
staged certificate profile, convergence-gated promotion, peer route cutover,
source cleanup, safe cancellation, lifecycle fences, and persistence migration.
The dedicated Linux smoke uses three original real-Nebula processes and one
non-Nebula routed host. It exercises both agent-facing renewals, exact heartbeat
gates, source-preserving prepare traffic, atomic promotion, target-routed traffic
with source forwarding disabled, terminal replay, and exact cleanup without
touching the separately running preview service.

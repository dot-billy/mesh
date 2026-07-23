# Active gateway routed-prefix editing

Status: implemented and verified

## Problem

An active gateway's routed prefixes are simultaneously durable ownership,
peer-side Nebula unsafe routes, gateway firewall `local_cidr` coverage, and
certificate unsafe-network authorizations. Updating only one representation can
publish an unauthorized route, retain unwanted authorization, or interrupt an
existing LAN while a replacement certificate is still pending.

The control plane therefore treats an active prefix-set edit as a crash-durable,
optimistic state machine rather than an ordinary node update.

## Scope and invariants

The first implementation replaces the complete exact IPv4 routed-prefix set of
one active, enrolled node. It supports adding the first prefix, additions,
removals, mixed add/remove edits, and removing the final prefix. The existing
eight-prefix limit, canonical ordering, special-range rejection, and graph-wide
overlap rules remain authoritative.

- A 16-128 character request ID and the visible network configuration revision
  bind every start. Exact replay is write-free; conflicting reuse is rejected.
- The requested final set is reserved immediately, including additions that are
  not yet published, so no concurrent network or node can claim an overlapping
  range during prepare.
- An added prefix may not overlap an original prefix, and the temporary union
  may not exceed eight prefixes. Those transitions must complete removals first
  and then start additions, because there is no safe bounded union artifact.
- An edit and a routed-subnet ownership transfer are mutually exclusive within
  one network. CA rotation and firewall rollout are also fenced.
- Additions are certificate-first. The owner receives a signed forced-renewal
  command for the union of its original and final prefixes while peers continue
  to receive only the original published routes.
- Promotion is unavailable until a healthy heartbeat proves the exact prepared
  generation, fingerprint, signed revision, config digest, and running runtime.
- Promotion atomically installs the requested durable set and advances the
  signed revision. Add-only edits are then certificate-complete.
- Removals are route-first. Peer routes are withdrawn before the owner is forced
  to renew a certificate containing only the requested final set. Removal-only
  edits therefore enter cleanup immediately at start; mixed edits enter cleanup
  after certificate-first promotion.
- Completion after any removal is unavailable until the owner proves its exact
  cleaned certificate and current signed config.
- Cancellation is available only before promotion. If the staged certificate
  was not issued, cancellation clears prepare in one revision. If it was issued,
  cancellation forces a second renewal back to the original set and remains
  incomplete until the owner proves cleanup convergence.
- Node revocation, identity replacement, administrator certificate rotation,
  and archival are fenced while that node participates in an active edit.

## State machine

Add-only:

`preparing_owner` -> `completed`

Removal-only:

`cleaning_owner` -> `completed`

Mixed add/remove:

`preparing_owner` -> `cleaning_owner` -> `completed`

Prepare cancellation is either:

- `preparing_owner` -> `cancelled` before staged issuance; or
- `preparing_owner` -> `cleaning_cancelled_owner` -> `cancelled` after issuance.

Completed and cancelled receipts remain readable until a new edit starts.
Reads never mutate state, and no timeout automatically promotes, completes, or
cancels an edit.

## API and dashboard

- `GET /api/v1/nodes/{nodeID}/route-profile`
- `POST /api/v1/nodes/{nodeID}/route-profile`
- `POST /api/v1/nodes/{nodeID}/route-profile/advance`
- `POST /api/v1/nodes/{nodeID}/route-profile/cancel`

Start contains `routed_subnets`, `expected_config_revision`, and `request_id`.
Advance and cancel repeat the exact request ID and current revision. Responses
use schema `mesh-node-route-profile-edit-v1` and expose only non-secret identity,
original/final prefix sets, additions/removals, phase, revision, desired/current
certificate generations, convergence, timestamps, and available actions.

The dashboard edits the complete set, shows the computed additions/removals
before confirmation, displays authoritative convergence, and renders only
actions returned by the server. Ambiguous responses are recovered through a
readback bound to the retained request ID.

Terminal advance/cancel retries accept only the current or immediately previous
revision bound to that same receipt. This makes a lost response replay
write-free even when the successful transition advanced the network revision.

## Verification

Tests cover the v9-to-v10 write-free migration, no-op and graph conflicts,
reserved staged additions, add-only, removal-only, mixed edits, signed staged
and cleanup certificates, exact convergence gates, pre/post-issuance
cancellation, response replay, lifecycle fences, strict HTTP handling, and
fail-closed dashboard parsing. `make route-profile-smoke` additionally withdraws
and restores one real routed LAN through real agents and Nebula 1.10.3 in
isolated namespaces. It proves route-first packet withdrawal, certificate-first
unpublished preparation, convergence-gated promotion, restored packets,
unchanged Nebula process identities, and byte-identical terminal replay. The
existing route-transfer proof remains green, and the separately running preview
is not restarted or mutated.

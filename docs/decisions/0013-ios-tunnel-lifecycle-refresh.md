# ADR 0013: Extension-owned pre-start iOS Tunnel lifecycle refresh

- Status: accepted for source implementation; device convergence pending
- Date: 2026-07-25

## Decision

Every start with an existing authenticated configuration must first run one
agent-authenticated lifecycle refresh inside the Packet Tunnel extension. The
containing app does not receive the node private key, agent credential, signed
configuration, or refresh result.

The lifecycle session opens only the existing extension-only `primary`
private-key and agent-credential items. It never creates either item and never
exports either secret. Before network access it normalizes the stored
control-plane origin, verifies that the current canonical
`mesh-ios-tunnel-configuration-v4` document names that exact origin, and
revalidates the signed configuration against the existing local private key.
It then authenticates `GET /api/v1/agent/bootstrap` with the derived agent
bearer.

The exact `mesh-ios-lifecycle-refresh-v1` result has three statuses:

- `ready` carries one fully revalidated v4 configuration for the same node,
  network, and origin with nondecreasing certificate, agent-credential, and
  configuration generations and the caller's next monotonic counter;
- `deferred` carries no configuration and is permitted only for transport
  failure, HTTP 429, or HTTP 5xx, allowing startup to use the still-valid
  current configuration; and
- `unauthorized` carries no configuration and fails startup closed.

Every other HTTP response, malformed or untrusted current state, origin or
identity substitution, generation rollback, invalid returned configuration,
missing credential, or failed monotonic activation fails startup closed. A
ready result is staged and atomically activated before engine construction.

## Consequences

The extension has a bounded pre-start desired-state convergence point without
placing node authority in the containing app or treating transient control
plane unavailability as revocation. A 401 cannot be hidden by stale local
state, while a bounded network/service failure does not discard an otherwise
valid configuration.

This is not continuous heartbeat, background monitoring, automatic timer-based
renewal, credential rotation, permanent-revocation erasure, response-loss
recovery, or evidence that iOS executed the Network Extension. Those behaviors
remain separate server, extension, physical-device, and release gates. Source,
simulator, signed-archive, and TestFlight-upload evidence does not establish
installed-device lifecycle convergence or a supported tunnel.

ADR 0014 subsequently defines source implementations for renewal, credential
rotation, bounded runtime evidence, quarantine, and explicit local identity
removal. Their physical-device and support gates remain open.

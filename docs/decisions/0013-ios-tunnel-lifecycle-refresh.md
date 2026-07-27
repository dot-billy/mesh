# ADR 0013: Host-side pre-start iOS Tunnel lifecycle convergence

- Status: amended for controlled-beta source implementation; device convergence pending
- Date: 2026-07-25
- Amended: 2026-07-27

## Decision

Immediately before it calls `startTunnel()`, the containing app opens a narrow
Go lifecycle session and refreshes the already installed authenticated
configuration. That session uses the shared device-only Keychain items in
place; it does not export the node private key or agent credential. The host
receives only the exact typed refresh outcome and may atomically install its
verified replacement configuration.

Apple's Packet Tunnel start callback then uses only that installed local
configuration and bounded local engine operations. It must not wait for
control-plane refresh or runtime-report HTTP requests. After Apple accepts the
settings, the Nebula engine starts, the lifecycle generation commits the
running coordinator, and the start completion handler succeeds, the extension
may begin agent-authenticated runtime reporting.

The lifecycle session opens only the existing shared device-only `primary`
private-key and agent-credential items. It never creates either item and never
exports either secret. Before network access it normalizes the stored
control-plane origin, verifies that the current canonical
`mesh-ios-tunnel-configuration-v4` document names that exact origin, and
revalidates the signed configuration against the existing local private key.
It then authenticates `GET /api/v1/agent/bootstrap` with the derived agent
bearer.

The `mesh-ios-lifecycle-refresh-v1` contract is used by the host before each
normal start or recovery start. Its exact result has three statuses:

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

The extension no longer holds Apple's `.connecting` state open on
control-plane availability. The host completes refresh before asking Apple to
start; the provider then validates the installed site locally, applies
settings, starts Nebula, and begins runtime reporting only after completing the
Apple callback. A verified unauthorized refresh fails before provider start. A
verified unauthorized or refresh-required runtime response may still
quarantine and stop a running session.

This ordering is source-tested, but it is not evidence that iOS executed the
Network Extension or that refresh and packet flow work on a device. Source,
simulator, signed-archive, and TestFlight-upload evidence does not establish a
supported tunnel.

ADR 0014 subsequently defines source implementations for renewal, credential
rotation, bounded runtime evidence, quarantine, and explicit local identity
removal. Their physical-device and support gates remain open.

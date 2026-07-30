# ADR 0014: Shared-custody iOS runtime lifecycle and local identity removal

- Status: accepted for source implementation; physical-device convergence pending
- Date: 2026-07-25

## Decision

Mesh Tunnel extends the shared host-and-extension boundary from the lifecycle
convergence contract in ADR 0013 to four narrowly scoped responsibilities.
ADR 0013's 2026-07-27 amendment moves refresh into the containing app before
provider start and keeps Apple's provider callback local. The four
responsibilities are:

1. certificate renewal using the existing shared device-only private key;
2. crash-recoverable agent-credential rotation;
3. bounded, authenticated mobile runtime evidence; and
4. explicit local identity removal.

The containing app never receives the node private key, current or pending
agent credential, or raw lifecycle HTTP result. Its narrow Go session uses
Keychain secrets in place and returns only a verified signed configuration or
an exact typed outcome.

### Certificate renewal

After authenticating and verifying bootstrap state, the lifecycle session
renews through `POST /api/v1/agent/certificate/renew` when the server requires
a CA or profile transition or the signed renewal time is due. It submits the
existing public key, requires a strictly newer certificate generation,
revalidates the complete returned configuration, and keeps node, network,
origin, public-key, and signing-key identity fixed.

An ambiguous response permits one exact retry followed by authenticated
bootstrap recovery. Ordinary due renewal may defer for transport failure,
HTTP 429, or HTTP 5xx while the current certificate remains valid. A mandatory
CA or profile transition never falls back to the old certificate.

### Agent-credential rotation

The host lifecycle session rotates an agent credential when its authenticated expiry is
within seven days. It creates one 32-byte pending secret in a fixed shared
host-and-extension, device-only Keychain item before the request and sends only
its SHA-256 hash. The current bearer authorizes the initial
`POST /api/v1/agent/credentials/rotate`; an ambiguous response is recovered
with the pending bearer and the same hash. The primary Keychain item changes
only after an exact newer generation and bounded future expiry are verified,
then the pending item is deleted. Restart recovery handles either side of that
commit without exporting either bearer.

### Mobile runtime evidence

While the extension is scheduled, it reports at a 60-second cadence through
`POST /api/v1/agent/mobile-runtime`. The strict v1 document binds extension
instance generation, monotonic sequence, state, configuration revision and
digest, certificate fingerprint and generation, engine identity, monotonic
runtime uptime, optional packet counters, and one bounded fixed error code.
The server records its own receive time in the nonauthoritative runtime
telemetry store and exposes a per-node projection. Ordinary reports use a
two-minute freshness bound; an explicit `suspended` report uses a 15-minute
bound because iOS may not immediately reschedule the extension.

Missing or stale evidence never becomes health. Suspension reporting is
best-effort because iOS may stop scheduling the extension. A generic HTTP 401
can mean an expired, rotated, or revoked credential; the client therefore
quarantines rather than claiming server revocation. Only authoritative server
state may label a node `revoked`.

An authenticated desired-state mismatch returns `refresh-required`. The
current source stops the active tunnel and requires the next start to perform
the full verified refresh and activation path. It does not hot-reload an
active engine in place.

### Local identity removal

The containing app exposes one destructive action that displays and requires
confirmation of the exact authenticated local node and network. It sends a
strict request containing a fresh request ID and the exact node ID. The
extension re-authenticates the current App Group envelope against its real
anti-rollback floor before deleting anything.

The deletion-only gomobile session attempts all three fixed shared device-only
Keychain removals: current agent credential, pending agent credential, and
node private key. It has no load, return, replace, or create operation. Only
after all authority deletions succeed does the extension erase the
candidate/current/recovery configuration slots and return a bounded,
non-secret receipt. A partial Keychain failure retains the authenticated
configuration context so the same exact removal can be retried safely. The
host removes the VPN preference only after confirmed local completion.
Each terminal cleanup owns a completion barrier. A concurrent Apple stop
awaits that barrier before reopening the provider lifecycle, so stale cleanup
cannot mutate a later start.

The handoff HMAC key and lifecycle high-water values are intentionally
retained. They are not node authority, and retaining them preserves local
authentication and rollback floors if the device is re-enrolled. Local
identity removal does not revoke or delete the server-side node; those remain
separate administrator operations.

## Consequences

Framework identity advances to `mesh-ios-mobile-framework-v5`. Its exact
capability is
`extension-enrollment-lifecycle-renewal-credential-rotation-mobile-evidence-identity-removal-signed-config-packet-session`.
Receipt gates require the runtime-report and identity-removal exports and
hash every engine source file plus the shared mobile-runtime contract.

The source now defines the intended renewal, rotation, evidence, quarantine,
and removal behavior without broadening the containing app's secret
authority. Simulator contracts, reproducible framework output, static-link
symbols, and unsigned security evidence do not prove iOS scheduling, physical
Keychain access groups, Network Extension execution, server convergence,
packet cutoff, or secure deletion on an iPhone or iPad. Those physical tests
remain mandatory before support.

The previously uploaded TestFlight `0.1.0 (1)` artifact contains the earlier
framework-v4 pre-start lifecycle implementation. This ADR does not authorize a
new signed build or upload.

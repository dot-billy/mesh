# ADR 0012: Provision-first iOS Tunnel enrollment

- Status: amended for source implementation; device and security approval pending
- Date: 2026-07-25
- Amended: 2026-07-27

## Decision

The containing application completes node provisioning before it asks iOS to
start the Packet Tunnel. This follows Mobile Nebula's provision-first,
connect-second lifecycle: authenticate the user, select an authorized network,
obtain one fixed-policy self-enrollment, create and validate the local Nebula
site, activate it durably, then call normal `startTunnel()` with no enrollment
options. The provider starts only from the authenticated current
configuration. Enrollment is never a provider-start operation.

The containing app may persist only one canonical HTTPS control-plane origin
in `NETunnelProviderManager`. It keeps the one-use token in memory, sends it
only to the narrow in-process Go enrollment session, and never writes it to
VPN preferences, the App Group, logs, diagnostics, UserDefaults, or a receipt.
Before the server mutation it re-enumerates and reloads the exact manager,
requires enabled/same-origin/schema-valid/on-demand-disabled state, and proves
that no configuration slot or Keychain authority already exists.

The Go enrollment session performs the token-scoped no-store preflight before
creating or reading node credentials. iOS accepts only an unexpired member
plan with at least one lighthouse. Every planned lighthouse name must resolve
locally to a usable underlay address outside the planned overlay before the
one-use token can be consumed.

After preflight, the Go mobile framework creates or loads two independent,
stable, host-and-extension-shared, non-synchronizing,
after-first-unlock-this-device-only Data Protection Keychain items:

- the raw X25519 node private key; and
- a 32-byte agent credential seed.

Only the enrollment token, derived public key, and hash of the derived agent
bearer cross the network enrollment boundary. Neither local secret is returned
through gomobile or Swift. An ambiguous self-enrollment response permits one
same-principal, same-device-name retry; the Go consuming request separately
permits one byte-identical replay followed by authenticated bootstrap recovery
using the device-owned agent bearer.

The framework accepts no configuration until it has strictly validated the
returned member/node/network identity, certificate and local-key match, CA and
configuration digests, signed metadata, lifecycle times, generation and
revision, preflight network and lighthouse binding, signed routes, native DNS
policy, and usable underlay endpoint. It returns only the verified canonical v4
engine configuration. The containing app allocates the next counter from the
maximum of the authenticated current slot and shared Keychain high-water
value, then stages and atomically activates that configuration. Only after
activation does the host refresh the site through its narrow lifecycle session
and create one exact, Keychain-backed start authorization. It then starts the
provider with only that authorization. The provider consumes it, reloads the
installed site, and performs only local settings and Nebula startup work.

The stable Keychain account is `primary`, not the post-enrollment node ID.
This lets pre-enrollment identity creation and later engine startup address the
same device-only item. The containing app is entitled to the identity group
only so its narrow Go session can provision the site; no Swift surface can
read either secret.

The self-enrollment mutation through local activation is protected from
ordinary background cancellation. On relaunch, an authenticated same-origin
candidate is activated locally before any network request only when it matches
a device-only initial-enrollment intent containing the exact origin, node, and
network. If only complete non-rotating Keychain authority remains and the
server commit succeeded, the existing agent credential performs one
authenticated bootstrap and the complete returned site must match that same
intent before installation. Recovery returns an exact versioned
`ready`, `deferred`, or `unauthorized` outcome. Only `ready` carries a
configuration; the other outcomes preserve authority and never trigger a new
token. A pending server node whose commit did not complete still requires
explicit administrator reconciliation. Crash/restart therefore remains an
installed-device qualification gate, not a retry-safe release claim. After
administrator review, terminal incomplete or unauthorized authority can be
deleted only through a destructive local confirmation that also removes the
saved VPN preference; deferred recovery does not expose that reset.
An authenticated current configuration that disagrees with a retained intent
cannot load or start. The host may still authenticate and inspect that current
configuration solely to offer its exact-node destructive removal; it clears
the mismatched intent only after provider-confirmed deletion. A missing or
disabled VPN preference is created or re-enabled with the exact authenticated
origin only after that confirmation and only to launch deletion; it is removed
after completion.

## Consequences

The App Group remains an authenticated configuration transport, not a
credential store. A device with an active configuration or any orphaned local
authority rejects enrollment; identity replacement is not an implicit
reconnect operation. The provider rejects every enrollment-bearing start
option.

This decision authorizes source and simulator compile/link evidence only. It
does not authorize live enrollment, production signing, upload, distribution,
or a support claim. Physical iPhone/iPad proof must validate the registered
Keychain access group, lock/unlock behavior, Network Extension scheduling,
actual one-use response-loss recovery, Apple settings, UDP and packet paths,
roaming, renewal, rotation, revocation, and resource use.

Secure identity removal remains a separate required design for logout, server
node deletion, permanent revocation, reinstall, and device transfer. Until
that design and the physical lifecycle matrix pass, Mesh Tunnel remains an
unsupported engineering proof.

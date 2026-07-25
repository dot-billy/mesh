# ADR 0012: Extension-owned iOS Tunnel enrollment

- Status: accepted for source implementation; device and security approval pending
- Date: 2026-07-25

## Decision

The Packet Tunnel extension owns iOS node enrollment and every node secret.
The containing app may persist only one canonical HTTPS control-plane origin
in `NETunnelProviderManager`. When the operator supplies a one-use enrollment
token, the app creates one strict `mesh-ios-tunnel-enrollment-v1` document and
passes its bytes as the sole `startTunnel(options:)` value. It clears the
transient token before control returns and never writes it to VPN preferences,
the App Group, logs, diagnostics, or Flutter state.

When no current authenticated configuration exists, the extension strictly
decodes that request and performs the token-scoped no-store preflight before
creating or reading node credentials. iOS accepts only an unexpired member
plan with at least one lighthouse. Every planned lighthouse name must resolve
locally to a usable underlay address outside the planned overlay before the
one-use token can be consumed.

After preflight, the Go mobile framework creates or loads two independent,
stable, extension-only, non-synchronizing,
after-first-unlock-this-device-only Data Protection Keychain items:

- the raw X25519 node private key; and
- a 32-byte agent credential seed.

Only the enrollment token, derived public key, and hash of the derived agent
bearer cross the network enrollment boundary. Neither local secret is returned
through gomobile. An ambiguous consuming response permits one byte-identical
replay, followed by authenticated bootstrap recovery using the extension-owned
agent bearer.

The framework accepts no configuration until it has strictly validated the
returned member/node/network identity, certificate and local-key match, CA and
configuration digests, signed metadata, lifecycle times, generation and
revision, preflight network and lighthouse binding, signed routes, native DNS
policy, and usable underlay endpoint. It returns only the verified canonical v4
engine configuration. The extension allocates the next counter from the
maximum of the authenticated current slot and extension-only Keychain
high-water value, then stages and atomically activates that configuration
before starting the engine.

The stable Keychain account is `primary`, not the post-enrollment node ID.
This lets pre-enrollment identity creation and later engine startup address the
same extension-only item without disclosing the private key to the containing
app.

## Consequences

Flutter and the containing app are outside the node-secret and signed-state
authority boundary. The App Group remains an authenticated configuration
transport, not a credential store. A device with an already active
configuration rejects a new enrollment start option; identity replacement is
not an implicit reconnect operation.

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

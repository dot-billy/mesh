# ADR 0007: iOS Nebula runtime

- Status: accepted for controlled-beta physical qualification
- Date: 2026-07-27

## Decision

Build a bounded Mesh/Nebula Go mobile framework from Mesh's exact pinned
Nebula source revision and reviewed patch set. The framework exposes narrow
engine, lifecycle, configuration, evidence, enrollment, identity-removal, and
public-key sessions to the containing app and Packet Tunnel Provider. It does
not expose the node private key or agent credential to Swift or Flutter.

Production iOS engine sessions follow Mobile Nebula's native transport. Inside
the Packet Tunnel process, Go discovers the `AF_SYSTEM`
`com.apple.net.utun_control` descriptor that Network Extension created and
constructs Nebula with `overlay.NewFdDeviceFromConfig`. Swift applies the
authenticated Apple network-settings plan but does not copy tunnel packets.

## Consequences

The framework receipt binds the upstream source URL and commit, Go and mobile
tool versions, Apple SDK, deployment target, architectures, build flags,
module graph, licenses, source digests, output slices, symbols, and
reproducibility result. No source or binary from a local reference checkout is
an input. The decision must be revised if the engine needs subprocesses,
executable memory, unsupported sockets, forbidden APIs, or unacceptable
resource use.

The current framework pins Nebula 1.10.3. It creates or reads one shared,
device-only Keychain identity, returns only its public key, reports non-secret
framework identity, and constructs one non-restartable engine session. ADR
0012 defines the host-owned enrollment and recovery session. ADR 0013 defines
existing-credential lifecycle refresh. ADR 0014 defines runtime evidence and
confirmation-gated local identity removal. Enrollment remains provision-first:
the host installs a verified signed configuration before normal provider
startup.

The production engine accepts only the exact signed v4 configuration, verifies
it against the Keychain private key, discovers the provider-owned `utun`
descriptor, gives that descriptor to Nebula's upstream iOS FD device, starts
Nebula, supports UDP rebind, and stops idempotently. The scan is confined to
descriptors 0 through 1024, validates the control ID with `CTLIOCGINFO`, and
returns no descriptor, packet, path, or credential to Swift.

Apple documents packet reads and writes through
[`NEPacketTunnelFlow`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow).
The production
[`DefinedNet/mobile_nebula`](https://github.com/DefinedNet/mobile_nebula)
implementation instead identifies the provider's `utun` control descriptor
and passes it to Nebula. Mesh originally built an `overlay.UserDevice` callback
bridge to stay on the documented Swift surface. Repeated physical builds did
not produce a working packet path. The controlled-beta successor therefore
adopts Mobile Nebula's native transport rather than maintaining a second iOS
packet architecture.

The in-memory `overlay.UserDevice` adapter remains only as a deterministic
host-test fixture. Unit tests prove packet validation, ownership, bounds,
backpressure, closure, and both directions. A native-host test runs two pinned
Nebula engines through that fixture over actual loopback UDP and proves
certificate-authenticated direct packets, rebind, and clean shutdown. Those
tests continue to validate Nebula behavior without making the callback bridge
the production iOS transport.

The host also follows Mobile Nebula's manager enable, save, reload, and normal
start lifecycle. The provider adds single-flight start, stop-race protection,
exact Keychain-backed start authorization, signed-configuration validation,
and post-connect control-plane reporting. A tested runtime coordinator
enforces engine identity, engine preparation, Apple settings, and engine start
in that order. Native-`utun` mode does not start the Swift packet pump and
rejects callback send or receive calls. Partial startup, rebind failure, and
stop run reverse cleanup.

The authenticated payload contains a data-only address, route, DNS, MTU, and
remote-endpoint plan. Swift accepts only canonical usable-unicast values,
network-aligned routes, bounded collections, and MTU 1280 through 1500. The
remote underlay endpoint cannot equal an overlay address and must be excluded
when an included route would otherwise capture it. These checks are source
contracts, not evidence that a physical device accepted the settings.

This ADR authorizes the upstream-aligned runtime for controlled-beta physical
qualification. Reproducible framework builds, static linkage, simulator
compilation, and source tests do not establish a working VPN. Physical
provider start, lighthouse reachability, authenticated peer traffic, roaming,
sleep/wake, and resource measurements remain required before support claims.

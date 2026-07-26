# ADR 0007: iOS Nebula runtime

- Status: accepted for feasibility implementation only
- Date: 2026-07-23

## Decision

Build a bounded Mesh/Nebula Go mobile framework from Mesh's exact pinned
Nebula source revision and reviewed patch set. The framework exposes a narrow
packet-flow, lifecycle, configuration, evidence, and public-key API to the
Packet Tunnel Provider. It does not expose the node private key to Swift or
Flutter.

## Consequences

The feasibility receipt must bind the upstream source URL and commit, Mesh
patch digest, Go and mobile tool versions, Apple SDK, deployment target,
architectures, build flags, module graph, licenses, output slices, symbols,
and reproducibility result. No source or binary from a local reference checkout
is an input. The decision must be revised if the engine needs forbidden APIs,
subprocesses, executable memory, unsupported sockets, or unacceptable resource
use.

The current source proof advances beyond the initial custody subset. It
reproducibly builds the exact pinned Nebula 1.10.3 module into a framework that
creates or reads an extension-only device Keychain identity, returns only its
public key, reports non-secret framework identity, and constructs one bounded
engine session. ADR 0012 adds one separate single-method enrollment session
that owns preflight, extension-only agent custody, enrollment/recovery, and
verified v4 configuration production without exporting either local
credential. ADR 0013 adds a separate existing-credential lifecycle session
that performs one agent-authenticated desired-state refresh before later
starts and returns only a ready, deferred, or unauthorized result. The engine
session accepts that exact signed v4 configuration,
starts Nebula on the in-memory packet device, rebinds its UDP listener, copies
validated packet callbacks in both directions, and stops idempotently. The
unsigned simulator source build binds the exact framework receipt and
statically links the archive into the extension; it embeds no dynamic engine
framework.

Packet transport remains an explicit feasibility question. Apple's documented
[`NEPacketTunnelFlow`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)
surface provides packet read/write operations. The current
[`DefinedNet/mobile_nebula`](https://github.com/DefinedNet/mobile_nebula)
implementation discovers a utun descriptor rather than receiving one from the
documented Packet Tunnel flow API. Mesh has not adopted or approved that
technique.

Mesh nevertheless treats the official Mobile Nebula application as a
behavioral reference for Network Extension lifecycle. The successor host
source follows its manager reload, enable, save, reload, then start sequence
when iOS retains a disabled VPN preference, while the provider adds equivalent
single-flight start and stop-race protection. This convergence is intentionally
limited to lifecycle behavior and does not adopt utun-descriptor discovery.

Pinned Nebula 1.10.3 also exports `overlay.UserDevice`, an in-memory packet
device intended for an embedding caller. Mesh has a bounded adapter that
validates and copies complete IPv4/IPv6 packets between that device and the
exported engine session. Unit tests prove both directions, ownership, packet
bounds, malformed-length rejection, and close behavior. A native-host test
then runs two real pinned Nebula engines through that callback device over
actual loopback UDP, proves certificate-authenticated bidirectional direct
packets with empty relay state, proves another packet after Nebula's mobile UDP
rebind, and repeats clean shutdown after adapting the upstream close error to
Nebula's production-loop contract. This removes the need to assume a utun file
descriptor and proves the engine-side UDP/callback composition on Darwin. The
Swift packet pump and provider source now implement bounded backpressure,
cancellation, and static engine linkage for a universal simulator build. This
still does not prove an executed Network Extension callback, accepted interface
settings, iOS UDP operation, resources, or physical packet flow.

The Swift source boundary now validates an authenticated address, route, DNS,
MTU, and remote-endpoint plan and tests a factory that maps it to Apple's
settings objects. The remote endpoint is a canonical usable-unicast underlay IP
selected by the control plane and authenticated in the same handoff envelope.
It cannot equal an overlay address; if an included route contains it, an
excluded route must also contain it so applying the tunnel routes does not
capture the engine's underlay endpoint. This is the source-schema decision for
Apple's required `tunnelRemoteAddress`, not evidence that a physical device
accepted or used the settings.

A tested runtime coordinator enforces exact engine identity, signed engine
preparation, Apple settings, bounded packet-pump startup, and engine startup in
that order. It runs reverse cleanup for partial startup, transport or rebind
failure, and stop, and emits running evidence only after every stage completes.
The provider's settings adapter contains the real
`setTunnelNetworkSettings`/clear calls. Its separate read/write tasks validate
and copy `NEPacketTunnelFlow` callback batches through the bounded coordinator,
cancel during stop, and terminate the extension on the first packet-loop
failure. After the initial `NWPathMonitor` observation, a path change invokes
the engine's bounded UDP rebind; failure clears runtime state and terminates the
tunnel. The reviewed unsigned simulator artifact contains the static engine
symbols and no dynamic `MeshMobile` dependency. These source contracts resolve
the authenticated remote-address, lifecycle-ordering, Apple callback-wiring,
and network-path rebind questions at compile/link scope; they do not prove an
executed runtime packet connection or device operation.

This ADR remains accepted only for feasibility implementation and must be
revisited after an
Apple-supported API review and physical-device prototype; static simulator
linkage and source tests do not settle the runtime decision.

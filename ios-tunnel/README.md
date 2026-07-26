# Mesh Tunnel iOS source proof

This directory is the source and controlled-beta qualification boundary for a
future Mesh Tunnel application on iPhone and iPad. Version `0.1.0` build `1`
contains the earlier framework-v4 pre-start lifecycle source and remains in
TestFlight. Version `0.1.0` build `2` contains the framework-v5 lifecycle,
runtime-evidence, identity-removal, host-control, and self-service OIDC
onboarding changes; Apple accepted its upload and export-compliance declaration
on 2026-07-26, approved its Beta App Review, and placed it in external testing.
Build `3` adds disabled-manager recovery and is also approved and in external
testing. A development-signed physical execution of the exact build-3 source
completed OIDC and desktop authorization, read the user's network inventory,
and then stopped while writing the retained disabled manager before requesting
self-enrollment. A development-signed build 4 avoided rewriting an enabled
manager, but two physical attempts reached the same disabled-manager write path
after OIDC and again sent no self-enrollment request. No token, node, local
identity, extension start, or packet path was proved. Current successor source
prepares the manager before OIDC and offers a confirmation-gated replacement
only for the exact disabled/no-identity recovery fixture. None of these builds
is a supported application, proven working VPN, production enrollment path, or
public App Store release.

## What exists

- `MeshTunnelHost`: a minimal UIKit containing app that uses the control
  plane's device-authorization protocol to open a same-origin OIDC sign-in in
  `ASWebAuthenticationSession`. After approval it keeps the resulting Mesh
  session cookies in ephemeral memory, lists the user's networks, prepares
  exactly one `NETunnelProviderManager` containing only the canonical
  non-secret HTTPS origin, and requests one fixed-policy self enrollment. The
  returned token is validated and passed directly to the extension through
  `NETunnelProviderSession.startTunnel(options:)`; it is never displayed or
  stored in VPN preferences, UserDefaults, the App Group, or the browser URL.
  A stable non-secret device name makes a same-principal pending retry reissue
  rather than duplicate the enrollment. The host can also rediscover exactly
  one Mesh provider, start an
  existing authenticated local identity without a new enrollment token,
  request stop, and inspect a request-bound status response. A running response
  comes from the live coordinator and includes the exact configuration
  revision, certificate generation, engine identity, and directional Apple
  callback counters. Neither those counters nor `NEVPNStatus` proves a peer
  reply or end-to-end connectivity. The onboarding view scrolls so the
  controls remain reachable on compact iPhones and with larger text. The
  current source also accepts one structurally valid but disabled saved manager
  after reinstall and presents a `Replace VPN and sign in` recovery action.
  Before opening OIDC, it proves that there is exactly one same-origin,
  structurally valid disabled Mesh manager and no current, candidate, or
  recovery identity slot, asks explicit destructive confirmation, revalidates
  those conditions, removes only that manager, and creates/reloads a fresh
  enabled manager. It never automatically removes an enabled manager, any
  manager with identity state, a mismatched manager, or duplicates. An
  already-valid enabled manager is reloaded and reused without rewriting
  preferences. Automatic setup preserves a fixed, non-secret failure stage
  instead of allowing an asynchronous VPN-status notification to replace the
  result, and it cannot request a token before manager readiness.
- `MeshPacketTunnel`: a Packet Tunnel Provider that authenticates the selected
  App Group configuration, or, when no current configuration exists, strictly
  decodes the single start-option enrollment request and performs enrollment
  through the statically linked Go framework. It activates the verified
  configuration monotonically, enforces the extension's Keychain high-water
  mark, and performs one extension-only agent-authenticated lifecycle refresh
  before every subsequent start. That refresh can renew the same-key
  certificate, rotate the agent credential through a crash-recoverable pending
  Keychain item, and recover ambiguous responses without exporting either
  secret. A verified newer result is activated, a
  bounded transport/429/5xx deferral may continue with the still-valid current
  configuration, and authorization rejection or malformed/rollback state
  fails startup closed. While scheduled, the running extension publishes
  bounded configuration/certificate/engine-bound runtime evidence every 60
  seconds and stops for verified desired-state mismatch; the next start runs
  the full refresh path. It also accepts an exact-node, confirmation-gated
  deletion-only local identity-removal request even when ordinary startup
  cannot authorize. It then constructs the engine session, applies
  validated Apple settings, starts the bounded packet loops, and requests an
  engine UDP rebind after subsequent `NWPathMonitor` updates. Enrollment,
  refresh, startup, packet, and rebind errors stop the coordinator and fail the
  extension closed. A locked provider lifecycle gate rejects duplicate starts,
  prevents a stop racing startup from publishing a running session, and latches
  stop for the lifetime of that provider instance.
- `Shared`: strict user-authorization, fixed-policy self-enrollment, and
  authenticated handoff schemas; a pure validated
  IPv4/IPv6 remote/address/route/DNS/MTU settings plan, a bounded packet-pump
  state machine, an exact Apple protocol-family batch codec, an ordered
  startup/cleanup coordinator, and a durable candidate/current/recovery
  configuration store.
- `ContractTests`: Swift Testing coverage for same-origin user authorization,
  self-enrollment permission and fixed-policy responses, exact extension
  enrollment, lifecycle refresh, runtime-report and identity-removal contracts, configuration
  decoding, authentication, nested Nebula config/CA
  digest and timestamp binding, settings and packet validation, atomic
  backpressure, stop-time queue erasure, coordinator ordering, rebind, and
  failure cleanup, running-evidence requirements, monotonic
  activation/recovery, replay, and symlink rejection.
  It also covers duplicate start, stop-during-start, and failed-start retry
  transitions for the provider lifecycle gate.
- `engine`: a separate Go module for a reproducible `MeshMobile.xcframework`
  packet-session proof. It pins Nebula 1.10.3, keeps identity custody in the
  extension-only Keychain group, and exports identity creation/public-key
  derivation, non-secret framework identity, one bounded enrollment session,
  one existing-credential lifecycle session with refresh and runtime-report
  operations, one deletion-only identity-removal session, and one bounded
  engine session with prepare, start, rebind, send, receive, and stop
  operations.

The unsigned source build binds the exact reproducible
`MeshMobile.xcframework` tree and statically links its Go/Nebula archive into
the extension; no dynamic engine framework is embedded. The provider adapter
applies and clears mapped `NEPacketTunnelNetworkSettings`, and two
lifecycle-owned tasks connect Apple `packetFlow` reads and writes to the
engine session through the validated bounded coordinator. Builds that omit the
module retain a fail-closed unavailable-engine adapter. The simulator receipt
proves the static symbols and source wiring, not an executed Network Extension
packet callback, applied interface settings, or physical packet path.

## Registered capability boundary

The containing app uses only:

- `packet-tunnel-provider`;
- `group.io.rw0.mesh.tunnel.mobile`; and
- `$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.handoff`.

The extension uses only:

- `packet-tunnel-provider`;
- the same App Group and handoff Keychain group; and
- `$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.identity`.

Development, TestFlight, and Custom App entitlement documents are separate.
Apple Team `Y3P5UNNG23` has registered the host and extension identifiers, the
App Group, and the Packet Tunnel capability. The checked-in Release settings
select the valid `Mesh Tunnel Host App Store` and
`Mesh Packet Tunnel App Store` profiles. The active host profile UUID is
`9ae4c36f-22a0-4d67-b078-f40049321616`; the active extension profile UUID is
`4201014e-16f3-4836-8da4-04b856709c51`. A current local Profile archive
verifies those exact signed entitlements and the statically linked lifecycle
and packet symbols. The manual export policy produced a strictly
post-export-verified App Store IPA, and Xcode uploaded those exact version
`0.1.0` build `1` bytes to App Store Connect on 2026-07-25.

App Store Connect completed processing and export-compliance review for
standard encryption with no France distribution. A read-only App Store Connect
check on 2026-07-25 showed build `0.1.0 (1)` in `Testing`, expiring in 90 days.
One invited tester had installed it on a physical iPhone that day. App Store
Connect showed no sessions, crashes, or feedback. This upload and installation
are controlled TestFlight qualification, not public App Store, Custom App,
supported release, or packet-path evidence. Build `0.1.0 (1)` is the earlier
framework-v4 artifact, not the current framework-v5 host and extension.

The successor framework-v5 archive and strictly verified IPA were uploaded as
`0.1.0 (2)` on 2026-07-26. App Store Connect reports the binary as valid and
the checked-in exempt-encryption declaration as accepted. The build is attached
to the external tester group, its Beta App Review is approved, and its external
state is `IN_BETA_TESTING`. It was installed and launched on a physical iPhone
on 2026-07-26. That launch confirmed the OIDC host UI and exposed a retained
Mesh VPN manager that iOS kept structurally valid but disabled after an
app-delete/reinstall cycle. The app-group container contained no current,
candidate, or recovery identity slot, and no enrollment, browser return,
extension start, packet callback, or packet-path result was established.

The build-3 source treated that disabled manager as recoverable state by
enabling, saving, and reloading it after sign-in. The provider also serializes
duplicate starts and latches stop across an in-flight start.

Build `0.1.0 (3)` contains that recovery source, is approved, and is in external
testing. A development-signed physical execution from the same source completed
OIDC and desktop authorization and reached the authenticated network-list
request. The server observed no self-enrollment request, and the app-group
container retained no current, candidate, or recovery identity. The bounded
evidence places the stop in an unnecessary save/reload of the already-valid
Apple VPN manager, before token issuance. Development-signed build 4 validates
and reuses an enabled manager without rewriting it, but the established
physical fixture is disabled. Two build-4 attempts completed OIDC and read the
single network, then stopped while enabling/saving that disabled manager; no
self-enrollment or mobile-runtime request was sent.

Current successor source moves all manager preparation before OIDC. With
exactly one structurally valid same-origin disabled Mesh manager and no current,
candidate, or recovery identity slot, it displays an explicit replacement
confirmation, revalidates the singleton/disabled/origin/identity conditions,
removes only that manager, and saves/reloads a fresh manager. Duplicate,
enabled, identity-bearing, or mismatched configurations fail closed and are
never automatically removed. A cancellation or Apple failure occurs before
login, and token issuance remains impossible until the fresh manager is ready.
This behavior is source/simulator tested only and does not establish physical
enrollment or tunnel behavior.

## TestFlight publishing

Mesh uses the same trusted-Mac release model as the Catalyst and Nodebyte
applications. Put the App Store Connect key identifiers, owner-only private-key
path, tester email, and optional external group name in the owner-only local
file `~/.config/mesh/testflight.env`. Never commit that file or the private key.

From a clean committed checkout, one command determines the next build number
from App Store Connect, runs the Apple source gates, reproduces and statically
links `MeshMobile.xcframework`, archives with the TestFlight configuration,
exports and strictly verifies the IPA, uploads it, waits for processing,
applies the checked-in export-compliance declaration, attaches the tester and
build to the external group, and submits Beta App Review:

```text
make ios-tunnel-testflight
```

Read or repair an already uploaded build without creating another binary:

```text
scripts/publish-ios-tunnel-testflight.sh status 2
scripts/publish-ios-tunnel-testflight.sh distribute 2
```

The release client signs short-lived ES256 API tokens locally and never places
the token or private key in command arguments, logs, repository files, or
release evidence. A failed upload does not advance a checked-in build number;
the next invocation reconciles the project floor with App Store Connect and
chooses the next unused integer.

The App Group stores authenticated configuration, never the node private key.
The handoff HMAC key is device-only Keychain data shared by the two targets.
The monotonic high-water item, stable X25519 private key, and independent
32-byte agent bearer seed belong to the extension-only identity group. The Go
framework never returns the private key or agent bearer.

The source enrollment ceremony separates user authority from
extension-owned node authority:

1. the containing app proves local identity slots are absent, validates or
   creates and reloads the Apple VPN manager, and completes any explicitly
   confirmed disabled-manager replacement before opening login;
2. the containing app starts device authorization, opens only the
   server-returned same-origin verification URL, and polls with a secret that
   never enters the browser;
3. after the user signs in and approves, the app requires an OIDC Mesh session
   carrying `nodes.enroll.self`, selects one visible network, and revalidates
   the already-ready same-origin manager without another preference write;
4. only after Apple confirms the VPN preference does the app request a
   server-fixed member/mobile/`all,members` enrollment; the app has no field
   for an IP, route, lighthouse, topology label, or alternate group;
5. it sends one canonical, bounded request containing a request ID, that
   origin, and a canonical 32-byte one-use token as the sole start option;
6. before creating or reading either local credential, the extension performs
   the strict no-store token preflight, requires an unexpired member plan with
   at least one lighthouse, resolves every planned lighthouse locally, and
   rejects unusable or overlay-captured results;
7. only then does the framework create or load the stable extension-only
   identity and agent credential, sending the enrollment token, public key,
   and agent-bearer hash to Mesh;
8. an ambiguous consuming response permits one byte-identical replay followed
   by node-authenticated bootstrap recovery;
9. the framework strictly validates the returned node/network identity,
   certificate and local-key match, CA and configuration digests, signature,
   lifecycle times, generation/revision, member role, preflight network and
   lighthouse binding, routes, native DNS policy, and underlay endpoint; and
10. the extension stages and atomically activates only the resulting verified
   v4 configuration above the current Keychain/App Group high-water floor.

Before every later start, the extension loads the existing private key and
agent seed without creating replacements, authenticates the stored origin,
revalidates the current signed configuration against the local key, and calls
the bounded agent bootstrap endpoint. It pins the returned configuration
signing key to the current trusted key. It accepts only the same node and
network with nondecreasing certificate, agent-credential, and configuration
generations. A ready result is revalidated and activated at the next monotonic
counter. Transport failure, 429, or 5xx produces an exact `deferred` outcome
and uses the still-valid current configuration; 401 produces `unauthorized`
and fails startup. Other failures, identity substitution, rollback, malformed
state, or origin substitution fail closed.

When certificate renewal is due, the lifecycle session submits the existing
public key to the certificate-renew endpoint and requires a strictly newer
certificate generation. Ambiguous transport permits one exact retry followed
by authenticated bootstrap recovery. Ordinary due renewal may defer while the
current certificate remains valid, but a mandatory CA or certificate-profile
transition never falls back to the old certificate.

When the authenticated agent-credential expiry is within seven days, the
extension first stores one random pending seed in a fixed device-only Keychain
item and sends only its SHA-256 hash. The current bearer authorizes the first
rotation request. Ambiguous or lost responses recover with the pending bearer
and same hash. Only an exact newer generation and bounded future expiry allow
the primary item to be replaced and the pending item removed.

While the extension is scheduled, it reports at a 60-second cadence through
the strict `mesh-ios-mobile-runtime-report-v1` contract. Each report binds an
extension instance generation, monotonic sequence, state, configuration
revision/digest, certificate fingerprint/generation, engine identity, runtime
uptime, optional packet counters, and one bounded fixed error code. The server
uses a two-minute ordinary freshness bound and a 15-minute bound only after an
explicit `suspended` report. Missing or stale evidence is not health, and a
suspension report is best-effort because iOS may stop scheduling the extension.
A generic 401 can mean expiry, rotation, or revocation, so the client
quarantines rather than claiming authoritative revocation. A
`refresh-required` result stops the active session; current source does not
hot-reload an engine in place.

The host's destructive “Remove local node identity” action displays and
requires confirmation of the exact authenticated node and network. The
extension rechecks that context against its real anti-rollback floor, stops
the runtime, and attempts all three fixed authority deletions: current agent
credential, pending agent credential, and private key. Only after all succeed
does it erase candidate/current/recovery configuration slots and return a
bounded non-secret receipt. A partial Keychain failure retains the signed
context for exact retry. The host removes the VPN preference only after
confirmed completion. The handoff HMAC and high-water values are retained
because they are not node authority and preserve rollback protection. Local
removal does not revoke or delete the server-side node.

These are lifecycle source and simulator-link contracts, not
physical-device renewal, rotation, evidence, revocation, deletion, or
convergence proof.

The containing app cannot retrieve the node identity or agent credential, and
neither credential is placed in start options, VPN preferences, or the App
Group.
The authenticated configuration carries canonical IP assignments,
network-aligned included/excluded routes, same-family DNS servers, and a
bounded MTU. It also carries a canonical usable-unicast underlay remote
endpoint IP authenticated by the same envelope. If that endpoint falls within
an included tunnel route, validation requires an excluded route to keep the
endpoint reachable outside the tunnel; it also cannot equal an overlay
address. A provider adapter maps every validated field into
`NEPacketTunnelNetworkSettings`. Tests prove the coordinator's exact
engine-identity, engine-prepare, settings, pump, and engine-start order plus
reverse cleanup. A subsequent network-path update invokes the engine's bounded
UDP rebind; a rebind failure stops the engine, clears settings, cancels packet
tasks, records only a fixed error code, and terminates the tunnel. No valid
device configuration has exercised those paths, so physical-device settings
and roaming remain unproved.

## Local source gates

On the pinned macOS/Xcode host:

```text
swift test --package-path ios-tunnel

MESH_APPLE_INPUT_RECEIPT=/absolute/source-receipt.json \
MESH_SOURCE_KEYCHAIN=/absolute/empty-source.keychain-db \
scripts/apple-ios-mobile-framework-build.sh /new/absolute/framework-output

MESH_APPLE_INPUT_RECEIPT=/absolute/source-receipt.json \
MESH_SOURCE_KEYCHAIN=/absolute/empty-source.keychain-db \
scripts/apple-ios-tunnel-source-build.sh /new/absolute/tunnel-output

scripts/apple-mobile-framework-security-baseline.sh \
  /absolute/MeshMobile.xcframework /absolute/framework-source-receipt.json

scripts/apple-ios-tunnel-security-baseline.sh \
  /absolute/Mesh\ Tunnel.app /absolute/tunnel-source-receipt.json
```

The framework gate copies the exact reviewed Go inputs into the recorded,
fixed `mesh-ios-mobile-framework-source-staging-v1` path before binding. It
rejects checkout-path leakage, builds twice with separate Go caches, normalizes
gomobile metadata and static archives, and requires identical complete-tree
digests. A dirty working path and a separately committed clean-source path
also produced the same framework tree.
The tunnel gate emits an unsigned universal simulator host/extension receipt
and rejects any dynamic embedded engine framework. That receipt binds the
exact framework tree before link and then requires its engine-session symbols,
framework/config/lifecycle identity markers, runtime-report and
identity-removal exports, and absence as a dynamic dependency in the extension
executable. It also binds renewal, credential rotation, mobile evidence,
deletion-only identity removal, settings contract, authenticated remote
endpoint, Apple mapper, packet pump, runtime coordinator, fail-closed provider,
network-path rebind wiring, request-bound status inspection, existing-identity
start, explicit stop, scrollable onboarding, exact AppIcon source inventory,
and Xcode project source digests. The current framework-v5 tree is
`01a9fe1088dfd22e5c2b494273e31a54fc7e2dfc7a0a1de0827db37b4b1b8c4c`;
source receipt SHA-256
`c21b20f379ba8a4df4ff3430ade26a2d7c41a8cc0e993c72961f6c911ad8b97e`
binds every engine Go source plus the shared mobile-runtime contract. The
unsigned simulator app tree is
`bc6efc0d52c4804959423202057c67cc9b681148c5822805f1632cf2ec6a44e4`;
source receipt SHA-256
`9a065b593c8a0133282f957bfece392ea76dd228f69376e57b8a3375db93375e`
and security receipt SHA-256
`c67915d918d713d2717c325afceb89e2ef7d3b6bb13c667d74cdec77b407780e`
record static linkage and passing dependency, privacy, vulnerability, and
secret gates. Both source receipts identify isolated clean snapshot commit
`51e305575df839ab548350ece8da484cc30bc312`; this is a local reproducibility
snapshot, not independent clean-host evidence. Runtime packet connectivity,
applied settings, signature, physical-device validation, and distribution
validation remain false.
The uploaded TestFlight `0.1.0 (1)` framework-v4 artifact does not contain
these newer host runtime controls or the framework-v5 source changes.
Build `0.1.0 (2)` contains those changes and is approved for external testing,
and a physical launch exposed the disabled saved-manager recovery defect
described above. That bounded installation evidence does not establish
enrollment, extension runtime, or packet behavior.
Build `0.1.0 (3)` contains the recovery source and is approved for external
testing. A development-signed run of the exact source proved OIDC completion
and authenticated network inventory, but stopped before self-enrollment while
writing the retained disabled manager. Development-signed build 4 avoided
rewriting enabled managers, but two attempts necessarily re-entered the same
disabled-manager write path after OIDC. Current successor source stages manager
readiness before login and uses the bounded confirmation-gated replacement
described above; it has not yet proved enrollment, extension runtime, or packet
behavior.

## Deliberately unresolved

Apple's documented Packet Tunnel flow is a packet callback interface. Mesh has
not adopted the current upstream mobile integration's utun-descriptor
discovery. Pinned Nebula 1.10.3 also exposes an in-memory
`overlay.UserDevice`, and `engine/packet_bridge.go` proves a bounded,
copy-owning IPv4/IPv6 adapter for that documented callback shape. The adapter
also normalizes close to Nebula's production-loop contract. A native-host test
runs two real Nebula engines over real loopback UDP and proves
certificate-authenticated direct request/reply packets, empty relay state, and
post-rebind traffic plus repeatable clean shutdown. The bounded adapter now
backs the exported engine session and is statically connected to the Swift
coordinator in the simulator build. The source also implements callback
cancellation and network-path-triggered rebind, but no valid device handoff
has started the extension and no physical packet callback has executed.

The project still needs security approval and live execution of the
source-defined enrollment and identity-removal ceremonies, an Apple-supported
transport review, physical-device network-settings, Keychain, UDP, packet, and
resource measurements, roaming/suspension/crash/reboot evidence,
heartbeat/renewal/rotation/revocation convergence, cutoff, response-loss,
reinstall, and transfer coverage, privacy and legal review, installed
TestFlight execution for build `2`, and Custom App distribution evidence. The
earlier framework-v4 build `0.1.0 (1)` entered `Testing` and was installed on
2026-07-25. Its launch and VPN permission screens do not prove that an
enrollment request reached Mesh or that any packet traversed the tunnel.

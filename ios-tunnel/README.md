# Mesh Tunnel iOS source proof

This directory is the source and controlled-beta qualification boundary for
Mesh Tunnel on iPhone and iPad. TestFlight builds `1` through `11` exercised
the signed application, OIDC, manager recovery, provision-first enrollment,
retained identity, provider startup, and host inspection in successive bounded
steps. Builds `8` and `9` proved that an authenticated local identity can be
enrolled, committed, and recovered, but no released build established a
running packet path. Build `10` corrects the initial-inspection race around an
already enrolled identity.

Externally distributed Build `0.1.0 (11)` changes the runtime architecture
instead of adding another host-state workaround. It keeps Mesh OIDC, fixed-policy
self-enrollment, device-only Go/Keychain custody, signed configuration, and the
normal Apple VPN manager flow. The Packet Tunnel now follows Mobile Nebula's
production transport: Go discovers the provider-owned `utun` descriptor and
constructs pinned Nebula 1.10.3 with
`overlay.NewFdDeviceFromConfig`. The production provider does not start the
Swift `NEPacketTunnelFlow` packet-copy loops. App Store Connect reports Build
11 valid, Beta Review approved, attached to `Mesh Tunnel External Testers`, and
`IN_BETA_TESTING`. Distribution is not physical packet-path evidence or a
supported VPN.

## What exists

- `MeshTunnelHost`: a minimal UIKit containing app that uses the control
  plane's device-authorization protocol to open a same-origin OIDC sign-in in
  `ASWebAuthenticationSession`. After approval it keeps the resulting Mesh
  session cookies in ephemeral memory, lists the user's networks, prepares
  exactly one `NETunnelProviderManager` containing only the canonical
  non-secret HTTPS origin, and requests one fixed-policy self enrollment. It
  passes the token directly to the narrow Go enrollment session in memory,
  validates the exact origin/node/network/counter result, and installs the
  authenticated site configuration above the Keychain/App Group high-water
  floor. Only after that commit does it call normal `startTunnel()` with no
  enrollment options. The token is never displayed or stored in VPN
  preferences, UserDefaults, the App Group, a receipt, or the browser URL.
  A stable non-secret device name makes a same-principal pending retry reissue
  rather than duplicate the enrollment. The host can also rediscover exactly
  one Mesh provider, start an
  existing authenticated local identity without a new enrollment token,
  request stop, and inspect a request-bound status response. A running response
  comes from the live coordinator and includes the exact configuration
  revision, certificate generation, engine identity, and legacy counter
  fields. Native-`utun` mode leaves those callback fields at zero. Neither
  runtime state nor `NEVPNStatus` proves a peer reply or end-to-end
  connectivity. The onboarding view scrolls so the
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
  result. After OIDC and network selection, it re-enumerates exactly one
  current Mesh manager, reloads preferences, rechecks identity-slot absence,
  validates enabled/origin/schema/on-demand state, and uses only that fresh
  manager for local enrollment. It cannot request a token before those
  checks pass.
- `MeshPacketTunnel`: a Packet Tunnel Provider that authenticates the selected
  App Group configuration and fails closed when no current configuration is
  installed. It rejects enrollment-bearing start options; enrollment is not a
  provider-start operation. It enforces the shared Keychain high-water mark,
  constructs the native-`utun` engine, applies Apple settings, and
  completes Apple's start callback without a control-plane HTTP dependency.
  Only after that local running commit does it create the runtime reporter and
  publish
  bounded configuration/certificate/engine-bound runtime evidence every 60
  seconds. Verified authorization or desired-state mismatch can still
  quarantine and stop the running session; unavailable reporting does not hold
  Apple in `.connecting`. The source-tested lifecycle refresh contract can
  renew the same-key certificate and rotate the agent credential, but scheduling
  that convergence outside the Apple start callback remains a controlled-beta
  qualification item. It also accepts an exact-node, confirmation-gated
  deletion-only local identity-removal request even when ordinary startup
  cannot authorize. It then constructs the engine session, applies
  validated Apple settings, starts Nebula on Network Extension's native
  descriptor, and requests an
  engine UDP rebind after subsequent `NWPathMonitor` updates. Enrollment,
  refresh, startup, and rebind errors stop the coordinator and fail the
  extension closed. A locked provider lifecycle gate rejects duplicate starts,
  prevents a stop racing startup from attaching a running session, compensates
  a post-connect report if stop wins, and resets only after stop completion so
  the same provider object can start again.
- `Shared`: strict user-authorization, fixed-policy self-enrollment, and
  authenticated configuration schemas; a pure validated
  IPv4/IPv6 remote/address/route/DNS/MTU settings plan, a bounded packet-pump
  test state machine, an exact Apple protocol-family batch codec, a
  native-`utun`-aware ordered startup/cleanup coordinator, and a durable
  candidate/current/recovery configuration store.
- `ContractTests`: Swift Testing coverage for same-origin user authorization,
  self-enrollment permission and fixed-policy responses, exact extension
  enrollment, lifecycle refresh, runtime-report and identity-removal contracts, configuration
  decoding, authentication, nested Nebula config/CA
  digest and timestamp binding, settings and packet validation, atomic
  backpressure, stop-time queue erasure, coordinator ordering, rebind, and
  failure cleanup, running-evidence requirements, monotonic
  activation/recovery, replay, and symlink rejection.
  It also covers duplicate start, stop-during-start, failed-start retry,
  restart-after-stop, and ambiguous high-water commit reconciliation.
- `engine`: a separate Go module for a reproducible `MeshMobile.xcframework`
  engine-session proof. It pins Nebula 1.10.3, keeps identity custody in the
  app-and-extension shared, device-only Keychain group, and exports identity creation/public-key
  derivation, non-secret framework identity, one bounded enrollment session,
  one existing-credential lifecycle session with refresh and runtime-report
  operations, one deletion-only identity-removal session, and one bounded
  engine session with prepare, start, rebind, send, receive, and stop
  operations.

The unsigned source build binds the exact reproducible
`MeshMobile.xcframework` tree and statically links its Go/Nebula archive into
the extension; no dynamic engine framework is embedded. The provider adapter
applies and clears mapped `NEPacketTunnelNetworkSettings`. The production
engine scans only the Packet Tunnel process's bounded descriptor table,
validates `com.apple.net.utun_control`, and gives that descriptor directly to
Nebula's upstream iOS device. The callback bridge and packet pump remain test
fixtures and are not wired by the production provider. Builds that omit the
module retain a fail-closed unavailable-engine adapter. The simulator receipt
proves the static symbols and native-transport source selection, not an
executed Network Extension, applied interface settings, or physical packet
path.

## Registered capability boundary

The containing app uses only:

- `packet-tunnel-provider`;
- `group.io.rw0.mesh.tunnel.mobile`; and
- both `$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.handoff` and
  `$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.identity`.

The extension uses only:

- `packet-tunnel-provider`;
- the same App Group, handoff Keychain group, and identity Keychain group.

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
OIDC and desktop authorization and attempted the network-list request. The
server observed no self-enrollment request, and the app-group container
retained no current, candidate, or recovery identity. Retained evidence did not
record the network-list response status or prove that the request was
authenticated.
TestFlight build `0.1.0 (4)` validates and reuses an enabled manager without
rewriting it and prepares manager readiness before OIDC. Two development-signed
build-4 attempts completed OIDC and desktop authorization; no self-enrollment
or mobile-runtime request was sent. A later screen showed one enabled,
structurally valid saved manager with no identity. That later state does not
establish the manager state or exact stop during any earlier attempt.

TestFlight build `0.1.0 (5)` contains the cookie-store and inspection-race
corrections. Its physical run completed OIDC, read the authenticated network,
created one fixed-policy pending mobile node, decoded the server response, and
submitted token-bearing start options to Network Extension without a
synchronous error. The node remained pending with no certificate, agent
credential, local identity, or mobile runtime, while iOS returned the manager
to disconnected. Provider option delivery, token consumption, and extension
enrollment remain unproved.

Current source keeps all manager preparation before OIDC. With exactly
one structurally valid same-origin disabled Mesh manager and no current,
candidate, or recovery identity slot, it displays an explicit replacement
confirmation, revalidates the singleton/disabled/origin/identity conditions,
removes only that manager, and saves/reloads a fresh manager. Duplicate,
enabled, identity-bearing, or mismatched configurations fail closed and are
never automatically removed. After login, the current manager and identity
absence are checked again. The app preserves the private ephemeral cookie store
supplied by `URLSessionConfiguration`, requires exactly one session cookie and
one distinct CSRF cookie for the exact server URL after authorization, then
requests one fixed-policy self-enrollment.

On launch, setup, start, inspection, and identity removal remain disabled until
the first VPN and identity inspection completes. If setup concurrently
discovers an authenticated current identity, it validates and prepares only
that identity's same-origin manager, skips OIDC and self-enrollment, and returns
to Start existing tunnel without requesting another token. This prevents a
stale Sign in action from converting an existing identity into a latched
setup failure.

The containing app passes the one-time token only to the narrow Go enrollment
session, which performs preflight and enrollment using the shared, device-only
identity Keychain group and returns no secret. The host validates the exact
origin, node, network, and monotonic counter, stages and activates the verified
configuration, and reconciles an ambiguous high-water write only when the
authenticated current configuration is exactly the candidate. Immediately
before each normal or recovery start, a narrow host lifecycle session
authenticates to the stored origin with the shared device-only agent credential
and atomically activates any verified replacement configuration. The app then
starts the Packet Tunnel with one exact start authorization and no enrollment
material. Success still requires a fresh
Apple connected transition plus an installed configuration for the exact
origin/node/network. Backgrounding during local identity commit or provider
observation does not cancel that critical section; other pre-token setup is
cancelled and its browser/session state is invalidated.

The UI reports the build and last fixed non-secret setup stage without
persisting server data, identities, cookies, tokens, request identifiers, or
raw errors. Provider observation uses at most 180 half-second samples within
one absolute 90-second budget. The provider loads only an installed current
configuration and rejects enrollment-bearing options. If a process
termination leaves an authenticated candidate, the next launch validates its
exact origin, node, and network against a device-only initial-enrollment
intent and activates it before making a network request. If the server already
committed the node but no configuration was activated, the host uses the
existing device Keychain identity and agent credential for one authenticated
bootstrap, requires that same intent binding, validates the complete site, and
installs it. A
versioned recovery result distinguishes ready, temporarily deferred, and
unauthorized state; deferred or unauthorized recovery never erases authority
or requests another enrollment token. A pending server node that never
committed its agent credential still requires explicit administrator
reconciliation. Incomplete or unauthorized no-configuration authority exposes
only a destructive, confirmation-gated local reset; it never resets on a
deferred or ambiguous recovery and it does not revoke the server node.
Crash/restart remains a physical qualification gate.
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
32-byte agent bearer seed belong to the app-and-extension identity group. The
Go framework never returns the private key or agent bearer to Swift.

The source enrollment ceremony separates user authority from
device-owned node authority:

1. the containing app proves local identity slots are absent, validates or
   creates and reloads the Apple VPN manager, and completes any explicitly
   confirmed disabled-manager replacement before opening login;
2. the containing app starts device authorization, opens only the
   server-returned same-origin verification URL, and polls with a secret that
   never enters the browser;
3. after the user signs in and approves, the app requires an OIDC Mesh session
   carrying `nodes.enroll.self`, selects one visible network, re-enumerates
   exactly one Mesh manager, reloads current preferences, rechecks identity
   absence, and validates enabled/origin/schema/on-demand state without another
   preference write;
4. only after Apple confirms the VPN preference does the app request a
   server-fixed member/mobile/`all,members` enrollment; the app has no field
   for an IP, route, lighthouse, topology label, or alternate group;
5. it sends one canonical, bounded in-process request containing a request ID,
   that origin, and a canonical 32-byte one-use token to the Go enrollment
   session; the token never enters Network Extension start options or provider
   messages;
6. before creating or reading either local credential, the Go session performs
   the strict no-store token preflight, requires an unexpired member plan with
   at least one lighthouse, resolves every planned lighthouse locally, and
   rejects unusable or overlay-captured results;
7. only then does the framework create or load the stable shared
   identity and agent credential, sending the enrollment token, public key,
   and agent-bearer hash to Mesh;
8. an ambiguous consuming response permits one byte-identical replay followed
   by node-authenticated bootstrap recovery;
9. the framework strictly validates the returned node/network identity,
   certificate and local-key match, CA and configuration digests, signature,
   lifecycle times, generation/revision, member role, preflight network and
   lighthouse binding, routes, native DNS policy, and underlay endpoint; and
10. the containing app stages and activates only the resulting verified v4
    configuration above the current Keychain/App Group high-water floor; and
11. the app performs one bounded lifecycle refresh, activates only a verified
    same-origin/node/network replacement, creates a one-use exact-configuration
    start authorization, and starts the Packet Tunnel;
    the provider then loads that installed configuration, applies Apple network
    settings, and starts Nebula without control-plane work inside Apple's start
    callback.

On a later launch with Keychain authority but no current configuration, the
host first requires the device-only initial-enrollment intent and rejects any
pending rotation credential. It then authenticates and activates a candidate
matching the exact origin/node/network intent. Otherwise it performs an
existing-credential agent bootstrap and accepts only a strict
`ready`, `deferred`, or `unauthorized` recovery outcome. Only `ready` can carry
a verified configuration matching that intent. The other outcomes preserve
authority and fail closed without automatic self-enrollment. After explicit
administrator review, terminal incomplete or unauthorized authority can be
deleted only through a destructive confirmation; deferred recovery never
enables that reset. If an authenticated current site and a retained recovery
intent disagree, ordinary load and start remain blocked, but inspection still
uses the authenticated site and exposes the same exact-node destructive
confirmation. The mismatched marker is cleared only after provider-confirmed
local identity removal. If the VPN preference is missing or disabled, that
same explicit confirmation creates or re-enables an exact same-origin manager
only to launch the deletion operation; the manager is removed after confirmed
completion.

Before every later app-driven start, a narrow host lifecycle session loads the existing private key and
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
host lifecycle session first stores one random pending seed in a fixed device-only Keychain
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

The containing app has entitlement access to the identity Keychain group so its
narrow Go enrollment session can provision the site before provider startup.
No Swift API retrieves the raw node private key or agent credential, and
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
and roaming remain unproved. Terminal cleanup owns a barrier that every
concurrent Apple stop waits before reopening provider startup, so an older
failure task cannot overwrite a newly started runtime.

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
and desktop authorization, but the server observed no self-enrollment request
and the app-group container retained no identity. Retained evidence did not
record the attempted network-list response status or prove an authenticated
inventory read. TestFlight build `0.1.0 (4)` contains the manager-readiness
successor; two development-signed attempts reached the same bounded
pre-enrollment result. TestFlight build `0.1.0 (5)` contains the cookie-store
correction and physically created a self-enrollment node before submitting its
token-bearing options to Network Extension without a synchronous error. That
node stayed pending and the manager disconnected, with no local identity or
mobile runtime. Build `0.1.0 (6)` then observed the real provider transition
and returned fixed host stage `apple-vpn-disconnected`. Sanitized server logs
for that exact attempt recorded the host self-enrollment reissue but zero
provider preflight, enrollment, or runtime requests. Build `0.1.0 (7)` then
physically reached `running-preparingProvider` and remained there without
requesting a token. Build `0.1.0 (8)` removes that circular
provider-readiness dependency and uses the provision-first/connect-second flow
described above. It also recovers a matching authenticated candidate or an
already committed active node without requesting a second token. The physical
Build-8 attempt completed OIDC and server enrollment: audit proves the existing
iPhone enrollment was reissued, its token was consumed, and node
`E3kVivz4BJPeBgvh` became active at `2026-07-27T20:39:01Z`. The containing app
then unexpectedly terminated during the post-enrollment host handoff. No Apple
crash log was available when checked, so the exact local substage is unknown.
Build `0.1.0 (9)` subsequently read and displayed the authenticated local
identity left by that attempt, proving local configuration commit and retained
identity recovery. Its initial inspection race allowed Sign in to reach fixed
stage `failed-starting` before Start existing tunnel was enabled. Build
`0.1.0 (10)` keeps all actions disabled until initial inspection completes and
routes a concurrently observed authenticated current identity to its prepared
same-origin manager without OIDC, self-enrollment, or another token. Build
`0.1.0 (11)` retains that correction, replaces the production Swift
packet-copy transport with the native `utun` transport described below, and is
externally distributed. No physical Build 11 run has proved provider startup or
packet exchange.

## Deliberately unresolved

Build 11 deliberately follows upstream Mobile Nebula's `utun` transport.
The bounded `overlay.UserDevice` callback adapter remains a native-host test
fixture, where two real Nebula engines prove certificate-authenticated direct
request/reply packets, empty relay state, post-rebind traffic, and repeatable
clean shutdown over loopback UDP. Production source instead selects
`overlay.NewFdDeviceFromConfig` after bounded validation of the provider-owned
`com.apple.net.utun_control` descriptor. Source and simulator checks prove that
selection and reject provider packet-copy tasks, but no physical Build 11 run
has yet proved that descriptor discovery, Apple settings, iOS UDP, or peer
traffic succeeds.

The project still needs security approval and live execution of the
source-defined enrollment and identity-removal ceremonies, review of the
upstream-aligned transport boundary, physical-device network-settings,
Keychain, UDP, packet, and resource measurements,
roaming/suspension/crash/reboot evidence,
heartbeat/renewal/rotation/revocation convergence, cutoff, response-loss,
reinstall, and transfer coverage, privacy and legal review, physical Build 11
TestFlight execution, and Custom App distribution evidence. The
earlier framework-v4 build `0.1.0 (1)` entered `Testing` and was installed on
2026-07-25. Its launch and VPN permission screens do not prove that an
enrollment request reached Mesh or that any packet traversed the tunnel.

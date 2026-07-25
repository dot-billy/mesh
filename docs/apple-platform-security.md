# Apple platform security and lifecycle contract

Status: architecture frozen for implementation; security review and every
product release gate remain pending.

This contract covers Mesh Admin for macOS, Mesh Node for macOS, Mesh Admin for
iPhone and iPad, and the separately gated Mesh Tunnel for iPhone and iPad. It
is based on source commit
`349d26e33e3fe61a25bd37930ca335d751b302a6`. It authorizes source work and
negative gates only; it is not signing, notarization, native-host, real-device,
packet, distribution, or support evidence.

The product decisions are recorded under
[`decisions/`](decisions/README.md). On 2026-07-24 Apple Team `Y3P5UNNG23`
registered the explicit Admin and Tunnel bundle identifiers and the Tunnel
App Group described below. That registration and the locally verified App
Store profiles are capability evidence, not release approval or distribution
evidence.

Current implementation evidence and outstanding gates are tracked in
[`apple-integration-status.md`](apple-integration-status.md).

## Product and authority boundaries

- Mesh Admin applications are unprivileged remote control-plane clients. Their
  installation never installs, enrolls, starts, stops, or configures a node or
  VPN.
- Mesh Node for macOS is a separately installed root-managed system service.
  Its installation grants no control-plane role or operator session.
- Mesh Tunnel is a separately entitled Packet Tunnel Provider. The containing
  application manages authorized configuration and shows bounded status; the
  extension owns tunnel execution.
- The shared Dart client preserves browser authorization, normalized origins,
  cookie and CSRF pairing, strict API parsing, server-enforced RBAC, exact
  revisions and request IDs, ambiguous-response readback, and one-time-secret
  erasure. Platform shells do not fork those semantics.
- Browser verification URLs must remain on the exact selected origin and
  contain only the public request ID. Completion polling retries rate limits
  and transient service unavailability only while the original server-issued
  expiry remains valid. The production disposable-control-plane test proves a
  consumed approval cannot create a second session.
- The existing Darwin agent, installer, immutable release layout, runtime
  gate, and sole `io.mesh.node-agent` launchd job remain authoritative for the
  macOS node. There is no transplanted daemon or second Nebula service.
- Linux and Windows contracts are invariants. An Apple change that relaxes a
  shared parser, authentication, authorization, release, revocation,
  high-water, or staleness rule is rejected.

## Apple threat analysis

| ID | Threat | Required control | Residual boundary |
| --- | --- | --- | --- |
| AT-01 | Control-plane session or CSRF theft | Browser-approved OIDC, IdP MFA, exact-origin Keychain item, paired session/CSRF use, prompt revocation, no browser URL secret, snapshot redaction, private logging | A valid stolen session has its server role until revoked; device and IdP controls remain required. |
| AT-02 | Local administrator or macOS root compromise | Sandbox the operator; keep node state root-owned; authenticate installed releases and privileged tools; separate operator and node artifacts | Root can read node keys, alter runtime, and spoof local evidence. Mesh does not claim remote attestation. |
| AT-03 | Malicious unprivileged local application | Keychain access control, sandboxing, no privileged file reads, authenticated/versioned IPC, command allowlist, bounded messages and rate limits | Accessibility, screen capture, or a compromised signed user session may still disclose displayed data. |
| AT-04 | Hostile package, snapshot, or release-origin input | Threshold metadata, exact target/size/digest/floor/architecture, bounded no-redirect capture, strict USTAR intake, immutable no-replace publication, high-water state | Compromised release signers remain release authority; availability attacks remain possible. |
| AT-05 | Symlink, hard-link, ACL, ownership, mount, or path substitution | Descriptor-relative `O_NOFOLLOW_ANY` walks, exact root:wheel modes, single links, no ACL/security xattr/flags, authoritative mount ownership, repeated identity checks | macOS kernel/root compromise is outside the boundary. |
| AT-06 | Replaced `launchctl`, `codesign`, `pkgutil`, `spctl`, or other privileged tool | Fixed absolute executable allowlist, descriptor identity and Apple signature/designated-requirement checks, empty environment, fixed arguments, bounded output and deadline | Apple platform trust or root compromise can replace the authority used to authenticate tools. |
| AT-07 | Stolen signing, notarization, App Store, or provisioning credential | Protected release context, non-exportable or tightly custodied keys, no PR access, short-lived API credentials, independent publication verification, rotation and revocation runbook | A valid stolen credential can sign within its Apple scope until revoked; Mesh release metadata remains an independent gate. |
| AT-08 | iOS application-container compromise | Store only bounded app state; device-only Keychain session; no node private key in Flutter or ordinary storage; erase transient secrets on lifecycle transitions | A running compromised app can exercise the signed-in principal's allowed API until session revocation. |
| AT-09 | App Group over-sharing or partial writes | One explicit app/extension group, fixed filenames, minimal non-secret/current-and-recovery state, create/sync/verify/select transaction, revision/digest binding | Both entitled targets share the group; either compromised target can deny service. |
| AT-10 | Keychain access-group or accessibility mistake | Separate operator-session and tunnel-identity groups, minimum target membership, device-only accessibility, access-control tests on physical devices | OS backup/transfer semantics must be revalidated for every accessibility or entitlement change. |
| AT-11 | Containing-app/extension confused deputy | Versioned authenticated handoff, target identity checks, exact network/node/certificate/config/engine binding, no arbitrary URLs/paths/commands, replay protection | A compromised entitled containing app can request only the narrow reviewed actions. |
| AT-12 | Malicious signed configuration or rollback input | Mesh signature, exact identity and digest, monotonic revision/generation, immutable current/recovery slots, explicit bounded rollback authority | A compromised network signing key is configuration authority until rotated and revoked. |
| AT-13 | Device loss | Device passcode, Keychain class, remote session/node revocation, no redisplayable secret, documented managed-device erase | An unlocked lost device may exercise existing session or tunnel authority until revoked. |
| AT-14 | Log, notification, pasteboard, screenshot, restoration, analytics, or crash leakage | Private Unified Logging, omit secrets, bounded redacted diagnostics, snapshot cover, no restoration secrets, explicit/time-bounded copy, no analytics or crash upload without privacy approval | A user can deliberately copy or photograph displayed one-time material. |
| AT-15 | Stale, suspended, missing, or ambiguous mobile evidence | Server receive time, exact extension sequence/config/certificate/engine binding, explicit suspended/stale/error states, no health inference, fresh-evidence recovery | iOS scheduling prevents desktop-style heartbeat guarantees; absence remains unknown rather than healthy. |

## macOS package trust chain

Each arrow is a checked binding. A missing receipt stops the chain:

1. reviewed source commit and submodule/module checksums;
2. machine-readable build inputs and locked Flutter, Go, Nebula, Xcode, SDK,
   Swift, deployment-target, and architecture identities;
3. deterministic unsigned binaries, frameworks, resources, plist, package
   metadata, SBOM, licenses, vulnerability results, and secret-scan results;
4. inside-out code signatures whose Team ID, designated requirements,
   entitlements, hardened runtime, architectures, and sealed resources match
   the allowlist;
5. an authenticated staged tree and signed installer package;
6. accepted Apple notarization submission and stapled ticket;
7. offline staple and Gatekeeper verification of the final bytes;
8. final size and SHA-256 in threshold-authenticated Mesh release metadata;
9. immutable publication and retrieval from the public operator URL;
10. independent re-verification of bytes, package contents, signatures,
    notarization, staple, entitlements, release metadata, and architecture;
11. native installer admission through compiled trust and persisted root
    history;
12. immutable installed release, exact selector, plist, gate, state, and
    launchd proof.

The GUI and node package have separate instances of this chain. A notarized
GUI never authenticates a node package, and a node package never authenticates
an operator session.

The GUI application now has source for step 3, protected portions of steps 4
through 7, and the local final-byte portion of step 8. Its create-only
`mesh-apple-admin-security-receipt-v1` gate snapshots one exact unsigned
universal Release app, reconciles the runtime Dart graph with Syft and SPDX
inventories, requires every runtime package in the embedded Flutter notices,
checks the minimal macOS privacy manifest, applies a fresh isolated Grype
database and the repository's fixable/High/Critical rejection policy, and
requires empty redacted Gitleaks reports for bound metadata and secret-scan
text from every regular bundle file. Generated byte digests inside exact
`_CodeSignature/CodeResources` plists are normalized to a fixed marker; paths
and all non-byte text remain scanned, and the original file remains bound by
the app tree digest. Public scanner pulls use an empty private Docker
configuration and cannot consult the user's registry credential helper.
Scanners are digest pinned, networkless,
read-only, non-root, and have no Docker socket; only the isolated Grype
database refresh receives network access. Notice coverage is inventory
evidence, not legal approval, and final signed dependency/privacy
reconciliation remains required.

The current local 2026-07-24 clean disposable-snapshot run binds unsigned app
tree
`3efedb861eb0b9ae8ba3141dec1c90eb69a3ac0d917424979f39c439df5a2d50`.
It reconciles 49 runtime hosted Dart packages, records 68 Syft and 69 SPDX
packages, finds all 49 runtime notice headings, reports zero Grype matches
against a fresh database, and emits two
empty Gitleaks reports. The security receipt SHA-256 is
`ddbc33e6f798890cabecc2532bdbadd99da3617af8154793b34d233b42c26080`;
it also binds the exact baseline, verifier, and Gitleaks-policy source hashes.
Source receipt SHA-256
`8c62c2067ab11da9c1c74ca0e0a8af7e3eace9e63c2735f167ceff684f344207`
records clean disposable snapshot commit
`1fbe569e49bc6aa9792d3e9e006637db24a3cd6c`.

The protected producer requires and CMS-validates an active all-device macOS
Developer ID provisioning profile. It binds Team `Y3P5UNNG23`, application
identifier `io.rw0.mesh.admin`, the signing certificate, and the profile's
application/Keychain entitlement allowlist, embeds it before the outer
signature, and revalidates it before and after notarization. The current
profile is UUID `1851d214-90a0-46e9-9490-617e3e6f5b20`, SHA-256
`71609763a34af24eaf36cb37733354fa957f2fbdd858229852f9b0e07645ba1a`.

The historical protected archive SHA-256 is
`e826af00de6bc62b0e57931e7691f95c84b519582e866c34c74c200d23ae8a69`.
Portable receipt SHA-256
`c948fd8c2d73a35a2e05a94ba9ff6e2c735c2efabdd529c363687acbd4abce2e`
binds signed tree
`644732ed9f542db504b3607ff1e524b11cbfabf3f052bc049d122acb690d6fc3`,
Apple submission `4e592d84-4ef0-4b96-9c0e-97bd53f820d6`, validated
staple, and accepted Gatekeeper assessment. Runtime receipt SHA-256
`fdca7bc66e2bf10096b088bbdfe41766cab525ce013c7ce3b413dad249d1ad2e`
records live test-control-plane authentication as `legacy_admin`, one network,
two active nodes, Keychain deletion on explicit sign-out, immediate re-login
availability, and successful session restoration after process termination
and relaunch. An earlier accepted feasibility submission lacked a
usable embedded provisioning profile and failed AMFI launch; it is superseded
and is not runtime evidence. The later runtime artifact is also superseded as
portable release evidence: its v2 receipt hashed host-specific symlink mode
bits, while `ditto` canonicalized those bits during extraction, so the public
native verifier correctly rejects the extracted tree. Its bounded live-runtime
observations remain historical local evidence only. This local run is not
production release authority, publication, re-download, or clean-host
acceptance.

The replacement protected v3 artifact was built from clean disposable snapshot
commit `1fbe569e49bc6aa9792d3e9e006637db24a3cd6c`. Its unsigned
source receipt SHA-256 is
`8c62c2067ab11da9c1c74ca0e0a8af7e3eace9e63c2735f167ceff684f344207`;
its exact-tree Admin security receipt SHA-256 is
`ddbc33e6f798890cabecc2532bdbadd99da3617af8154793b34d233b42c26080`.
The protected archive SHA-256 is
`d79f49137001c60fe226f4719cea3c33fa7e07b91fce3c3026b97c8cadcf3fe2`;
portable receipt SHA-256
`fe90ef4295875b5ecbd62596576ea1b3a38814f4ae016dc84629ffa88aae1111`
binds signed and extracted tree
`8b73d512195852c47ecb596856a40d00ee8b0ac5a9776872af17a745855581d2`,
32 regular files, 45,192,251 regular-file bytes, and Apple submission
`6dd0c3a6-f8fa-4c47-884e-73c76560f90b`. The platform-neutral verifier accepted
the exact archive/receipt/source/Team binding. A second extraction under an
ordinary umask reproduced that tree and passed deep code-signature, staple,
and Gatekeeper checks. A complete native downloaded-artifact pass then used a
freshly compiled verifier and explicitly disposable local-test root with a
two-of-two release threshold; native receipt SHA-256
`945d721866dda77114329d7eff6ae6e0518a45ab06ab9f9e92677627f394561b`
binds the root, manifest, both signatures, verifier, archive, protected
receipt, exact signed tree, Team, entitlements, nested code, staple, and
Gatekeeper result. The four local-test private keys were removed immediately
afterward. The network-isolation option was not requested. This is corrected
bounded local release-path evidence, not an approved production root or
manifest, publication, public re-download, clean-host acceptance, continuously
isolated verification, or release authority.

The protected producer requires that fresh security receipt in addition to a
clean receipt-bound unsigned tree, an exact reviewed nested-code inventory, one
Developer ID Application identity for the compiled Team ID, hardened-runtime
signatures with exact designated requirements and entitlements, authenticated
Apple/Xcode tools, accepted notarization, staple validation, Gatekeeper
assessment, and post-staple re-verification before hashing a create-only
archive. Symlink permission bits are normalized to `0777` in the application
tree identity because they are not authorization bits on Darwin and are not
preserved by `ditto`. The producer then extracts the final archive into a fresh
private directory and repeats exact-tree, signed-code, provisioning-profile,
deep-seal, staple, and Gatekeeper checks. Its portable receipt v3 binds both
source and security receipt digests plus the equal pre-archive and
post-extraction tree, file-count, and byte-count evidence. A strict portable
parser can bind that archive to the source receipt, Team ID, security evidence,
and sanitized protected receipt without signing secrets. The receipt is not
self-authenticating. Release-authoring source now requires the exact
archive and receipt as distinct `macos-admin/universal` and
`macos-admin-evidence/portable` targets in one root-derived threshold-signed
manifest, with fresh evidence and the compiled Team ID. A separate portable
verifier authenticates both downloaded files with an independently
authenticated current root before matching the receipt again. Immutable
publication, real public re-download, independent native re-verification,
clean-host acceptance, and retention evidence remain closed gates. Native
post-download verification source pins
the portable verifier and current root by independently authenticated hashes,
rechecks the exact extracted tree and Apple evidence, and can sample absence
of default routes and non-loopback unicast addresses before and after its
staple/Gatekeeper checks. That sampled state is not continuous network
containment; running `stapler validate` in the online protected job or outside
an externally isolated clean-host fixture is not the required offline proof.

The node installer now implements the admission shape for step 11 without
claiming completion of steps 4 through 10. A canonical linker frame can carry
one approved Team ID and distinct `meshctl`, `nebula`, and `nebula-cert` code
identifiers. The installer derives fixed Apple requirement language from that
frame, performs strict native verification before activation, and rejects its
development no-policy sentinel. It also verifies the Apple designated
requirements of the fixed codesign and launchctl tools. Final identifiers,
Developer ID artifacts, hardened-runtime and entitlement evidence,
Node notarization, publication, re-download, and a full
signed-bundle-matching native receipt remain absent.

A digest-pinned Go 1.26.5 Debian 12 LinuxKit VM passed the cold-cache
dual-architecture Darwin staging-bundle smoke and the Linux-verifiable
path-security cross-build. The bundle harness now resolves the pinned patched
Nebula module graph in a disposable source copy, then leaves the authenticated
module-cache source untouched while the production builder runs with
`GOPROXY=off`. Receipt SHA-256
`d4b278dbeb974dd4edf3a3b1ed990c43ba3cb4936df67502ab09b7e6ae09cf0e`
binds test-log SHA-256
`c85ff62599d7f2857187ccda806254fabbcda05b8598204f6a816448e141a4fd`.
This is supplementary VM evidence only; it is not native Linux CI, a native
Mac lifecycle run, launchd mutation, package production, or release authority.

The approved Apple Silicon development Mac also ran a bounded root-owned
native subset after adapting descriptor opens and current-link publication to
macOS 26.5. Darwin rejects redundant `O_NOFOLLOW | O_NOFOLLOW_ANY` opens with
`EINVAL`, and applies the process umask to new symlink mode bits; the native
implementation now uses `O_NOFOLLOW_ANY` directly and normalizes the
descriptor-relative link itself to mode `0777`. The installer capture path also
retains and closes its transaction lock across error returns. Canonical partial
receipt SHA-256
`82d870ea0fb91a87b357c02e4254b7cbceae3fc529e9d8ed4412b55079df1984`
binds passing native path, installer-gate, release-layout, exact-child,
process-group, and reap tests plus the complete source inventory. It records no
bundle and no system-launchctl mutation and therefore cannot satisfy the full
native verifier. A separate gated attempt exercised and cleaned the exact
system launchd proof fixture, but the unsigned staging bundle was then
correctly rejected because no approved Node code-signature policy is compiled;
no full receipt was emitted.

## iOS trust chain

### Mesh Admin source boundary

Mesh Admin for iPhone and iPad is an unprivileged foreground control-plane
client. Its registered identifier is `io.rw0.mesh.admin.mobile`; the
matching source Keychain group is
`$(AppIdentifierPrefix)io.rw0.mesh.admin.mobile`. Development, TestFlight,
App Store, and managed-distribution entitlement documents are separate even
where their current minimum contents are identical, and the machine-readable
build inputs select each document by distribution path. No Admin entitlement
authorizes VPN, Network Extension, App Group, background execution, local
node state, or a Nebula runtime.

A product-specific distribution verifier now keeps Admin archive/IPA evidence
independent from Mesh Tunnel. Current
`mesh-apple-ios-product-distribution-receipt-v3` SHA-256
`d6abcc0250a579c9671831acaf69ef20c16a5f4084409ff454da72587d99dd4f`
rechecks the active App Store profile, signed application tree
`e371793d8a43c6732400601e0e06cee45358eff524f6ec43a88c20c0e1124fdd`,
exported IPA SHA-256
`5ffaea1c166dc423ce353539b05c913e2da62c7f656d41bec4a66f2e97e539b5`,
Team, identifier, and entitlement allowlist. An independent rerun reproduced
every receipt field except its timestamp. The limitation map is Admin-specific:
no upload, managed distribution, real browser authentication, physical device,
or release authority is claimed.

The native application covers its window before inactive/background
snapshots, signals protected-data loss to the shared controller, and places an
explicitly copied one-time value only on the local pasteboard with a two-minute
expiration. If that native bridge is unavailable, the copy fails rather than
falling back to an ordinary pasteboard item. The controller erases one-time
material outside the foreground,
on protected-data loss, logout, origin replacement, completion, and teardown.
Browser approval polling pauses outside the foreground and is invalidated by
explicit cancellation or origin replacement. Only the exact-origin session
and CSRF pair are eligible for the app-only, non-synchronizing,
`unlocked_this_device` Keychain item.

The macOS runner separately observes only the fixed screen-lock, screen-sleep,
system-sleep, application-hide, main-window-close, and
application-termination notifications. It maps them to the same argument-free
`protectedDataUnavailable` or `processTerminating` methods used by the shared
controller, which idempotently erases visible one-time material. Unknown
native events have no mapping. Its native menu similarly emits only
argument-free Refresh and Preferences commands into the existing Flutter
shell; it does not create another controller or API client. This is source and
XCTest evidence; actual signed-host lock, sleep, hide, close, wake, and
termination transitions remain release gates.

Pinned Flutter 3.44.8 emits a misleading cross-architecture native-assets
warning while grouping the locked `objective_c` 9.4.1 asset. Its grouping code
allocates a transient collision name for the second architecture before
reusing the existing identical asset ID. Mesh does not patch or silently
replace the verified Flutter SDK. Instead, every Admin artifact receipt binds
that SDK commit/digest and package version/digest, then requires one exact
`objective_c.framework`, an identical manifest path and Mach-O install name
for every expected architecture, the complete framework architecture set, and
no `objective_c1.framework` string in the application. This verifies the final
packaged boundary but is not an upstream correction or physical execution
evidence. A Flutter or package update invalidates the disposition and requires
fresh review.

Shared controller entrypoints erase one-time material before selecting another
network or returning to the network directory. Internal authoritative refresh
of the already selected network bypasses those public context-change
entrypoints, so it cannot accidentally destroy a newly issued token before the
operator acknowledges custody.

The Apple Admin preferences source also exposes an explicit bounded diagnostic
copy. Its 16 KiB `mesh-apple-admin-diagnostic-v2` JSON schema accepts only application/release
identity, enumerated session/load state, aggregate counts/age, fixed
preference-presence booleans, and a fixed error/remediation catalog. There is
no input field for origins, names, IDs, credentials, certificates,
configuration bodies, raw errors, logs, or files. Mesh does not persist or
upload it. The document declares its actual copy boundary: iOS uses a
local-only pasteboard item with a 120-second expiration, while the macOS
system clipboard has no automatic expiration and requires the initiating
operator to clear or replace it immediately after transfer. Approved support
recipients may retain the document only for the associated support case and
must delete every copy when that case closes. Mesh cannot enforce deletion
outside the application, so the schema records that limitation instead of
claiming automatic recipient deletion. This source mechanism does not prove Unified Logging,
physical-device pasteboard behavior, or a complete signed-product support
workflow.

Both Apple Admin native runners use an `OSLog.Logger` wrapper whose public
surface accepts only a closed Swift enum. Each switch branch emits one fixed
reviewed lifecycle code; there is no interpolation or parameter for origins,
identities, errors, credentials, configuration, or user data. Native tests pin
the exact code inventory. This establishes a source boundary, not physical
log-archive inspection, retention configuration, or proof against
platform/crash-collector behavior.

The runners also expose one fixed notification channel. Dart requests
operating-system permission and sends only `fleet-warning` or
`fleet-critical`; native code maps those enums to fixed reviewed titles and
the fixed instruction to open Mesh Admin for fresh authoritative evidence.
Names, identifiers, counts, alert details, server text, and secrets cannot
enter the native request. The first foreground fleet result establishes a
non-notifying baseline, repeated severity is suppressed, and a later warning
or critical transition may notify. There is no background mode or background
poller. Source and simulator tests do not prove permission, presentation,
Focus-mode behavior, managed notification policy, or physical delivery.

Both runners also expose one fixed
`io.rw0.mesh.admin/managed-configuration-v1` read method. iOS reads only
Apple's `com.apple.configuration.managed` dictionary. macOS reads the
application's managed preference domain. Each native reader accepts exactly
seven fields: schema, HTTPS control-plane origin, origin-change permission,
release-channel label, update-ring label, local-status display policy, and
notification policy. It rejects unknown keys, non-Boolean policy values,
non-canonical labels, unsafe origins, and a locked policy without an origin.
Dart independently repeats those checks. The controller rejects a callback-
supplied or stored origin that differs from locked policy, and the UI removes
local origin editing. Managed notification policy cannot be changed locally.
Foreground resume re-reads the managed source. A newly invalid payload
invalidates browser authorization, erases one-time material, stops polling,
clears cookies and persisted session state, disconnects the transport, and
keeps connection callbacks fail-closed until valid policy is available.

The macOS `com.apple.ManagedClient.preferences` mobileconfig and iOS managed
application dictionary under
`packaging/apple/managed-configuration` are bounded, machine-verified,
**unsigned source examples**. They carry no enrollment/recovery token,
session, cookie, access credential, private key, or unrestricted enrollment
authority. Release-channel and update-ring fields are labels only; they do not
authenticate or select release bytes. `ShowLocalStatus` is display policy and
does not make Admin a node controller. A local Keychain capability audit found
no S/MIME identity and no approved MDM profile signer; receipt SHA-256
`9b604b915f9f4c995c6967125f9bb286c398f48af459bec1a1ef997748713d12`
records that the available Developer ID application certificate was not
misrepresented as MDM profile authority.

No Packet Tunnel VPN/on-demand profile is checked in. Per-App VPN is
MDM-configured and the eventual payload must bind `VPNSubType` to the
registered extension identifier. The identifier, Team, App Group, and Network
Extension capability now have valid App Store provisioning, but no MDM
payload, physical installation, or packet-path proof exists. The source
examples therefore prove neither signed MDM deployment nor
supervised/unsupervised behavior.

The checked-in macOS and iOS Admin privacy manifests declare the UserDefaults
required-reason category with only Apple's `AC6B.1` reason for reading managed
configuration; they declare no tracking or collected-data category. The
macOS source receipt now requires that exact manifest in the packaged app.
These manifests describe Mesh-owned source and must be
reconciled with final dependency privacy manifests and App Store Connect
answers for each signed archive. An unsigned simulator build and manifest
inspection are source evidence, never physical-device, provisioning, privacy
declaration, or distribution evidence.

The iOS Admin source path now has a separate create-only security gate for one
exact unsigned universal simulator application. It reconciles the runtime Dart
graph with Syft/SPDX, requires every runtime package in the embedded Flutter
notices, validates an exact four-manifest packaged privacy inventory covering
Mesh, Flutter, secure storage, and URL launching, refreshes an isolated Grype
database, and requires empty redacted Gitleaks reports for bound metadata and
secret-scan text from every regular application file. Generated byte digests
inside nested `_CodeSignature/CodeResources` plists are normalized only in
the scan text; their paths and non-byte values remain scanned, and the exact
original files remain app-tree-bound.

The local 2026-07-24 run binds unsigned simulator app tree
`e4f111be40c9de06b674e961f520ad1ae6004506ca22091853bd601d1f8daf1b`.
It records 49 runtime hosted packages, 68 Syft and 69 SPDX packages, all 49
runtime notice headings, four exact packaged privacy manifests, zero Grype
matches against database schema v6.1.9 built at
`2026-07-24T07:05:19Z`, and two empty Gitleaks reports. Its security receipt
SHA-256 is
`cd1e4f0948663a8451f79f6d3711b1bf27a4c786600b3ece68af8a5baeaea809`.
The receipt explicitly records a Debug simulator build, no signature or
applied entitlements, and no physical-device or distribution validation. Its
dirty source receipt, notice inventory, and privacy inventory cannot satisfy
clean-source, legal, App Store declaration, signing, provisioning,
physical-device, or distribution gates. A future signed archive must consume
a fresh matching security receipt and independently reconcile its final
dependency manifests and store declarations.

The exact receipt-bound unsigned tree was also installed and launched on an
iPhone 17 Simulator running iOS 26.5. Advisory runtime receipt SHA-256
`c2086b8acd43272a0c95636255cfc04dd00b0c9ef6d0e14e40a4081bb6710b98`
binds the source receipt, security receipt, app tree, live process, and
screenshot SHA-256
`a9da556603a0ddba364cdc01cc6764b44414bd891eab3df1649f427ea0d31e87`.
The rendered connection screen visibly reports that secure session storage is
unavailable. Security.framework logged OSStatus `-34018`: the intentionally
unsigned source artifact has neither an application identifier nor
Keychain-access-group entitlements. This launch performed no interaction and
proves no Keychain storage, real browser authorization, managed configuration,
notification delivery, network transition, accessibility matrix,
physical-device behavior, or distribution.

A separate Xcode `Sign to Run Locally` Debug simulator build proved the next
boundary without altering the unsigned source artifact. The Flutter
secure-storage plugin reached Security.framework and the rendered connection
screen no longer showed the storage warning. Native Runner tests passed 7/7,
including an exact add/read/delete round trip using
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, a non-synchronizable item, and
the data-protection Keychain. Advisory receipt SHA-256
`8dd7c309896513a958b610a9e0e2657f6182b4336801b3754e76d0f08f96375f`
binds the local-sign runtime and test evidence. Xcode's simulator app remains
ad hoc with no embedded Team identifier or entitlement dictionary. This
evidence therefore proves only default signed-simulator Keychain admission,
not the registered physical-device access group, Flutter session write,
browser authorization, lock/unlock behavior, background erasure, or
distribution. The Apple source workflow reproduces the local-sign native test,
verifies the resulting simulator bundle, and publishes only the bounded
`.xcresult` summary with the source receipts.

### Mesh Tunnel trust chain

1. source and dependency receipt;
2. reviewed archive with explicit app, extension, static-engine, privacy
   manifest, and entitlement allowlists;
3. Apple signing and provisioning for the selected TestFlight or Custom App
   channel;
4. installed containing application and its exact Packet Tunnel extension;
5. pinned statically linked Nebula engine matching its reproducible build
   receipt;
6. extension-bound local device-only private key and derived public key;
7. one-use Mesh enrollment bound to network, node, and public key;
8. validated Mesh certificate and CA;
9. signed monotonic Mesh configuration bound to certificate generation and
   engine identity;
10. acknowledged extension evidence bound to the exact selected state and real
    packet/peer observations.

Flutter and the containing application may request enrollment and configuration
handoff, but cannot retrieve the node private key or substitute for extension
runtime evidence.

### Current Mesh Tunnel source and controlled-beta boundary

Current unsigned source/security receipts, the earlier strictly reverified
signed archive/IPA, and App Store Connect processing satisfy bounded but
different trust-chain evidence. They do not satisfy installed-device step 4 or
any later runtime step. The current source product contains a separate app and
Packet Tunnel extension, binds the exact reproducible framework-v5
`MeshMobile.xcframework` input, and statically links its Go/Nebula archive into
the extension without a dynamic framework dependency. The compiled
enrollment, renewal, credential-rotation, runtime-report, identity-removal,
engine, settings, Apple callback, and network-path rebind paths are present,
but no receipt or TestFlight state claims an executed callback, applied
interface setting, installed Keychain item, lifecycle convergence, secure
deletion, or physical packet path.
The containing app and extension also implement the source-defined
extension-owned enrollment ceremony from ADR 0012. The app persists only a
canonical HTTPS origin and passes the one-use token directly as one exact
start option. The extension performs strict preflight, local lighthouse
resolution, Keychain identity/agent creation, enrollment, signed-bundle
validation, monotonic activation, and engine startup. No live server or device
has executed that ceremony. ADR 0013 adds one existing-credential,
agent-authenticated lifecycle refresh before later starts; ready state
activates monotonically, bounded service unavailability may defer, and
authorization or invalid state fails startup closed.
The registered identifiers and entitlement values are:

- containing app: `io.rw0.mesh.tunnel.mobile`;
- extension: `io.rw0.mesh.tunnel.mobile.packet-tunnel`;
- App Group: `group.io.rw0.mesh.tunnel.mobile`;
- shared handoff Keychain suffix:
  `io.rw0.mesh.tunnel.mobile.handoff`; and
- extension-only identity Keychain suffix:
  `io.rw0.mesh.tunnel.mobile.identity`.

The containing app receives the Packet Tunnel capability, App Group, and
handoff Keychain group only. The extension additionally receives the
extension-only identity group. Separate development, TestFlight, and Custom
App entitlement documents prevent one distribution path from silently
selecting another path's capability file. Apple Team `Y3P5UNNG23` registered
these values and issued valid App Store profiles. Enabling Network Extension
on the host invalidated historical profile
`ee85c79b-dd9b-444b-a0c3-4dd2b06885e2`; regenerated host profile
`9ae4c36f-22a0-4d67-b078-f40049321616` and extension profile
`4201014e-16f3-4836-8da4-04b856709c51` are active through 2027-05-17 UTC.

A current Profile archive verifies the exact Team, App Group, Packet Tunnel,
Keychain, AppIcon, static-engine, lifecycle-refresh, and bundle boundaries.
The exact manual App Store export produced a 10,740,866-byte IPA whose
post-export signatures, entitlements, embedded profiles, static symbols, and
identity markers were reverified. Product-specific
`mesh-apple-ios-product-distribution-receipt-v3` SHA-256
`1d5dd6e6a4f9d45f456aec005e168c829e565a6413c45f92a8bed89b11117b30`
binds the signed application tree
`9d1cf0c6d19efb1df9ac91ecc7e543b763fd2dfacc7867b2c860914fcd5133a9`,
profiles, build inputs, and IPA SHA-256
`f8512fadfc626cf5fae26d27a77344792767e634d02b0fffa246c869b02006da`,
while explicitly denying release authority, physical-device, applied-setting,
lifecycle, and packet-path evidence.

Xcode uploaded those exact version `0.1.0` build `1` bytes to App Store
Connect app `6794340524` on 2026-07-25. Processing and the standard-encryption,
no-France-distribution compliance questionnaire completed. Build UUID
`7539de60-2da3-4071-b326-ed08db6786dc` completed Beta App Review. A read-only
App Store Connect check on 2026-07-25 showed build `0.1.0 (1)` in `Testing`,
expiring in 90 days. Individual tester `wtmuller.media@gmail.com` had installed
it that day on an iPhone 17 Pro Max running iOS 26.5.2. App Store Connect
showed no sessions, crashes, or feedback. This operational state authorizes no
public App Store or Custom App distribution and proves no authenticated
enrollment, tunnel runtime, or packet behavior. Build `0.1.0 (1)` contains the
earlier framework-v4 pre-start implementation, not the current framework-v5
additions. The registered Devices inventory contains the development Mac but
no iPhone or iPad; TestFlight installation does not require development-device
registration.

A create-only security gate now binds the exact ten-file unsigned
static-engine simulator product and its nested extension tree. SwiftPM
independently reports an empty external dependency graph. Syft and SPDX recover
the statically linked Go package inventory, while the verifier separately
requires the exact 29-module runtime graph from the bound framework receipt.
The gate also requires the exact two empty app/extension privacy manifests, a
fresh Grype report with no High/Critical or published-fix finding, and empty
redacted Gitleaks reports over bound metadata and strings from all ten
product files.

The refreshed 2026-07-25 framework-v5 extension-enrollment, lifecycle,
mobile-evidence, identity-removal, static-engine, AppIcon, network-rebind,
request-bound status, existing-identity start, and stop source run binds
containing-app tree
`bc6efc0d52c4804959423202057c67cc9b681148c5822805f1632cf2ec6a44e4`
and extension tree
`68d08e1d106c6158580bdca6fe30f61f80d81ee450a6d401dd156f5f38cce6fe`.
Its security receipt SHA-256 is
`c67915d918d713d2717c325afceb89e2ef7d3b6bb13c667d74cdec77b407780e`;
the bound source receipt SHA-256 is
`9a065b593c8a0133282f957bfece392ea76dd228f69376e57b8a3375db93375e`.
That receipt records version `0.1.0` build `2` for both the containing app and
extension. It records zero SwiftPM dependencies, the exact 29 static-engine
runtime modules, 65 Syft packages, 66 SPDX packages, two empty privacy
manifests, and two empty Gitleaks reports. Grype database schema v6.1.9 built at
`2026-07-24T07:05:19Z` reports two non-fixable Unknown matches for advisory
`GO-2026-5932`, and no High/Critical or published-fix finding. The receipt
records static engine linkage and source-wired Apple packet callbacks, but
runtime packet-flow connection, applied network settings, signature,
entitlements, physical-device validation, and distribution validation remain
false. Its clean-source local simulator boundary is not an independent CI
host, a protected release, or a later trust-chain step. Both current Tunnel
and framework source receipts identify isolated clean snapshot commit
`51e305575df839ab548350ece8da484cc30bc312`. These unsigned v5 bytes
are not the earlier signed archive, IPA, or TestFlight build.

The App Group is an authenticated transport, not a secret store. A random
32-byte handoff key is created in the shared, non-synchronizing,
after-first-unlock-this-device-only Data Protection Keychain group. It
authenticates a strict bounded configuration envelope with HMAC-SHA256. Slot
reads use no-follow file descriptors and require a regular single-link object;
writes use create-exclusive private temporaries, full write and file
synchronization, atomic `renameat`, and directory synchronization. Candidate,
current, and recovery slots are bound to the exact network, node, certificate,
configuration, engine, revision, and monotonic counter. The current slot is
durable before the extension-only Keychain high-water item advances. Recovery
derives the effective floor from both authorities, so an ambiguous high-water
write cannot make an older candidate acceptable. Initial enrollment derives
its next counter from the maximum of that authenticated current slot and
Keychain floor before staging and activating the verified framework output.

The separate `MeshMobile.xcframework` proof establishes key custody and a
bounded packet-session primitive. Its Go source directly creates or reads the
raw 32-byte X25519 private key in the extension-only, non-synchronizing,
after-first-unlock-this-device-only Data Protection Keychain group, zeroes
temporary buffers, and returns only the derived public key. A separate stable
32-byte agent credential seed uses the same extension-only group and is never
returned. Both use the pre-node-ID account `primary`, so enrollment and later
engine startup address the same local identity. The generated Objective-C
surface exports `IosmobileEnsureIdentity`,
`IosmobileFrameworkIdentity`, `IosmobileFrameworkIdentitySHA256`,
`IosmobileNewEngineSession`, `IosmobileNewEnrollmentSession`, and
`IosmobileNewLifecycleSession`, plus
`IosmobileNewIdentityRemovalSession`. The enrollment session exposes only one
bounded `enroll` method. The lifecycle session exposes only `refresh` and
`reportRuntime`; the identity-removal session exposes only `remove`. The
engine session exposes only framework identity, signed configuration
preparation, start, UDP rebind, packet send, packet receive, and idempotent
stop. None exports the private key or either agent bearer. Framework identity
is `mesh-ios-mobile-framework-v5`; its exact capability string names
enrollment, lifecycle, renewal, credential rotation, mobile evidence, identity
removal, signed configuration, and packet session. Its receipt binds Nebula
1.10.3, the exact gomobile module revision,
Go/Xcode/SDK/deployment identities, source digests, slices, headers, binary
identities, every engine Go source, the shared mobile-runtime contract, and
two independent identical normalized trees. The build stages exact source at
the fixed `mesh-ios-mobile-framework-source-staging-v1` root before gomobile
binding, rejects the caller's checkout path in every slice, and has produced
the same tree from dirty and separately committed clean-source checkout paths.

A separate create-only security gate snapshots one exact unsigned framework
tree and binds it to that source receipt. It resolves the iOS arm64 target's
exact 29-module runtime graph, copies and hashes all 35 reviewed module
license/notice files, and reconciles those modules with Syft and SPDX. The
digest-pinned scanners run networkless, read-only, non-root, without the
Docker socket or registry credentials; only a fresh isolated Grype database
update receives network access. A separate Gitleaks policy requires empty
redacted reports for the bound source/module/license metadata and strings
from every regular framework file.

The current local 2026-07-25 run binds framework-v5 tree
`01a9fe1088dfd22e5c2b494273e31a54fc7e2dfc7a0a1de0827db37b4b1b8c4c`
and framework source receipt SHA-256
`c21b20f379ba8a4df4ff3430ade26a2d7c41a8cc0e993c72961f6c911ad8b97e`.
It records 29 runtime modules, 35 license/notice files, 40 Syft packages, 41
SPDX packages, and two empty Gitleaks reports. Grype database schema v6.1.9
built at `2026-07-24T07:05:19Z` reports one remaining non-fixable Unknown
module advisory, `GO-2026-5932`, and no High/Critical or published-fix
finding. The security receipt SHA-256 is
`18da794a1814fd2c91139606c0e6fa2997658d60593fdc65445f201d11a4d6a1`.
The exact license inventory is not legal approval, and local clean-source
reproduction cannot satisfy an independent clean-host or protected release.
The standalone framework receipt does not itself assert a Tunnel link; the
Tunnel receipt separately binds this exact framework source receipt and tree
and proves its static symbols in the extension executable. The current signed
archive and IPA contain the earlier framework-v4 surface, not this v5
framework. Physical-device packet-path and Apple release gates remain
independent.

Apple's documented `NEPacketTunnelFlow` API exposes packet read/write
callbacks. Mesh does not adopt the current upstream mobile implementation's
utun-descriptor discovery. Nebula 1.10.3 also exports an in-memory
`overlay.UserDevice`; the bounded Mesh adapter validates and copies complete
IPv4/IPv6 packets between that device and the exported engine callback loop.
Go tests prove both directions, ownership, malformed-length rejection, bounds,
and close behavior. A native-host feasibility test also runs two pinned Nebula
engines with callback devices and real loopback UDP, proves
certificate-authenticated direct ICMP request/reply packets with no relay,
rebinds the real UDP listener and proves post-rebind traffic, and repeats clean
start/stop after translating `UserDevice` closure to the `os.ErrClosed`
condition required by Nebula's production loop. The engine session now
connects that adapter to Swift in the universal simulator build, and the
provider maps Apple callback batches into the bounded coordinator. This
remains source/link and native-host compatibility evidence only: no valid
device handoff has started the extension, and there is no physical-device,
accepted Apple interface, iOS UDP, resource, roaming, or iOS packet evidence.
Apple-supported API review and physical native proofs must precede a tunnel
support claim.

The authenticated payload also contains a data-only network-settings plan.
Swift accepts only canonical usable-unicast IPv4/IPv6 assignments and DNS,
network-aligned same-family routes, disjoint included/excluded route entries,
bounded collections, and an MTU from 1280 through 1500. This validation does
not apply settings, authorize traffic, or constitute device evidence.
The same authenticated payload now requires a typed canonical usable-unicast
underlay remote endpoint because Apple's initializer requires the IP address
of the endpoint providing the tunnel service. Validation rejects an overlay
address and requires an explicit excluded route whenever an included route
would otherwise capture the endpoint. A tested factory and provider adapter
map the validated remote endpoint, IPv4, IPv6, routes, DNS, and MTU into
Network Extension objects and can apply or clear those settings.
Payload v4 also binds the exact Nebula config and CA digests, canonical
certificate issue/renewal/expiry timestamps, certificate generation and
fingerprint, public-key hash, config-signing key and signature, and CA
transition metadata. Swift rejects unknown nested fields and inconsistent
digests before startup; the Go engine independently verifies the signed
configuration, certificate, CA, local private-key match, routes, and PKI paths
before constructing Nebula.

When no current slot exists, the provider accepts only one canonical
`mesh-ios-tunnel-enrollment-v1` start option. The Go enrollment session first
uses the token-scoped no-store preflight and requires an unexpired member plan
with at least one locally resolvable usable lighthouse outside the planned
overlay. Only after that non-consuming gate does it create or read the local
identity and agent credential. It sends only the one-use token, public key, and
agent-bearer hash; an ambiguous result permits one byte-identical replay and
then authenticated bootstrap recovery. Before returning a v4 configuration it
binds the signed member role, certificate network, local key, native DNS, and
selected underlay remote back to the preflight plan. The containing app clears
the token and never places it in VPN preferences or the App Group. These are
source and test contracts, not evidence that a real token was consumed or a
physical Keychain item was created.

When a current slot exists, startup first creates a separate lifecycle session
that can open only the existing extension identity and agent items. It verifies
the current v4 document against the local private key and exact stored origin,
pins the bootstrap configuration-signing key to the currently trusted key, and
performs one agent-authenticated bootstrap. The exact
`mesh-ios-lifecycle-refresh-v1` result is ready, deferred, or unauthorized.
Ready state must name the same node/network/origin with nondecreasing
certificate, agent-credential, and configuration generations, is independently
revalidated, and is staged and activated at the next monotonic counter.
Transport failure, 429, and 5xx may defer to the still-valid current state.
Unauthorized, malformed state, origin or identity substitution, rollback, or
any other response fails startup closed.

When the signed renewal time is due or bootstrap requires a CA or certificate
profile transition, the lifecycle session submits the existing public key to
`POST /api/v1/agent/certificate/renew`. The returned certificate generation
must be strictly newer, and the entire resulting configuration is revalidated
without changing node, network, origin, key, or signing-key identity.
Ambiguous transport permits one exact retry followed by authenticated
bootstrap recovery. Ordinary due renewal may defer for transport, 429, or 5xx
while the current certificate remains valid. A mandatory CA/profile transition
never falls back to the old certificate.

When the authenticated agent-credential expiry is within seven days, the
extension creates one random 32-byte pending seed in a fixed extension-only
Keychain item before calling `POST /api/v1/agent/credentials/rotate`. Only its
SHA-256 hash crosses the network. The current bearer authorizes the first
request; ambiguous response recovery uses the pending bearer and the same
hash. The primary item changes only after an exact newer generation and
bounded future expiry are verified, then the pending item is deleted. Restart
recovery handles a crash on either side of that local commit without exporting
either bearer.

While scheduled, the provider emits a strict runtime observation every 60
seconds through `POST /api/v1/agent/mobile-runtime`. The v1 report binds the
extension instance generation, monotonic sequence, lifecycle state,
configuration revision/digest, certificate fingerprint/generation, engine
identity, monotonic runtime uptime, optional packet counters, and one bounded
fixed error code. The server stores its receive time separately from
authoritative lifecycle state. It projects a two-minute freshness bound for
ordinary reports and a 15-minute bound only after an explicit `suspended`
report. Missing, stale, suspended, duplicated, malformed, future, or
unsupported evidence never becomes health. Suspension reporting is
best-effort because iOS may stop scheduling the extension.

An authenticated desired-state mismatch returns `refresh-required`, stops the
active tunnel, and requires the next start to run the full verified refresh
and monotonic activation path. The current source does not hot-reload an
active engine. A generic HTTP 401 can represent expiry, rotation, or
revocation, so the provider quarantines rather than claiming authoritative
revocation. Only server authority may label the node `revoked`.

The containing app also exposes one destructive local identity-removal action.
It loads only authenticated local context, shows the exact node and network,
and sends a strict request containing a fresh request ID and exact node ID.
The extension re-authenticates that context against its real high-water floor,
stops runtime work, and calls a deletion-only gomobile session. That surface
attempts all three fixed authority deletions—current agent credential, pending
agent credential, and private key—and has no load, return, replace, or create
operation. Configuration slots are erased only after every Keychain authority
deletion succeeds. Partial failure retains signed context for exact retry.
After a bounded completion receipt, the host removes the VPN preference.
The handoff HMAC and lifecycle high-water values remain because they are not
node authority and preserve authentication and rollback protection. Local
removal is not server revocation or node deletion.

The current containing-app source also rediscovers exactly one provider with
the Mesh extension identifier, starts an existing authenticated local identity
without another enrollment token, requests stop, and sends a fresh
request-ID-bound status request. A running response is produced from the real
coordinator and carries its configuration revision, certificate generation,
engine identity, and directional Apple callback counters; non-running states
cannot carry those fields. The host verifies the response request ID and exact
schema before display. Neither the counters nor `NEVPNStatus` is presented as
peer authentication or end-to-end connectivity. The onboarding surface is
scrollable for compact iPhones and enlarged text. These controls are current
unsigned source evidence and are not present in the uploaded framework-v4
TestFlight build.

These are source, unit, reproducible-framework, static-link, and unsigned
security contracts. They are not physical-device scheduling, renewal,
rotation, revocation cutoff, Keychain deletion, or lifecycle convergence
evidence.

A tested runtime coordinator enforces engine identity, engine preparation,
Apple settings, packet-pump start, and engine start in that order. Stop and
startup, packet, and rebind failures run reverse cleanup, and running evidence
is not emitted before all stages complete. Its packet-pump actor copies and validates complete
packets, bounds batches and directional queues, rejects a whole batch under
pressure, preserves accepted order, records directional counters, and clears
queued bytes on idempotent stop.

The reviewed unsigned provider build uses the statically linked engine
adapter. Its two `NEPacketTunnelFlow` tasks start only after engine
preparation, settings, pump, and engine startup succeed. After the initial
network observation, `NWPathMonitor` changes invoke the engine's UDP rebind;
failure cancels both tasks, stops the engine, clears settings, and terminates
the tunnel with a fixed code. The artifact receipt proves those symbols and
source paths but records no executed callback or applied setting, so packet
transport and roaming remain source-contract evidence, not iOS device evidence.

## Evidence classification

### Authoritative

- Server-stored identity, permissions, request receipts, signed revisions,
  certificate history, revocation, and server receive time for accepted
  evidence.
- Threshold-authenticated release/root metadata and exact artifact bytes.
- Apple code-signature, provisioning, notarization, staple, and Gatekeeper
  results when independently rechecked against the final artifact.
- Installer high-water/root history, authenticated installed bytes, selector,
  gate, plist, and kernel process identity.
- Extension-generated evidence authenticated by the node credential and bound
  to its certificate generation, config digest, engine, sequence, and observed
  packet/peer counters.

Authoritative means authoritative only for the named fact. For example, a
valid code signature says nothing about packet flow, and an accepted heartbeat
says nothing about peer reachability without matching packet evidence.

### Advisory

- Client platform and model labels, application foreground/background hints,
  low-power or path status, notification state, user-visible local errors,
  MDM inventory, and containing-app tunnel summaries.
- Runtime observations from a root-compromisable host or entitled extension.
  They can inform diagnosis but cannot create identity, policy, or release
  authority.

### Unavailable or prohibited

- Remote attestation of uncompromised macOS root or iOS kernel.
- Guaranteed iOS extension scheduling while suspended.
- Health inferred from process existence, IPC response, configured routes,
  DNS configuration presence, or a generic VPN status.
- A direct/relay or packet-path claim without corresponding engine and packet
  evidence.
- Raw private keys, sessions, enrollment/recovery tokens, unrestricted signed
  configuration, arbitrary host files, or unrestricted diagnostics in an
  operator projection.

## Secret classes and custody

| Class | Allowed process/storage | Forbidden boundary |
| --- | --- | --- |
| Operator session and CSRF pair | Admin app memory and exact-origin, app-only, device-only Keychain item | Browser URL, App Group, extension, profiles, logs, notifications, restoration, analytics |
| Browser authorization poll secret | Admin app memory; device-only Keychain only for a bounded resumable request | Verification URL, control-plane logs, extension, profiles, analytics |
| Legacy administrator bearer | Admin app memory only | Keychain, disk, extension, diagnostics |
| Enrollment and recovery secret | Short-lived custody view and request memory | Persistence after close/background/lock/logout/origin change; snapshots, pasteboard history, logs |
| macOS node private key | Root-owned node state used by the authenticated Mesh agent/Nebula runtime | Admin app, control plane, profiles, diagnostics, ordinary user storage |
| iOS node private key | Extension-accessible device-only Keychain item; cryptographic operation stays in the narrow native/runtime boundary | Flutter, ordinary app storage, App Group, control plane, logs, crash reports |
| Agent credential | Root-owned macOS state or extension-accessible device-only Keychain | Admin app, profiles, notifications, unrestricted diagnostics |
| Signed configuration and certificate | Authenticated immutable node state; minimum app/extension recovery handoff on iOS | Unbounded operator/diagnostic export; use as a private-key substitute |
| Release/notary/provisioning credentials | Protected release context only | Source, PR jobs, developer fixtures, process arguments, artifacts, logs |
| Non-secret policy | Signed MDM profile or managed preferences after schema validation | Any field that turns MDM possession into unrestricted Mesh enrollment authority |

No analytics, diagnostic upload, crash SDK, pasteboard integration, or new
device inventory field is permitted without a separate privacy decision.

## Release verification inventory

`packaging/apple/release-verification-matrix.json` v2 pins the complete Phase 9
gate names and minimum evidence classes for all four Apple products. It is a
non-release policy document: `release_eligible` is permanently false and all
products are unsupported. The verifier fails if a gate disappears, repeats,
moves to an unknown proof class, or if the document asserts support. It also
requires final source/provenance and signing-secret-independent verification
for every product. Both macOS products require release-metadata binding,
authenticated publication, public re-download, and sanitized release receipts.
The macOS Node inventory separately requires final signed-bundle and Installer
signature verification, notarization/staple, and Gatekeeper assessment. iOS
Admin retains the final privacy-manifest/declaration review, while iOS Tunnel
retains both distribution validation and Network Extension channel approval.

The policy explicitly prevents source or simulator results from satisfying
protected-release, provenance, publication, native-host, clean-host,
physical-device, accessibility, distribution, control-plane, or packet-path
evidence. The matrix does not authenticate any result. Each result still
requires the artifact-specific verifier and receipt that proves the final
bytes, environment, identity, and observed behavior.

## Versioned local bridge

No bridge implementation is authorized until this schema is reviewed.
The initial envelope is `mesh-apple-local-bridge-v1`:

```json
{
  "schema": "mesh-apple-local-bridge-v1",
  "request_id": "UUID",
  "operation": "status.read",
  "expected_revision": 7,
  "body": {}
}
```

Responses carry the same schema and request ID, one bounded result or stable
error code, the proved local service/release identity, current signed revision
and evidence time, and for mutations an idempotent receipt containing previous
state, resulting state, actor, and outcome. All strings, arrays, messages, and
request rates have explicit limits in the implementation schema.

The macOS bridge authenticates the audit token, effective console user, code
signature, designated requirement, Team ID, and approved bundle identifier.
The iOS handoff additionally relies on the exact app/extension entitlement and
provisioning boundary. Neither bridge accepts executable paths, arguments,
environment, file paths, URLs, shell fragments, raw configuration, arbitrary
actions, or secrets. Version mismatch, identity mismatch, stale state, unknown
field, duplicate field, oversized message, or ambiguous authorization fails
closed.

The only initially reserved operations are:

- `status.read`;
- `diagnostics.describe`;
- `tunnel.configuration.stage`;
- `tunnel.configuration.select`;
- `tunnel.start`;
- `tunnel.stop`; and
- `identity.remove`.

Reservation is not implementation approval. Each operation needs a specific
request/response schema, authorization rule, idempotency behavior, audit
receipt, size/rate bound, and negative test before exposure.
The current iOS source implements a narrower local-only `identity.remove`
request and bounded receipt inside the app/extension boundary described above.
It does not expose a server mutation and does not implement the other reserved
bridge operations.

## Server-visible Apple lifecycle

`POST /api/v1/agent/mobile-runtime` now accepts the strict authenticated v1
mobile observation and returns no content with `Cache-Control: no-store`.
`GET /api/v1/nodes/{nodeID}/mobile-runtime` exposes the bounded per-node
projection to an authorized operator. Mobile evidence is
stored in the nonauthoritative runtime telemetry document, is removed with its
node/network lifecycle cleanup, and cannot advance signed configuration or
authoritative lifecycle state. The lifecycle vocabulary is versioned
independently of display text:

| State | Meaning and required evidence |
| --- | --- |
| `foreground` | Advisory containing-app state only; never node health. |
| `background` | Advisory containing-app state only; never tunnel state. |
| `suspended` | The OS may not schedule fresh extension evidence; last accepted evidence remains visible with age and is not healthy. |
| `tunnel-starting` | Fresh extension receipt accepted for the selected identity/config, but interface and packet readiness are not yet proved. |
| `tunnel-running` | Fresh extension evidence proves the selected identity/config/engine and active interface; peer and packet claims remain separate fields. |
| `tunnel-stopping` | Fresh stop receipt accepted; no stopped claim until runtime absence is proved. |
| `stale` | The server freshness bound elapsed without acceptable evidence. |
| `quarantined` | The runtime deliberately denies packet operation because signed state, certificate, key, gate, or revocation status cannot be trusted. |
| `revoked` | Server authority permanently revoked the node; this dominates client state. |
| `extension-error` | Fresh bounded extension error evidence; error class does not imply compromise or revocation. |

Transitions are monotonic per extension instance and bind the node ID, network
ID, certificate fingerprint and generation, signed revision and digest, engine
identity, event sequence, monotonic runtime instant where available, and server
receive time. A new extension instance explicitly breaks continuity. Only
fresh `tunnel-running` evidence can recover from `suspended`, `stale`, or
`extension-error`. `revoked` cannot be cleared by client evidence. Quarantine
clears only after the underlying authority is freshly revalidated.

UI language separately presents control-plane reachability, signed lifecycle
state, tunnel runtime, peer authentication, relay use, and packet-path proof.
It never collapses these into “connected.”

The Packet Tunnel extension source logs only eighteen fixed reviewed event
codes: start and stop requests, three configuration rejection classes,
enrollment-request rejection, enrollment failure, lifecycle deferral,
lifecycle failure, agent-authorization rejection, unavailable engine,
network-rebind failure, packet-flow failure, and accepted or rejected bounded
status requests, plus identity-removal requested, completed, or failed.
Its logging API accepts an enum rather than text and never receives the
provider stop reason, configuration, errors, identities, packet content, or
dynamic values. A simulator build proves that wrapper is compiled into the
extension; physical log collection, retention, redaction, and crash-path
review remain required.

## Backward-compatible API and rollout contract

The mobile evidence API and storage migration now implement the originally
planned additive rollout shape:

1. optional, versioned evidence fields and strict maximum sizes;
2. old documents migrate to an explicit absence value without changing
   signed configuration, revision, or timestamps;
3. deploy strict readers to every server replica before any writer persists
   the new document version;
4. deploy server writes before clients rely on the projection;
5. old-client behavior remains unknown/unsupported, never healthy;
6. the typed route catalog, generated OpenAPI, JSON/PostgreSQL/archive/migration
   tests, and strict HTTP tests change together; and
7. block rollback to a strict reader that cannot read the document once a
   write occurs.

Every mutation retains server RBAC, request ID, expected revision,
idempotency, actor-attributed audit, and authoritative readback. Client
platform labels remain advisory.

Before each foreground fleet poll, the shared Apple Admin controller refreshes
`/api/v1/session` and binds presentation to the exact returned permission set,
not to a role-derived approximation. A downgrade removes privileged
affordances and Access inventory state and erases one-time material. Audit and
Access responses that finish after permission loss are discarded. A 401
revocation clears the cookie pair and local authenticated state; a changed
session identity or unverifiable authority response also fails closed to
signed-out state. This is source and local-test evidence, not a physical-device
or external identity-provider revocation result.

The macOS runner maps application hide and the main window's close notification
into the same data-free one-time-material erasure boundary used for lock,
screen sleep, system sleep, and termination. Its native menu exposes only
Refresh and Preferences and sends argument-free fixed commands to the existing
Flutter shell; it is not a second API client or authorization context. Native
and widget tests prove the source mapping and menu installation, but signed
clean-host hide/window-close behavior remains a release gate.

The iOS Admin source gate exercises iPhone portrait/landscape and iPad
split/portrait/full-landscape layouts at 100, 200, and 320 percent text scale.
It also evaluates propagation of reduced-motion and high-contrast settings,
semantic labels, iOS tap-target sizes, and rendered contrast. The responsive
shell keeps role context visible and stops using the height-constrained
desktop rail on iPhone landscape. This is repeatable widget evidence, not a
claim of physical VoiceOver, Switch Control, display accommodation, or
assistive-input validation.

## Review and release gates

Security review must explicitly accept this contract and all nine ADRs before
an Apple artifact can be release-approved. Review records the reviewers,
commit, unresolved risks, expiration/re-review trigger, and disposition.

Independent gates remain closed until their matching evidence exists:

- macOS Admin: clean unsigned build, completed SBOM/vulnerability/secret scan
  receipt, legal and final privacy review, authentication/RBAC/secret/
  accessibility tests, signature/entitlement/notarization/staple, clean-host
  workflows, update, migration, and uninstall;
- macOS Node: supported installer command, installed-runtime enrollment gate,
  both architectures' native execution, clean install, launchd, reboot,
  packets, DNS/firewall/relay, renewal/rotation/revocation/staleness, upgrade,
  interruption, rollback, uninstall, signing/notarization, and public
  re-download;
- iOS Admin: simulator plus physical-device browser auth, Keychain,
  background/lock/termination erasure, RBAC/mutations, accessibility, privacy
  manifest, update, and approved distribution;
- iOS Tunnel: entitlement/provisioning, reproducible engine, physical iPhone
  and supported iPad packet matrix, roaming/suspension/crash/reboot,
  renewal/rotation/revocation, key custody, privacy, and distribution.

Compilation, mocks, process existence, simulator-only evidence, a local
developer signature, or the presence of an entitlement cannot satisfy a
native-host, device, packet, signing, notarization, or distribution gate.

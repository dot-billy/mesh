# Apple integration evidence status

Last updated: 2026-07-27.

This is an implementation and review ledger, not a support statement. Mesh
does not yet ship or support a macOS or iOS artifact. The source work in this
checkout is the build-9 successor; its exact
commit is recorded by the release receipt after the source is committed.
The goal-to-evidence mapping and remaining external dependencies are tracked in
[`apple-goal-completion-audit.md`](apple-goal-completion-audit.md).

## Gate status

| Capability | Current evidence | Gate still required |
| --- | --- | --- |
| Apple architecture | Product ADRs, threat analysis, trust chains, custody boundaries, lifecycle vocabulary, and rollout order are recorded. | Independent security review must accept the decisions and threat model. |
| Apple build environment | Xcode, SDK, Swift, Go, Flutter, archive digests, deployment targets, simulator runtimes, disk, network time, credentials, source state, and build outputs have machine-readable checks. Unsigned jobs use a private empty Keychain and reject release credential variables. Admin artifact receipts also bind the exact locked `objective_c` package and verify its final framework inventory, architecture map, install names, and absence of Flutter's transient collision name. A clean pre-static-engine disposable commit historically reproduced macOS Debug and universal Release, iOS Admin simulator, iOS Tunnel simulator, and two identical mobile-framework builds with isolated Go/Pub/build caches and one empty Keychain; all five receipts bind the same clean preflight. The current framework-v5 build now stages exact inputs at one recorded canonical path, rejects checkout-path leakage, reproduces twice per checkout, and produced the same tree from both the dirty working path and a separately committed clean-source path. That clean-source framework is statically linked into a clean-source Tunnel simulator receipt. The workflow source also defines credential-free Ubuntu and Windows regression jobs. Ubuntu uses the exact Go pin, Nebula 1.10.3 test tools, a short owner-private temporary root, canonical docs/Go test and build gates, and the nested Tunnel engine tests. Windows installs the same exact test tools and runs the repository-wide Go test and build graphs natively. Every Go-source change triggers these jobs. | Run the current static-engine source on independent clean Apple, native Linux, and native Windows CI hosts and retain their review artifacts; the new regression jobs have not run externally, and the local disposable checkout/container is not clean-host evidence. The pinned Flutter native-assets diagnostic remains emitted and must be re-reviewed when Flutter or `objective_c` changes. |
| Mesh Admin for macOS | A sandboxed full-window Flutter runner builds unsigned Debug arm64 and unsigned Release arm64+x86_64 applications from the pinned SDK. Source tests cover strict browser authorization, exact-origin device-only Keychain configuration, one-time-secret lifecycle erasure including fixed data-free native lock, screen sleep, system sleep, application hide, main-window close, and termination events, keyboard and enlarged-text behavior, viewer-denied mutation behavior, and authoritative session refresh on every foreground fleet poll. A fixed data-free native menu bridge wires only Refresh and Preferences into the same Flutter controller/navigation path. A role or exact-permission downgrade removes privileged presentation and one-time material; a server-revoked session signs out and erases local cookie custody. An exact-confirmation pre-uninstall action attempts both the session and saved-profile Keychain deletions even if one fails, clears in-process custody, and explicitly retains MDM, OS permissions, server records, and any separately installed Node. The source also provides an explicit bounded diagnostic-copy schema containing only aggregate state and fixed remediation codes, truthfully declaring non-expiring macOS clipboard custody and recipient deletion limits, and an Apple Unified Logging wrapper that accepts only a closed enum of reviewed lifecycle codes. A native reader and Dart independently validate a strict non-secret managed-preferences schema; a verifier pins an unsigned `com.apple.ManagedClient.preferences` source example. A native test performs an isolated file-Keychain round trip. A cross-language test runs every current `MeshApi` read and mutation against the real file-backed Go control plane with exact Nebula 1.10.3 certificate operations. The packaged app contains the exact minimal UserDefaults required-reason privacy manifest. Historical protected bytes authenticated to the live test control plane as `legacy_admin`, displayed one network and two active nodes, and restored the Keychain session after process termination and relaunch; their nonportable v2 receipt is superseded. A clean replacement build, exact-tree security scan, protected signing/notarization job, and ordinary-umask second extraction now produce a v3 archive whose pre-archive and extracted tree identities match and whose portable verification, deep signature, profile, staple, and Gatekeeper checks pass. An explicitly disposable local-test root and two-of-two release threshold exercised the complete downloaded-artifact native verifier; its receipt binds all inputs and the private test keys were removed. | This is bounded local test evidence, not a release-authority decision. Embedded notice coverage is not legal approval, and final signed dependency/privacy reconciliation remains pending. No approved production root or manifest, signed MDM profile, managed-device installation, publication, public re-download, production-root native receipt, or clean-host evidence exists. Prove actual lock/sleep/hide/window-close erasure on the replacement signed app, run real OIDC-provider and physical-browser flows, complete physical accessibility and clean-host matrices, and pass release-metadata, publication, update, uninstall, real log-collection/redaction, MDM, and support gates. |
| Mesh Node for macOS | The Darwin build of the narrow `mesh-install` command now composes authenticated online/offline intake, immutable publication, journal recovery, fixed launchd activation, post-enrollment runtime-gate opening, exact persisted-previous rollback, and state-last runtime deactivation with retained trust/enrollment state. A compiled-policy adapter derives exact Developer ID requirements for all three executables, strictly invokes the fixed Apple codesign tool, authenticates launchctl's Apple designated requirement, and is wired before activation and enrollment execution. Its development sentinel fails closed. Protected authoring source now converts exact unsigned bundle-v1 inputs into deterministic signed bundle-v2 artifacts only after proving signature-region-only Mach-O replacement and matching a fresh native receipt; release preflight requires that native receipt plus a final package-security receipt. A Darwin `meshctl` source boundary authenticates the exact active installed release, current selector, live plist, quiescent installer state, closed gate, and compiled code-signature policy before any runtime execution, then deliberately rejects production enrollment. Existing Darwin code-signing-policy, bundle, package-security, launchd, native-evidence, and node-agent source tests pass on the development Mac. A fresh root-owned Apple Silicon v3 receipt binds the macOS 26.5 `O_NOFOLLOW_ANY`, symlink-mode, and artifact-lock compatibility fixes and passes every enabled native path, installer-gate, exact-child, process-group, and reap test; it explicitly records no bundle and no system-launchctl mutation. A separately gated attempt exercised and cleaned the exact proof launchd label before the unsigned staging bundle was rejected by the fail-closed code-signature admission policy. Two locally installed Developer ID Installer identities were enumerated by exact SHA-1 fingerprint, and one signed a new payload-free proof package whose signature validates as trusted with a secure timestamp; the proof package was never installed or notarized. | Final Team ID and code identifiers are not approved or embedded; no real Developer ID signed bundle-v2, installer payload package, or full verifier-accepted native receipt exists. The partial receipt and payload-free signature prove only bounded native and local Installer-identity feasibility. Phase 3 production-command execution, enrollment, immutable-runtime, full system-launchd lifecycle, reboot, interruption, upgrade, rollback, uninstall, revocation, packet, Intel and full Apple-silicon, native signature, protected signing, notarization, clean-host, and MDM proofs remain pending. Production enrollment stays disabled. |
| Mesh Admin for iPhone and iPad | A pinned Flutter iOS runner now compiles as an unsigned universal iPhone/iPad simulator application with a create-only source receipt. It uses the shared API/auth/RBAC/transport/presentation code, including authoritative session refresh on every foreground fleet poll, exact server-returned permission presentation, downgrade-driven removal of privileged state and one-time material, and fail-closed sign-out after server revocation. It also has iPhone and iPad compact layouts, explicit device-only Keychain options, separate development/TestFlight/App Store/managed entitlement files, a minimal privacy manifest, lifecycle and protected-data secret erasure, app-switcher redaction, foreground-only polling, and a local-only two-minute iOS pasteboard boundary that now fails closed if the native bridge is absent. The explicit bounded diagnostic-copy schema uses the same expiring boundary and excludes origins, names, IDs, credentials, raw errors, logs, and configuration. A native Unified Logging wrapper accepts only fixed lifecycle codes and cannot receive arbitrary strings. Native and Dart managed-application readers independently accept only seven reviewed non-secret fields; locked origin and notification policy are enforced in the controller/UI, and a verifier pins the MDM dictionary source example. Widget evidence now covers iPhone portrait/landscape, iPad split/portrait/full landscape, 100%/200%/320% text scaling, reduced-motion and high-contrast propagation, labeled controls, iOS target sizes, and contrast. Shared tests and native simulator XCTest cover the implemented source contracts. A local create-only simulator security receipt binds the exact app tree, reconciles 49 runtime hosted packages with 68 Syft/69 SPDX packages and all 49 embedded notice headings, validates the exact four-manifest packaged privacy inventory, reports zero matches against a fresh Grype database, and requires empty metadata and all-app-file string Gitleaks reports. Apple Team `Y3P5UNNG23` registered `io.rw0.mesh.admin.mobile`; App Store Connect app `6794340010` and a valid App Store profile exist. A local signed Release archive passed store and signature validation, and Xcode successfully exported a strictly reverified App Store IPA under the exact manual export policy. Product-specific distribution receipt v3 independently binds the Admin profile, archive tree, exported IPA digest, Team, and Admin-specific limitations without coupling the gate to Mesh Tunnel. | The local security receipt is from a dirty-checkout debug simulator build and cannot satisfy a signed distribution release; it has not been refreshed for the local signed archive. Notice coverage is not legal approval, and the reviewed packaged privacy inventory is not a final App Store declaration. The MDM dictionary is an unsigned source example, not distribution evidence. The IPA was not uploaded and is not release-authorized. No physical-device installation, physical Keychain access-group proof, real browser return, lock/unlock, screenshot, notification, supervised/unsupervised result, signed managed configuration, VPN/on-demand profile, network-transition, update, TestFlight upload, Custom App selection, App Store declaration, real log-collection/redaction, or distribution evidence exists. The generic generated app icon is also not release artwork. |
| Mesh Tunnel for iPhone and iPad | The UIKit host, Packet Tunnel extension, framework v5, shared device-only Keychain custody, lifecycle refresh, runtime evidence, and identity removal compile and pass local gates. Builds 2 through 10 are externally distributed. Build 8 physically completed provision-first OIDC and server enrollment; Build 9 recovered and displayed the committed authenticated local identity; Build 10 corrects its first-inspection race. No released build proved packet transport. The current successor retains Mesh authentication, signed configuration, Go/Keychain custody, and Mobile Nebula's manager lifecycle, but replaces the separate Swift packet-copy path with Mobile Nebula's production transport: Go validates the provider-owned `utun` descriptor and constructs pinned Nebula with `overlay.NewFdDeviceFromConfig`. Production source does not start `NEPacketTunnelFlow` copy tasks. | Committed local configuration and retained identity recovery are physically proved. Native-transport selection passes source and simulator gates only. Installed-device provider startup, lighthouse reachability, authenticated peer traffic, lifecycle, credential rotation, roaming, response loss, crash/restart, resource measurements, and successor distribution remain required. |
| Existing platforms | Public/API documentation checks and the exact Nebula 1.10.3 `internal/httpapi` test pass on the development Mac. Targeted Darwin Go tests pass with a private physical temporary directory. A digest-pinned Go 1.26.5 Debian 12 LinuxKit VM also passed the cold-cache dual-architecture Darwin staging-bundle smoke and the Linux-verifiable Darwin path-security cross-build; its receipt explicitly denies native-host and release-authority claims. A separate exact-Go non-root Linux container passes corrected `mesh-install`, `mesh-release`, and every `linuxinstall` test except the three that explicitly need host anonymous-file, authentic systemd, or unified-cgroup behavior. An isolated current-working-copy snapshot cross-compiles the complete root-module Windows test graph and all packages for both `amd64` and `arm64`; the tests were deliberately not executed through that cross-compile. | The repository-wide Linux and Windows build, test, package, storage, backup, and packet gates must run on their native CI hosts before any Apple release. Cross-compilation, the LinuxKit VM, and the Docker Desktop container are supplementary and do not replace native Windows or Linux CI or the root-only native-Mac lifecycle harness. `make test` is not a valid macOS-wide gate because the repository contains Linux- and Windows-host-specific packages. |

### Current TestFlight successor state

This 2026-07-27 update supersedes the table row's earlier build-2 wording.
Framework-v5 builds `0.1.0 (2)` through `(9)` were strictly verified, uploaded,
and attached to the `Mesh Tunnel External Testers` group. App Store Connect
reported the binaries valid, export-compliance complete, Beta Review approved,
and externally available. Physical build 5 completed OIDC, authenticated
network selection, and containing-app self-enrollment. Physical build 6
returned fixed stage `apple-vpn-disconnected`; exact sanitized server
correlation recorded the self-enrollment reissue and zero provider preflight,
enrollment, or runtime requests. Physical build 7 then stalled at
`running-preparingProvider` before requesting a token, proving that the
provider-readiness-first sequence was circular. Build 8 instead provisions and
activates the verified site in the containing
app, enables/saves/reloads the manager, and performs only local settings and
engine startup before completing Apple's callback. Control-plane reporting
begins post-connect. This matches Mobile Nebula's lifecycle boundary. Its
physical attempt completed server enrollment before the app unexpectedly
terminated in post-enrollment host handoff. Build 9 then displayed the
authenticated local identity retained from that attempt, proving local
configuration commit and recovery, but its first-inspection race allowed
Sign in to enter `failed-starting` before Start existing tunnel was enabled.
Build 10 corrects that inspection race. The current successor additionally
adopts Mobile Nebula's native `utun`-descriptor engine transport; this is
source-tested and not yet physical packet-path evidence.
The successor keeps every action disabled until initial inspection completes;
if setup concurrently discovers an authenticated current identity, it
prepares only the same-origin manager and returns to Start existing tunnel
without OIDC, self-enrollment, or a new token. No physical result yet proves a
running tunnel or packet exchange.

## Locally reproduced source evidence

The following commands are the current local source gates:

```text
make apple-source-check
make docs-check
(
  cd desktop
  dart pub get --enforce-lockfile
  dart format --output=none --set-exit-if-changed lib test
  flutter analyze
  flutter test
)
scripts/apple-ios-source-build.sh /new/absolute/derived-data
scripts/apple-ios-admin-security-baseline.sh \
  /absolute/Runner.app \
  /absolute/mesh-apple-ios-simulator-source-receipt.json \
  /absolute/verified-flutter/bin/flutter
scripts/apple-ios-mobile-framework-build.sh /new/absolute/framework-proof
scripts/apple-ios-tunnel-source-build.sh /new/absolute/tunnel-proof
scripts/apple-ios-tunnel-security-baseline.sh \
  "/absolute/Mesh Tunnel.app" \
  /absolute/mesh-apple-ios-tunnel-simulator-source-receipt.json
scripts/apple-mobile-framework-security-baseline.sh \
  /absolute/MeshMobile.xcframework \
  /absolute/mesh-apple-ios-mobile-framework-source-receipt.json
scripts/apple-admin-security-baseline.sh \
  "/absolute/Release/Mesh Admin.app" \
  /absolute/mesh-apple-release-source-receipt.json \
  /absolute/verified-flutter/bin/flutter
make postgres-mobile-runtime-smoke
```

The preflight and source-build scripts additionally prove:

- the official Flutter 3.44.8 archive matches the declared SHA-256;
- the host matches Xcode 26.5 build 17F42, the macOS/iOS 26.5 SDKs,
  Swift 6.3.2 build `swiftlang-6.3.2.1.108`, Go 1.26.5, and the exact
  `nebula-cert` 1.10.3 tool resolved from the pinned Go module;
- the required iOS simulator runtimes are installed;
- the source build receives no release credential variable and its explicitly
  selected source Keychain contains zero code-signing identities;
- the Debug application has the native host architecture;
- the Release application contains both `arm64` and `x86_64`;
- neither source application has a valid code signature or applied release
  entitlement; and
- every receipt is bounded, create-only, and binds the source state, declared
  inputs, executable, and complete application tree.

A fresh 2026-07-25 current-source build binds preflight receipt SHA-256
`c49fb5c9aca25baa8d92d47fa15a3f49d7e3e10862766de7e386f49b2be277a5`
to three new unsigned Admin artifacts:

- macOS universal Release receipt SHA-256
  `2003ba43374af0f0ad0d16e01418176912376b9078b2553a4755ed81144f9279`
  and app tree
  `89b783febdcc260a992dc910e333420547d980d357eeb5ca518e6820bec7cd58`;
- macOS arm64 Debug receipt SHA-256
  `fd4909b7530d1d7db448a86afe3e7510a4f82cfa594d73536a5512168d4a6f9a`
  and app tree
  `3720f73a6048fc5d83a152e62f43601bc1a91c753a2f6f4e2a74ce9c4256a71a`;
  and
- iPhone/iPad universal simulator Debug receipt SHA-256
  `6453d6eb1b46e86d07932bec8ef0fac24a51a242a0385feb499ec60df321c118`
  and app tree
  `d96790530ce8187316fa55878072569194e5e13537eb4c558ad0fcafeed0c945`.

All three receipts declare the exact confirmation-gated session/profile
Keychain deletion and retained-state disclosure boundary. They also bind
frozen v1 session/profile compatibility fixtures and unknown-schema
fail-closed upgrade tests. They record absent release signatures, absent
applied entitlements, no physical-device validation, and a dirty source
checkout. They prove that the current shared Admin source compiles into
inspected application bundles; they are not clean source, protected release,
clean-host, installed-app, physical-device, or distribution evidence.

Local canonical source-matrix receipt SHA-256
`864614391052303695c0e79710f9e89aedfbbd8c951f825f6f0b605dc9f0bb19`
binds disposable commit
`f6b178f1ece1912003c4680c8b44cbf324c81e60`, preflight receipt SHA-256
`6696e56e31a83f3c4384be4477d9eca1fa769a98f2057851aaa5e2c6342585c1`,
and the five create-only source receipts. Companion local isolation receipt
SHA-256
`2ef243ccd26f552dcf2697a7f02b16effc62a8e4df9d96ee0ede8a7c0ed0d60`
records the fresh isolated Go module/build and Pub caches, zero signing
identities, and no release credential environment. This is local
Apple-silicon source evidence only: the iOS products remain simulator-only,
that clean matrix predates the static-engine link, and neither receipt grants a
CI, release-authority, device, or support claim. The newer framework-v5 and
Tunnel receipts below add local clean-source static-engine proof but do not
replace independent CI or clean-host evidence.

The Admin security gate must run after the unsigned universal Release receipt
and before protected signing. It requires the digest-pinned Syft 1.44.0,
Grype 0.112.0, and Gitleaks v8.30.1 containers and a working Docker daemon.
It uses an empty private Docker configuration for anonymous public pulls and
does not receive registry or Apple release credentials. A scanner-unavailable
result produces no receipt and cannot satisfy protected release.

The local 2026-07-24 run produced
`mesh-apple-admin-security-receipt-v1` SHA-256
`bf75a0ae8bad335e67e945bccbabe3facfd9b19b68d2b188d8a3a73f85f16816`
for unsigned app tree
`a28dddfef0ba5fc4e4047a5c5450108ebd17bd045d1a27fe2b2c0457385106a9`.
Its source receipt records a dirty checkout, so the protected producer still
rejects it even though its independent security-receipt parser accepts the
app/source binding.

The current local framework-v5 security run produced
`mesh-apple-ios-mobile-framework-security-receipt-v1` SHA-256
`18da794a1814fd2c91139606c0e6fa2997658d60593fdc65445f201d11a4d6a1`
for unsigned `MeshMobile.xcframework` tree
`01a9fe1088dfd22e5c2b494273e31a54fc7e2dfc7a0a1de0827db37b4b1b8c4c`.
It binds matching source receipt SHA-256
`c21b20f379ba8a4df4ff3430ade26a2d7c41a8cc0e993c72961f6c911ad8b97e`,
exact runtime module manifest, 29 Go mobile modules, 35 license/notice files,
40 Syft and 41 SPDX packages, fresh Grype database schema v6.1.9, and two
empty Gitleaks reports. Grype records one remaining non-fixable Unknown
advisory, `GO-2026-5932`, against `golang.org/x/crypto`; it does not record a
High/Critical or published-fix finding. The receipt remains source-only: its
source checkout is a local disposable clean commit, license review is pending,
and it records neither static Tunnel linkage nor physical-device validation.
The separate Tunnel receipt binds this exact framework source receipt and
proves its enrollment, renewal, credential-rotation, runtime-report,
identity-removal, and packet-session static symbols in the extension.

The local iOS Admin security run produced
`mesh-apple-ios-admin-simulator-security-receipt-v1` SHA-256
`cd1e4f0948663a8451f79f6d3711b1bf27a4c786600b3ece68af8a5baeaea809`
for unsigned simulator app tree
`e4f111be40c9de06b674e961f520ad1ae6004506ca22091853bd601d1f8daf1b`.
It binds 49 runtime hosted Dart packages, 68 Syft and 69 SPDX packages, all 49
runtime notice headings, the Mesh, Flutter, secure-storage, and URL-launcher
privacy manifests, a fresh Grype database with zero matches, and two empty
Gitleaks reports. The receipt explicitly records Debug simulator
configuration, no signature or applied entitlements, and no physical-device
or distribution validation. Its source receipt records a dirty checkout;
legal review and final App Store privacy declarations remain pending.

The exact security-bound Admin tree was installed and launched on an iPhone 17
Simulator running iOS 26.5. The process remained alive after 110 seconds, and
screenshot SHA-256
`a9da556603a0ddba364cdc01cc6764b44414bd891eab3df1649f427ea0d31e87`
shows the control-plane connection screen and its secure-session-storage-
unavailable disclosure. Advisory simulator-runtime receipt SHA-256
`c2086b8acd43272a0c95636255cfc04dd00b0c9ef6d0e14e40a4081bb6710b98`
binds the source receipt, security receipt, artifact tree, simulator runtime,
launch, screenshot, and limitations. No interaction was performed. The
runtime log identifies the expected unsigned-source boundary precisely:
Security.framework returned OSStatus `-34018` because the source artifact has
neither an application identifier nor Keychain-access-group entitlements. The
receipt explicitly records no physical-device, Keychain-storage, real-browser
authorization, managed-configuration, notification, network-transition,
accessibility-matrix, or distribution proof.

A separate Xcode `Sign to Run Locally` Debug simulator build then launched
without the secure-storage warning and reached Security.framework through the
Flutter secure-storage plugin. Native Runner tests passed 7/7 on the same
iPhone 17 Simulator, including add, copy-and-compare, delete, and post-delete
not-found for a non-synchronizable data-protection Keychain item using
`WhenUnlockedThisDeviceOnly`. Advisory signed-simulator Keychain receipt
SHA-256
`8dd7c309896513a958b610a9e0e2657f6182b4336801b3754e76d0f08f96375f`
binds both signed simulator app trees, the test source, `.xcresult` tree,
summary, and screenshot. Xcode's simulator signature is ad hoc and embeds no
Team access group, so this proves neither the physical-device access group nor
real session persistence, browser authentication, lock/unlock erasure, or
distribution. The Apple source workflow now runs this native test through
Xcode's ad-hoc local-sign path, verifies the signed simulator bundle, and
uploads the bounded `.xcresult` summary without exposing release credentials.

The refreshed framework-v5 enrollment, lifecycle, mobile-evidence,
identity-removal, static-engine, AppIcon, network-rebind, request-bound
status, existing-identity start, and stop source run
produced reproducible framework tree
`01a9fe1088dfd22e5c2b494273e31a54fc7e2dfc7a0a1de0827db37b4b1b8c4c`.
Framework source receipt SHA-256
`c21b20f379ba8a4df4ff3430ade26a2d7c41a8cc0e993c72961f6c911ad8b97e`
binds every exact engine Go source, the shared mobile-runtime contract, and the
generated Objective-C surface. Framework security receipt SHA-256
`18da794a1814fd2c91139606c0e6fa2997658d60593fdc65445f201d11a4d6a1`
binds 29 runtime modules, 35 license/notice files, 40 Syft and 41 SPDX
packages, one non-fixable Unknown `GO-2026-5932` match, no High/Critical or
published-fix finding, and two empty Gitleaks reports. Both the dirty working
path and local disposable clean-source commit
`51e305575df839ab548350ece8da484cc30bc312` produced that exact framework
tree through the canonical staging contract.

The unsigned universal Tunnel simulator tree is
`bc6efc0d52c4804959423202057c67cc9b681148c5822805f1632cf2ec6a44e4`;
its nested extension tree is
`68d08e1d106c6158580bdca6fe30f61f80d81ee450a6d401dd156f5f38cce6fe`.
Both targets report version `0.1.0` build `2`.
Historical source receipt SHA-256
`9a065b593c8a0133282f957bfece392ea76dd228f69376e57b8a3375db93375e`
binds the exact enrollment, lifecycle, runtime-report and identity-removal
adapters, monotonic activation, authenticated remote endpoint, runtime
coordinator, provider settings adapter, bounded Apple callback codec/tasks,
18-event logger, static engine symbols, network-path rebind boundary,
request-bound real-coordinator status, existing-identity start, explicit
stop, scrollable onboarding, Xcode project, and 15 AppIcon PNGs plus their
manifest. Security receipt SHA-256
`c67915d918d713d2717c325afceb89e2ef7d3b6bb13c667d74cdec77b407780e`
binds all ten product files, an independently empty SwiftPM dependency graph,
the same exact 29-module runtime, 65 Syft and 66 SPDX packages, two empty
privacy manifests, two non-fixable Unknown `GO-2026-5932` matches, no
High/Critical or published-fix finding, and two empty Gitleaks reports. It
records the pre-successor static engine linkage and Apple packet flow but no
executed callback, applied setting, signature, physical-device validation, or
distribution validation. These v5 bytes are not the earlier signed/TestFlight
build.

A current Profile archive was signed on 2026-07-25 with Apple Distribution
Team `Y3P5UNNG23`. The strict verifier accepted host profile
`9ae4c36f-22a0-4d67-b078-f40049321616`, extension profile
`4201014e-16f3-4836-8da4-04b856709c51`, both exact App Group/Keychain
allowlists, both `packet-tunnel-provider` entitlements, the AppIcon, and every
required enrollment, lifecycle-refresh, and packet-session symbol/identity
marker. Its signed containing-app tree SHA-256 is
`9d1cf0c6d19efb1df9ac91ecc7e543b763fd2dfacc7867b2c860914fcd5133a9`.
Xcode exported a 10,740,866-byte App Store IPA, whose SHA-256 is
`f8512fadfc626cf5fae26d27a77344792767e634d02b0fffa246c869b02006da`.
Distribution receipt
`mesh-apple-ios-product-distribution-receipt-v3` SHA-256
`1d5dd6e6a4f9d45f456aec005e168c829e565a6413c45f92a8bed89b11117b30`
independently rechecked both signatures, profiles, entitlement allowlists,
static symbols, bundle identifiers, version `0.1.0`, build `1`, and the
explicit no-device/no-packet/no-release-authority limitations.

Xcode's authenticated upload completed at 2026-07-25 02:08 UTC. App Store
Connect app `6794340524` processed build UUID
`7539de60-2da3-4071-b326-ed08db6786dc`, accepted the declaration of standard
encryption with no France distribution, and completed Beta App Review. A
read-only check on 2026-07-25 showed build `0.1.0 (1)` in `Testing`, expiring in
90 days. One invited tester had installed it on a physical iPhone that day.
App Store Connect showed no sessions, crashes, or feedback. This live App
Store Connect state is operational evidence, not a cryptographic receipt or
authorization for public App Store/Custom App distribution. The installed
build is the earlier framework-v4 artifact; it does not qualify the current
framework-v5 flow.

An authenticated Apple Developer portal readback on 2026-07-25 confirmed the
exact Admin, Tunnel host, and Packet Tunnel App IDs; the shared App Group; the
host/extension App Group association; and Network Extension capability on both
Tunnel targets. Enabling the host capability invalidated historical host
profile `ee85c79b-dd9b-444b-a0c3-4dd2b06885e2`; regenerated host profile
`9ae4c36f-22a0-4d67-b078-f40049321616` and existing extension profile
`4201014e-16f3-4836-8da4-04b856709c51` are active with embedded expiration
2027-05-17 UTC. The account's Devices inventory contains only the development
Mac and no iPhone or iPad, so no physical iOS development profile or device
test can be produced from the current registered inventory.

The exact receipt-bound unsigned tree was also installed and launched on an
iPhone 17 Simulator running iOS 26.5. A first advisory launch receipt SHA-256
`b8777a9709c841d9b338ed842599839d28d9eccab096a85208b01660ff7fec15`
binds the source receipt, artifact tree, simulator runtime, live process, and
the initial engineering-only disclosure. After the Mac display became
available, Computer Use invoked only the read-only “Inspect installed
configuration” action. The app returned one existing Mesh Tunnel
configuration and explicitly stated that this source proof did not install or
start it. Follow-up advisory receipt SHA-256
`e0e854a078aec62ef8962e80eb76a05b7e2ffcb8921d9f7435f283d66c3baa98`
binds before/after screenshots SHA-256
`3506885a68c360cbeb40bb17b60511e4c81d8c8ce7702ca0bb556eb84b3cc5d8`
and
`5db4f58b7f0f5dafa247bc5e90bc01890e42f1302182062c56a14012ee9ecbb3`.
No configuration was installed, changed, or started; the existing
configuration's provenance is unproved. This remains simulator UI evidence
only, not physical-device, extension, applied-settings, engine, or packet
evidence.

The macOS Release and iOS simulator builds emit a Flutter native-assets
warning saying that `objective_c` supplied different framework names across
architectures. Inspection of pinned Flutter 3.44.8 identifies the actual cause
in its fat-asset grouping: it allocates a collision name for the second
architecture before reusing the first architecture's identical asset ID.
`objective_c` 9.4.1 supplies one locked asset ID and filename. The source
artifact receipt now fails unless the final bundle has exactly one
`objective_c.framework`, every architecture maps the same asset ID to
`objective_c.framework/objective_c`, the framework contains the full expected
architecture set, every Mach-O install name is
`@rpath/objective_c.framework/objective_c`, and no transient
`objective_c1.framework` name appears anywhere in the bundle. The receipt binds
the pinned Flutter commit and SDK digest plus the `objective_c` version and
package digest. This is a bounded disposition of the final packaged output,
not an upstream fix or native Intel execution proof; any Flutter or package
change reopens the review.

## Phase 9 release-matrix policy

`packaging/apple/release-verification-matrix.json` v2 is the canonical,
machine-checked inventory of the Phase 9 macOS Admin, macOS Node, iOS Admin,
and iOS Node gates. It keeps every product explicitly `unsupported` and
`release_eligible` false. Its verifier rejects an omitted or duplicate gate,
an unknown proof class, a support claim, or simulator evidence assigned to the
iOS node. Every product now has explicit final source/provenance and
signing-secret-independent verification gates. Both macOS products have
release-metadata, authenticated-publication, public-re-download, and retained
sanitized-receipt gates. Mesh Node for macOS additionally has final
signed-bundle, Installer-signature, notarization/staple, and Gatekeeper gates.
iOS Admin retains final privacy-declaration review, while iOS Tunnel retains
distribution validation and Network Extension channel approval.

The matrix is not a test result or receipt. Source and simulator evidence
cannot satisfy its protected-release, provenance, publication, native-host,
clean-host, physical-device, physical accessibility, distribution,
control-plane, or packet-path classes. Every future entry still requires its
gate-specific artifact authentication and bounded receipt. No Phase 9 product
matrix is complete in this checkout.

## Phase 2 macOS source evidence

The current desktop source evidence covers the following bounded contracts:

- the macOS secure-storage adapter requests an app-only, non-synchronizing
  data-protection Keychain item with
  `unlocked_this_device` accessibility and an explicit account namespace;
- session restoration is bound to the exact normalized control-plane origin,
  and malformed, expired, or cross-origin storage fails closed;
- saved control-plane names and exact normalized origins use a separate,
  canonical, bounded Keychain record from session cookies. Sign-out deletes
  only the credential-bearing session record; relaunch restores at most eight
  saved profiles and re-verifies system TLS plus the server-advertised
  authentication methods before enabling sign-in. Malformed, duplicate,
  over-limit, or managed-policy-conflicting profiles fail closed without
  exposing stored content;
- a native XCTest creates a private physical mode-`0600` file Keychain,
  confirms that creation does not alter the user's Keychain search list,
  adds and reads an exact-origin generic-password item, proves another origin
  cannot read it, deletes it, and restores the original search list;
- a fixed native macOS menu installs only Command-R Refresh and Command-comma
  Preferences actions; both send argument-free reviewed commands into the
  same Flutter shell path, and native plus widget tests reject arbitrary
  server-selected commands;
- the browser authorization start and completion objects reject unknown
  fields, interval or expiry drift, duplicate or secret-bearing verification
  URLs, non-terminal credentials, and unsafe or cross-control-plane origins;
- disposable loopback protocol-fixture tests cover explicit cancellation
  before the poll secret is transmitted, redacted browser-launch failure,
  denial, expiry, approval, a transient 503 completion interruption retried
  only inside the original expiry, exact scoped-cookie persistence,
  CSRF-authenticated logout, local erasure, and a viewer-denied create request
  whose fixture inventory remains unchanged;
- a separate cross-language end-to-end test starts the production Go
  `control`, `identity`, `httpapi`, and runtime-telemetry implementations on
  an ephemeral IPv4 loopback listener with private file stores, resolves the
  exact Nebula 1.10.3 certificate tool pinned by `go.mod`, and exercises every
  current public `MeshApi` read and mutation, including rejection of replaying
  an already consumed browser-authorization completion;
- that real-control-plane test covers desktop authorization approval, legacy
  and break-glass sessions, logout, all fleet and network reads, network and
  node creation, pending enrollment reissue, exact-name pending-enrollment
  cancellation with invalidated-credential and revision readback, real
  certificate enrollment and rotation, node revocation, session inventory and
  revocation, audit reads, recovery-code registration, and viewer-denied
  creation with an unchanged authoritative network count;
- the macOS Nodes surface exposes cancellation only for a never-enrolled
  pending node, captures the exact node name in a destructive confirmation,
  posts the current network revision through the typed API, strictly parses
  the cancellation receipt, refreshes authoritative inventory, and records a
  durable operation receipt without retaining the invalidated enrollment
  credential;
- a separate opt-in external-environment test uses the same bounded Flutter
  transport against an operator-supplied HTTPS control plane, keeps its
  emergency administrator bearer only in process memory, creates no cookie
  session, performs no control-plane mutation, and covers every advertised
  fleet and per-network read. Its first 2026-07-24 Mac run found that the Dart
  HTTP client negotiated an encoded response even though the transport rejects
  encoded bodies; the transport now explicitly requests `identity`, retains
  its encoded-response rejection and byte ceiling, and the live test passes.
  On 2026-07-25 the deployment advertised hybrid OIDC while hiding legacy
  browser login and break-glass, and the updated read-only bearer probe passed
  against the two-node environment. This does not prove the OIDC browser
  ceremony. The earlier pinned Flutter 3.44.8 and Dart 3.12.2 pass is bound by
  advisory receipt SHA-256
  `7a969c908258a6408b0da95fb41019c208dada055d31837b030dc92df86b0441`;
- one-time material is erased on application hiding and remains erased through
  the valid inactive, hidden, paused, and detached lifecycle progression;
- public network selection and back-to-directory callbacks erase one-time
  material before changing context, while internal refresh of the current
  network does not discard an active custody view;
- the macOS runner maps only screen lock, screen sleep, system sleep, and
  application termination to the existing data-free controller erasure
  methods; a native test pins the exact notification-to-method map and rejects
  an arbitrary event, but no signed clean-host lock/sleep transition has run;
- the app shell has source tests for Command-comma preferences navigation,
  its existing refresh shortcut, viewer read-only presentation, and a
  900-by-700 layout at 200% text scale; and
- each Admin artifact receipt rejects native-asset drift from the exact
  locked `objective_c` 9.4.1 dependency, including a missing architecture,
  per-architecture manifest path or install-name differences, an unexpected
  framework, or leakage of Flutter's transient collision name; and
- the native runner source test keeps release entitlements narrow, terminates
  after the last window closes, and rejects secret/session terminology in the
  native host source.

The real-control-plane fixture uses the production handlers and file-backed
stores, but its browser decision, viewer-session setup, and node activation are
token-protected test setup rather than an external identity provider, physical
browser, or real node. These tests therefore do not prove a signed application
access group, physical-device Keychain behavior, OIDC-provider interoperability,
multi-replica or PostgreSQL behavior, or a complete accessibility review.
Those distinctions remain release-blocking gates, not inferred evidence.
The external-environment pass also remains source-test evidence: it is not an
installed final application, physical browser/OIDC ceremony, mutation drill,
clean-host receipt, or substitute for the native-host release matrix.

## Phase 6 iPhone and iPad Admin source evidence

The iOS work is an operator application only. There is no Network Extension,
VPN entitlement, App Group, embedded Nebula engine, local node enrollment, or
tunnel lifecycle in `desktop/ios`.

The current source boundary provides:

- the exact pinned Flutter 3.44.8 scene-based Swift runner with the registered
  `io.rw0.mesh.admin.mobile` application identifier and iOS/iPadOS 17 minimum;
- distinct development, TestFlight, App Store, and managed-distribution
  entitlement files containing only the stable application Keychain access
  group, with all four paths selected explicitly in the machine-readable
  build inputs, Debug/Profile/Release mapped in Xcode, and managed selection
  reserved for a future protected archive job;
- an application privacy manifest declaring no tracking, tracking domains, or
  collected-data categories and exactly Apple's `AC6B.1` UserDefaults reason
  for reading the MDM-managed application-configuration dictionary;
- no background mode, Network Extension entitlement, VPN API, App Group, or
  caller-selected native capability;
- an exact managed-application schema for HTTPS origin, origin locking,
  release-channel and update-ring labels, local-status display policy, and
  notification policy; unknown fields and wrong types fail closed at both the
  native and Dart boundary, and a locked origin is checked again in the
  controller rather than relying on hidden UI; foreground resume re-reads the
  policy, while a newly invalid payload clears authenticated local state and
  keeps direct connection callbacks disabled;
- an unsigned macOS ManagedPreferences source profile and an iOS MDM
  application-configuration dictionary, both machine-verified against the
  exact seven allowed keys and prohibited from carrying enrollment, recovery,
  session, cookie, access-credential, or private-key fields;
- `unlocked_this_device`, non-synchronizing Keychain options for only the
  exact-origin session and CSRF pair;
- browser approval that pauses completion polling outside the foreground,
  resumes a still-valid attempt, and wakes immediately on cancellation or
  origin replacement without sending the old origin's poll secret; a bounded
  503 interruption retries within the original server-issued expiry, while
  cross-origin verification URLs and consumed completion replays fail closed;
- controller-owned one-time-secret erasure on every non-resumed Flutter
  lifecycle state and on the native protected-data-unavailable signal, plus
  local erasure for logout, origin replacement, view completion, and process
  teardown;
- an opaque native privacy shield installed before inactive/background
  snapshots and removed only after the scene becomes active;
- explicit iOS secret copy through a local-only pasteboard item with a
  two-minute expiration, with no ordinary-clipboard fallback when the native
  bridge is absent, while other platforms retain the existing explicit
  clipboard action;
- an operator-initiated, non-uploading, non-persisted diagnostic JSON schema
  capped at 16 KiB and restricted to application/release identity, aggregate
  state, and fixed error/remediation entries; its type boundary accepts no
  origin, user, organization, network, node, request, credential, certificate,
  configuration, raw-error, log, or arbitrary-file value; version 2 declares
  the iOS 120-second local pasteboard expiration, the non-expiring macOS
  system clipboard, required operator deletion after macOS transfer, the
  support-case retention limit, and that Mesh cannot enforce deletion of
  recipient copies;
- a fixed native notification boundary for only `fleet-warning` and
  `fleet-critical`; permission denial fails closed, the first foreground poll
  is a non-notifying baseline, unchanged severity is suppressed, and native
  titles/bodies contain no names, identifiers, counts, server text, or
  secrets; there is no background monitoring and no physical delivery proof;
- a drawer-based compact navigation shell at iPhone portrait/landscape and
  standard iPad split/portrait widths, persistent visible role context,
  responsive fleet/activity evidence without status-label truncation, and the
  shared server-authoritative permission gates;
- an authoritative `/api/v1/session` refresh before each foreground fleet
  poll; exact returned permissions drive every privileged affordance, a
  downgrade clears Access state and one-time material, stale auxiliary
  responses are discarded, and a revoked or identity-mismatched session
  fails closed to signed-out state;
- widget gates across iPhone portrait/landscape and iPad
  split/portrait/full-landscape sizes at 100, 200, and 320 percent text scale,
  plus reduced-motion/high-contrast feature propagation, labeled controls,
  iOS tap-target sizing, and contrast; and
- a credential-free build script that binds the pinned source preflight,
  empty mode-0600 Keychain, universal `arm64`/`x86_64` simulator executable,
  exact iPhone/iPad device family, minimum OS, privacy manifest, absent
  release signature, absent applied entitlements, executable digest, and full
  application tree into a create-only receipt.

Native XCTest on the iOS 18.6 simulator proves the privacy shield covers,
restores, and remains idempotent, and validates the exact native managed
configuration type/key/origin boundary. The shared Flutter suite covers the bounded
mobile accessibility matrix above, authorization pause/resume and
cancellation, origin replacement, exact permission downgrade, server-side
session revocation, RBAC, mutation receipts, Keychain option selection, and
secret erasure. A product-specific
`mesh-apple-ios-product-distribution-receipt-v3` independently reverified a
fresh signed archive and 7,871,705-byte App Store IPA against active profile
`bbf9a052-cc14-49a1-a7be-af1636efb0cf`. Receipt SHA-256
`d6abcc0250a579c9671831acaf69ef20c16a5f4084409ff454da72587d99dd4f`
binds signed application tree
`e371793d8a43c6732400601e0e06cee45358eff524f6ec43a88c20c0e1124fdd`
and IPA SHA-256
`5ffaea1c166dc423ce353539b05c913e2da62c7f656d41bec4a66f2e97e539b5`
with explicit no-upload, no-managed-distribution, no-real-browser, no-device,
and no-release-authority limitations. A second verifier invocation reproduced
every field except `verified_at`. Simulator and source tests do not prove a
physical Keychain access group, protected-data behavior under real lock,
browser return through iOS, physical VoiceOver/Switch Control use, screenshots,
network handoff, Apple privacy declarations for the final dependency graph, or
any distribution channel. Those remain explicit release gates.

The managed source examples are not signed profiles and have not been
installed through MDM. A local Keychain audit found seven basic identities
and four code-signing identities, but no S/MIME, SSL client, or SSL server
identity and no approved MDM profile signer. Audit receipt SHA-256
`9b604b915f9f4c995c6967125f9bb286c398f48af459bec1a1ef997748713d12`
records that the Developer ID application certificate was not substituted as
MDM authority. Release-channel and update-ring values are advisory labels and
do not select or authorize release bytes. `ShowLocalStatus` only controls
presentation and grants no local-node authority. No tunnel
VPN/on-demand payload is provided: final `VPNSubType`, Team, bundle,
provisioning, and Network Extension capability values are registered and
locally verified in App Store profiles, but there is no MDM distribution or
physical packet-path evidence. Apple's declarative application
configuration is available on current supported OS versions without a blanket
supervision requirement, while Per-App VPN is MDM-owned; Mesh still requires
separate real supervised and unsupervised device matrices before making any
deployment or locking claim.

## Phase 7 iPhone and iPad Tunnel source evidence

`ios-tunnel` is a separate product from the Flutter Admin application. Its
registered containing-app identifier is `io.rw0.mesh.tunnel.mobile`; its
Packet Tunnel extension identifier is
`io.rw0.mesh.tunnel.mobile.packet-tunnel`. The checked-in Release settings
pin Team `Y3P5UNNG23`, the Apple Distribution identity class, and the exact
App Store profile names; no signing credential or provisioning profile is
checked in.

The current source boundary provides:

- distinct containing-app and Packet Tunnel targets, with development,
  TestFlight, and Custom App entitlement files selected independently by the
  Xcode build configuration;
- the Packet Tunnel capability, shared App Group, handoff Keychain group, and
  device-only identity Keychain group in both targets. Host access to the
  identity group exists only for the narrow Go provisioning session; no Swift
  API retrieves either credential;
- a containing app that prepares or reloads at most one exact provider
  configuration with only a canonical non-secret HTTPS origin before OIDC.
  After login and network selection it re-enumerates and reloads that manager,
  rechecks absent configuration slots and Keychain authority, and requires
  enabled/same-origin/schema-valid/on-demand-disabled state before requesting
  one fixed-policy self-enrollment;
- a Mobile Nebula-aligned provision-first sequence: the token crosses only one
  bounded in-process Go enrollment request, never enters Network Extension
  start options or provider IPC, and is never placed in VPN preferences, the
  App Group, UserDefaults, or a durable receipt. The host validates the exact
  origin/node/network/counter result, stages and activates the authenticated
  site, then creates one exact Keychain-backed authorization and calls
  `startTunnel(options:)` with only that authorization. The provider rejects a
  Settings-only or enrollment-bearing start and loads only the installed
  current site;
- a critical self-enrollment-to-activation interval that ordinary background
  transitions do not cancel, exactly one same-principal/same-device retry for
  an ambiguous self-enrollment result, real Keychain high-water inspection,
  orphaned-authority refusal, exact candidate reconciliation after an
  ambiguous high-water commit, local activation of a matching authenticated
  candidate after relaunch, and existing-agent bootstrap recovery after a
  committed server enrollment. Deferred or unauthorized recovery preserves
  authority and does not request another token. An interrupted uncommitted
  pending node remains an explicit administrator and qualification case;
- exact-provider rediscovery plus controls to start an existing authenticated
  local identity without re-enrollment, request stop, and inspect a
  request-ID-bound extension outcome. Running evidence comes from the live
  coordinator and includes configuration revision, certificate generation,
  engine identity, and legacy counter fields. Native-`utun` mode leaves the
  callback counters at zero, and the UI does not present runtime state or
  `NEVPNStatus` as peer or end-to-end connectivity,
  and its scrollable surface keeps every control reachable on compact iPhones
  and with larger text;
- exact, unknown-field-rejecting control, configuration, authenticated
  envelope, and evidence schemas, including explicit suspended, stale,
  quarantined, revoked, and extension-error states;
- a pure authenticated network-settings plan that rejects noncanonical
  IPv4/IPv6 text, host bits in routes, route-family gaps, duplicates,
  included/excluded conflicts, unusable unicast addresses, excessive list
  sizes, and MTUs outside 1280–1500, without calling Network Extension APIs;
  the same authenticated payload requires a canonical usable-unicast underlay
  remote endpoint, rejects an overlay address, and requires an exclusion when
  an included route would otherwise capture that endpoint;
- a tested Apple settings mapper and provider adapter that convert every
  validated address, prefix, included/excluded route, DNS server, MTU, and
  authenticated remote endpoint into the corresponding Network Extension
  object and can apply or clear it;
- a Swift packet-pump actor that validates complete IPv4/IPv6 lengths and
  family, owns packet bytes, bounds each batch and both directional queues,
  applies all-or-nothing backpressure, preserves ordering, records directional
  counters, and erases queued packets during idempotent one-shot stop without
  importing Network Extension;
- a tested runtime coordinator that requires the exact engine identity, then
  prepares the engine, applies Apple settings, starts the packet pump, and
  starts the engine; startup, packet, rebind, and stop paths execute bounded
  reverse cleanup, and running evidence is available only after all startup
  stages complete;
- an HMAC-SHA256 App Group handoff with bounded files, no-follow reads,
  single-link regular-file checks, create-exclusive temporary writes, file
  and directory synchronization, atomic rename, current/recovery slots, and
  monotonic replay rejection;
- a shared handoff authentication key stored as non-synchronizing,
  after-first-unlock-this-device-only Keychain data, plus a high-water item
  available to the shared identity access group;
- a host-invoked narrow Go enrollment session that performs the token-scoped
  no-store preflight and locally resolves every planned lighthouse before
  creating or reading credentials or consuming the token; it accepts only an
  unexpired member plan, stores stable `primary` identity and agent seeds in
  the shared device-only Keychain group, sends only the public key and agent-bearer
  hash with the token, permits one byte-identical ambiguous replay followed by
  authenticated bootstrap recovery, and returns only a configuration whose
  signature, certificate/local-key, network, role, lifecycle, native DNS,
  routes, and selected remote are bound back to the preflight;
- a host-invoked lifecycle session that opens only existing credentials,
  revalidates the current signed configuration, signing key, and exact stored
  origin, and performs one agent-authenticated bootstrap before every later
  start. It renews the same-key certificate when due or mandatory, never
  defers a mandatory CA/profile transition, and rotates a near-expiry agent
  credential through a fixed pending Keychain item with ambiguous-response
  recovery. It accepts only the same node/network with nondecreasing
  generations, activates ready state at the next monotonic counter, permits
  bounded deferral only for eligible transport/429/5xx failures, and fails
  startup on unauthorized, malformed, substituted, or rollback state;
- a strict mobile-runtime evidence session that reports a configuration,
  certificate, engine, instance, sequence, uptime, state, optional packet
  counters, and bounded error code at a 60-second scheduled cadence. Server
  receive time plus a two-minute ordinary freshness bound and a 15-minute
  bound only after an explicit suspended report prevent missing or stale
  evidence from becoming health. Generic authorization rejection quarantines
  the client rather than proving revocation, and a desired-state mismatch
  stops the active tunnel for full refresh on the next start;
- a confirmation-gated deletion-only identity-removal path that rechecks the
  exact authenticated node against the extension high-water floor, attempts
  deletion of current and pending agent credentials plus the private key, and
  erases candidate/current/recovery slots only after every authority deletion
  succeeds. The non-authority handoff HMAC and high-water state remain for
  authentication and anti-rollback protection. Local removal is not
  server-side revocation or node deletion;
- an extension provider wired through that coordinator and the statically
  linked Go engine session. Host-side pre-start refresh and any ready
  activation complete before provider start and engine construction. Start
  generations prevent a
  detached continuation from an earlier stopped start from attaching to a
  later start or clearing its task. Production sessions discover and validate
  the provider-owned `utun` descriptor inside Go and construct Nebula with
  `overlay.NewFdDeviceFromConfig`; no Swift packet-copy tasks are started.
  Subsequent `NWPathMonitor` updates invoke bounded UDP rebind, and rebind
  failure stops the engine and fails the tunnel closed;
- an extension-only Unified Logging wrapper that accepts a closed enum of
  fifteen fixed start, stop, configuration-rejection,
  lifecycle-deferred, lifecycle-failure,
  agent-authorization-rejection, unavailable-engine, network-rebind-failure,
  status-request, and identity-removal codes; no stop
  reason, configuration content, error value, identity, packet data, or
  arbitrary string can enter the logging call;
- an unsigned simulator build receipt proving one universal iPhone/iPad host,
  one universal Packet Tunnel extension, exact identifiers and extension
  point, 15 AppIcon PNGs plus compiled asset catalog, minimal privacy
  manifests, no dynamic engine framework, no applied entitlements, and no
  valid signature; the receipt also binds the exact framework source
  receipt/tree and requires its enrollment/lifecycle/runtime-report/
  identity-removal/engine static symbols plus the settings contract,
  authenticated remote endpoint, Apple mapper, packet pump, runtime
  coordinator, provider adapters, provider, network-path rebind, and Xcode
  project source digests. The successor receipt records a statically linked
  engine and native-`utun` source selection, but no runtime packet connection
  or physical-device validation. It also binds the current request-bound status,
  existing-identity start, stop, and scrollable-host source boundaries; and
- a separate Go packet-session framework source boundary pinned to Nebula 1.10.3 and
  gomobile
  `v0.0.0-20260709172247-6129f5bee9d5`. Its Mesh exports create/read an
  X25519 private key in the shared device-only Data Protection Keychain, return
  only the public key, report non-secret framework identity, construct one
  single-method enrollment session, construct one existing-credential
  lifecycle-refresh session, and construct one opaque signed-config packet
  session with prepare, start, rebind, send, receive, and stop methods. No
  private-key or agent-bearer API is exported.

The framework build uses Go 1.26.5, `-trimpath`, an empty Go build ID, iOS
17.0, and separate caches for two builds. Because gomobile records local
module replacement paths even with `-trimpath`, the gate copies the exact
reviewed inputs to the fixed
`mesh-ios-mobile-framework-source-staging-v1` root, rejects caller-checkout
paths in every binary, and then canonicalizes gomobile's timestamped framework
metadata, archive symbol tables, and XCFramework slice ordering. The receipt
requires identical full-tree digests, exact device `arm64` and simulator
`arm64`/`x86_64` slices, iOS 17.0 and SDK 26.5 Mach-O object metadata, the six
reviewed Objective-C exports and exact enrollment-, lifecycle-, and
engine-session methods, pinned module identity strings, full upstream Nebula
and gomobile commits and module sums, the complete module-graph digest, exact
29-module license inventory, an explicit no-patch digest, source digests, and
explicit statements that packet transport is implemented while static Tunnel
linkage and physical-device validation are separate receipt scopes. A dirty
working path and separately committed clean-source path produced the exact
same framework tree.

This remains source/link and reproducibility evidence, not a tunnel. Mobile
Nebula's production iOS runtime discovers the provider-owned `utun` descriptor
and constructs Nebula with `overlay.NewFdDeviceFromConfig`. The successor now
uses that same path. Go bounds the descriptor scan to 0 through 1024, validates
the `AF_SYSTEM` control ID, retains key custody, and returns no descriptor or
packet surface to Swift. Production provider source selects native transport
and starts no `NEPacketTunnelFlow` copy tasks. The in-memory
`overlay.UserDevice` adapter remains a deterministic test fixture: tests still
prove exact IPv4/IPv6 validation, bounds, ownership, both directions, clean
closure, two real pinned Nebula controls over loopback UDP, authenticated
direct packets, empty relay state, and post-rebind traffic. The coordinator
proves native-mode startup ordering, reverse cleanup, network-path rebind,
lifecycle gating, and scheduled runtime evidence. These do not prove physical
descriptor discovery or traffic. Framework-v5 TestFlight builds 2
through 10 reached controlled external testing. Build 5 physically completed
the containing-app OIDC, network-selection, and self-enrollment write. Build 6
reported fixed stage `apple-vpn-disconnected`; exact sanitized server
correlation recorded the self-enrollment reissue and zero extension preflight,
enrollment, or runtime requests. Build 7 then stalled at
`running-preparingProvider` before requesting a token. Build 8 replaces that
circular provider-readiness-first ceremony with
containing-app provisioning, authenticated site activation, and normal
provider start. Its physical attempt completed OIDC and token consumption; the
server node is active at certificate and agent-credential generation 1, but the
app then unexpectedly terminated during post-enrollment host handoff. Build 9
subsequently read and displayed the authenticated local identity, proving that
the configuration commit survived and could be recovered. Build 9 did not
start the framework-v5 runtime: its first-inspection race let Sign in reach
`failed-starting` before Start existing tunnel was enabled. The successor
disables every action until initial inspection completes and routes any
concurrently observed current identity to its prepared same-origin manager
without another login, self-enrollment, or token. A physical provider start
and packet exchange remain unproved.

A separate local `make postgres-mobile-runtime-smoke` run used one exact
loopback-only PostgreSQL 17 container and passed both the current
`postgresstore` integration test and a new production-adapter composition
test. The prior source used migration 004 to bind the database import
constraint through control v13. The converged v14 source adds append-only
migration 005 and must rerun this smoke before claiming current control-v14
import proof. The prior test then initialized an empty reconstructible
schema-v8 telemetry document, persisted a non-empty mobile record, read it
through a second independent pool, committed an identical concurrent
transition exactly once, verified revision-1 through revision-3 receipts, and
cleaned the exact labeled container. This is local storage and two-pool
evidence, not proof that the persistent qualification service runs these
bytes or that a physical extension emitted the record.

Security approval, physical secure-removal and
heartbeat/renewal/rotation/revocation behavior, physical-device feasibility,
native descriptor discovery, accepted Apple network settings, iOS UDP
operation, resource measurement, and real-device peer evidence remain
required before any tunnel claim may be made.

## Phase 4 application-release source boundary

The native protected producer and platform-neutral receipt verifier implement
the fail-closed application-release shape without claiming an Apple release:

- the producer accepts only a clean Release source receipt with the complete
  pinned build inputs, an exact matching unsigned application tree, and a
  fresh canonical Admin security receipt bound to both;
- the only accepted nested code is the reviewed universal `App.framework`,
  `FlutterMacOS.framework`, and `objective_c.framework` inventory, with exact
  identifiers and no nested entitlements;
- the producer authenticates fixed Apple tools and exact Xcode `notarytool`
  and `stapler` binaries before and after use, snapshots the private mode-0600
  Keychain and release entitlement policy, and rejects input or output drift;
- signing uses exactly one Developer ID Application identity for the compiled
  Team ID, requires an active all-device macOS Developer ID provisioning
  profile whose certificate and application/Keychain entitlements match,
  embeds that profile before signing, applies hardened runtime inside out, and
  rechecks strict signatures, designated requirements, architectures,
  entitlements, the embedded profile, deep sealing, and tools before receipt
  creation;
- notarization must return `Accepted` with a canonical submission UUID before
  stapling, staple validation, Gatekeeper assessment, post-staple signature
  recheck, and final archive hashing;
- symlink permission bits are canonicalized to `0777` because Darwin does not
  use them for authorization and `ditto` does not preserve them, then the
  producer extracts the final archive into a fresh private directory and
  repeats tree, signed-code, profile, deep-seal, staple, and Gatekeeper checks;
  and
- portable protected receipt v3 records the Admin security receipt digest and
  equal pre-archive/post-extraction tree, regular-file, and byte-count evidence,
  and
  `mesh-release verify-apple-app-release` strictly parses canonical receipt
  bytes and independently hashes a stable physical archive against the
  expected source-receipt digest and Team ID on any Go-supported platform.
- release authoring reserves the exact `macos-admin/universal` target for the
  zip and `macos-admin-evidence/portable` for the receipt, requires both in the
  same root-derived manifest, rejects stale or mismatched protected evidence,
  and checks the compiled Team ID before creating metadata; and
- `mesh-release verify-published-apple-app` verifies the downloaded manifest
  with the release threshold from an independently authenticated current root,
  authenticates both downloaded artifacts, and reapplies the receipt,
  source-digest, version, and Team-ID bindings.
- a separate native post-download verifier pins the portable verifier and
  current root to independently supplied SHA-256 values, extracts exactly one
  application, rematches the signed tree, and rechecks all signatures,
  identifiers, entitlements, architectures, sealed resources, staple, and
  Gatekeeper before emitting a create-only local receipt; and
- its opt-in offline mode samples for no default route and no non-loopback
  IPv4/global-IPv6 address before and after native verification. Continuous
  isolation still belongs to the external clean-host fixture.

The local native receipt also has a strict platform-neutral parser and matcher.
It requires canonical bytes, the exact Apple-tool and nested-code inventories,
authenticated root/manifest/signature/verifier digests, final archive and
protected-receipt identities, fresh time, Team ID, staple, Gatekeeper, and,
when selected, the explicit pre/post network-isolation classification.

The portable receipt is evidence to bind into authenticated release metadata;
it is not itself signed authority and cannot substitute for native Apple
re-verification of a publicly downloaded artifact. An earlier accepted
notarization-feasibility copy lacked a usable embedded provisioning profile
and failed native launch under AMFI; it is superseded and is not runtime
evidence.

The historical local protected test artifact was built from clean disposable
snapshot commit `4e927794b2f030407bfd52a58c9ef868dd07aefc`. Its unsigned
source and security receipt SHA-256 values are
`87a92c446d9c71b8860605c43c29a2c65621865caf53d8fa55a1be86b794bd1c`
and
`74a49888d95dcf1ae4ef2bb53df79d2b8f236cf6f33eb7571ed0d50be2104579`.
The protected archive SHA-256 is
`e826af00de6bc62b0e57931e7691f95c84b519582e866c34c74c200d23ae8a69`;
portable receipt SHA-256
`c948fd8c2d73a35a2e05a94ba9ff6e2c735c2efabdd529c363687acbd4abce2e`
records Apple submission `4e592d84-4ef0-4b96-9c0e-97bd53f820d6`,
validated staple, and accepted Gatekeeper assessment. The embedded profile is
UUID `1851d214-90a0-46e9-9490-617e3e6f5b20`. Runtime receipt SHA-256
`fdca7bc66e2bf10096b088bbdfe41766cab525ce013c7ce3b413dad249d1ad2e`
records live `legacy_admin` authentication, Keychain deletion on explicit
sign-out, immediate re-login availability, and successful session restoration
after terminating and relaunching the exact protected bytes. It is superseded
for portable release evidence: its v2 tree digest included host-specific
symlink mode bits and does not match the same application after `ditto`
extraction.

The replacement v3 artifact was built from clean disposable snapshot commit
`1fbe569e49bc6aa9792d3e9e006637db24a3cd6c`. Its source and
security receipt SHA-256 values are
`8c62c2067ab11da9c1c74ca0e0a8af7e3eace9e63c2735f167ceff684f344207`
and
`ddbc33e6f798890cabecc2532bdbadd99da3617af8154793b34d233b42c26080`.
The protected archive SHA-256 is
`d79f49137001c60fe226f4719cea3c33fa7e07b91fce3c3026b97c8cadcf3fe2`;
portable v3 receipt SHA-256
`fe90ef4295875b5ecbd62596576ea1b3a38814f4ae016dc84629ffa88aae1111`
records accepted submission `6dd0c3a6-f8fa-4c47-884e-73c76560f90b` and
equal signed/extracted tree
`8b73d512195852c47ecb596856a40d00ee8b0ac5a9776872af17a745855581d2`.
The platform-neutral verifier accepted the archive/receipt/source/Team
binding; a separate ordinary-umask extraction reproduced the tree and passed
deep signature, staple, and Gatekeeper checks. A complete native verifier pass
used explicitly disposable local-test threshold metadata and emitted receipt
SHA-256
`945d721866dda77114329d7eff6ae6e0518a45ab06ab9f9e92677627f394561b`;
the four local-test private keys were removed. Its network-isolation option was
not requested.
There is still no approved production root or release manifest, public
artifact, re-download, clean-host or continuously isolated verification, or
release-authority decision.

## Phase 3 installer source evidence

The Darwin `mesh-install` build now has the same fixed command names as the
Linux installer, dispatched to Darwin-only production orchestration rather
than importing Linux-only code. Its source contract:

- requires one already-canonical HTTPS bundle URL for online intake;
- accepts only the exact physical root-private offline snapshot format;
- closes the immutable artifact-capture descriptor before deterministic
  staging and journal handoff;
- preserves the existing journal ordering for create-only release publication,
  gate close, launchd bootout, current selection, exact-plist replacement,
  bootstrap, gate restoration, and install-state commit;
- resumes a durable activation or rollback journal without accepting new
  authority, and resumes a durable accepted intake only after its exact
  artifact capture is complete;
- compares an explicit rollback installed ID to the persisted previous
  authority again while holding the cross-process installer lock;
- holds that same lock while post-enrollment activation reauthenticates the
  active release, live plist, fixed-path agent state, signed current bundle,
  matching recovery keypair, schema compatibility, and credential freshness;
- runs bundle validation only with the authenticated release's physical
  Nebula executables, empty environment, `/` working directory, exact argument
  allowlist, bounded time/output, and stable pre/post executable identity,
  then opens the fixed gate and invokes only the non-restarting
  `launchctl kickstart system/io.mesh.node-agent`; and
- closes the gate and proves service absence if that kickstart fails.
- exposes an exact `uninstall-runtime` deactivation that closes the gate,
  proves launchd absence, removes only the authenticated live plist and active
  selector, clears active/previous state last, and retains releases, trusted
  roots, high-water authority, installer files, and agent enrollment state.

The production `meshctl` Darwin path now resolves `meshctl`, `nebula`, and
`nebula-cert` into one physical directory before command execution. While
holding the installer transaction lock, it requires that directory to be the
exact persisted active release, reauthenticates the immutable release tree,
proves the exact `current` selector and live plist, rejects active journal or
intake state, and requires the persistent gate to be closed. It then returns
the explicit release-gate error before running either Nebula binary or reading
an enrollment bearer. This implements the source validator without removing
the goal's native-evidence gate.

The opt-in root-only native harness is source-bound to this validator and, when
given an exact scanned bundle on an approved Mac, exercises the physical active
release success case plus `current`-selector, open-gate, accepted-intake, and
active-journal rejections in its disposable release tree.
The same fixture performs runtime uninstall after rollback and verifies that
activation state is gone while both published releases and anti-rollback
authority remain.
The approved Apple Silicon development Mac ran the default root-owned native
subset after macOS 26.5 compatibility fixes. Canonical v3 receipt SHA-256
`82d870ea0fb91a87b357c02e4254b7cbceae3fc529e9d8ed4412b55079df1984`
binds system SHA-256
`80200be4621bb830ac6ca10f95d063bbc04ede0e0144e553259009be9690b824`,
test transcript SHA-256
`557ce36ad4d42a546226f7af13a063dc675343b778fa8364a69470ff49520acd`,
and complete source inventory SHA-256
`2bf390c0aa173427a991bc39f64f305e258f5bb120fbc08abd172839c2dd4070`.
Every enabled native path, installer-gate, release-layout, exact-child,
process-group, and reap test passed. The receipt explicitly records
`darwin_bundle_sha256=none` and
`system_launchctl_mutation_test=0`, so the full native verifier must reject it.
A separately gated run proved and cleaned the exact system launchd fixture,
then intentionally stopped when the unsigned staging bundle reached the
compiled fail-closed code-signature admission boundary; it emitted no full
receipt.

A separate supplementary LinuxKit run used digest-pinned
`golang@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651`
with Go 1.26.5 on Debian 12 arm64. It passed both
`darwin-bundle-smoke.sh` and `darwin-path-security-smoke.sh`, including
reproducible locked Nebula and Mesh artifacts for darwin/amd64 and
darwin/arm64, threshold-manifest verification, appended-candidate rejection,
portable ACL/path faults, launchd path contracts, and deterministic Mach-O
cross-builds. Receipt SHA-256
`d4b278dbeb974dd4edf3a3b1ed990c43ba3cb4936df67502ab09b7e6ae09cf0e`
binds test-log SHA-256
`c85ff62599d7f2857187ccda806254fabbcda05b8598204f6a816448e141a4fd`
under `bin/darwin-linux-vm-smoke/20260724T201215Z`. The receipt explicitly
classifies this as Linux-VM evidence with no native Linux, native macOS,
launchd-lifecycle, or release-authority claim.

This is source-level orchestration, not native lifecycle evidence. It has not
installed a production release into `/opt/mesh`, replaced the production
LaunchDaemon, enrolled a real Mac, survived reboot or injected interruption,
or passed packet, revocation, upgrade, rollback, Intel, signing, notarization,
package, clean-host, or uninstall proof. The command must not be distributed
as supported, and Darwin production enrollment remains disabled.

The new code-signature admission source does not change that classification.
The registered Team ID and identifiers are build inputs, not release
authority. A
development build reports an empty Darwin code-signing policy digest and
refuses production activation; protected release tooling must generate and
compile the approved canonical frame into `mesh-install`, `meshctl`, protected
native receipt generation, Linux signed-bundle assembly, and release authoring.
The assembly and dual-receipt preflight boundaries are implemented and tested
with synthetic structural signatures, but no real Developer ID runtime-bundle
signature, approved policy, Node notarization result, or full
signed-bundle-matching native receipt was produced.

The login Keychain also contains two Developer ID Installer identities with
the same common name. The local proof therefore selected one identity by its
exact SHA-1 fingerprint rather than by name, signed a newly created
payload-free package, and passed `pkgutil --check-signature` with a trusted
timestamp. That package was never installed, submitted for notarization, or
used as release evidence. It proves that the local Installer certificate and
private key are usable; it does not define the Mesh Node payload, scripts,
identifier, versioning, receipt, uninstall behavior, or protected package
producer. Those source boundaries remain deliberately open rather than being
filled by a misleading wrapper around an unauthenticated staging tree.
The reviewed target shape is now frozen in
[`ADR 0010`](decisions/0010-macos-node-package-bootstrap.md): a separate flat
package per architecture, an authenticated production `mesh-install`, the
exact three-file root-private snapshot, and a compiled no-input post-install
entrypoint. Final package and installer identifiers plus fixed bootstrap paths
still require release-policy approval before implementation may replace its
development sentinel. [`ADR 0011`](decisions/0011-macos-node-release-identifiers.md)
records one exact `io.rw0.mesh.node` proposal and its canonical policy digests;
its status is explicitly proposed, so no value has been embedded or used for
signing.

The first enforceable source pieces now exist. Darwin code-signing policy v2
requires four distinct identifiers, adding `mesh-install` to the three release
executables. A separate canonical node-package policy binds the flat package
identifier, fixed `/Library/Application Support/Mesh` install location, one
direct Mesh-owned package root, installed bootstrap path, and root-private
snapshot path. Its exact six-entry payload plan contains only that package
root, bootstrap, snapshot directory, and three snapshot files, so no system
ancestor can enter the BOM; the policy has an unparseable development
sentinel. `mesh-release darwin-node-package-policy` emits only the canonical
v2 frame or its digest. A native payload-free Installer probe on this Mac
proved that current Installer passes four post-install arguments: package
path, configured install location, target volume, and system root. A Darwin
`mesh-install` executed as the package's compiled `postinstall` now validates
that exact arity, requires both volume and root to be `/`, binds the install
location to compiled policy, authenticates the installed bootstrap under the
compiled Developer ID requirement, and imports only the policy snapshot path.
The package-specific installer composition resumes any durable journal or
accepted intake before applying the packaged snapshot, preserves idempotent
same-release activation, and never enrolls or opens the runtime gate.
The native code-signing receipt is now v2 and binds the package `mesh-install`
plus the three final runtime executables under one policy, while bundle
assembly and release authoring consume only its exact runtime subset. Protected
package producer source validates that receipt, the package policy, final
bundle-security receipt, exact root-private snapshot, signed bootstrap, private
release Keychain, selected Installer fingerprint, and fixed Apple tools before
building the six-entry payload. It rechecks the exact BOM and compiled
postinstall, signs with `productsign`, requires accepted notarization, staples,
validates, runs Gatekeeper, re-expands the final package, hashes its final
bytes, and emits canonical portable package receipt v1. The platform-neutral
`mesh-release verify-darwin-node-package-release` command reparses that receipt
and binds package bytes, both compiled policies, architecture, version, Team
ID, native receipt, and bundle-security receipt before publication. This is
source behavior only: no clean signed bundle/bootstrap input, protected
package production, accepted package notarization, native post-download
verification run, or installed-host proof exists. The independent native
verifier authenticates its Apple tools and a digest-pinned portable verifier,
reruns the portable receipt gate, checks the Installer signature, staple and
Gatekeeper, independently expands the package, rechecks the exact BOM,
payload, snapshot, postinstall and signed bootstrap, and emits a separate
canonical native receipt. The native argument probe was payload-free, created
no product files, and its unique temporary receipt was absent after the run;
it is invocation evidence, not a Node installation or package release.

## Known contract decision

The goal names administrator, operator, auditor, and viewer behavior. The
current Mesh server and desktop contract exposes only `admin`, `operator`, and
`viewer`. Apple clients must not invent an `auditor` role. Adding one would be
a server/API/storage/rollout decision with its own authorization and
compatibility tests; until that decision is approved, the Apple clients
preserve the current three-role contract exactly.

## Evidence handling

Local DerivedData directories, empty test Keychains, and local receipts are
diagnostic and are not release evidence. CI may upload only the sanitized
source receipts and bounded native-test summaries declared in the Apple
workflow. Signing identities, notary credentials, provisioning material, and
App Store Connect credentials are never valid inputs to the source gate.
The native-test sanitizer consumes the pinned Xcode 26.5 summary schema,
requires one destination and an all-passing, no-skip result, binds the result
to the clean source receipt, and retains only counts, architecture, OS
version/build, pinned tool identity, and completion time. Raw Xcode summaries,
device identifiers and names, configuration identifiers, insights, failure
text, and environment descriptions are not uploaded.
The workflow also emits a canonical source-matrix receipt only after all five
unsigned artifact receipts prove the same clean source commit and exact
preflight digest with the reviewed macOS/iOS schemas, configurations, and
platform labels. Mixed-commit or mixed-preflight artifact sets fail before
upload. The source job disables setup-go cache restoration and roots its Go
module/build and Dart Pub caches under the current runner's private temporary
directory rather than an engineer or prior job's package cache.
The same workflow source declares a separate Ubuntu job with no release
credentials. It installs exact Nebula 1.10.3 test binaries into the runner
temporary directory, creates short owner-private `/mnt/t` storage for tests
whose Unix-socket and ancestry contracts cannot use the ordinary shared
temporary directory, runs `make test` and `make build`, and then runs the
nested `ios-tunnel/engine` module. This declaration is not CI evidence until a
GitHub-hosted run completes and its result is reviewed.
The workflow also declares a credential-free Windows job on a native Windows
runner. It installs the same exact Nebula test binaries and executes the
repository-wide root-module Go test and build graphs. Both native regression
jobs are triggered by every Go source change. A local `GOOS=windows`
cross-compile of every test package for `amd64` and `arm64` proves only source
compatibility; it does not execute the Windows tests or satisfy the native
Windows gate.

An Apple Admin diagnostic bundle is support data, not release evidence. Mesh
retains no application copy and performs no automatic upload. The iOS local
pasteboard item expires after 120 seconds; the macOS system clipboard does
not, so the operator must clear or replace it immediately after transfer.
Support recipients must limit every transferred copy to the approved case and
delete it when the case closes. This recipient-side deletion policy is not
technically enforced by Mesh. Physical pasteboard, clipboard, log archive,
crash path, ticket-system retention, and deletion verification remain release
gates.

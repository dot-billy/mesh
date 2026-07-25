# Mesh Apple Platform Integration Goal

Status: proposed

> **For implementation workers:** Execute this goal in ordered, reviewable
> phases. Do not enable production macOS enrollment or claim iOS tunnel support
> until the corresponding native proof and release gates below pass. Every
> final approved user-, operator-, or API-facing change must also use the
> repository's `update-mesh-docs` workflow.

## Goal

Deliver first-class Apple platform support without weakening Mesh's existing
security or lifecycle contracts:

1. a supported macOS operator console built from the existing Mesh Flutter
   application;
2. a supported signed and notarized macOS node package built from Mesh's
   existing Darwin agent, installer, release, and launchd foundations;
3. an iPhone and iPad operator application that reuses the Mesh control-plane
   client and preserves browser authentication, RBAC, one-time-secret custody,
   and lifecycle evidence;
4. a separately gated iOS Mesh node implemented as an Apple Packet Tunnel
   Network Extension with an iOS-compatible Nebula runtime; and
5. repeatable release, security, clean-host, real-device, packet, upgrade,
   rollback, revocation, and documentation evidence for every supported Apple
   artifact.

The reviewed reference applications are research inputs only. They are not a
runtime dependency, source dependency, authentication authority, package
authority, or reason to replace Mesh's existing agent.

## Enterprise product mandate

This work is not a literal port of MacManager and is not one consumer VPN
application stretched across two Apple operating systems. It creates a new,
enterprise-focused Mesh software family with separate operator and managed
endpoint responsibilities.

The intended product family is:

### Mesh Admin for macOS

A full-window and optionally menu-bar-capable enterprise operator console for
administrators, network engineers, help-desk operators, auditors, and
read-only viewers. It connects to a remote Mesh control plane and exposes only
the workflows allowed by the signed-in principal's server-enforced role.

It must work whether or not the Mac is itself a Mesh node. Installing Mesh
Admin must not silently install or enroll the endpoint runtime.

### Mesh Node for macOS

A signed, notarized, root-managed endpoint package containing the exact Mesh
agent and Nebula runtime. It participates in the overlay, installs signed
configuration, reports lifecycle evidence, renews credentials, enforces
revocation and staleness, and is manageable through enterprise software
deployment.

Mesh Node is a system service, not a user application pretending to be one.
Its security boundary remains valid when no user is logged in and when Mesh
Admin is not installed.

### Mesh Admin for iPhone and iPad

A mobile operator console for safe fleet observation and explicitly supported
administrative workflows. It shares Mesh's API, authentication, RBAC, audit,
and one-time-secret semantics with the web and desktop clients while providing
an Apple-native mobile experience.

Installing the mobile admin application must not implicitly configure a VPN
or enroll the phone as a node.

### Mesh Tunnel for iPhone and iPad

A separately entitled and separately gated managed endpoint capability built
around an Apple Packet Tunnel Network Extension. It is responsible for the
device's Nebula tunnel, local node identity, signed configuration, runtime
evidence, network transitions, certificate lifecycle, and revocation response.

The containing application is a management and status surface. The Network
Extension is the tunnel runtime. Neither Flutter nor an ordinary iOS
application process can substitute for that extension boundary.

### Product separation requirements

- The four capabilities have independent support and release gates.
- Operator-console installation never implies node installation.
- Node installation never grants control-plane administrator privileges.
- A user may install Mesh Admin without Mesh Node, Mesh Node without Mesh
  Admin, both, or neither.
- iOS operator support may ship before iOS tunnel support.
- The names above are working product labels. Final naming and bundle
  identifiers require approval before signing, provisioning, documentation,
  or external distribution.
- Marketing and UI language must distinguish "signed into the control plane,"
  "node installed," "tunnel running," "peer authenticated," "traffic relayed,"
  and "packet path verified."

## Enterprise requirements

The Apple software must be designed for managed organizations rather than
single-user manual setup.

### Identity, roles, and audit

- Use Mesh browser-approved authentication and production OIDC.
- Preserve identity-provider MFA requirements and do not replace them with a
  native password form.
- Enforce permissions on the server for every read and mutation.
- Support the existing administrator, operator, auditor, and viewer behavior
  without inventing client-only authority.
- Reflect permission downgrade, session revocation, identity-provider logout,
  and disabled accounts promptly.
- Create durable actor-attributed audit records for every mutation.
- Preserve exact request IDs, expected revisions, idempotent replay, and
  ambiguous-response readback.
- Expose security-relevant session and device events without exposing session
  secrets.

### Enterprise deployment

- Support noninteractive, signed macOS package installation through common MDM
  and software-distribution systems.
- Define installation, update, repair, rollback, and removal exit codes.
- Ensure package scripts are minimal, bounded, idempotent, and implemented in a
  reviewed compiled installer wherever the existing Mesh installer owns the
  invariant.
- Provide signed configuration-profile examples for managed, non-secret
  settings such as:
  - the allowed Mesh control-plane origin;
  - release channel;
  - update ring;
  - whether the operator may change the origin;
  - whether local status is shown;
  - approved notification behavior; and
  - approved tunnel/on-demand behavior where iOS support permits it.
- Keep enrollment tokens, recovery tokens, sessions, private keys, and other
  secrets out of ordinary configuration profiles.
- Define a safe zero-touch or low-touch enrollment ceremony before claiming
  automated enrollment. MDM possession alone must not silently become
  unrestricted Mesh enrollment authority.
- Support managed iOS distribution through an approved App Store, Custom App,
  TestFlight, or enterprise/MDM path as selected by the product decisions.
- Document supervised-device and unsupervised-device differences.
- Document which Network Extension and VPN settings can be installed or locked
  by MDM.

### Fleet lifecycle and change control

- Publish exact installed application, agent, Nebula, schema, and release
  identities.
- Support phased update rings and bounded deferral.
- Support canary release, convergence observation, pause, resume, rollback,
  and failed-update recovery.
- Never replace a healthy installed release with a moving latest binary.
- Preserve signed release metadata, security floors, high-water protection,
  immutable releases, and explicit rollback authority.
- Make mixed-version compatibility and server/client rollout order explicit.
- Report drift between intended and installed release without silently
  repairing it outside the approved enterprise policy.
- Define end-of-support behavior for old macOS/iOS versions and old Mesh
  clients.

### Supportability

- Use Apple Unified Logging with private values marked private and sensitive
  values omitted entirely.
- Produce an explicit, user- or administrator-initiated diagnostic bundle that
  is bounded, schema-versioned, and redacted.
- Include application, extension, agent, package, release, and non-secret
  lifecycle identities in diagnostics.
- Exclude private keys, bearer tokens, cookies, CSRF values, recovery codes,
  enrollment credentials, raw signed secret material, and unrestricted network
  configuration.
- Provide stable operator-facing error codes and remediation text.
- Distinguish configuration failure, authorization denial, control-plane
  outage, stale signed state, local service failure, tunnel failure, peer
  absence, relay use, and packet-path failure.
- Define a support-data retention and deletion policy.

### Compliance and release evidence

- Generate SBOM, dependency, vulnerability, secret-scan, signing,
  notarization, entitlement, provenance, and clean-host test evidence for
  release artifacts.
- Review third-party licenses for Flutter plugins, Swift packages, Go mobile
  dependencies, Nebula, packaging tools, and any telemetry or crash SDK.
- Require an explicit privacy decision before adding analytics, diagnostics
  upload, crash reporting, or device inventory fields.
- Collect no device or user data merely because an Apple API makes it
  available.
- Keep public documentation, the actual entitlement set, privacy manifests,
  App Store declarations, and runtime behavior consistent.

### Enterprise user experience

- Optimize routine screens for fleet scale, evidence freshness, role clarity,
  and safe bulk interpretation.
- Do not turn complex lifecycle changes into context-free connect/disconnect
  switches.
- Make destructive, identity-changing, route-changing, firewall-changing, and
  revocation actions explicit and confirmation-gated.
- Preserve exact organization, network, node, revision, and request context
  through confirmation and result receipts.
- Provide useful empty, loading, offline, denied, stale, degraded, and partial
  states.
- Support accessibility, keyboard operation on macOS, Dynamic Type and
  VoiceOver on iOS, reduced motion, increased contrast, and localization-ready
  strings.
- Keep secret custody screens intentionally short-lived and resistant to
  background snapshots.

## Repository acquisition and project orientation

### Clone Mesh

Mesh is publicly available from:

```text
https://github.com/dot-billy/mesh
```

On a new Mac, create a dedicated checkout that does not overlap MacManager or
another user's working tree:

```bash
mkdir -p "${HOME}/Development"
cd "${HOME}/Development"
git clone https://github.com/dot-billy/mesh.git mesh
cd mesh
git status --short --branch
git rev-parse HEAD
```

GitHub CLI is also acceptable:

```bash
mkdir -p "${HOME}/Development"
cd "${HOME}/Development"
gh repo clone dot-billy/mesh mesh
cd mesh
git status --short --branch
git rev-parse HEAD
```

The expected default branch is `main`. Before changing files:

1. read `AGENTS.md` completely;
2. confirm the checkout and branch;
3. inspect `git status --short --branch`;
4. preserve every pre-existing modification and untracked file;
5. use a new worktree or disposable clone when the current checkout is dirty;
6. do not copy secrets, `data/`, local signing material, build caches, or
   generated development credentials between machines; and
7. record the exact base commit in the implementation plan and release
   evidence.

Do not run cleanup, reset, checkout, or overwrite commands against an existing
dirty working tree. A clean implementation worktree can be created from a
reviewed branch without disturbing the main checkout:

```bash
git fetch origin
git worktree add ../mesh-apple-integration -b apple-integration origin/main
cd ../mesh-apple-integration
git status --short --branch
```

The branch name is illustrative. Use the repository's approved issue/branch
convention when implementation begins.

### Initial Mesh verification

Read the root `README.md`, then verify the base source before Apple-specific
changes:

```bash
make test
make build
make desktop-check
make docs-check
```

Some package and live-network smoke tests require Linux capabilities and remain
on the Linux verification host. Apple-native tests run on an approved Mac.
Cross-compilation on Linux and native proof on macOS are complementary; neither
substitutes for the other.

Mesh Desktop pins Flutter in `desktop/tool/flutter-sdk.json`. The Apple build
must install and use that exact SDK archive and digest in an isolated toolchain
location. An arbitrary `flutter` already on `PATH` is not sufficient evidence.

### Important Mesh source areas

- `desktop/` — current Flutter operator console, shared API client, auth, RBAC,
  state controller, presentation models, widgets, and tests.
- `internal/httpapi/` — authenticated HTTP behavior and typed OpenAPI route
  catalog.
- `internal/identity/` — sessions, browser authorization, principals, roles,
  permissions, and identity persistence.
- `cmd/meshctl/` — enrollment, recovery, signed lifecycle agent, runtime
  supervision, and production runtime prerequisite.
- `internal/nodeagent/` — signed state, heartbeat, renewal, runtime evidence,
  quarantine, DNS, and platform-independent agent behavior.
- `internal/darwinbundle/` — deterministic Darwin staging artifacts and strict
  candidate inspection.
- `internal/darwininstall/` — native Darwin intake, journaling, immutable
  publication, activation, launchctl control, rollback, and path invariants.
- `internal/darwinnativeevidence/` — canonical clean-host native evidence.
- `internal/darwinpackagesecurity/` — Darwin package-security receipt.
- `cmd/mesh-package/`, `cmd/mesh-release/`, and `cmd/mesh-deps/` — artifact,
  release, dependency, and evidence construction.
- `packaging/launchd/` — the reviewed future macOS job and ownership contract.
- `scripts/darwin-*` — Darwin package, path-security, and native-runtime gates.
- `docs/public-guide.json` — canonical public documentation.
- `internal/httpapi/openapi.go` — canonical typed API route catalog.
- `docs/openapi.json` — generated OpenAPI 3.1 artifact.

### Obtain the MacManager inspiration checkout

The private MacManager repository requires authorized GitHub access. It may be
cloned beside Mesh strictly as a reference:

```bash
mkdir -p "${HOME}/Development"
cd "${HOME}/Development"
gh auth status
gh repo clone dot-billy/macManager Macinspirstion
cd Macinspirstion
git status --short --branch
git rev-parse HEAD
```

`Macinspirstion` intentionally preserves the requested folder spelling. If an
existing MacManager checkout contains local work, do not reuse it for baseline
comparison or test builds. Clone a separate disposable copy.

The Mesh build must never import source, binaries, signing material, credentials,
generated configuration, private keys, package receipts, or caches from the
reference checkout. Any adapted idea must be reimplemented under Mesh's
architecture, reviewed for license and provenance, tested, and documented.

## How MacManager inspires the new software

MacManager demonstrates a useful end-user shape:

- a Mac menu-bar application can make connection and lifecycle state available
  without requiring a large window;
- native Keychain, notifications, and network-path observation improve the Mac
  experience;
- a user-facing application can communicate with a separately privileged
  runtime;
- a single signed and notarized delivery can install related application and
  daemon components; and
- an Apple release pipeline can build multiple architectures, sign, notarize,
  publish, re-download, hash, and verify an artifact.

Its Flutter application also demonstrates that shared controller, API, secure
storage, notifications, and cross-platform presentation code can reduce
duplication across desktop operating systems.

Those ideas influence product experience and release ergonomics, not Mesh's
trust model. Mesh must retain and extend its own stronger contracts:

- browser-approved OIDC rather than password/JWT login;
- server-enforced RBAC rather than a locally implied administrator;
- local node-key generation rather than receiving a private key from an API;
- one-use enrollment and recovery ceremonies;
- signed monotonic configuration revisions;
- exact digest, certificate generation, fingerprint, and process evidence;
- immediate revocation and bounded stale-state quarantine;
- authenticated pinned Nebula releases rather than downloading latest;
- immutable release publication, high-water protection, and explicit rollback;
- strict command-level local authorization; and
- real peer/packet evidence rather than synthetic connection labels.

The result should feel as approachable as a polished native Mac product while
behaving like managed enterprise security software.

## Why this goal exists

Mesh already has a Linux and Windows Flutter operator console, a strict
control-plane API, browser-approved desktop sessions, RBAC, signed
configuration revisions, one-time enrollment, locally generated node keys,
heartbeat evidence, certificate renewal and revocation, recovery, and
fail-closed staleness behavior.

Mesh also already contains substantial macOS groundwork:

- deterministic Darwin staging bundles for `arm64` and `amd64`;
- pinned Darwin Nebula runtime construction;
- a privileged native installer model with verified intake, immutable release
  publication, high-water protection, activation journaling, rollback, and a
  mutation-only launchctl controller;
- a root launchd contract in which `meshctl agent --supervise-nebula` owns one
  exact Nebula child;
- native evidence and package-security receipt models; and
- a root-only native smoke entrypoint.

However, the current contract deliberately remains incomplete:

- `cmd/meshctl` rejects production enrollment on Darwin;
- the Darwin bundle is explicitly a non-installing staging artifact;
- the production launchd job is not installed by a supported command;
- the current native proof does not establish production package signing,
  notarization, installation, reboot, live packets, upgrade, rollback, or
  clean-host recovery;
- Mesh Desktop has no `macos/` or `ios/` runner; and
- Mesh has no iOS Network Extension or mobile-node lifecycle contract.

This goal closes those gaps in a controlled order.

## Reference implementation findings

The reference repository contains two desktop applications and one privileged
runtime:

- a SwiftUI macOS menu-bar application;
- a Flutter desktop application; and
- a root Go daemon that provisions and supervises Nebula.

It does not contain an iOS application, iOS build target, UIKit application,
Packet Tunnel Provider, or other Network Extension. The useful reference
patterns are:

- an unprivileged GUI separated from a privileged runtime;
- a compact menu-bar lifecycle experience;
- Keychain-backed secret storage;
- native notifications and network-path observation;
- a signed, notarized, unified macOS package; and
- a protected macOS release workflow with post-publication verification.

The following reference behavior must not be copied:

- username/password JWT login in place of Mesh browser authentication;
- server-generated or server-returned private node keys;
- direct privileged-file scanning by an unprivileged GUI;
- labeling local daemon response time as overlay latency;
- a broadly writable local command socket with coarse user authorization;
- configuration formats or API models that bypass signed Mesh revisions;
- silent download of an upstream moving "latest" Nebula binary; or
- a second daemon that competes with Mesh's existing agent and launchd model.

## Non-negotiable architecture

### Shared control-plane client

The existing `desktop/` Flutter application remains the source of truth for
Apple operator functionality. Shared Dart code owns:

- control-plane origin validation;
- browser authorization;
- cookie, CSRF, and session handling;
- role and permission presentation;
- strict API parsing;
- network, node, fleet, access, and activity models;
- lifecycle polling;
- one-time-secret presentation and erasure; and
- mutation receipts and ambiguous-response recovery.

Platform shells may adapt navigation, windowing, background behavior,
notifications, and native services. They must not fork the Mesh authorization
or API semantics.

### macOS node runtime

The supported macOS node uses the existing Mesh Darwin architecture:

- immutable releases below `/opt/mesh/releases`;
- `/opt/mesh/current` as the authenticated selected release;
- lifecycle state at `/private/var/db/mesh-agent/state.json`;
- the persistent runtime gate at
  `/private/var/db/mesh-installer/runtime.enabled`;
- one root-owned `/Library/LaunchDaemons/io.mesh.node-agent.plist`; and
- one `meshctl agent --supervise-nebula` job that owns the exact Nebula child.

There is no independent Nebula LaunchDaemon and no transplanted reference
daemon.

### macOS operator and local-node boundary

The macOS operator console remains useful without a local Mesh node. Installing
the GUI must not silently install, enroll, start, or modify a node.

If local-node status or actions are later exposed in the GUI, they use a
versioned, narrow, authenticated native bridge. The bridge:

- authenticates the calling signed application and effective user;
- returns bounded, non-secret status;
- exposes an explicit command allowlist;
- performs command-level authorization;
- cannot return private keys, enrollment bearers, recovery codes, raw
  configuration secrets, or arbitrary files;
- cannot accept arbitrary executable paths, arguments, environment variables,
  file paths, URLs, or shell fragments;
- cannot bypass the installer gate, signed revision, or quarantine behavior;
- records every mutation in an auditable receipt; and
- fails closed when client identity, protocol version, runtime identity, or
  state freshness cannot be proved.

Direct reads of `/opt/mesh`, `/private/var/db/mesh-agent`, or launchd state from
the sandboxed application are prohibited.

### iOS operator boundary

The iOS operator application is a control-plane client. It does not become a
node merely by adding an iOS Flutter runner. Its session, background, and
one-time-secret behavior must be safe under:

- application backgrounding and foregrounding;
- device lock and unlock;
- process termination and state restoration;
- screenshot and task-switcher snapshots;
- expired browser authorization;
- interrupted browser-to-app transitions; and
- intermittent Wi-Fi and cellular connectivity.

### iOS node boundary

An iOS node is a separate product capability implemented with:

- a native Apple Packet Tunnel Provider extension;
- an iOS-compatible Nebula engine inside that extension;
- a narrow native bridge between Flutter and Swift;
- App Group storage only where cross-target access is required;
- Keychain access groups with the minimum required accessibility class;
- locally generated node private keys that never enter Flutter, logs, the
  control plane, analytics, crash reports, or ordinary app storage;
- Mesh-authenticated enrollment, signed configuration, certificate lifecycle,
  revocation, and runtime evidence; and
- explicit server semantics for operating-system suspension.

The macOS root daemon, Unix socket, launchd job, arbitrary subprocess model,
and desktop heartbeat assumptions do not apply to iOS.

## Product decisions required before implementation

- [ ] Record whether the initial macOS release is:
  - operator console only;
  - node package only; or
  - two independently installable artifacts released together.
- [ ] Record whether the menu-bar experience is:
  - integrated into the Flutter macOS runner;
  - a small signed Swift companion; or
  - deferred until the full-window operator console is supported.
- [ ] Record whether the macOS operator application is distributed as:
  - a notarized direct-download application/package;
  - the Mac App Store; or
  - both, with explicitly different entitlements and local-node capabilities.
- [ ] Record whether Darwin node releases remain separate `arm64` and `amd64`
  artifacts or become one universal artifact. Do not merge architectures
  without preserving per-input provenance and release-manifest verification.
- [ ] Record the minimum supported macOS, iOS, and iPadOS versions based on API
  requirements and a tested device matrix, not the current development host.
- [ ] Record whether iOS phase one is operator-only or whether Packet Tunnel
  research begins concurrently.
- [ ] Select the iOS Nebula integration:
  - build the upstream mobile-compatible Nebula core into a pinned framework;
  - build a bounded Mesh/Nebula Go mobile framework; or
  - adopt another reviewed upstream-supported integration.
- [ ] Document the license, source, commit, compiler, SDK, architecture, and
  reproducibility boundary for the selected iOS Nebula artifact.
- [ ] Decide how the server represents an iOS node that is valid but suspended
  by the operating system. It must not be falsely labeled healthy, compromised,
  or administratively revoked.
- [ ] Decide whether iOS node distribution targets:
  - TestFlight/App Store;
  - managed enterprise or MDM deployment; or
  - both.

Each decision must be captured in a short architecture decision record before
the affected implementation phase starts.

## Phase 0: Freeze the Apple threat model and contracts

### Deliverables

- [ ] Add an Apple-platform threat-model section covering:
  - control-plane session theft;
  - local administrator and root compromise;
  - malicious unprivileged local applications;
  - hostile installer input;
  - symlink, hard-link, ACL, ownership, and path substitution;
  - malicious or replaced launchctl and codesign tools;
  - stolen signing credentials;
  - iOS application-container compromise;
  - App Group over-sharing;
  - Keychain access-group mistakes;
  - extension/app confused-deputy behavior;
  - malicious configuration or rollback input;
  - device loss;
  - log, notification, screenshot, and crash-report leakage; and
  - stale or ambiguous mobile runtime evidence.
- [ ] Specify the exact macOS package trust chain:
  source commit -> deterministic inputs -> built artifacts -> code signatures ->
  signed package -> notarization -> staple -> release manifest -> authenticated
  retrieval -> native installer admission -> immutable installed release.
- [ ] Specify the iOS trust chain:
  App Store/TestFlight/MDM artifact -> containing app -> Packet Tunnel extension
  -> pinned embedded Nebula engine -> local key -> Mesh certificate -> signed
  Mesh configuration -> acknowledged runtime evidence.
- [ ] Define which Apple evidence is authoritative, advisory, or unavailable.
- [ ] Define secret classes and their allowed process, storage, and log
  boundaries.
- [ ] Define a versioned local bridge schema before implementing any bridge.
- [ ] Define server-visible lifecycle states for foreground, background,
  suspended, tunnel-starting, tunnel-running, tunnel-stopping, stale,
  quarantined, revoked, and extension-error conditions.
- [ ] Confirm no Apple implementation path reduces existing Linux or Windows
  security guarantees.

### Exit criteria

- [ ] Security review accepts the threat model and architecture decisions.
- [ ] The API and lifecycle changes, if any, have explicit backward-compatible
  schemas and rollout order.
- [ ] No implementation task depends on unresolved private-key custody or
  mobile suspension semantics.

## Phase 1: Prepare a reproducible Apple build environment

### Toolchain

- [ ] Use the Flutter version and archive digest pinned by
  `desktop/tool/flutter-sdk.json`. Do not silently use an older global Flutter
  installation.
- [ ] Pin the accepted Xcode build version, macOS SDK, iOS SDK, Swift version,
  deployment targets, and command-line tools selection in a machine-readable
  build receipt.
- [ ] Verify required macOS and iOS simulator runtimes.
- [ ] Verify that release signing identities are available only to the
  protected release context.
- [ ] Keep Developer ID, Apple Distribution, notary, App Store Connect, and
  provisioning credentials out of source, shell history, process arguments,
  test fixtures, artifacts, and logs.
- [ ] Separate unsigned continuous-integration builds from protected signing
  and notarization jobs.
- [ ] Add bounded disk-space, SDK, clock, network, and credential preflights.
- [ ] Record tool versions and input digests in every Apple build receipt.

### Continuous integration

- [ ] Add a macOS source gate that runs:
  - Go tests that contain Darwin build tags;
  - native Darwin package/installer tests;
  - Flutter dependency lock enforcement;
  - Dart formatting;
  - Flutter analysis;
  - Flutter tests;
  - a debug macOS build; and
  - a release macOS build without release signing.
- [ ] Add an iOS source gate that runs:
  - Dart checks and shared tests;
  - iOS simulator compilation;
  - Swift unit tests;
  - extension compilation once the extension exists; and
  - entitlement and embedded-framework inspection.
- [ ] Prevent pull-request jobs from accessing release credentials.
- [ ] Make build receipts and sanitized test results available for review.
- [ ] Fail when the selected Flutter, Xcode, SDK, Nebula, or Go version differs
  from the declared input.

### Exit criteria

- [ ] A clean Apple build host can reproduce unsigned developer artifacts from
  a documented source commit.
- [ ] No build requires files from an engineer's existing working copy,
  Keychain session, global package cache, or untracked source.
- [ ] The pre-existing reference checkout and any user-owned dirty work remain
  outside the Mesh build.

## Phase 2: Add the macOS operator console

### Project structure

- [ ] Add a `desktop/macos/` Flutter runner using the repository-pinned Flutter
  toolchain.
- [ ] Keep the shared Dart package and test layout intact.
- [ ] Use a stable reverse-DNS bundle identifier and product name.
- [ ] Add development and release entitlements explicitly.
- [ ] Default to the macOS application sandbox unless a reviewed native
  capability proves it cannot be used.
- [ ] Add only the outbound network, Keychain, notification, and other
  entitlements actually exercised by supported features.
- [ ] Do not grant root, full-disk, arbitrary-file, or broad automation access
  to the operator application.

### Authentication and storage

- [ ] Preserve strict HTTPS origin validation and loopback-only development
  exceptions.
- [ ] Preserve the browser-approved session flow. Do not introduce a password
  form or embed an untrusted web login view.
- [ ] Store only the approved session and CSRF cookie pair in macOS Keychain.
- [ ] Keep legacy administrator bearer material memory-only.
- [ ] Bind stored sessions to the exact normalized control-plane origin.
- [ ] Prove logout, server revocation, local erasure, expired session,
  permission downgrade, and origin-change behavior.
- [ ] Ensure logs and crash output redact cookies, CSRF values, request polling
  secrets, enrollment bearers, recovery codes, certificate bodies, and private
  keys.

### macOS experience

- [ ] Adapt navigation, menus, keyboard shortcuts, focus, window sizing, and
  empty/loading/error states to macOS conventions.
- [ ] Support accessible labels, VoiceOver order, keyboard-only operation,
  reduced motion, increased contrast, and Dynamic Type-equivalent scaling.
- [ ] Preserve server-authoritative RBAC and permission gates.
- [ ] Preserve one-time enrollment and recovery custody behavior when the
  window closes, the app hides, the Mac locks, the process terminates, or the
  user changes networks.
- [ ] Add safe notifications for operator-relevant events without including
  secrets or overclaiming runtime health.
- [ ] If a menu-bar item is included, make it a projection of the same
  controller state rather than a second API client.
- [ ] Clearly distinguish:
  - control-plane reachability;
  - signed Mesh lifecycle evidence;
  - local node state, if available; and
  - actual peer or packet evidence.

### Tests

- [ ] Run all existing desktop tests unchanged.
- [ ] Add macOS widget tests for menus, keyboard operation, window resizing,
  one-time-secret erasure, and role changes.
- [ ] Add Keychain tests using an isolated test service/access group.
- [ ] Add browser authorization tests for approve, deny, expiry, cancellation,
  interrupted browser return, and logout.
- [ ] Add an end-to-end test against a disposable Mesh control plane for every
  supported read and mutation.
- [ ] Prove the macOS console cannot perform an operation denied to the same
  principal through the API.

### Exit criteria

- [ ] A notarization-independent release build succeeds on a clean Mac.
- [ ] The application can perform its documented operator workflows without a
  local Mesh node.
- [ ] No macOS-specific code forks Mesh API authorization semantics.
- [ ] The public guide identifies the macOS console as an operator client, not
  a node or tunnel installer.

## Phase 3: Complete the supported macOS node installer

### Production command surface

- [ ] Add a supported Darwin installer entrypoint that invokes the existing
  `internal/darwininstall` primitives rather than reimplementing them in shell.
- [ ] Support authenticated online intake and root-private offline snapshots.
- [ ] Require exact release metadata, artifact size, digest, target
  architecture, security floor, and high-water validation.
- [ ] Preserve create-only publication and immutable installed releases.
- [ ] Preserve crash-durable activation journaling and deterministic recovery.
- [ ] Preserve explicit rollback rules and prohibit silent downgrade.
- [ ] Install only the declared release, current selector, state directories,
  runtime gate, and exact launchd plist.
- [ ] Refuse symbolic, multiply linked, group-writable, world-writable,
  non-root-owned, unexpectedly ACL-bearing, or substituted path components.
- [ ] Authenticate every privileged system executable used by the installer.
- [ ] Never accept an arbitrary post-install script, shell fragment,
  environment override, executable path, or launchd plist from a caller.

### Runtime package

- [ ] Include exact authenticated `meshctl`, `nebula`, and `nebula-cert`
  binaries from one release.
- [ ] Keep Nebula pinned through Mesh release metadata; do not download an
  upstream moving latest release during enrollment.
- [ ] Verify Mach-O target, architecture, ownership, modes, link counts, code
  signatures, designated requirements, and Team ID before activation.
- [ ] Preserve separate architecture provenance even if distribution later
  uses a universal package.
- [ ] Install the exact root:wheel launchd plist without extended ACLs.
- [ ] Ensure the plist contains no enrollment token, bearer, private key,
  signing key, environment override, shell, user-selected path, or writable log
  path.

### launchd and supervision

- [ ] Prove `io.mesh.node-agent` is the sole production job.
- [ ] Prove `meshctl agent --supervise-nebula` starts only the authenticated
  selected Nebula executable with the managed configuration.
- [ ] Prove an empty child environment, dedicated process group, exact kernel
  identity, exact argument vector, and exact reap.
- [ ] Prove the persistent gate before initial start and every child operation.
- [ ] Prove stale signed state causes quarantine within the documented bound.
- [ ] Prove agent SIGTERM, SIGKILL, crash, and launchd restart cannot leave an
  unauthorized Nebula child behind.
- [ ] Prove upgrade and rollback boot out the old job and process group before
  selecting or starting the replacement.
- [ ] Prove reboot starts only an authenticated, enabled, non-stale release.

### Enrollment

- [ ] Implement Darwin installed-runtime validation so production enrollment
  accepts only one authenticated installed Mesh release.
- [ ] Generate the node private key locally.
- [ ] Keep the private key within the root-owned node state boundary.
- [ ] Preserve one-use enrollment bearers and exact network/node binding.
- [ ] Preserve signed bundle verification, revision monotonicity, agent bearer
  binding, certificate generation, renewal, rotation, recovery, and
  revocation.
- [ ] Remove the Darwin production-enrollment rejection only after all
  installer, runtime, and native proof gates pass.
- [ ] Keep unsupported or development configurations fail-closed with precise
  operator guidance.

### Native proof

- [ ] On a clean Apple Silicon Mac, prove:
  - installation from authenticated online input;
  - installation from a root-private offline snapshot;
  - exact file ownership, mode, ACL, link, and path invariants;
  - launchd bootstrap, print, kickstart, bootout, and recovery;
  - enrollment;
  - first signed poll before Nebula start;
  - heartbeat and signed revision convergence;
  - direct peer packets;
  - lighthouse discovery;
  - relay packets;
  - managed DNS;
  - firewall allow and deny;
  - certificate renewal;
  - immediate revocation cutoff;
  - stale-state quarantine;
  - reboot;
  - application and agent crash recovery;
  - upgrade;
  - interrupted upgrade recovery;
  - rollback; and
  - uninstall with documented retained/deleted state.
- [ ] Repeat architecture-level execution for Intel macOS on real or
  sufficiently representative hardware. Do not claim `amd64` support from
  cross-compilation alone.
- [ ] Produce a canonical native evidence directory and verify it through
  `mesh-release verify-darwin-native-evidence`.
- [ ] Confirm every proof is self-cleaning and refuses pre-existing production
  objects unless the test explicitly targets an installed test machine.

### Exit criteria

- [ ] Darwin production enrollment is enabled only for authenticated installed
  releases.
- [ ] A clean-host package install survives reboot and passes the complete
  packet and lifecycle matrix.
- [ ] Revocation and stale-state quarantine stop packets within their declared
  bounds.
- [ ] The installer can recover from every injected interruption without
  selecting an unverified or partially installed release.

## Phase 4: Sign, notarize, distribute, and verify macOS artifacts

### Application signing

- [ ] Sign every executable, framework, helper, and application bundle from
  the inside out.
- [ ] Require hardened runtime where applicable.
- [ ] Verify designated requirements, Team ID, entitlements, architectures,
  nested code, and sealed resources after signing.
- [ ] Reject unexpected entitlements and ad-hoc signatures.

### Installer signing

- [ ] Build the installer from an authenticated staged tree.
- [ ] Sign the installer with the correct Installer identity.
- [ ] Submit the final artifact to Apple's notarization service.
- [ ] staple the accepted ticket;
- [ ] verify the staple offline;
- [ ] run Gatekeeper assessment; and
- [ ] re-hash the final stapled artifact before release publication.

### Publication

- [ ] Bind the final artifact digest and size into Mesh release metadata.
- [ ] Publish through the authenticated Mesh release path.
- [ ] Re-download the artifact from the public operator URL.
- [ ] Re-verify digest, signature, notarization, staple, package contents, and
  release metadata after download.
- [ ] Retain sanitized build, signing, notarization, and verification receipts.
- [ ] Keep signing and notarization credentials out of downloadable artifacts
  and logs.
- [ ] Document certificate-expiry, revocation, and signing-identity rotation
  procedures.

### Exit criteria

- [ ] A clean Mac accepts the downloaded artifact without a quarantine bypass.
- [ ] The downloaded artifact is byte-bound to the published Mesh release.
- [ ] Installation creates only the documented files, services, and receipts.
- [ ] The release can be independently verified without access to signing
  secrets.

## Phase 5: Add an optional macOS local-node experience

This phase is optional and must not delay a supported remote operator console or
node package.

### Native bridge

- [ ] Select XPC/Mach service or another reviewed macOS-native IPC mechanism.
- [ ] Version the request and response schemas.
- [ ] Authenticate the caller's audit token, code signature, designated
  requirement, Team ID, and expected bundle identifier.
- [ ] Bind mutating requests to the active console user where required.
- [ ] Rate-limit requests and bound request/response sizes.
- [ ] Expose only:
  - installed release identity;
  - agent service state;
  - signed config revision and age;
  - certificate generation and expiry summary;
  - quarantine reason;
  - runtime evidence already safe for the operator; and
  - narrowly reviewed lifecycle actions.
- [ ] Return no secrets or arbitrary file content.
- [ ] Audit mutations with actor, request ID, previous state, resulting state,
  release identity, and outcome.
- [ ] Recover ambiguous mutations by idempotent request ID and authoritative
  readback.

### User experience

- [ ] Show control-plane status separately from local-node status.
- [ ] Show actual signed lifecycle evidence rather than synthetic latency.
- [ ] Explain quarantine, stale state, revoked identity, disabled runtime, and
  missing installation distinctly.
- [ ] Make destructive actions explicit and confirmation-gated.
- [ ] Never display "connected" solely because a process exists.
- [ ] Never display "healthy" solely because IPC responds.

### Exit criteria

- [ ] An untrusted local process cannot read status or invoke actions.
- [ ] An authorized GUI cannot bypass signed policy or installer state.
- [ ] Local controls cannot leave an unmanaged Nebula process running.

## Phase 6: Add the iOS and iPadOS operator application

### Project structure

- [ ] Add `desktop/ios/` using the pinned Flutter toolchain.
- [ ] Keep API, auth, RBAC, transport, polling, presentation, and shared widget
  code in shared Dart modules.
- [ ] Isolate platform window, tray, filesystem, process, and desktop-only
  behavior behind explicit interfaces.
- [ ] Remove compile-time reliance on `dart:io` APIs unavailable to the
  supported iOS context, or confine them to platform implementations.
- [ ] Add stable application and Keychain access-group identifiers.
- [ ] Configure development, TestFlight, App Store, and managed-distribution
  entitlements separately.

### Mobile navigation and accessibility

- [ ] Implement compact navigation for networks, nodes, fleet, access,
  activity, help, and preferences.
- [ ] Support iPhone portrait/landscape and iPad split/full-screen layouts.
- [ ] Support Dynamic Type, VoiceOver, Switch Control, sufficient contrast,
  reduced motion, and touch target sizing.
- [ ] Preserve evidence freshness and permission context on small screens.
- [ ] Avoid hiding critical lifecycle or destructive-operation context behind
  hover, desktop tooltips, or truncated labels.

### Authentication

- [ ] Preserve the Mesh browser-approval protocol.
- [ ] Keep the one-time poll secret inside the application process and secure
  storage only when state restoration requires it.
- [ ] Put no session, poll secret, recovery code, enrollment bearer, or private
  key in a browser URL.
- [ ] Resume a still-valid authorization safely after foregrounding.
- [ ] Stop polling and erase transient state on denial, expiry, logout, origin
  change, or explicit cancellation.
- [ ] Prove authorization cannot complete twice or on a different origin.

### Secret custody

- [ ] Store the session and CSRF cookie pair in Keychain with a reviewed
  device-only accessibility class.
- [ ] Clear one-time enrollment and recovery material when:
  - its view closes;
  - the application backgrounds;
  - protected data becomes unavailable;
  - the process terminates;
  - the operator logs out; or
  - the control-plane origin changes.
- [ ] Redact application-switcher snapshots while secret material is visible.
- [ ] Prevent secret values from notifications, analytics, pasteboard history,
  restoration state, logs, and crash reports.
- [ ] Make copy operations explicit and time-bounded where iOS permits.

### Tests

- [ ] Run all shared Dart and API contract tests for the iOS target.
- [ ] Add iPhone and iPad golden/widget tests across supported text sizes.
- [ ] Add simulator tests for navigation, auth state restoration, RBAC,
  mutation receipts, and secret erasure.
- [ ] Add real-device tests for Keychain, lock/unlock, backgrounding, process
  termination, browser authorization, screenshots, and network transitions.
- [ ] Prove every supported mutation is accepted or denied identically by the
  control plane from web, desktop, macOS, and iOS clients.

### Exit criteria

- [ ] The iOS operator app is feature-defined and documented independently of
  iOS node support.
- [ ] Real-device evidence proves browser login, Keychain storage, background
  erasure, RBAC, and supported mutations.
- [ ] App Store/TestFlight privacy manifests and declarations match actual
  behavior.

## Phase 7: Build the iOS Packet Tunnel proof

This phase is an engineering proof until every exit criterion passes.

### Feasibility spike

- [ ] Build a minimal containing application and Packet Tunnel Provider target.
- [ ] Obtain and validate the required Apple Network Extension capability and
  provisioning.
- [ ] Compile the selected pinned Nebula engine for physical iOS devices.
- [ ] Prove the extension can:
  - start;
  - configure a virtual interface;
  - read and write packets through the packet flow;
  - open required UDP sockets;
  - stop cleanly; and
  - report a bounded non-secret status to the containing app.
- [ ] Measure binary size, memory, CPU, battery, startup time, and sustained
  tunnel behavior.
- [ ] Stop and revise the architecture if the engine depends on forbidden APIs,
  unsupported process behavior, or unacceptable resource use.

### Enrollment and key custody

- [ ] Generate the Nebula private key inside the narrowest practical
  app/extension security boundary.
- [ ] Store it in an extension-accessible, device-only Keychain item.
- [ ] Ensure the Flutter runtime cannot retrieve or print the key.
- [ ] Send only the public key and authorized enrollment request to Mesh.
- [ ] Preserve one-use bearer, exact node/network binding, certificate
  generation, and audit behavior.
- [ ] Validate the returned certificate, CA, network identity, and signed
  configuration before accepting them.
- [ ] Define secure identity removal for logout, node deletion, permanent
  revocation, reinstall, and device transfer.

### Configuration delivery

- [ ] Use a versioned, authenticated app-to-extension configuration handoff.
- [ ] Store only the minimum current and recovery state in the App Group.
- [ ] Bind every accepted configuration to:
  - network ID;
  - node ID;
  - certificate fingerprint and generation;
  - signed config revision and digest;
  - release/engine identity; and
  - monotonic rollback protection.
- [ ] Make incomplete writes impossible to select.
- [ ] Make rollback explicit, bounded, and auditable.
- [ ] Prevent another application or extension from injecting configuration.

### Tunnel runtime

- [ ] Translate Mesh/Nebula configuration into exact Apple tunnel settings:
  overlay address, routed prefixes, excluded routes, DNS, MTU, and any required
  proxy settings.
- [ ] Preserve Mesh firewall policy in the Nebula engine.
- [ ] Support direct UDP, lighthouse discovery, configured relays, roaming, and
  network-path changes.
- [ ] Never claim direct connectivity when traffic is relayed.
- [ ] Never claim DNS health from configuration presence alone.
- [ ] Report real engine, peer, and packet evidence where available.
- [ ] Bound and redact extension logs.
- [ ] Stop or quarantine the tunnel when signed configuration, certificate,
  local key, or revocation state cannot be trusted.

### Mobile lifecycle

- [ ] Define extension behavior across:
  - application foreground/background;
  - device lock/unlock;
  - Wi-Fi to cellular;
  - cellular to Wi-Fi;
  - address change;
  - captive portal;
  - airplane mode;
  - low-power mode;
  - extension memory pressure;
  - extension crash;
  - device reboot; and
  - operating-system update.
- [ ] Make heartbeats evidence-based and compatible with extension scheduling.
- [ ] Distinguish absence of evidence caused by OS suspension from explicit
  tunnel failure.
- [ ] Preserve a bounded server-side stale state without falsely asserting
  compromise or revocation.
- [ ] Require fresh evidence before returning from stale/suspended to healthy.

### Revocation and rotation

- [ ] Prove permanent node revocation prevents new authenticated handshakes.
- [ ] Define how an online extension learns revocation promptly.
- [ ] Define the bounded behavior when the device is offline during revocation.
- [ ] Prove certificate renewal keeps the private key local.
- [ ] Prove certificate rotation, CA rotation, firewall rollout, relay changes,
  DNS changes, and signed revisions converge without using stale policy.
- [ ] Preserve response-loss recovery and idempotent lifecycle receipts.

### Exit criteria

- [ ] A physical iPhone and iPad exchange packets with supported Mesh peers.
- [ ] Direct, lighthouse, relay, DNS, firewall, renewal, rotation, and
  revocation proofs pass.
- [ ] Background, lock, roaming, crash, and reboot behavior match the published
  lifecycle contract.
- [ ] No private key or session secret crosses an unauthorized boundary.
- [ ] The capability is approved for the intended Apple distribution channel.

## Phase 8: Control-plane and API adaptations

Only add server behavior proven necessary by the Apple clients.

- [ ] Reuse existing routes and schemas wherever possible.
- [ ] Add platform/runtime metadata only when it affects an operator decision.
- [ ] Treat client-supplied platform labels as advisory unless cryptographically
  or operationally proven.
- [ ] Add explicit mobile suspension/runtime evidence fields instead of
  overloading generic heartbeat status.
- [ ] Keep reads side-effect free.
- [ ] Bind mutations to request IDs and expected revisions.
- [ ] Preserve RBAC on every Apple-originated mutation.
- [ ] Preserve strict maximum document versions and migration compatibility.
- [ ] Define mixed-version rollout and rollback ordering before schema writes.
- [ ] Update `internal/httpapi/openapi.go` for every API change.
- [ ] Regenerate `docs/openapi.json`.
- [ ] Add strict HTTP, storage, migration, backup, PostgreSQL, and
  multi-replica tests for new state.
- [ ] Add fail-closed client parsing and contract tests.

## Phase 9: Release verification matrix

### macOS operator application

- [ ] clean build;
- [ ] arm64 execution;
- [ ] amd64 execution;
- [ ] signature and entitlement verification;
- [ ] notarization and staple;
- [ ] browser authentication;
- [ ] Keychain persistence and erasure;
- [ ] every documented read;
- [ ] every documented mutation;
- [ ] RBAC denial;
- [ ] logout and server-side session revocation;
- [ ] one-time-secret background erasure;
- [ ] accessibility;
- [ ] upgrade and settings migration; and
- [ ] uninstall.

### macOS node

- [ ] authenticated online install;
- [ ] authenticated offline install;
- [ ] arm64 and amd64 native execution;
- [ ] immutable release and path invariants;
- [ ] launchd lifecycle;
- [ ] enrollment;
- [ ] signed revision convergence;
- [ ] heartbeat and runtime evidence;
- [ ] direct packets;
- [ ] lighthouse discovery;
- [ ] relay packets;
- [ ] DNS;
- [ ] firewall allow and deny;
- [ ] routed-prefix behavior where supported;
- [ ] certificate renewal and rotation;
- [ ] permanent revocation;
- [ ] CA rotation;
- [ ] stale-state quarantine;
- [ ] reboot;
- [ ] sleep/wake;
- [ ] network change;
- [ ] crash and forced kill;
- [ ] upgrade;
- [ ] rollback;
- [ ] interrupted install/upgrade recovery; and
- [ ] uninstall.

### iOS operator

- [ ] supported iPhone sizes;
- [ ] supported iPad sizes;
- [ ] simulator build;
- [ ] physical-device build;
- [ ] browser authentication;
- [ ] Keychain behavior;
- [ ] background and lock erasure;
- [ ] every documented read;
- [ ] every documented mutation;
- [ ] RBAC denial;
- [ ] accessibility;
- [ ] network interruption;
- [ ] upgrade and state migration; and
- [ ] TestFlight/App Store or managed-distribution validation.

### iOS node

- [ ] physical iPhone;
- [ ] physical iPad if supported;
- [ ] Packet Tunnel start and stop;
- [ ] local key generation and custody;
- [ ] enrollment;
- [ ] direct packets;
- [ ] lighthouse discovery;
- [ ] relay packets;
- [ ] DNS;
- [ ] firewall allow and deny;
- [ ] Wi-Fi and cellular;
- [ ] Wi-Fi/cellular roaming;
- [ ] lock and background;
- [ ] low-power behavior;
- [ ] extension crash and restart;
- [ ] reboot;
- [ ] signed revision convergence;
- [ ] renewal and rotation;
- [ ] revocation cutoff;
- [ ] App Store/TestFlight/MDM update; and
- [ ] identity removal.

No checkbox may be marked complete from compilation, mocks, simulator-only
evidence, or process existence when the requirement explicitly calls for a
real host, device, packet, signature, notarization, or lifecycle transition.

## Phase 10: Documentation and operator handoff

- [ ] Update `docs/public-guide.json` for every approved Apple feature.
- [ ] Regenerate `internal/httpapi/web/docs.html`; never edit it directly.
- [ ] Update the typed OpenAPI catalog and regenerate `docs/openapi.json` for
  every API change.
- [ ] Document:
  - supported OS and architecture matrix;
  - prerequisites;
  - safe installation order;
  - signing and Gatekeeper expectations;
  - macOS operator installation;
  - macOS node installation and enrollment;
  - iOS operator installation;
  - iOS node availability and distribution limitations;
  - permissions and entitlements;
  - login and logout;
  - node renewal and revocation;
  - quarantine and stale evidence;
  - upgrade and rollback;
  - uninstall and retained state;
  - troubleshooting;
  - evidence interpretation; and
  - known limitations.
- [ ] Clearly distinguish operator applications from node/tunnel capability.
- [ ] Do not publish internal host addresses, signing identities, credentials,
  private repository details, or unproved behavior.
- [ ] Run:

```bash
python3 scripts/generate-public-docs.py
python3 scripts/generate-api-docs.py
make docs-check
go test ./internal/httpapi
```

- [ ] Pass public and API documentation change gates before completion.

## Ordered implementation sequence

1. Approve Phase 0 architecture decisions and threat model.
2. Establish the pinned Apple build and CI environment.
3. Add and verify the macOS operator runner.
4. Complete native macOS installer and launchd proof.
5. Enable Darwin production enrollment only after the proof passes.
6. Sign, notarize, publish, re-download, and clean-host verify macOS artifacts.
7. Add the optional local-node bridge/menu-bar experience.
8. Add and verify the iOS operator runner.
9. Complete the iOS Packet Tunnel feasibility spike.
10. Implement iOS enrollment, config, lifecycle, and evidence only after the
    spike passes.
11. Run the full real-device iOS node matrix.
12. Update public/API documentation and complete release review.

The macOS operator console, macOS node, iOS operator, and iOS node are separate
release gates. Completion of one does not imply completion of another.

## Overall completion criteria

This goal is complete only when:

- [ ] the macOS operator application is supported, packaged, signed, notarized,
  documented, and verified;
- [ ] the macOS node installs through a supported authenticated path and passes
  clean-host, packet, lifecycle, revocation, upgrade, rollback, and reboot
  proofs on supported architectures;
- [ ] the iOS operator application passes simulator and physical-device auth,
  RBAC, secret-custody, accessibility, and mutation tests;
- [ ] if iOS node support is declared, the Packet Tunnel extension passes the
  full real-device tunnel, roaming, suspension, renewal, rotation, revocation,
  and distribution matrix;
- [ ] every distributed artifact is bound to source and release metadata and
  has independently verifiable signing/provenance evidence;
- [ ] no Apple path returns a node private key to the control plane, Flutter
  runtime, logs, or ordinary application storage;
- [ ] Linux and Windows source, package, API, storage, backup, and packet gates
  remain green;
- [ ] public and API documentation accurately describe only proved behavior;
  and
- [ ] unresolved limitations are explicit rather than represented as supported
  features.

## Explicit non-goals

- Replacing the Mesh agent with the reviewed reference daemon.
- Supporting iOS merely because Flutter can compile an iOS application.
- Treating an iOS simulator as proof of a working packet tunnel.
- Installing Nebula by downloading an upstream moving latest release.
- Allowing the GUI to read or write privileged runtime files directly.
- Adding a second independently supervised Nebula service on macOS.
- Returning a node private key from the control plane.
- Weakening browser authentication, RBAC, signed revisions, high-water
  protection, revocation, or fail-closed staleness behavior.
- Claiming App Store, TestFlight, MDM, Intel Mac, relay, DNS, firewall,
  background, or revocation support without the corresponding evidence.

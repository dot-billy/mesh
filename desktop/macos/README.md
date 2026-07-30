# Mesh Admin for macOS source runner

This is the source-only Flutter runner for the unprivileged Mesh operator
console. It does not install Mesh Node, enroll the Mac, configure a tunnel,
read privileged Mesh state, or claim production support.

The application identifier `io.rw0.mesh.admin` is registered to Apple Team
`Y3P5UNNG23`; the final public product name still requires release approval.
The release entitlement set is deliberately limited to the application
sandbox, outbound networking, and the default application Keychain group
required for the exact-origin Mesh session and CSRF cookie pair. Debug-only
JIT and local server entitlements do not ship in the release configuration.
Saved control-plane names and normalized origins use a separate bounded
Keychain record. Sign-out deletes only the credential-bearing session record;
relaunch restores at most eight profiles and re-verifies system TLS and
advertised authentication methods before enabling sign-in.

Before removing the application, Preferences provides an
exact-confirmation **Erase local data** action. It attempts deletion of both
the session record and the saved-profile record, clears in-process cookies and
one-time material, and reports when server-side session revocation cannot be
confirmed. Organization-managed profiles, operating-system permissions,
server records, and a separately installed Mesh Node remain outside that
action. This source behavior does not satisfy the clean-host uninstall gate.

Install the exact archive from `desktop/tool/flutter-sdk.json` outside the
checkout, verify its SHA-256, and validate the host with
`scripts/apple-build-preflight.py` using a separate empty, private source-build
Keychain. From `desktop/`, run:

```sh
dart pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
MESH_FLUTTER=/absolute/pinned/flutter/bin/flutter \
MESH_APPLE_INPUT_RECEIPT=/absolute/preflight-receipt.json \
MESH_SOURCE_KEYCHAIN=/absolute/empty-source.keychain-db \
../scripts/apple-source-build.sh debug /absolute/new/debug-derived-data
MESH_FLUTTER=/absolute/pinned/flutter/bin/flutter \
MESH_APPLE_INPUT_RECEIPT=/absolute/preflight-receipt.json \
MESH_SOURCE_KEYCHAIN=/absolute/empty-source.keychain-db \
../scripts/apple-source-build.sh release /absolute/new/release-derived-data
```

These commands produce unsigned/ad-hoc developer artifacts only. They are not
signing, notarization, clean-host, Intel execution, packaging, distribution,
or support evidence.

## Protected application release boundary

`scripts/apple-protected-app-release.py` is a native-Mac, create-only protected
job boundary. It accepts only a clean, pinned, unsigned Release application
whose complete tree matches its source receipt. It authenticates the fixed
Apple and selected Xcode tools, requires exactly the reviewed `App`,
`FlutterMacOS`, and `objective_c` frameworks, rejects already-signed or
unexpected nested code, selects exactly one Developer ID Application identity
for the compiled Team ID, and signs each exact identifier inside out with the
hardened runtime. The outer application receives only
`Runner/Release.entitlements`.

The job then submits a temporary archive through an explicitly selected
private Keychain notary profile, requires an accepted canonical submission,
staples and validates the application, runs Gatekeeper assessment, rechecks
the signature and sealed resources, and creates the final `ditto` zip. Its
canonical receipt binds the final bytes, source receipt, Team ID, exact
entitlements, nested-code inventory, notarization ID, staple, Gatekeeper
result, and authenticated tool hashes.

`mesh-release verify-apple-app-release` performs a portable, secret-free check
that a physical archive matches that canonical receipt, the expected source
receipt digest, and the approved Team ID. That receipt is not self-authenticating
and the portable check does not replace native re-verification after public
download. The in-job staple validation also does not prove the separate
network-isolated staple check required for release approval.

Production release authoring represents the application and its evidence as
two non-confusable targets in one threshold-signed Mesh release manifest:
`macos-admin/universal` is the exact zip and
`macos-admin-evidence/portable` is the exact protected receipt.
`create-release-manifest` accepts that pair only with a matching protected
receipt, its expected unsigned source-receipt digest, the compiled Team ID
policy, the same application version, and a protected verification no more
than 24 hours old. `mesh-release verify-published-apple-app` then uses an
independently authenticated current Mesh root and its release threshold to
verify the downloaded manifest, signatures, zip, and receipt together before
reapplying the source-digest and Team-ID checks. It still makes no native Apple
acceptance claim.

`scripts/apple-native-app-verify.py` is the separate post-download native
boundary. It first pins the `mesh-release` verifier to an independently
authenticated SHA-256 and requires the current Mesh root's independently
authenticated SHA-256. It then runs the threshold publication check, extracts
exactly one application, matches the complete signed tree, and independently
rechecks designated requirements, Team ID, universal architectures, hardened
runtime, exact outer and empty nested entitlements, sealed resources, staple,
and Gatekeeper. Its create-only receipt binds the downloaded bytes, root,
manifest, signatures, verifier, Apple tools, and native results.

With `--require-network-isolated`, that verifier rejects a default route or
any non-loopback IPv4/global-IPv6 address both before and after the staple and
Gatekeeper checks. This is a bounded local sample; a release proof still needs
an externally controlled clean-host fixture that keeps networking disabled
throughout the run.
The resulting receipt has a strict portable parser; malformed, noncanonical,
stale, artifact-drifted, Team-drifted, or falsely isolated evidence is
rejected.

The product identifier `io.rw0.mesh.admin` is registered to Team
`Y3P5UNNG23`. A current dirty-source Release build has fresh source/security
receipts, and a separately labeled local feasibility copy is Developer ID
signed with exact Release entitlements, hardened runtime, secure timestamp,
and strict nested verification. Gatekeeper rejects it specifically as
`Unnotarized Developer ID`. No protected clean-source execution, accepted
notarization submission, staple, Gatekeeper acceptance, protected receipt,
threshold-signed application metadata, published bytes, or re-downloaded
artifact exists.

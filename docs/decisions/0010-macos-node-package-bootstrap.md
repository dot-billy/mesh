# ADR 0010: macOS node package bootstrap

- Status: accepted for engineering
- Date: 2026-07-24

## Decision

Distribute Mesh Node for macOS as one signed and notarized flat installer
package per supported architecture. The package is only a transport for one
authenticated Mesh release; it is not a second release authority.

The package payload contains exactly:

- one production `mesh-install` Mach-O whose compiled installer trust,
  architecture, build identity, Team ID, and code identifier match the
  protected package policy;
- one mode-`0700` Mesh-owned package root below the fixed
  `/Library/Application Support/Mesh` install location, so the package bill
  of materials cannot contain or rewrite `/Library`, `/Library/Application
  Support`, or any other existing system ancestor;
- one root:wheel mode-`0700` package-snapshot directory containing only
  `install.json`, `bundle.json`, and `mesh-darwin-bundle.tar`, with each file
  root:wheel mode `0400`; and
- the fixed package receipt metadata needed to identify that architecture and
  product version.

The post-install entrypoint is compiled code from the same reviewed
`mesh-install` source, not a shell script. It accepts no package-selected URL,
path, executable, environment override, launchd property list, or command
fragment. It imports only the fixed package-snapshot path through
`internal/darwininstall`, resumes only an already durable matching installer
transaction, and treats a retry of the same authenticated active release as
an idempotent success.

The package does not enroll a node or open the persistent runtime gate.
Enrollment remains a separate one-use control-plane ceremony. The installed
release, current selector, launchd property list, gate, immutable releases,
trusted roots, anti-rollback high water, and retained enrollment state remain
owned by `mesh-install`, not by package scripts or Installer receipt logic.

The protected producer must authenticate the clean source receipt, production
`mesh-install`, signed Darwin bundle-v2, native code-signing receipt, final
package-security receipt, exact payload tree, Apple tools, and an explicitly
selected Developer ID Installer identity before building. It then signs the
final package, requires accepted notarization, staples and validates the
ticket, runs Gatekeeper assessment, hashes the final stapled bytes, and emits
a canonical receipt suitable for threshold-authenticated Mesh release
metadata and post-download native verification.

The package identifier, production `mesh-install` code identifier, package
root, package-snapshot path, and installed bootstrap path remain release-policy
constants. Their final strings require approval before the development
sentinel may be replaced or any package may be notarized.

## Consequences

- `darwin/arm64` and `darwin/amd64` packages remain separate and retain
  independent build, signing, package-security, native-execution, notarization,
  and installed-host evidence.
- A payload-free signed package proves only Installer-certificate usability.
  It cannot satisfy this contract.
- A package containing only the Darwin staging tar cannot satisfy this
  contract because it omits the authenticated bootstrap installer and offline
  release envelope.
- A shell `postinstall`, caller-selected snapshot path, moving online URL, or
  package-authored launchd mutation is prohibited.
- The protected producer must prove the package's exact bill of materials and
  must not author or rewrite ownership or mode metadata for existing system
  ancestors such as `/usr`, `/usr/local`, `/private`, or `/private/var`.
  Staging-tree convenience cannot become authority to mutate those paths.
- Reinstall and interrupted-install behavior must be proven through the same
  journal and intake state machines used by online and offline installation.
- Removing the package receipt is not runtime uninstall. The documented
  `mesh-install uninstall-runtime` command continues to retain immutable
  releases, trust/high-water state, installer files, and enrollment state.
- Production enrollment remains disabled until the complete native package,
  lifecycle, reboot, packet, revocation, clean-host, Apple Silicon, and Intel
  evidence gates pass.

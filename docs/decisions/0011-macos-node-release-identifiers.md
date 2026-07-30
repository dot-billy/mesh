# ADR 0011: macOS node release identifiers

- Status: proposed; explicit release-policy approval required
- Date: 2026-07-24

## Context

The protected macOS node pipeline cannot sign or notarize a real bundle or
installer package while the Darwin code-signing and node-package linker
identities remain development sentinels. Apple Team `Y3P5UNNG23` is already
the registered authority used by the approved Mesh Admin and Mesh Tunnel
identifiers under the `io.rw0.mesh` namespace. The existing launchd label
`io.mesh.node-agent` is an installed-runtime compatibility constant and is not
being renamed by this proposal.

## Proposed decision

Approve the following exact release-policy values:

| Role | Proposed value |
| --- | --- |
| Apple Team ID | `Y3P5UNNG23` |
| Flat package identifier | `io.rw0.mesh.node` |
| `mesh-install` code identifier | `io.rw0.mesh.node.mesh-install` |
| `meshctl` code identifier | `io.rw0.mesh.node.meshctl` |
| `nebula` code identifier | `io.rw0.mesh.node.nebula` |
| `nebula-cert` code identifier | `io.rw0.mesh.node.nebula-cert` |
| Package root | `/Library/Application Support/Mesh/Node` |
| Installed bootstrap | `/Library/Application Support/Mesh/Node/mesh-install` |
| Root-private snapshot | `/Library/Application Support/Mesh/Node/snapshot` |

The current canonical tooling produces Darwin code-signing policy SHA-256
`2c442602d13440db36da7aa39702a76da4fad4969e6fd5602dbf467d90f2f5e9`
and Darwin node-package policy SHA-256
`aabd3ca4518aef2f932476cad9b32aa5a50d71393d643d10f5ba0324dee6eae5`
for those exact values.

## Approval boundary

This record is a proposal, not approval. It does not authorize linker
embedding, code signing, package signing, notarization, installation,
publication, enrollment, or a support claim. Until an authorized product and
release-policy owner explicitly accepts every value above:

- `darwincodesign.Identity` and `darwinnodepackage.Identity` remain their
  unparseable development sentinels;
- protected Node bundle and package production must not run with these values;
- no test-only `io.mesh.node.*` identifier may be substituted; and
- the existing `io.mesh.node-agent` launchd label and runtime paths remain
  unchanged.

Approval must also confirm that the selected Developer ID Application and
Installer certificates belong to Team `Y3P5UNNG23`, that the package namespace
is owned for the intended product, and that changing any approved string
requires new compiled policies and fresh bundle, package, native-host,
notarization, publication, and clean-host evidence.

## Consequences if approved

The protected build can compile the two canonical policy frames into
architecture-specific `mesh-install`, `meshctl`, `nebula`, and `nebula-cert`
executables, produce the native code-signing receipt, assemble signed Darwin
bundle v2 on Linux, run the final bundle-security gate, create the exact flat
package, and proceed to notarization and native verification. Approval alone
does not satisfy any of those downstream gates.

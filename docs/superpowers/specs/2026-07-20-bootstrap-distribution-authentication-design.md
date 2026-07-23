# First-installer bootstrap distribution and authentication

**Status:** Local authorization, dedicated verifier, deterministic verifier
packages, and a canonical one-digest handoff are implemented and live-proved
on Linux. Production distribution channels, independently authenticated
handoff publication, and operator custody remain deployment work.

## Problem

The first `mesh-install` binary contains the immutable version-1 release root.
Neither the Mesh control plane, its browser UI, the release object store, nor
TLS can authenticate that first binary without creating a circular trust
claim. Before this slice, operators could build the right binary but had no
canonical root-role authorization record or fail-closed verification command.

## Trust boundary

The independently authenticated value may be the SHA-256 of canonical root
version 1, or one canonical `mesh-bootstrap-handoff-v1` document digest that
binds that root plus the exact `amd64` and `arm64` verifier packages. A root
cannot authenticate itself, so the handoff is deliberately unsigned.
Production must carry the selected root or handoff digest over a channel
independent of the installer, manifest, signatures, release URL, object store,
control plane, and browser session.

`mesh-bootstrap-verify` is also security-sensitive. Its command surface has no
signing, key-generation, download, extraction, or installation operation, but
it must still come from an already trusted operator package/build or have its
own digest authenticated independently. Downloading the verifier beside the
installer and trusting its success output would remain circular. An operator
may instead publish the installer SHA-256 itself over the independent channel
and use the host's already trusted `sha256sum`; the root-authorized manifest
remains the auditable multi-custodian approval. `mesh-release
verify-bootstrap` remains a compatibility entry point using the same verifier
implementation.

## Root-authorized record

`mesh-bootstrap-manifest-v1` is compact canonical JSON plus one LF. It contains
no URL, credential, or mutable channel pointer. It binds:

- channel, root version 1, release epoch 1, and exact root SHA-256;
- the exact compiled installer-bootstrap SHA-256;
- a canonical production build identity and Go toolchain version;
- exact `mesh-install` name, Linux architecture, byte length, and SHA-256; and
- a canonical issue/expiry window of at most 31 days that stays within the
  authorizing root's validity.

The manifest is signed in a distinct `bootstrap` domain by the root role. The
release role cannot authorize it. Threshold evaluation counts only distinct,
valid root-key votes; malformed, duplicated, unknown, wrong-domain, and
minority signatures do not create authority.

## Authoring flow

1. Create and independently compare canonical root version 1.
2. Build `mesh-install` with exactly that root and a production build identity.
3. Run `create-bootstrap-manifest`. It statically inspects the bounded ELF and
   executes no candidate code.
4. Have the required independent root custodians sign the exact manifest bytes.
5. Build both canonical Linux verifier packages and run
   `create-bootstrap-handoff`. It statically validates their exact USTAR/ELF
   bytes, shared build identity/toolchain, platform coverage, and root floor.
6. Publish the handoff, verifier packages, installer, canonical root, manifest,
   and detached signatures as immutable objects. Their transport is an
   untrusted courier.
7. Publish the handoff digest through the independent ceremony. Directly
   publishing the root plus verifier-package digests remains an equivalent
   lower-level option; publishing the installer digest permits direct
   `sha256sum` verification too.

## Verification flow

In the preferred single-digest mode, the verifier authenticates the bounded
handoff before opening the root, resolves the exact Linux platform package,
and requires the root bytes and semantics to match the handoff. Only then does
it open the larger manifest, signatures, and installer, evaluate root-role
threshold authorization, and statically check the installer against the
authorized size/SHA-256, architecture, production build identity, Go build
settings, sole v2 bootstrap frame, absence of legacy trust frames, exact
bootstrap digest, and exact embedded root. It never executes or installs the
candidate and returns a bounded v2 JSON receipt containing the handoff,
selected verifier-package, and root digests. A mutually exclusive direct-root
mode remains for compatibility and returns the v1 receipt.

## Failure behavior

Verification fails before execution on a missing or mixed trust-anchor mode, a
changed or expired handoff, changed root bytes, a handoff/root/platform
mismatch, an expired root or manifest, insufficient root votes, release-role
votes, wrong signature domains, changed exact manifest bytes, noncanonical
JSON, identity or platform drift, changed installer bytes, multiple/missing
bootstrap frames, or a compiled root mismatch. Authoring and signature files
are create-only and stable-read before success.

## Proof boundary

The standalone verifier smoke creates ephemeral independent 2-of-2
root/release roles, builds the production installer, creates and root-signs its
bootstrap manifest, verifies it with the exact root digest, and requires exact
receipt parity with the compatibility command. It rejects a wrong independent
digest, a distinct root, release-role authorization, one-of-two approval,
changed installer bytes, expiry, and a symlinked root. The Linux install smoke
uses the same standalone executable before continuing through online/offline
installation and runtime proof. Both paths remove their private key
workspaces. Before that trust proof, the standalone gate builds the verifier
with a production identity and packages it twice. The canonical USTARs must be
byte-identical and contain exactly package metadata plus the verifier; the gate
rejects development or identity-mismatched binaries, linked input paths, and
output replacement. The release-origin gate then carries the complete
two-architecture bootstrap set over native TLS while retaining only the exact
handoff digest outside that origin. It authenticates the downloaded handoff,
derives and checks the selected verifier-package and root digests, validates
the two-member USTAR before extraction, and passes the same independent
handoff digest to both the extracted narrow verifier and compatibility entry
point. Their v2 receipts must be byte-identical; a wrong handoff digest,
changed root, or exact-expiry handoff is rejected. It separately proves the
2-of-2 online release path and makes an indexed installer mutation fail both
origin readiness and retrieval closed.

This mechanism does not provision a production artifact host, transparency
log, DNS record, package repository, hardware-backed signer, independently
authenticated handoff publication, printed recovery card, or second
communication channel. Those remain required before calling first-installer
distribution supported in production.

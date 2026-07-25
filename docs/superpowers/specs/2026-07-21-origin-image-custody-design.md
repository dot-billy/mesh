# Release-origin image identity and custody

**Status:** Implemented mechanism; production registry publication and key
custody remain deployment work.

## Problem

Immutable origin generations and external HTTPS auditing do not identify the
container program serving those bytes. A mutable image tag or an implicit
production build can replace that program without changing the selected
generation. The deployment contract needs one exact manifest digest plus a
separate authentication step rooted outside the registry and origin host.

## Boundary

The origin image is deployment machinery, not release authority. Authenticating
it limits courier substitution but cannot authorize an installer or release.
The independent bootstrap-handoff digest, root threshold, and release threshold
remain the software-authorization boundary.

Production Compose accepts one registry repository and one 64-character
lowercase SHA-256 manifest digest. It contains no build stanza and has no tag or
local-image default. A second `compose.build.yaml` is an explicit local/test
override and is never part of the production command.

## Verification gate

`mesh-origin-image-verify` accepts exactly:

- a canonical `registry/repository@sha256:<digest>` image reference;
- one clean absolute, bounded, single-link, non-group-writable Cosign public
  key provisioned independently of the image registry and origin host;
- one clean absolute, bounded, executable, non-group-writable Cosign program;
  and
- one bounded total deadline and optional create-only receipt path.

The command takes a stable snapshot of the public key, SHA-256 binds that
snapshot and the Cosign executable, then invokes `cosign verify` without a
shell. Claim checking is explicit. Every returned verified signature payload
must be a Cosign container-image signature naming the requested manifest
digest. The executable is rehashed after verification. Failure emits no
receipt.

## Receipt

Success emits canonical `mesh-origin-image-verification-v1` JSON plus one LF.
It binds the exact image reference and manifest digest, public-key SHA-256,
Cosign-executable SHA-256, UTC verification time, and verified signature count.
A file output is clean absolute, create-only, fsynced, and never replaced. The
receipt is rollout evidence, not an authorization signature or transparency
log.

## Rollout order

The release pipeline builds once, pushes once, resolves the registry manifest
digest, signs that exact digest under the external image-signing ceremony, and
publishes the digest separately from the private signing key. The production
operator provisions the public key independently, verifies the exact digest,
stores the receipt externally, renders the production-only Compose file,
pulls that digest, starts with builds disabled, and runs the external origin
auditor before traffic cutover. Generation rollback does not change the image;
an image rollback repeats signature verification for the retained exact digest.

## Proof and exclusions

Focused tests reject mutable tags, implicit registries, malformed or uppercase
digests, unsafe key/tool paths, linked keys, output replacement, malformed
Cosign output, wrong signed digests, wrong signature types, and noncanonical
receipts. A real subprocess fixture proves exact argument order, explicit claim
checking, and use of the snapshotted key. The origin smoke proves production
Compose fails without image identity, renders one digest reference without a
build, and uses the separate build override only for its disposable image.

The repository does not contain a production registry, image-signing private
key, CI signer, transparency-log policy, Cosign installation, public-key
distribution system, receipt archive, or admission controller. Those must be
provisioned and exercised before a production claim.

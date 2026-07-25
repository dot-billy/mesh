# Independently transferable bootstrap anchor

**Status:** Implemented and proved on 2026-07-21.

## Problem

The canonical bootstrap handoff reduces first-install trust to one SHA-256, but
the standalone verifier accepts that authority only as a manually copied
command-line value. That is cryptographically sufficient but operationally
fragile. Operators need one small, create-only file that can be copied to
read-only media, printed/re-keyed, or delivered through a separately controlled
configuration channel without treating anything from the release origin or
Mesh dashboard as authoritative.

## Boundary

`mesh-bootstrap-anchor-v1` is deliberately unsigned. Possession through the
operator's independent channel is its authority. A copy fetched from the
release origin, dashboard, or the same DNS/TLS/control path as the installer is
untrusted and provides no security.

The anchor contains only reviewable public facts: channel; exact handoff name,
size, SHA-256, issuance, and expiry; root name/version/epoch/SHA-256; production
build version/commit/security floor; and the ordered amd64/arm64 verifier-package
names and SHA-256 values. It contains no URL, executable command, key, signature,
or origin-selected indirection.

`mesh-release create-bootstrap-anchor` accepts one canonical handoff and writes
one canonical create-only anchor. It does not publish or transfer it. Operators
must move that exact file through an independently administered channel and
keep it out of the origin generation.

## Verification order

Anchor mode in `mesh-bootstrap-verify` must:

1. stably read the independently supplied bounded single-link anchor before
   opening the handoff or any larger courier input;
2. strictly parse its canonical schema and validity window;
3. stably read the courier handoff and compare exact size and SHA-256 before
   interpreting it;
4. require every duplicated human-review field to match the now-authenticated
   canonical handoff;
5. continue through the existing root, platform verifier-package, threshold
   manifest, installer-byte, and embedded-trust checks; and
6. emit a `mesh-bootstrap-verification-v3` receipt binding the anchor SHA-256,
   handoff SHA-256, selected verifier-package SHA-256, root, manifest, installer,
   build, platform, and root-role signers.

Direct-root digest mode and direct-handoff digest mode remain available and
emit v1 and v2 receipts respectively. Exactly one of those modes or anchor mode
is allowed. The anchor cannot be combined with an expected digest, and no
origin/dashboard field can silently fill a missing anchor.

## Proof

Unit tests require canonical round trips and reject duplicate/unknown fields,
wrong digest/size, field drift, invalid time, package reordering, linked files,
and mixed trust modes. The release-origin smoke retains the anchor only outside
the indexed repository, proves the public origin cannot serve it, authenticates
the fetched handoff and verifier package from that anchor, and requires exact v3
receipt parity between the narrow verifier and compatibility command. Wrong,
changed, linked, expired, or mixed anchors fail without a receipt.

This mechanism makes a real independent channel file-shaped and auditable; it
does not provision physical media, a second domain/account, MDM, offline vault,
human custody, or delivery monitoring. Production must choose, operate, and
test one such channel.

# Versioned Release Root Chain and Signing-Key Rotation Design

**Date:** 2026-07-20

**Status:** Implemented and release-quality verified on 2026-07-20

## Purpose

Mesh currently authenticates Linux releases with one immutable threshold policy
compiled into `mesh-install`. That is a sound bootstrap boundary, but it has no
in-band way to replace or revoke a release signer. A separately authenticated
installer binary must be redistributed whenever the trusted signing set
changes.

This slice adds a small, TUF-inspired root role above the existing release
metadata. The separately authenticated installer still establishes the first
trust anchor. After that, a versioned chain of threshold-signed root documents
can rotate root keys, delegate a distinct release-signing role, revoke release
keys, raise trust floors, and move release metadata into a new epoch without
turning the repository, TLS connection, control plane, or candidate release
into an authority.

This is a purpose-built Mesh protocol, not a general TUF implementation. It
adopts the root-continuity rule that every root update is signed by the
threshold in its immediate predecessor and by the threshold in the new root.
Mesh keeps its existing exact-byte manifests, detached Ed25519 envelopes,
channel-to-release binding, artifact verification, and privileged Linux
transaction.

## Scope

This design adds:

- a canonical, expiring, versioned Mesh release-root document;
- disjoint threshold roles for root authorization and release publication;
- immediate-predecessor plus self-threshold verification for each root update;
- explicit release epochs for release-key rotation and revocation;
- v2 channel and release manifests that bind their release epoch;
- a bounded root-update envelope and ordered root-update chains;
- root-chain carriage in both online bundles and offline snapshots;
- a root-private, create-only, crash-durable accepted-root history;
- a new compiled bootstrap frame containing the immutable initial root;
- deterministic release tooling for root creation, signing, transition
  assembly, publication, and inspection;
- a safe migration from the existing pre-release installer state when its
  compiled policy exactly matches the initial root's release delegation;
- unit, race, subprocess, filesystem-fault, online/offline, and real Linux
  proofs for rotation and revocation.

This design does not add:

- automatic update polling or unattended installation;
- a network timestamp, snapshot, delegation graph, or mirror protocol;
- remote signing, HSM integration, secret escrow, or key recovery;
- recovery after an attacker controls a threshold of the root role;
- authentication of the first `mesh-install` binary;
- control-plane custody of any root or release private key;
- private repository credentials, custom roots, redirects, or proxies;
- native macOS or Windows installation and platform code signing;
- permission for a root update to replace the installer build's supported
  security semantics.

If an attacker controls a threshold of the currently trusted root role, safe
in-band recovery is not assumed. The operator must distribute a new bootstrap
installer through a separately authenticated path and treat already affected
machines as potentially compromised.

## Security invariants

1. The authenticated bootstrap installer contains the immutable initial root.
   No file, flag, environment variable, URL, HTTP response, control-plane
   value, release manifest, or persisted candidate may select a different
   trust universe.
2. Root version `N+1` is accepted only from trusted root version `N`, and only
   when the exact candidate bytes satisfy both `N`'s root threshold and
   `N+1`'s root threshold.
3. Root and release roles are disjoint within every root document. A release
   key cannot authorize a root transition, and a root key cannot publish a
   release merely because it can authorize delegations.
4. Omitting a key from a newly accepted role revokes that key for all future
   trust decisions made under that root. Previously fsynced exact release
   decisions remain resumable so a crash cannot strand the host.
5. A change to release-role keys or threshold requires the release epoch to
   advance exactly once. Channel and release manifests bind that epoch, so old
   signed bytes cannot replay across a role transition even when a key remains
   in both release roles.
6. Root version, release epoch, release sequence, and security floor never move
   backward. A sequence may reset only when the release epoch advances.
7. The latest root reached during one fixed update attempt must be unexpired.
   An expired trusted root may authenticate only its exact sequential
   successors; it cannot authenticate a release.
8. Root updates become trusted one at a time through create-only, fsynced
   history entries. A crash exposes either the prior contiguous chain or the
   same chain plus one complete, re-verifiable update, never a partially
   replaced current root.
9. Release metadata is verified using only the final trusted root reached for
   that attempt. A chain suffix cannot make a release valid under an
   intermediate key set.
10. A release trust decision records the root version, root digest, release
    epoch, exact manifest digests, artifact digest, and verification time. A
    different candidate cannot reuse that decision.
11. Root advancement is independent of release installation. A valid key
    revocation remains persisted even if artifact retrieval or activation later
    fails.
12. Existing artifact, package, state-compatibility, service, rollback,
    recovery, and runtime-gate checks remain mandatory after root and release
    authentication succeed.

## Trust roles

Every root document defines exactly two roles:

- `root`: offline keys authorized to change the root document;
- `release`: independently controlled keys authorized to sign channel and
  release manifests for the document's release epoch.

Each role requires at least two distinct Ed25519 keys and a threshold of at
least two. The combined document contains at most `release.MaxTrustedKeys`
public keys. Key identifiers retain the existing derived form
`ed25519-sha256:<64 lowercase hex>` and must match their public-key bytes.

The two role key-ID sets must be disjoint. The document's key list is exactly
the union of the two role sets: missing, duplicate, and unreferenced keys are
rejected. Key IDs and public-key entries are strictly sorted. A key may remain
in the same role across root versions, but one physical key must not be reused
between root and release duties in a single version.

The root role should be kept offline and split across independent operators.
Release keys may be used more frequently, but remain offline in this slice.
All existing owner-only private-key file checks and Linux-only private-key
operations continue to apply.

## Root document

The new schema is `mesh-release-root-v1`. Its canonical compact JSON is
followed by exactly one LF byte:

```json
{
  "schema": "mesh-release-root-v1",
  "version": 2,
  "channel": "stable",
  "release_epoch": 2,
  "minimum_release_sequence": 1,
  "minimum_security_floor": 1,
  "issued_at": "2026-07-20T12:00:00Z",
  "expires_at": "2027-07-20T12:00:00Z",
  "keys": [
    {
      "schema": "mesh-ed25519-public-key-v1",
      "key_id": "ed25519-sha256:...",
      "public_key": "..."
    }
  ],
  "roles": {
    "root": {
      "threshold": 2,
      "key_ids": ["ed25519-sha256:...", "ed25519-sha256:..."]
    },
    "release": {
      "threshold": 2,
      "key_ids": ["ed25519-sha256:...", "ed25519-sha256:..."]
    }
  }
}
```

The example is expanded for readability. Accepted bytes must equal the one
canonical encoding emitted by the root encoder. The top-level object and both
role objects have exactly the shown fields. Root documents are limited to 64
KiB.

Validation requires:

- positive `version`, `release_epoch`, `minimum_release_sequence`, and
  `minimum_security_floor`;
- the existing canonical channel syntax;
- canonical UTC RFC3339 timestamps without fractions;
- `expires_at` strictly after `issued_at`;
- a validity interval of at most 366 days;
- exactly the `root` and `release` roles;
- role thresholds of at least two and no greater than their key counts;
- canonical, strictly sorted role key IDs and public-key entries;
- exact key-union membership and disjoint roles;
- existing strict UTF-8, surrogate, duplicate-field, unknown-field, trailing
  value, key encoding, and key-ID checks.

The initial compiled root is version 1 and release epoch 1. Its channel,
release threshold, release keys, release-sequence floor, and security floor are
the exact authority represented by the current immutable installer policy.
Root keys are new and separate. The authenticated binary directly establishes
version 1, so initial-root self-signatures are not needed to bootstrap trust.

## Root-transition rules

Given trusted root `N` and candidate root `C`, structural parsing occurs inside
strict size and count bounds before candidate authority is considered. The
transition is accepted only when all of these conditions hold:

1. `C.version == N.version + 1`, with overflow rejected.
2. `C.channel == N.channel`.
3. `C.minimum_security_floor >= N.minimum_security_floor`.
4. `C.release_epoch` equals `N.release_epoch` or
   `N.release_epoch + 1`, with overflow rejected.
5. If the release epoch is unchanged:
   - release role keys and threshold are byte-for-byte equivalent;
   - `minimum_release_sequence` cannot decrease.
6. If release role keys or threshold change, the release epoch must advance.
   In a new epoch, `minimum_release_sequence` may reset but remains positive.
7. The exact candidate root bytes receive at least `N`'s root threshold from
   distinct keys authorized by `N`.
8. The same exact bytes receive at least `C`'s root threshold from distinct
   keys authorized by `C`.

The existing detached envelope schema is extended with manifest type `root`.
Its domain-separated, length-bound signature message continues to bind the
manifest type and exact bytes. One signature from a key retained across the
transition may count once toward each applicable threshold. Duplicate
envelopes or duplicate votes do not increase either count. Malformed, unknown,
wrong-role, and invalid signatures do not become votes and cannot veto
thresholds already satisfied by valid signatures.

All root signatures are checked before the update is persisted. A release-role
signature never counts toward either root threshold.

## Expiry and fixed update time

Each install attempt records one nonzero UTC update-start time before loading
or applying a chain. All root and release expiry decisions in that attempt use
that fixed time, preventing a long operation from crossing its own trust-time
boundary inconsistently.

An expired current root may be used only to authenticate root version `N+1`.
Intermediate roots in a valid catch-up chain may also be expired. After all
provided sequential updates are processed, the final root must:

- have `issued_at` no more than the existing five-minute clock-skew allowance
  in the future; and
- have `expires_at` strictly later than the fixed update-start time.

If no successor is available, an expired root blocks release verification.
Repository or transport control can withhold a successor and cause denial of
service, but cannot extend an expired root or authorize a release.

## Release epochs and v2 manifests

The new release schemas are `mesh-channel-manifest-v2` and
`mesh-release-manifest-v2`. Each adds one required positive field:

```json
"release_epoch": 2
```

The channel and referenced release continue to bind the same release sequence,
version, release-manifest size, and release-manifest SHA-256. Channel and
release epochs must equal each other and the final trusted root's epoch.

For the current epoch, the effective release-sequence floor is the maximum of:

- the root's `minimum_release_sequence`; and
- the persisted high-water sequence when the high-water decision is in the
  same epoch.

When the trusted root moves to the immediately next release epoch, release
sequence numbering may restart at the new root's positive floor. Ordering is
lexicographic by `(release_epoch, sequence)`. A lower epoch always fails,
regardless of its sequence. Same-epoch, same-sequence candidates remain exact
retries only; different manifest or artifact bytes are equivocation.

The effective security floor is the maximum of the root floor, persisted
installer floor, and candidate manifest floor. It remains bounded above by the
running installer build's compiled supported security floor.

For migration only, v1 channel and release manifests are interpreted as epoch
1 when all of these conditions hold:

- the final trusted root is version 1 and release epoch 1;
- the root's release delegation exactly matches the legacy compiled policy;
- the existing release and channel checks succeed unchanged.

Once root version or release epoch advances, v1 manifests are rejected. Newly
generated release metadata uses v2.

## Root-update envelope and chain

One transition is transported in canonical schema
`mesh-release-root-update-v1`:

```json
{
  "schema": "mesh-release-root-update-v1",
  "root_manifest": "BASE64URL_EXACT_ROOT_BYTES",
  "signatures": ["BASE64URL_EXACT_SIGNATURE_ENVELOPE", "..."]
}
```

The envelope is an unsigned transport container. Each field uses canonical
unpadded base64url, and decoding then encoding must reproduce the same bytes.
It carries no predecessor, URL, trust flag, clock, threshold, or alternate key
source. Authority comes only from verification against the current trusted
root and the candidate root embedded in the exact bytes.

One envelope is limited to 1 MiB and at most twice
`release.MaxTrustedKeys` detached signatures. Byte-identical signature
envelopes are rejected. Root-update arrays contain at most 32 entries per
input. The maximum supports decades of ordinary rotation while retaining an
explicit memory, disk, and parsing bound. A repository approaching the bound
must ship a newer separately authenticated bootstrap before old version-1
clients can no longer catch up from one static release input.

Chains are ordered by decoded root version. Versions must be strictly
increasing. A client may ignore bounded entries older than its current root.
An entry equal to its current root must carry byte-identical root bytes; a
different document at the same version is equivocation. The first newer entry
must be exactly current version plus one, and every following entry must be
the exact successor.

Each transition is verified and persisted before the next is considered. If a
later entry fails, earlier accepted entries remain trusted. The install attempt
fails and can resume from the newly persisted version with a corrected chain.

## Compiled bootstrap trust

`internal/installtrust` gains a v2 canonical frame whose authority is still
established only by the authenticated `mesh-install` binary. The frame
contains:

- the exact canonical initial-root bytes;
- the derived initial-root SHA-256;
- the SHA-256 of the equivalent legacy v1 policy document used only to gate
  one-time state migration.

The encoder requires initial root version 1 and release epoch 1. It derives the
legacy policy digest from the initial root's channel, release role, sequence
floor, and security floor rather than accepting an arbitrary digest. Loading
returns fresh key slices so caller mutation cannot poison global trust.

There is no runtime initial-root override. A build containing the development
sentinel cannot perform production installation. Existing binary inspection,
single-frame, package-identity, and no-duplicate-linker-value checks are
extended to the v2 frame.

## Crash-durable accepted-root history

Linux stores accepted transitions under a dedicated root-private directory,
separate from agent state and release artifacts:

```text
/var/lib/mesh-installer/trust/
  roots/
    00000000000000000002.root-update.json
    00000000000000000003.root-update.json
```

The initial root remains in the authenticated binary. Each later file is the
exact canonical root-update envelope that authorized that version. The current
root is derived by replaying the contiguous history from the compiled initial
root; there is no mutable `current` pointer that can disagree with the chain.

The trust directory and roots directory are root-owned mode `0700`. Accepted
files are root-owned, single-link, regular files mode `0400`. Loading uses
anchored no-follow descriptors, exact UID/mode/link checks before and after
reads, strict names, bounded counts and bytes, and rejects unknown entries,
gaps, symlinks, special files, hard links, or same-version differences.

Publication holds a dedicated root-store lock and performs:

1. replay and validate the complete current chain;
2. verify the exact next transition against both root thresholds;
3. create one random recognized temporary file with no-follow, exclusive
   semantics;
4. write, sync, chmod `0400`, close, reopen, and verify exact bytes and file
   identity;
5. publish to the fixed 20-digit version name without replacement;
6. sync the roots directory before reporting success.

Normal failures remove only the invocation's exact temporary file. Startup may
remove only recognized incomplete temporary names after anchored inspection;
unknown entries fail closed. If a target version already exists and its bytes
are identical, application is idempotent. Different bytes at that version fail
as root equivocation.

This append-only layout makes one accepted root the atomic trust unit. After a
crash, an entry is absent or complete and independently re-verifiable. Keeping
the signed history also permits audit and verification of a previously fsynced
release decision after later signer revocation.

## Installer-state binding and migration

Installer state advances to `mesh-linux-install-state-v3`. Every
`ReleaseIdentity` adds:

- `release_epoch`;
- `trusted_root_version`;
- `trusted_root_sha256`.

The root digest binds the exact root manifest, not the unsigned update
envelope. New high-water ordering uses `(release_epoch, sequence)`. Active,
previous, pending, rollback, resume, and same-sequence checks retain exact
manifest, artifact, bundle, compatibility, and verification-time binding.

A root may advance without changing installer state. Before a new release
decision is prepared, verification reloads the root history and binds the
candidate to the latest root. If the root changes between online preflight and
the existing pre-transaction verification, the candidate is rechecked under
the new root. Revocation therefore wins over stale downloaded metadata.

An exact candidate whose trust decision and artifact identity were already
fsynced in v3 may resume under its recorded historical root and original
verification time. A later root revocation does not strand crash recovery, but
no different bytes or new release can use that historical authority.

The one-time v2-to-v3 migration is allowed only when:

- state v2 validates under all existing rules;
- its `trust_policy_sha256` equals the v2 bootstrap frame's derived legacy
  policy digest;
- the initial root is version 1 and epoch 1;
- its release delegation, channel, sequence floor, and security floor exactly
  represent that legacy policy;
- no root-history entry already exists; and
- no unfinished transaction exists.

The migration maps every existing release identity to epoch 1, initial-root
version 1, and the initial-root digest, then writes v3 with the existing
atomic journal semantics before accepting a new candidate. A pending v2
transaction must be completed by the old installer or explicitly rolled back
before upgrade; guessing its trust epoch is forbidden.

## Offline snapshot carriage

The offline snapshot descriptor advances to a v2 schema with an ordered
`root_updates` filename array. Files use deterministic names such as
`root-update-000.json`, followed by the existing exact channel manifest,
channel signatures, release manifest, release signatures, artifact, and
descriptor.

The root-update list may be empty. Assembly sorts by decoded root version,
rejects duplicates and gaps, and writes exact bytes mode `0400` inside the
existing private snapshot. Materialization and readback include the new files
in the exact allowed tree, size accounting, no-follow, collision, identity,
and fsync proofs.

An existing v1 snapshot is treated as carrying no root updates and is accepted
only when its v1 release metadata satisfies the epoch-1 migration rules. New
snapshot tooling emits v2.

`mesh-install install ABSOLUTE_SNAPSHOT_DIR` applies and persists valid root
updates before release verification. If release verification, extraction, or
activation then fails, the root updates remain accepted and the managed
runtime remains unchanged.

## Online bundle carriage

The online schema advances to `mesh-online-release-bundle-v2` by adding one
required array:

```json
"root_updates": ["BASE64URL_EXACT_ROOT_UPDATE_BYTES", "..."]
```

It retains the exact channel manifest, channel signatures, release manifest,
and release signatures. The array may be empty. Root updates are authenticated
and persisted immediately after the bounded HTTPS bundle is decoded and before
the artifact URL is selected or requested.

The v2 outer bound is 40 MiB, derived from the existing 6 MiB release-metadata
bound plus 32 bounded root-update envelopes and canonical JSON/base64url
overhead. Actual normal chains should be far smaller. The client still does
not follow redirects, use proxy environment variables, accept credentials,
or trust TLS as release authority.

An existing v1 online bundle is parsed as an empty root chain and remains
usable only under the epoch-1 compatibility rule. New publication tooling
emits v2.

The online flow becomes:

1. record the fixed update-start time;
2. fetch and strictly decode the bounded bundle;
3. load and replay compiled plus persisted root trust;
4. authenticate and persist each sequential root update;
5. require the final root to be current and unexpired;
6. authenticate the exact channel and release metadata under its release role;
7. request the single artifact selected by that authenticated release;
8. verify artifact bytes and materialize the private offline snapshot;
9. re-load current root and installer state at the privileged transaction
   boundary;
10. re-authenticate unless resuming an exact fsynced decision, then execute the
    existing transaction.

No artifact request occurs before steps 3 through 6 succeed.

## Release tooling and operator workflow

`mesh-release` gains deterministic commands for the following operations:

```text
mesh-release create-root
mesh-release assemble-root-update
mesh-release inspect-root
```

`create-root` creates one canonical root document and never overwrites output.
For version 1 it requires explicit root-role and release-role public keys. For
later versions it also requires the previous root, derives the exact next
version, enforces all monotonic transition rules, and refuses ambiguous role
membership.

Existing `mesh-release sign` recognizes root manifests and produces the same
one-signature-per-file detached envelope with manifest type `root`. It never
decides whether the key is authorized; authorization is a verifier decision.

`assemble-root-update` accepts the previous root, new root, and repeated
detached signatures. It validates the exact dual-threshold transition before
creating the canonical unsigned envelope. The previous root is validation
context and is not copied into the update.

`installer-policy` is retained as the bootstrap-frame command but takes the
canonical version-1 root rather than an arbitrary release-key list. It prints
only the framed public bootstrap value.

Release and channel manifest generation emits v2 and binds a positive release
epoch. Tooling takes the current root as context and derives channel, epoch,
release threshold, sequence floor, and security-floor constraints rather than
allowing contradictory manual values.

Online-bundle and offline-snapshot assembly accept repeated root-update files,
sort them by decoded root version, reject duplicate versions or bytes, validate
one contiguous chain, and carry exact update bytes. They remain non-authorities:
assembly does not make an untrusted previous root trusted.

A normal release-key rotation is:

1. generate new release keys on independently controlled secured POSIX hosts;
2. create root `N+1` with the new release role and epoch `E+1`;
3. have the old root threshold and new root threshold sign exact root `N+1`;
4. assemble and independently verify the root-update envelope;
5. create epoch `E+1` channel and release manifests;
6. sign both manifests with the new release threshold;
7. assemble online and offline inputs carrying the contiguous root chain;
8. publish immutable artifacts, root updates, release metadata, and bundle;
9. switch the stable channel only after independent readback verification.

Revoking a compromised release key follows the same sequence and omits that
key from the new release role. Rotating only root keys keeps the release epoch
unchanged and requires no release re-signing, though the final root still must
be unexpired.

## Concurrency and transaction behavior

Root-history mutation is serialized by a dedicated root-store lock. The
existing installer operation lock continues to serialize release-state and
managed-runtime changes. Locks have one documented order whenever both are
needed: root store first, installer operation second. No network request or
service operation occurs while the root-store lock is held.

Online preflight may persist roots, release the root lock, and download an
artifact. The privileged verification pass later reacquires trust, so a root
advanced by another process can revoke the preflight signer and reject the
stale candidate safely. Installer state is unchanged by that rejection.

An already prepared v3 transaction is an exact persisted trust decision.
Recovery uses its bound historical root and exact digests; new candidates use
only the latest root. Root advancement never rewrites pending state, active
links, service intent, or runtime gates.

## Compatibility

- Existing public/private key file and detached-signature envelope schemas are
  retained; `root` is a new signature manifest type.
- Existing channel/release v1 manifests, online-bundle v1, and offline-snapshot
  v1 have the narrow epoch-1 compatibility path described above.
- Newly generated channel, release, online, and snapshot data uses v2.
- Existing artifacts, Linux bundle, package metadata, build identity, agent
  state, enrollment, service units, rollback, recovery, and telemetry schemas
  do not change.
- Installer state migrates from v2 to v3 only through the exact legacy-policy
  bridge and only without a pending transaction.
- The control plane continues to publish only an informational bundle URL. It
  neither serves root keys nor claims that the configured URL is trusted.
- Old installers ignore no new security data: they reject unknown v2 schemas.
  Operators must not switch a stable channel to v2 until the authenticated
  bootstrap installer has been distributed.

## Verification plan

Implementation is test-driven. Required proof includes:

### Root model and cryptography

- canonical schema, exact fields, UTF-8/surrogate/duplicate/unknown/trailing
  JSON rejection, 64 KiB bound, timestamp and 366-day validity rules;
- key-ID derivation, strict sorting, exact union, disjoint roles, threshold
  bounds, duplicate keys, unreferenced keys, and caller-mutation isolation;
- root signature domain separation from channel and release signatures;
- old threshold failure, new threshold failure, retained-key dual counting,
  duplicate vote rejection, release-key rejection, malformed/unknown signature
  tolerance, and exact-byte mutation failure;
- version gap, overflow, channel change, floor decrease, epoch decrease/jump,
  sequence-floor decrease, and release-role change without epoch advance;
- expired intermediate catch-up and expired final-root rejection at one fixed
  update time.

### Root update, tooling, and persistence

- canonical base64url root-update round trip, counts, bytes, duplicate
  signatures, and 1 MiB bound;
- deterministic root and update output independent of flag order;
- private-key ownership/mode regression and create-only publication;
- symlink, directory, FIFO, device, hard-link, mutation, truncation, growth,
  collision, readback, file-sync, and directory-sync failure cases;
- create-only root history, exact idempotence, same-version equivocation,
  unknown entry, gap, malformed filename, interrupted temporary, and replay of
  every persisted transition from the compiled root;
- concurrent writers proving one contiguous accepted chain and no overwrite.

### Release epochs and installer state

- v2 channel/release exact parsing and epoch equality;
- v1 acceptance only under untouched initial epoch-1 root;
- lexicographic epoch/sequence replay, reset, same-sequence exact retry, and
  cross-epoch equivocation cases;
- effective sequence/security floor calculations and unsupported semantics;
- v2-to-v3 migration success only for an exact legacy policy and rejection for
  mismatch, existing root history, or pending transaction;
- root version/digest binding on high-water, active, previous, pending,
  rollback, recovery, and exact resume;
- later revocation rejecting a downloaded but unprepared candidate while an
  already fsynced exact candidate remains recoverable.

### Offline and online carriage

- v2 snapshot and online schemas, deterministic ordering, empty chain, 32-entry
  and outer-size bounds, duplicate versions/bytes, gaps, and exact readback;
- v1 empty-chain compatibility and rejection after root advancement;
- no artifact request before the entire supplied root chain, final expiry, and
  release-role verification succeed;
- successful roots remaining persisted after invalid release metadata,
  artifact failure, cancellation, or activation rollback;
- state/root advancement races between preflight and privileged verification;
- existing redirect, proxy, cookie, compression, timeout, size, digest,
  cleanup, and offline compatibility proofs.

### Real Linux proof

Extend the systemd container smoke to use independently generated root and
release roles and prove:

1. bootstrap install from root version 1, release epoch 1;
2. ordinary epoch-1 upgrade;
3. root-only key rotation with dual old/new threshold;
4. release-key rotation to epoch 2 with sequence reset;
5. explicit revocation of one old release key;
6. rejection of releases signed by the revoked key or old epoch;
7. catch-up across multiple sequential roots, including an expired
   intermediate root;
8. rejection of a version gap, root rollback/equivocation, insufficient old
   threshold, insufficient new threshold, expired final root, and role overlap;
9. online and offline carriage of the same chain and exact release bytes;
10. crash after one root-history publication, safe restart, and idempotent
    continuation;
11. v2 state migration without managed-runtime change;
12. activation, rollback, recovery, service intent, state compatibility,
    runtime gates, and cleanup remaining correct.

The full Go suite, targeted race tests, `go vet`, Node browser tests, shell
syntax checks, Linux architecture builds, non-Linux fail-closed builds, binary
frame inspection, privacy searches, and temporary-resource cleanup audit must
pass before this slice is described as complete.

## Acceptance criteria

This slice is complete only when:

1. A separately authenticated installer rooted at version 1 can reach and
   durably replay a contiguous multi-version root chain.
2. Every accepted transition satisfies both predecessor and new root
   thresholds over the exact candidate bytes.
3. Root and release keys are structurally disjoint and cryptographically
   limited to their roles.
4. A release-key rotation or revocation advances the release epoch, after
   which old-epoch and revoked-key metadata cannot authorize new installation.
5. Expired final roots, rollback, gaps, equivocation, role overlap, lowered
   floors, and invalid thresholds fail before artifact retrieval or installer
   state change.
6. Each accepted root survives power-loss boundaries as one create-only,
   fsynced, re-verifiable history entry.
7. Both online and offline installers carry and apply the same exact root chain
   before entering the unchanged authenticated artifact and transaction
   boundary.
8. A valid root revocation remains durable even when the associated release or
   installation fails.
9. Existing pre-release state migrates only through the exact epoch-1 policy
   bridge, and crash recovery remains possible after later root rotation.
10. The real Linux smoke proves first install, rotation, revocation, catch-up,
    upgrade, rollback, recovery, and cleanup using production binaries and
    filesystem semantics.

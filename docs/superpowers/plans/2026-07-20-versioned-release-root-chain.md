# Versioned Release Root Chain Implementation Plan

> Execute this plan in order. Every production change starts with a focused
> failing test, and every completed task leaves its package tests green.

**Goal:** Allow a separately authenticated `mesh-install` bootstrap to rotate
and revoke release-signing keys through a bounded, expiring, dual-threshold,
crash-durable root chain carried by both online bundles and offline snapshots.

**Architecture:** `internal/release` owns canonical root documents, root-update
envelopes, exact-byte signatures, dual-threshold transition verification, and
release-epoch manifests. `internal/installtrust` owns the immutable compiled
version-1 root. `internal/linuxinstall` owns root-history persistence,
state migration, candidate binding, and transaction integration. Existing
online/offline transport remains a courier and the existing privileged
installer transaction remains the only runtime mutation boundary.

**Tech stack:** Go standard library, Ed25519, strict JSON, root-anchored Linux
filesystem operations, existing deterministic release tooling, Node browser
tests, shell/systemd container smoke.

**Design:**
`docs/superpowers/specs/2026-07-20-versioned-release-root-chain-design.md`

## File map

New production files:

- `internal/release/root.go` — root model, canonical encoding, transition
  semantics, dual-threshold verification.
- `internal/release/root_update.go` — bounded canonical root-update transport.
- `internal/linuxinstall/root_store.go` — append-only accepted-root history.
- `internal/linuxinstall/root_store_platform_unix.go` — ownership/link metadata
  and durable directory sync helpers.
- `internal/linuxinstall/root_store_rename_linux_amd64.go` and architecture
  peers — no-replace history publication.
- `cmd/mesh-release/root_commands.go` — create, inspect, and assemble commands.

Primary modified files:

- `internal/release/model.go`, `verify.go`, `release_test.go`
- `internal/installtrust/policy.go`, `policy_test.go`
- `internal/linuxinstall/state.go`, `store.go`, `verify.go`, `metadata.go`,
  `online.go`, `online_intake.go`, and tests
- `internal/onlinerelease/bundle.go` and tests
- `cmd/mesh-release/main.go`, manifest/bundle/snapshot assembly, and tests
- `internal/linuxbundle/model.go`, `binary.go`, and tests
- `cmd/mesh-install/main.go` and tests
- `docs/release-trust.md`, `README.md`, and smoke scripts

## Task 1: Add the strict canonical release-root model

- [x] Add failing tests in `internal/release/root_test.go` for:
  - canonical version-1 root round trip and SHA-256;
  - exact field set and compact-JSON-plus-LF encoding;
  - root and release threshold minimums;
  - derived key IDs, strict key/key-ID ordering, exact key union, and disjoint
    role membership;
  - positive version, epoch, sequence floor, and security floor;
  - canonical timestamps, future/expiry ordering, and 366-day maximum;
  - malformed UTF-8, unpaired surrogates, duplicate/unknown fields, trailing
    values, caller mutation, and the 64 KiB limit.
- [x] Run `go test ./internal/release -run 'TestRoot'` and confirm the new tests
  fail because the root API does not exist.
- [x] Implement `Root`, `RootRole`, `ParsedRoot`, `EncodeRoot`, and `ParseRoot`
  in `internal/release/root.go`, reusing existing strict JSON and key parsing.
- [x] Keep all returned public keys and role slices defensive copies.
- [x] Run the focused root tests and the complete release package.

## Task 2: Extend exact-byte signatures with the root domain

- [x] Add failing tests proving root signatures:
  - use manifest type `root`;
  - cannot verify as channel/release signatures and vice versa;
  - bind every exact root byte;
  - retain envelope size, key-ID, signature-encoding, and duplicate-vote rules.
- [x] Extend `ManifestKind`, `declaredManifestKind`, `SignManifest`, envelope
  parsing, and signature vote helpers without allowing root input through
  ordinary release semantic verification.
- [x] Extract a bounded role-signature counter usable by both release and root
  verification while preserving the existing invalid-extra behavior.
- [x] Run `go test ./internal/release`.

## Task 3: Verify dual-threshold root transitions

- [x] Add failing tests for exact `N+1`, old threshold, new threshold, retained
  key dual counting, wrong-role signatures, version overflow, channel changes,
  security-floor decreases, epoch decrease/jump, same-epoch role changes,
  sequence-floor decreases, and valid root-only/release-role rotations.
- [x] Implement `VerifyRootTransition(previous, candidateRaw, signatures)`.
- [x] Return the parsed candidate, root digest, old/new signer IDs, and release
  role as defensive copies.
- [x] Add fixed-time final-root validation with expired intermediate support.
- [x] Run root-transition tests, then `go test ./internal/release`.

## Task 4: Add the canonical root-update envelope and chain evaluator

- [x] Add failing tests in `internal/release/root_update_test.go` for canonical
  base64url, exact round trip, duplicate signatures, 1 MiB bound, signature
  count, caller mutation, ordered versions, old-prefix handling, same-version
  equivocation, gaps, 32-update bound, expired catch-up, and final expiry.
- [x] Implement `RootUpdate`, `EncodeRootUpdate`, `ParseRootUpdate`, and a chain
  evaluator that emits one verified transition at a time.
- [x] Ensure evaluation has no persistence or network side effects.
- [x] Run `go test ./internal/release` and `go test -race ./internal/release`.

## Task 5: Add release epoch v2 manifests

- [x] Add failing tests for v2 channel/release parsing, exact epoch equality,
  root-epoch mismatch, lexicographic replay floors, sequence reset, and v1
  epoch-1 compatibility restrictions.
- [x] Add v2 schemas and `ReleaseEpoch` fields without weakening v1 parsing.
- [x] Extend `VerificationPolicy` with expected/minimum release epoch and make
  `VerifyChannelRelease` bind channel/release epochs.
- [x] Keep v1 behavior unchanged unless the caller explicitly enables the
  initial-root epoch-1 bridge.
- [x] Run `go test ./internal/release`.

## Task 6: Replace the compiled static policy with a versioned-root bootstrap

- [x] Add failing `internal/installtrust` tests for the v2 frame, version-1 and
  epoch-1 requirements, initial-root digest, derived legacy-policy digest,
  exact release-role equivalence, development sentinel, strict framing,
  canonical payload, size bounds, and caller mutation.
- [x] Implement the v2 encoded bootstrap while retaining a parser for the
  legacy v1 policy only to derive and test migration compatibility.
- [x] Change `Policy`/`PolicySpec` call sites to `Bootstrap`/`BootstrapSpec` or
  an equally explicit root-owned API.
- [x] Extend binary inspection to find exactly one v2 frame and reject stale or
  duplicate installer trust frames.
- [x] Run `go test ./internal/installtrust ./internal/linuxbundle`.

## Task 7: Add root lifecycle commands to `mesh-release`

- [x] Add failing CLI tests for `create-root`, `inspect-root`, and
  `assemble-root-update`, including argument errors, deterministic output,
  create-only publication, dual-threshold verification, and no private bytes
  on stdout/stderr.
- [x] Add commands in `cmd/mesh-release/root_commands.go` and usage dispatch.
- [x] Reuse stable no-follow reads, mutation checks, exact readback, and parent
  fsync helpers from existing manifest/publication commands.
- [x] Extend `sign` to recognize root documents while leaving authorization to
  transition verification.
- [x] Change `installer-policy` to accept a canonical version-1 root.
- [x] Run `go test ./cmd/mesh-release` plus Windows fail-closed private-key
  cross-tests.

## Task 8: Generate epoch-aware release metadata from a current root

- [x] Add failing manifest-generation tests that require root context, derive
  channel/epoch/floors, reject release-role inconsistencies, and emit
  deterministic v2 manifests.
- [x] Update release and channel manifest generators to emit the v2 schemas.
- [x] Preserve a narrowly named legacy test helper rather than a production
  flag that can silently emit v1.
- [x] Update command help and examples.
- [x] Run `go test ./cmd/mesh-release ./internal/release`.

## Task 9: Build crash-durable accepted-root history

- [x] Add `internal/linuxinstall/root_store_test.go` failing tests for:
  - an empty store deriving the compiled root;
  - exact sequential publication and full replay on restart;
  - mode `0700` directories and mode `0400` root-owned single-link files;
  - symlink, FIFO, directory, hard-link, special-bit, wrong-owner, mutation,
    replacement, truncation, growth, unknown entry, malformed name, and gap;
  - exact idempotence and same-version equivocation;
  - write, file-sync, readback, no-replace rename, and directory-sync failures;
  - recognized temporary cleanup and unknown-entry refusal;
  - concurrent writers producing one contiguous chain.
- [x] Implement `root_store.go` using anchored `os.Root` operations and a
  dedicated nonblocking process lock.
- [x] Add architecture-specific no-replace publication matching current Linux
  support; non-Linux code must fail closed.
- [x] Run focused tests, `go test -race ./internal/linuxinstall -run RootStore`,
  and the whole Linux installer package.

## Task 10: Advance installer state to v3 with an exact migration bridge

- [x] Add failing state tests for root version/digest and epoch binding,
  lexicographic high-water rules, same-epoch equivocation, epoch reset,
  active/previous/pending validation, rollback, and exact resume.
- [x] Add migration tests for exact legacy-policy success and mismatch,
  preexisting root history, pending transaction, malformed v2 state, and
  crash-safe v3 publication.
- [x] Add `ReleaseEpoch`, `TrustedRootVersion`, and `TrustedRootSHA256` to every
  release identity and change state schema to v3.
- [x] Implement a one-time v2 decoder/migrator that accepts no pending
  transaction and never guesses trust identity.
- [x] Update fixtures and run `go test ./internal/linuxinstall`.

## Task 11: Verify release candidates under the latest trusted root

- [x] Replace static-policy verifier tests with root-aware cases for root
  release delegation, v2 epochs, effective sequence/security floors, v1 bridge,
  revoked keys, and root changes between passes.
- [x] Add exact-resume tests using the historical root bound in v3 state.
- [x] Change production verification to load the compiled bootstrap, replay
  persisted roots, require final-root validity, and use only its release role.
- [x] Bind candidate metadata and final release identity to root version/digest
  and epoch.
- [x] Run `go test -race ./internal/linuxinstall -run 'Verify|Candidate|State'`.

## Task 12: Carry root updates in offline snapshots

- [x] Add failing descriptor/open tests for v2 `root_updates`, deterministic
  names/order, empty list, duplicates, gaps, exact allowed tree, bounds,
  mutation, and v1 empty-chain compatibility.
- [x] Update `InstallSnapshotDescriptor`, snapshot opening, and materialization
  to return exact root-update bytes with signed metadata.
- [x] Update `mesh-release assemble-snapshot` stable input handling and private
  output proofs for repeated root updates.
- [x] Apply/persist the chain before offline release verification.
- [x] Run `go test ./internal/linuxinstall ./cmd/mesh-release`.

## Task 13: Carry root updates in online bundles

- [x] Add failing `internal/onlinerelease` tests for v2 schema, canonical exact
  root-update bytes, empty list, duplicate bytes/versions, 32-entry and 40 MiB
  bounds, caller mutation, and v1 compatibility.
- [x] Update bundle encode/parse/clone and response-size handling.
- [x] Update online assembly to accept stable repeated root-update files and
  validate a contiguous chain before create-only publication.
- [x] Run `go test ./internal/onlinerelease ./cmd/mesh-release`.

## Task 14: Integrate online root advancement before artifact retrieval

- [x] Add failing trace tests proving the exact order: fixed time, fetch
  bundle, load trust, persist every root, validate final expiry, verify release,
  then fetch artifact.
- [x] Prove insufficient thresholds, gaps, equivocation, expired final root,
  revoked signer, wrong epoch, or root-store failure performs no artifact
  request and no installer-state/runtime mutation.
- [x] Prove valid roots remain persisted after later metadata, artifact,
  cancellation, materialization, or activation failure.
- [x] Reverify under the latest root at the privileged apply boundary and reject
  a preflight signer revoked during download.
- [x] Run `go test -race ./internal/linuxinstall -run Online`.

## Task 15: Preserve package and binary trust identity

- [x] Update Linux bundle/package tests so `mesh-install` carries exactly one
  v2 bootstrap frame and `meshctl` carries none.
- [x] Bind the bootstrap-root digest into package metadata anywhere the legacy
  policy digest is currently bound, without allowing package metadata to
  replace compiled trust.
- [x] Update staging, package comparison, binary inspection, and installed
  release identity.
- [x] Run `go test ./internal/linuxbundle ./cmd/mesh-package ./cmd/mesh-install`.

## Task 16: Update operator documentation and UI wording

- [x] Update `docs/release-trust.md` with initial root creation, separate key
  custody, dual signing, release rotation/revocation, expiry, epoch reset,
  online/offline chain publication, failure recovery, and bootstrap compromise.
- [x] Update `README.md` and CLI usage examples to v2 commands.
- [x] Ensure the web install guide still describes bootstrap authentication
  accurately and makes no claim that the URL or control plane supplies trust.
- [x] Run documentation command searches and browser regression tests.

## Task 17: Extend the real Linux/systemd rotation smoke

- [x] Generate independent old/new root and release roles with production
  tooling inside the smoke environment.
- [x] Prove first install, same-epoch upgrade, root-only rotation, epoch-2
  release-key rotation with sequence reset, revoked-key rejection, multi-root
  catch-up, and expired intermediate handling.
- [x] Add negative cases for gaps, rollback/equivocation, insufficient old/new
  threshold, expired final root, role overlap, old epoch, and revoked keys.
- [x] Prove both online and offline chains, v2 state migration, activation,
  rollback, recovery, state race rejection, service provenance, runtime gates,
  and exact cleanup.
- [x] Restore every host/container resource even after failure.

## Task 18: Complete regression and release-quality verification

- [x] Run `gofmt` on all changed Go files.
- [x] Run `go test ./...`.
- [x] Run targeted race suites for release, root store, verifier, online, state,
  and transaction packages.
- [x] Run `go vet ./...`.
- [x] Run Node browser tests and shell syntax checks.
- [x] Cross-build supported Linux architectures and fail-closed non-Linux
  release/private-operation paths.
- [x] Inspect production binaries for exactly one canonical bootstrap frame and
  no private-key material.
- [x] Run the complete live systemd smoke and record its final PASS line.
- [x] Audit and remove preview/smoke processes, temporary roots, containers,
  mounts, and host setting changes.
- [x] Update every completed checkbox in this plan and the design/operations
  documentation before calling the slice complete.

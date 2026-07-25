# First-installer bootstrap authorization plan

## Task 1: Define the non-circular trust boundary

- [x] Require the version-1 root SHA-256 to arrive independently.
- [x] Keep release URLs, TLS, the object store, control plane, and UI outside
  bootstrap authority.
- [x] State that the verifier itself must already be trusted or independently
  authenticated.

## Task 2: Add a canonical root-authorized bootstrap manifest

- [x] Bind exact root, compiled bootstrap, build identity, Go version, platform,
  installer size/SHA-256, and bounded validity.
- [x] Add strict exact-object parsing, canonical compact encoding, and defensive
  verification-time checks.
- [x] Add a distinct bootstrap signature domain and root-threshold evaluation.
- [x] Ensure ordinary release verification cannot treat bootstrap votes as
  channel or release authority.

## Task 3: Add static authoring and verification commands

- [x] Add `mesh-release create-bootstrap-manifest` with create-only publication
  and production ELF/bootstrap inspection.
- [x] Extend `mesh-release sign` to bootstrap manifests.
- [x] Add `mesh-release verify-bootstrap` requiring the independent root digest.
- [x] Return a bounded machine-readable receipt without executing the installer.

## Task 4: Prove negative and live paths

- [x] Unit-test canonical encoding, threshold, role/domain separation, exact-byte
  binding, expiry, ambiguity, and ordinary-release separation.
- [x] Integrate author/sign/verify into the real Linux clean-host smoke.
- [x] Live-prove rejection of release-role signatures, a wrong independent root
  digest, and changed installer bytes before installation.
- [x] Run the complete online/offline systemd regression with exact cleanup.

## Task 5: Document the remaining production ceremony

- [x] Document operator authoring and end-user verification commands.
- [x] Document verifier bootstrap and direct `sha256sum` alternatives honestly.
- [ ] Provision the real immutable artifact origin and at least one independent
  root/installer digest channel.
- [ ] Package or independently authenticate the verifier on supported hosts.
- [ ] Exercise root-custodian signing, publication, revocation response, and
  recovery with production-held keys.

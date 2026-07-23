# Production hardening guide

This guide is the minimum operational baseline for a production-shaped Mesh
deployment. It does not turn the current single-replica Compose proof, rendered
Helm contract, or PostgreSQL preview into supported production HA, and it does
not replace an external security review.

## Release gate

Run from the repository root:

```sh
make security-baseline
make image-security-baseline
make observer-security-baseline
make origin-image-security-baseline
make helm-chart-smoke
# After building the exact candidate control-plane image:
MESH_HELM_SMOKE_IMAGE=registry.example.com/mesh/control-plane@sha256:... make helm-runtime-smoke
# Cluster-admin, self-cleaning RKE2 mechanism proof using a matching fresh
# image-security receipt and a proof-owned node-local PV:
MESH_HELM_KUBERNETES_IMAGE=mesh-control-plane:helm-contract-verified make helm-kubernetes-smoke
# Repeat for each exact Linux amd64/arm64 candidate:
make linux-package-security-baseline BUNDLE=/absolute/path/mesh-linux-bundle.tar
# Repeat for each exact Windows amd64/arm64 staging candidate:
make windows-package-security-baseline BUNDLE=/absolute/path/mesh-windows-bundle.tar
# Repeat for each exact Darwin amd64/arm64 staging candidate:
make darwin-package-security-baseline BUNDLE=/absolute/path/mesh-darwin-bundle.tar
```

The source gate resolves exactly Go 1.26.5, verifies every module checksum, runs the
complete Go tests and vet, installs `govulncheck` v1.6.0 through the Go checksum
database, and checks reachable source symbols against the current Go
vulnerability database. It then runs Gitleaks v8.30.1 from a digest-pinned
container with no network, a read-only filesystem, no capabilities, bounded
memory/PIDs, redacted output, and the generated `bin/` directory hidden.

The separate [control-plane image gate](image-security.md) freezes the exact
Linux amd64 Docker image ID, verifies its complete scratch filesystem, generates
bound Syft and SPDX inventories, and applies current Grype component policy plus
final-rootfs and binary-string Gitleaks scans. Retain its create-only evidence
with the release. The [observer artifact gate](observer-security.md) separately
reproducibly authenticates both Linux architectures, rejects reachable findings
in the exact patched source, binds per-architecture Syft/SPDX and current Grype
evidence, and secret-scans all four executables. Retain both create-only
receipts. The [release-origin image gate](origin-image-security.md)
independently freezes the exact Linux amd64 courier Docker ID, validates its
18-path scratch filesystem and five-package Syft inventory, and applies the
same fail-closed component and secret policy. Retain its complete create-only
evidence and pass its receipt, together with the registry-signature receipt, to
`mesh-origin-runtime-verify`; the v2 result must bind both receipt hashes and
the running local Docker ID before cutover. The [Linux node-package
gate](linux-package-security.md) then verifies each final bundle-v3 archive,
all four executables and shipped service/text assets, exact 59/60-package
Syft/SPDX inventories, current Grype policy, and empty secret reports. Release
manifest creation requires its matching receipt for every Linux artifact.
The [final signed Windows bundle gate](windows-package-security.md) independently
reconstructs each current bundle-v3 archive, verifies the source-built patched
Nebula runtime plus exact upstream Wintun provenance, binds the exact
8-file/9-directory tree and 59/60-package inventories, and applies the same
fail-closed vulnerability and secret policies. Release creation requires both
the matching package-security receipt and fresh native Authenticode receipt per
Windows artifact. This does not cover a native Windows installer, DACLs,
service integration, or an installed host;
the [Darwin staging-bundle gate](darwin-package-security.md) independently
reconstructs each bundle-v1 archive, verifies the source-built patched thin
Mach-O runtime plus reviewed launchd assets, binds the exact 7-file/9-directory
tree and 52/53-package inventories, and applies the same fail-closed scanner
policies. Release creation requires one matching receipt per Darwin artifact.
Native macOS installation, launchd activation, extended-ACL enforcement,
codesigning/notarization, and installed-host validation remain separate work.
The cross-built [Darwin path-security and supervised-child adapter](darwin-path-security.md)
now implements the intended fail-closed descriptor/ACL, persistent-gate,
direct-child, identity/argv proof, and teardown mechanisms. Only portable tests
and Mach-O builds have run; a real Mac must execute the native syscall,
process, signal, orphan, reboot, and race matrix before installer work can rely
on them. `make darwin-native-runtime-smoke` packages the first self-cleaning,
root-only native subset and publishes canonical v3 hash-bound local evidence
with a strict full-system verifier, but it has not
run on this Linux host and does not install launchd or cover reboot, signing,
upgrade, rollback, packet, or adversarial race cases. The installer-owned
persistent-gate mutation, exact-plist replacement, publication/activation
journal, and same-lock high-water/active/previous state now have portable crash-order fault injection and both Darwin
cross-builds. The fixed system-domain controller now proves service state only
through successful gate-closed bootout/bootstrap mutations and never parses
launchctl's non-API status output. Native execution of that controller and real
system-domain activation remain mandatory. Compiled-root metadata intake,
create-only trusted-root persistence, bounded online artifact capture,
root-private offline snapshot assembly/import, deterministic intake-stage
recovery, and journaled rollback are implemented but still require clean-host
native proof. The offline snapshot reader accepts only an exact physical
root:wheel private tree and authenticates its artifact exclusively through the
signed release metadata before immutable capture.
The native harness now has a second explicit gate for a proof-only system
launchd label and exact `/Library/LaunchDaemons` fixture. Its v2 receipt binds
the gate, label, scanned bundle digest, host facts, and transcript. Passing
receipts from clean Intel and Apple Silicon Macs are still required; a portable
cross-build is not native launchd evidence.

The separate cross-built [Windows path-security and service lifecycle](windows-path-security.md)
foundation now defines exact file and SCM-object DACLs, no-reparse path walks,
stable single-link candidate intake, protected immutable extraction,
write-through no-replace publication/recovery, full-artifact current selection,
a persistent runtime gate, crash-recoverable activation journal, exact
LocalSystem service configuration, and suspended Job Object containment. Its
production authority path now binds compiled trust/build identity to exact
threshold-signed online bytes, append-only root history, durable anti-rollback
high water, accepted-intake handoff, exact root-private offline intake, bounded signed-artifact capture, and authority-bound activation
or rollback finalization plus deterministic stage recovery under one cross-process lock. A separate Windows-only privileged command now exposes canonical online/offline install, exact private snapshot preparation, recovery, post-enrollment runtime activation, exact persisted-previous rollback, and an adjacent-phase `uninstall-runtime` that retains release/enrollment/trust/high-water authority. Direct-root bootstrap manifests plus deterministic Windows verifier USTARs and the four-package v2 handoff/anchor authorize, select, and statically inspect exact amd64/arm64 verifier and installer PEs. Role-separated Authenticode policy continuity, signed-v3 bundle authoring, dual-receipt release preflight, native activation checks, and response-loss-safe NRPT split DNS are implemented; clean-host verifier, uninstall, resolver, and lifecycle receipts remain outstanding. Its elevated native harness has not
run on a clean Windows
`amd64` or `arm64` host, so these mechanisms do not change the staging gate's
scope or establish a supported Windows installer, service, or installed-host
claim. Retain a passing bundle-hash-bound native receipt for each architecture
before any release checklist treats those mechanisms as native evidence.

The gate needs network access to download a missing Go toolchain/module and to
query the vulnerability database. It needs a working Docker daemon to obtain
the digest-pinned scanner image. Treat network or scanner unavailability as a
failed release gate, not as a clean result. The vulnerability result is valid
only for the database state at scan time. The source secret scan covers the
current tree; both image gates cover their exact final filesystem projections.
None covers repository history, runtime volumes, crash dumps,
external deployment stores, registry metadata, or running-container state.

Do not add path-wide secret exceptions. The narrow inline exceptions currently
identify deterministic test keys, format sentinels, or values generated only
during a test. Review any new `gitleaks:allow` line as a security-sensitive code
change. Scanner logs must remain fully redacted.

## Control-plane host

- Use a dedicated, supported Linux host with automatic security updates,
  synchronized time, encrypted storage, restricted console/root access, and no
  unrelated workloads.
- Build and run with the exact patched toolchain declared in `go.mod`; rebuild
  all static binaries and images after a toolchain or dependency security
  update. Never reuse binaries produced by an older toolchain merely because
  source tests pass.
- Prefer the digest-only, read-only, capability-free container mechanism in
  `packaging/compose`. Keep the Docker daemon/socket and deployment account out
  of the Mesh container.
- Expose only the authenticated HTTPS listener through a trusted edge. Reject
  plaintext, unexpected hostnames/origins, direct database access, and public
  access to node-private observer sockets or state directories.
- Disable core dumps for Mesh, the database client, and managed agents. Restrict
  process inspection and diagnostic collection to the service account.

## Keys and credentials

- Generate independent high-entropy Mesh master, administrator, backup, OIDC,
  database, release-root, release, and image-signing credentials. Never reuse a
  secret between roles or environments.
- Supply credentials only through the documented owner-controlled regular files
  and exact CLI mechanisms. Do not put them in arguments, environment dumps,
  Compose files, image layers, shell history, logs, tickets, or scanner output.
- Keep encrypted archives and their backup keys in different access and failure
  domains. Maintain a separately protected monotonic recovery-point catalog.
- Use OIDC with enforced MFA for daily access, retain the minimum documented
  one-use break-glass inventory under separate operator custody, and revoke
  unused browser sessions. The offline administrator bearer is emergency
  authority, not a shared daily password.
- Treat CA/signing-key access, database ownership, Docker control, host root,
  backup-key access, and release-root signing as privileged security roles even
  where the current product cannot enforce separation.

## Persistence

- JSON mode is a single-writer deployment. Place control, identity, TLS,
  credential, and runtime-observation files in dedicated mode-private local
  storage with tested disk-full and backup alerts. Never copy one live state
  file independently as a backup.
- PostgreSQL requires the documented migration, import, and runtime roles;
  hostname-verified TLS to every route; private credential files; and a
  read-write authority fence. Do not grant the runtime role DDL, delete, schema
  ownership, broad `pgcrypto`, or document insertion privileges.
- Until the target deployment passes its own sustained failover, PITR, trust,
  secret-lifecycle, monitoring, and crash-collector drills, treat PostgreSQL as
  a preview and keep one explicit recovery authority.
- Monitor storage capacity, file metadata, database readiness, receipt/WAL
  growth, lock waits, backup age, restore tests, and failed exact-document
  validation. A checksum is corruption evidence, not protection from a database
  owner.

## Browser, OIDC, and edge

- Use a dedicated HTTPS origin with a valid hostname certificate. Development
  loopback cookies trust other services on that host and are not a production
  isolation boundary.
- Configure one exact external base URL and exact OIDC issuer/client policy.
  Require PKCE, nonce/state, verified identity selectors, and an MFA ACR/AMR
  claim suitable for the IdP.
- Put distributed connection and authentication limits at a trusted edge for
  multi-replica or internet-facing service. Do not trust arbitrary forwarded
  client-IP headers.
- Apply no-store behavior end to end and prevent proxies, browser extensions,
  session recording, or support tooling from retaining one-time credentials and
  recovery disclosures.

## Managed nodes and network

- Use the packaged supervisor ownership model. Remove competing Nebula
  supervisors and fail-open/PID-only launch paths before calling a node managed.
- Protect node root, its Nebula private key, agent state, recovery journal, and
  installer anti-rollback state. A host-root compromise controls that node and
  its local telemetry.
- Keep the five-minute signed-state freshness gate and a poll interval no more
  than half that bound. Alert on quarantine, stale configuration, certificate
  expiry, credential expiry, failed activation, and inability to prove the
  stopped state.
- Restrict lighthouse, relay, routed-gateway, DNS, and public-UDP exposure to the
  exact signed policy. Readiness is scoped current evidence, not a general SLA.
  Validate external firewalls/NAT, relay capacity, routed failover, and DNS from
  the real production edge.
- Native split DNS is Linux/systemd-resolved only and forwards only the signed
  Mesh suffix. Do not treat it as a recursive resolver or enable equivalent
  behavior on an unproved platform.

## Release and bootstrap

- Publish only content-addressed immutable origin generations and digest-pinned
  container images. Retain create-only publication, image-verification,
  runtime-binding, and external-audit receipts outside the served generation.
- Keep the bootstrap authority anchor off the origin and move it through an
  independently administered channel. Perform threshold signing and recovery
  with separate custodians and recorded procedures.
- Verify the full root chain, release metadata, artifact size/digest, target
  platform, installer state compatibility, and static candidate identity before
  installation. Never weaken a failed verification into an interactive bypass.
- Image signing, registry publication, continuous admission, native package
  signing, and the real multi-custodian ceremony remain required production
  operations; the repository mechanisms alone do not perform them.

## Backup and incident response

- Schedule coordinated encrypted backups, independently authorize recovery
  points, and regularly perform a restore into a new fenced directory or a
  separately isolated database authority.
- For suspected administrator/session theft, revoke sessions and credentials,
  inspect both audit domains, and rotate affected external identity secrets.
- For a node-key compromise, use identity replacement or revocation; agent
  credential recovery is not a private-key remedy.
- For CA/signing-key or control-host compromise, stop writes, preserve evidence,
  isolate the deployment, retire or rebuild affected trust domains, and use only
  an independently authorized recovery point. Ordinary same-key rotation is not
  a CA-compromise ceremony.
- For release-root or bootstrap-authority compromise, halt publication and
  installation, revoke through an independently trusted root path where still
  possible, and do not rely on the compromised origin or registry for recovery
  instructions.
- Keep logs and diagnostics secret-free. Preserve timestamps, version/digest
  identifiers, receipts, audit events, and deployment topology without copying
  raw credentials, private state, or unredacted payloads.

## Release checklist

1. `make security-baseline`, `make image-security-baseline`,
   `make observer-security-baseline`, and `make origin-image-security-baseline`
   pass, and every Linux candidate passes `make linux-package-security-baseline
   BUNDLE=/absolute/candidate.tar`; every Windows staging candidate passes
   `make windows-package-security-baseline BUNDLE=/absolute/candidate.tar`;
   every Darwin staging candidate passes `make
   darwin-package-security-baseline BUNDLE=/absolute/candidate.tar`,
   with current vulnerability data and no unreviewed secret exceptions. Retain
   every bound artifact receipt and never use a test-only unscanned bypass in a
   production manifest.
2. Full race tests, builds, platform compile gates, and every affected real
   lifecycle smoke pass with the release toolchain.
3. The image/package and origin objects are rebuilt, authenticated, immutable,
   and referenced only by digest.
4. Production TLS/OIDC/edge/database readiness and least-privilege checks pass.
5. Backups, recovery-point authorization, alert delivery, and a recent restore
   exercise are verified.
6. Known residual risks from the [threat model](threat-model.md) and
   [roadmap](roadmap.md) are accepted by the accountable operators.

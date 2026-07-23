# Mesh threat model

## Scope and security objective

This threat model covers the Mesh control plane, administrator web UI and CLI,
managed node agent, release and installer path, JSON and PostgreSQL persistence,
runtime-observation plane, and recovery artifacts in this repository. It is a
design and verification baseline, not an external assessment.

Mesh must prevent an unauthenticated party, ordinary Nebula member, compromised
network path, stale client, or compromised release origin from silently gaining
certificate authority, changing signed node policy, reviving a revoked identity,
or converting missing evidence into a positive security claim. It must preserve
recoverable, attributable lifecycle operations when responses are lost.

Mesh does not claim to remain trustworthy after compromise of the control-plane
host, its live master key, the applicable network CA private key, or the root
account on a managed node. Those are explicit authority boundaries.

## Protected assets

- Per-network Nebula CA private keys and configuration-signing private keys.
- The Mesh master key, administrator bearer, OIDC client secret and policy,
  browser-session and CSRF credentials, enrollment and recovery credentials,
  and database credentials.
- Node Nebula private keys and node-agent bearers.
- Authoritative control and identity documents, audit history, revocation
  history, release-root state, installer anti-rollback state, and backup/WAL
  recovery points.
- The integrity and freshness of signed node bundles, installer packages,
  release metadata, runtime ownership, and operator-visible health evidence.
- Availability of the control plane and the managed Nebula process.

## Actors and adversaries

- A network attacker able to observe, delay, replay, redirect, or terminate
  HTTP, DNS, PostgreSQL, release-origin, or Nebula underlay traffic.
- An unauthenticated internet client or malicious authenticated node agent.
- An administrator whose browser, bearer, OIDC session, or workstation is
  stolen.
- A compromised ordinary Nebula member, lighthouse, relay, routed gateway, or
  host root account.
- A compromised release origin, registry, database role, backup store, or
  monitoring/logging system.
- A malicious or mistaken database owner, host administrator, release signer,
  CA custodian, or other privileged insider.
- Resource-exhaustion traffic and malformed persisted or protocol input.

## Trust boundaries and data flow

1. An administrator authenticates to the HTTPS control plane through an opaque
   browser session, OIDC, one-use break-glass recovery, or the offline
   administrator bearer where that mode is permitted.
2. The control plane validates a complete transaction against one stable state,
   persists it before returning success, and signs per-node desired artifacts
   with a network-scoped signing key.
3. A future node performs a token-scoped preflight, generates its private key
   locally, enrolls over HTTPS, pins the Mesh signing key and Nebula CA, and then
   accepts only monotonic signed bundles matching that identity.
4. The managed agent validates and atomically activates bundles, owns the local
   Nebula process under the platform supervisor, and reports authenticated
   lifecycle state. Runtime observations use a distinct nonauthoritative store
   and never advance lifecycle state.
5. JSON storage relies on a dedicated host and private single-writer files.
   PostgreSQL is a separate authority boundary with role-specific credentials,
   TLS, exact-document checksums, and write receipts; a database owner remains
   capable of replacing a self-consistent authority.
6. Release metadata and artifacts are authenticated independently of the
   untrusted origin. The first installer still depends on an independently
   transferred release authority and real custodian operations.
7. Encrypted recovery archives become full control-plane authority when paired
   with their separately held backup key.

## Threat analysis

| ID | Threat | Current control | Residual risk and required boundary |
| --- | --- | --- | --- |
| TM-01 | Control host or live master-key compromise | Network-scoped encrypted keys, private files, non-root production container, and narrow runtime image | Full authority compromise remains possible. Isolate, patch, monitor, and rebuild from independently authorized recovery material. |
| TM-02 | CA or signing-key theft | Keys are encrypted at rest; node private keys never reach Mesh; signed artifacts bind complete identity and configuration | A stolen decrypted CA can issue identities. Offline/subordinate roots and HSM/KMS custody are not implemented. |
| TM-03 | Administrator credential or session theft | Hash-only opaque sessions, CSRF separation, bounded expiry, session revocation, OIDC policy fingerprinting, MFA claim enforcement, and one-use break-glass codes | A valid full administrator session can perform destructive lifecycle actions. Scoped roles and approval rules are not implemented. |
| TM-04 | Enrollment interception or replay | HTTPS, expiring one-time token, atomic claim, local key generation, response-loss replay binding, and post-enrollment signing-key/CA pins | First enrollment is trust on first use over HTTPS. A transport compromise during that exchange can choose the pins. |
| TM-05 | Agent bearer theft or malicious agent report | Hash-only scoped bearer, rotation/recovery generations, monotonic heartbeat sequence, exact desired digest/certificate checks, rate limits, and strict report schemas | A stolen active bearer can deny service and spoof bounded node evidence. It cannot use the Nebula identity without the node private key. |
| TM-06 | Managed-node root compromise | Private node state, immutable bundle staging, signed validation, supervisor ownership, and fail-closed staleness quarantine | Host root controls the node private key, process, and local observer and can spoof that host's operational evidence. This is not remote attestation. |
| TM-07 | Configuration replay, rollback, or equivocation | Monotonic revisions, exact digests, signed envelopes, persisted anti-rollback state, exact retries, and compare-and-commit lifecycle transitions | Availability can still be denied. Hosts outside the packaged ownership model do not inherit the enforcement bound. |
| TM-08 | Revoked identity continues operating | Complete issuance history, blocklist propagation, credential invalidation, signed convergence, and delayed safe archival | An offline or fail-open host cannot be synchronously stopped. Operators must stop unmanaged processes and retain blocklists through authority expiry. |
| TM-09 | Runtime telemetry becomes false health | Separate store/API, exact heartbeat binding, server receive time, aggregate allowlists, config-bound probe transitions, and explicit non-health language | Local root can fabricate observations. Missing, stale, unsupported, or partial evidence must remain unknown and must not trigger destructive automation. |
| TM-10 | Database tampering or ambiguous commit | Exact bounded documents, checksums, immutable receipts, role separation, TLS verification, no transparent callback retry, and readiness fencing | A database owner can replace documents, checksums, receipts, and provenance together. Production HA/PITR authority and monitoring remain deployment obligations. |
| TM-11 | Release-origin or registry compromise | Threshold root/release roles, digest-bound artifacts, root-chain rotation/revocation, immutable origin generations, independent bootstrap authority, an exact origin image security gate, and two-receipt runtime verification | Production image scanning/signing, anchor transfer, key/evidence custody, and continuous admission are operationally unproved. An origin remains untrusted by design. |
| TM-12 | DNS, relay, routed-gateway, or underlay manipulation | Signed topology/policy, exact target recomputation, bounded readiness evidence, split-DNS scoping, and conservative route checks | Evidence is point-in-time and scoped. It is not a general application SLA, recursive DNS guarantee, or proof of future sites and routes. |
| TM-13 | Parser or resource exhaustion | Closed JSON schemas, duplicate/unknown-field rejection, document and collection limits, bounded concurrency/deadlines, and pre-authentication budgets | Internet-facing HA still requires a trusted edge with distributed limits. Sustained load, receipt retention, and production observability remain unproved. |
| TM-14 | Tenant or privilege-boundary confusion | Network-scoped cryptographic authorities and globally validated object references | Mesh is currently one administrative trust domain. Organizations, tenant isolation, scoped service accounts, and approval workflows are not implemented. |
| TM-15 | Backup rollback, loss, or disclosure | Authenticated encrypted archives, separate backup key, create-only publication, restore fencing, and exact verification | Archive plus backup key grants full authority; self-consistent old recovery points require an independently protected monotonic catalog. |
| TM-16 | Secret or vulnerable dependency enters a release | Patched minimum Go toolchain, module checksum verification, tests/vet, reachable-code `govulncheck`, redacted Gitleaks source scanning, bound Syft/SPDX/Grype/Gitleaks gates over the exact Linux amd64 control-plane and release-origin images, both locked Linux observer architectures, each final Linux bundle, and each exact non-installing Windows and Darwin staging bundle; release authoring requires one canonical receipt matching every Linux, Windows, and Darwin artifact, while the v2 origin runtime receipt requires the scanned local Docker identity | Scans are point-in-time. Native macOS installation, launchd activation, extended ACLs, codesigning/notarization, and installed-host state; Windows installer, DACL, service, Authenticode, and installed-host state; other installed hosts; Git history; registry/deployment/runtime stores; external assessment; continuous admission/attestation; and rapid patch operations remain separate obligations. |

## Security invariants

- Successful lifecycle writes are atomic or explicitly reported as uncertain;
  ambiguous requests are retried only through their exact durable binding.
- No node private key crosses the enrollment boundary.
- Agent evidence cannot select its own desired configuration or advance control
  state, and runtime observations cannot become lifecycle health implicitly.
- Missing, malformed, stale, future, partial, duplicated, or unsupported
  evidence never becomes a passing result.
- Private digests, process identities, packet details, raw routes, resolver
  details, and agent errors stay outside aggregate administrator projections.
- Revocation and trust retirement take precedence over stale artifacts and
  credentials; removal is delayed until retained authority is no longer needed.
- The release origin and database are not treated as independent integrity
  anchors.

## Verification and review triggers

Run `make security-baseline`, `make image-security-baseline`,
`make observer-security-baseline`, and `make origin-image-security-baseline`
for every release candidate, and run
`make linux-package-security-baseline BUNDLE=/absolute/candidate.tar` for each
exact Linux artifact before release-manifest creation. Repeat the affected gates
after any Go,
module, authentication, cryptography, parser, storage, release, or secret-flow
change. Run the relevant real lifecycle and platform smoke gates listed in the
[roadmap](roadmap.md) for changes to their boundaries.

Re-review this model when adding a platform, tenant, administrator role,
external signer, HSM/KMS, recursive resolver, automatic telemetry action,
database authority, ingress, release channel, backup authority, or new data in
an API projection. Any new `gitleaks:allow` exception requires line-level human
review proving that the match is a format sentinel, generated-at-test-runtime
value, or deterministic non-production fixture.

Security reports should include the affected version, deployment mode, exact
boundary, reproduction conditions, and whether authority or only availability
is affected. Do not place credentials, private keys, raw state, or unredacted
scanner output in an issue or diagnostic bundle.

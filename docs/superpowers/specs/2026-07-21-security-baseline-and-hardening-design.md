# Security baseline and hardening design

Status: implemented and verified on 2026-07-21

## Outcome

The repository has one fail-closed security target that proves the declared Go
toolchain is patched, module content is intact, the complete Go test and vet
gates pass, reachable dependency vulnerabilities are absent according to the
current Go vulnerability database, and the current source tree contains no
Gitleaks finding. Operators also have one threat model and one production
hardening checklist that state the implemented boundary and residual risks.

This is an internal release baseline. It is not an external security review,
penetration test, image or SBOM scan, repository-history scan, deployment-store
scan, runtime secret scan, or production authorization ceremony.

The separate implemented
`2026-07-21-control-plane-image-security-baseline.md` design now covers the
exact Linux amd64 control-plane image. That later proof does not broaden this
source-gate design or cover the other release and runtime domains listed here.

## Pinned and fail-closed gate

`make security-baseline` executes `scripts/security-baseline.sh` with no
arguments. The script:

- resolves exactly Go 1.26.5 through `GOTOOLCHAIN`, disables Go telemetry and
  workspace inheritance, verifies module checksums, and runs all Go tests and
  vet;
- installs exactly `govulncheck` v1.6.0 into a mode-private temporary directory
  and checks source-reachable symbols against current vulnerability data;
- runs exactly Gitleaks v8.30.1 from a digest-pinned image with the network
  disabled, a read-only root and source mount, an isolated bounded temporary
  filesystem, no Linux capabilities, `no-new-privileges`, a non-root UID/GID,
  and memory/PID bounds;
- rejects source files above the scanner's ten-megabyte limit instead of
  silently skipping them, hides only the generated `bin/` output, limits archive
  and decode recursion, and fully redacts findings; and
- fails on missing tools, unavailable downloads or vulnerability data, version
  mismatch, test/vet failure, a reachable vulnerability, or a secret finding.

The initial gate found reachable standard-library vulnerabilities in Go 1.26.0
and one reachable `golang.org/x/net` vulnerability. The module now declares Go
1.26.5 and `x/net` v0.53.0 or later through the resolved graph. Any future
upgrade must rerun this exact gate and the wider release matrix.

## Exception boundary

The default Gitleaks rules remain enabled. The only exceptions are line-local
`gitleaks:allow` comments for deterministic test keys, public format/schema
sentinels, or private-key material generated only in process during a test.
Every added or changed exception requires line-level human review. Broad source
path exemptions are prohibited; generated `bin/` artifacts are scanned through
the release/image pipeline rather than classified as source.

## Published operational boundary

`docs/threat-model.md` inventories protected assets, adversaries, trust
boundaries, security invariants, implemented controls, residual risks, and
review triggers. `docs/production-hardening.md` turns those boundaries into a
release and deployment checklist covering the host, credentials, persistence,
browser/OIDC edge, managed nodes, release/bootstrap, backup, and incident
response.

Both documents deliberately preserve the current limitations: host/root/key
compromise is an authority compromise, scoped administrator roles and approval
policy are not implemented, PostgreSQL remains a deployment preview until real
environment drills pass, and external review plus penetration testing remain
required.

## Verification

The implemented proof includes the passing security target, rejection of
unexpected target arguments, detection and full redaction of a synthetic
Nebula private-key fixture, the complete Go race suite, strict browser tests,
PostgreSQL-tagged maximum-document tests, Linux builds, Windows and Darwin
compile gates, shell syntax validation, and an unchanged live preview process.

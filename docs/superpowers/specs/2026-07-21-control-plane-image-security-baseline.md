# Control-plane image security baseline design

Status: implemented and verified on 2026-07-21

## Outcome

One no-argument target builds and freezes the Linux amd64 control-plane scratch
image, proves its complete final filesystem, generates mutually consistent
Syft and SPDX inventories, applies current component-level vulnerability
policy, scans final text and binary strings for secrets, and publishes one
create-only evidence set bound to the Docker image ID.

It does not claim image signing, registry publication, SBOM attestation,
runtime admission, other architectures, the release-origin image, node
packages, native OS artifacts, deployment/runtime secret scanning, or external
assessment.

## Trust separation

- Docker builds from a digest-pinned Go 1.26.5 builder and returns one immutable
  local image ID. Archive creation addresses that ID, never the temporary tag.
- A local bounded verifier checks the archive and extracts only the exact final
  files. Scanners never receive a Docker socket.
- Syft, Grype scanning, and both Gitleaks passes have no network, a read-only
  root, no capabilities, `no-new-privileges`, a non-root UID/GID, and explicit
  memory/PID/tmpfs bounds.
- Only Grype's database-update process has network. It sees one initially empty
  private cache and no source, image, SBOM, credentials, or Docker authority.
- Scanner images are release- and digest-pinned; version output must match the
  expected release before the build begins.

## Exact image and SBOM contract

The image must contain exactly three content-addressed layers and 22 known
filesystem entries: the public CA bundle, empty credential/TLS bind targets,
private runtime directories, and exactly `mesh-server`, `mesh-healthcheck`, and
`nebula-cert`. Runtime identity, entrypoint, environment, labels, port,
ownership, modes, types, emptiness, and size bounds are closed contracts.

The Syft 16.1.3 document must bind its image-config digest to the archive,
contain only Go modules located in those binaries, and prove Go 1.26.5, Nebula
v1.10.3, x/crypto v0.53.0, x/net v0.56.0, and x/sys v0.46.0 where applicable. SPDX 2.3 must be
created by the same pinned Syft release and cover every Syft purl.

## Finding policy

The Grype database must be valid schema v6 and at most 72 hours old. High and
Critical findings fail even without a fix; any finding with a published fix
fails at every severity; ignored findings are prohibited. Nonfixed findings
below that boundary remain visible in the full report and receipt. The first
passing run retained only two binary locations for the same severity-Unknown,
nonfixed `GO-2026-5932` advisory.

Gitleaks scans final nonbinary files and `strings -a -n 8` output for all three
binaries. The only exception is the exact public oauth2 v0.36.0 `go.sum`
checksum that the generic API-key rule mistakes for a credential. Reports must
be exact empty arrays.

## Evidence and failure behavior

The final verifier hashes all scanner outputs and writes one canonical
`mesh-image-security-receipt-v1`. Only after every check passes does the shell
create a new digest-and-UTC-named directory under `bin/image-security`; all
artifacts are mode 0400 and the directory is mode 0700. Existing paths are
never replaced, and a failed or interrupted run removes only its own validated
temporary workspace and partial publication.

Implementation discovery itself proved the gate's value: it found an outdated
container Go builder, a separately resolved `nebula-cert` dependency graph,
fixed x/crypto/x/sys component findings, an insufficient database-update memory
bound, and false-positive exception shapes. Each failed closed before evidence
publication; the final run passed only after the shipped graph and exact policy
were corrected.

# Nebula observer artifact security baseline

Mesh's Linux node bundle consumes a source-built Slack Nebula v1.10.3 fork so
the managed agent can read authenticated runtime observations through a
root-private Unix socket. `make observer-security-baseline` is the fail-closed
security gate for the exact `nebula` and `nebula-cert` executables selected by
that embedded build lock on Linux amd64 and arm64.

This is an internal build and scanner baseline, not an external assessment. It
covers the locked observer stage. The separate
[Linux node-package gate](linux-package-security.md) consumes and revalidates
this stage inside each final bundle; release origin, registry, installed host,
runtime state, and macOS remain separate boundaries. The non-installing Windows
staging path reuses the authenticated patched source and security-module floor
but compiles the observer endpoint as a reviewed no-I/O stub, binds exact PE
outputs through a separate layered Windows lock, and applies its own [final
staging-bundle gate](windows-package-security.md). That is not Windows runtime
telemetry or native package coverage. The non-installing Darwin staging path
uses the same authenticated source and no-I/O observer boundary, binds exact
thin Mach-O outputs through its own layered lock, and applies the separate
[Darwin staging-bundle gate](darwin-package-security.md). That is not macOS
runtime telemetry, installation, launchd activation, codesigning, or
notarization coverage.

## Run the gate

Run as the unprivileged Docker build account from the repository root:

```sh
make observer-security-baseline
```

The gate needs the exact Go 1.26.5 toolchain, Slack Nebula v1.10.3 source and
dependencies in the authenticated local module cache, current Go vulnerability
data, and a working Docker daemon. Missing dependencies, scanners, database
updates, or network access needed to refresh current vulnerability data fail
the gate rather than becoming a clean result.

Each successful run creates, without replacement:

```text
bin/observer-security/<observer-policy-sha256>-<UTC>/
```

The directory contains the canonical receipt, patched-source `govulncheck`
result, Grype database status, empty redacted Gitleaks report, and Syft, SPDX,
and Grype documents for both supported architectures. Retain that directory
with release evidence. It contains no private key, credential, source tree, or
executable payload; the receipt binds the exact executable sizes and hashes
already selected by the source-controlled build lock.

## Bound inputs and checks

The gate first invokes the production `mesh-deps build-nebula-observer` path for
both architectures. That builder authenticates the complete cached upstream
tree, ordered patch names and bytes, patched tree, Go toolchain, build flags,
security-sensitive module versions and checksums, ELF/static build identity,
and exact output bytes. It independently builds each executable twice with
clean caches and rejects non-reproducible or unlocked output.

The current patch lock upgrades the upstream dependency graph to:

- `golang.org/x/crypto v0.53.0`;
- `golang.org/x/net v0.56.0`;
- `golang.org/x/sys v0.46.0`; and
- `golang.org/x/term v0.44.0`.

The final binary verifier reads embedded Go build information and requires
those exact versions and Go checksums wherever each module is expected. A
replacement module, missing dependency, older version, different checksum, or
different Go toolchain fails before publication.

`third_party/nebula-windows-runtime/v1.10.3-build.lock.json` separately binds
this base policy digest to reproducible amd64/arm64 Windows PE outputs. It does
not change or broaden the Linux observer lock or this gate's executable set.

The remaining checks are:

1. Reconstruct the exact patch series in a private directory and run pinned
   `govulncheck v1.6.0` over both command graphs. Every reachable finding fails.
2. Generate Syft 1.44.0 schema 16.1.3 and SPDX 2.3 inventories for each exact
   stage in networkless, read-only, non-root containers. The verifier requires
   41 Syft packages, 42 SPDX packages, Go 1.26.5 in both executables, and all
   locked security dependency versions at their expected binary locations.
3. Refresh an isolated Grype v0.112.0 database, require schema v6 and an age no
   greater than 72 hours, then scan both bound SBOMs offline. Any High or
   Critical result, any published fix at any severity, or any ignored match
   fails.
4. Extract printable strings from all four locked executables and scan them with
   digest-pinned Gitleaks v8.30.1. The only configured exception is the exact
   public `golang.org/x/oauth2 v0.36.0` module checksum shared with the
   control-plane image gate; path-wide and unredacted exceptions are forbidden.
5. Validate every report and publish a canonical create-only receipt binding
   policy, source/patch identities, executable hashes, SBOMs, vulnerability
   database, reports, and scanner versions.

Only the Grype database refresh and Go vulnerability/tool installation step has
network access. Artifact and SBOM scans run without a network, Docker socket,
capabilities, writable root filesystem, or root user. Scanner containers have
bounded memory and process counts.

## Findings closed by this baseline

The first source scan found eight reachable `x/crypto/ssh` vulnerabilities in
the upstream v0.47.0 graph through Nebula's embedded SSH server. Upgrading to
v0.52.0 removed every reachable finding. The first component scan then rejected
`GO-2026-5026` in `x/net v0.54.0`; the lock selected the fixed v0.55.0 even
though the affected IDNA symbols were not reachable in the source scan. A later
fresh package scan rejected fix-available `GO-2026-5942` in v0.55.0; the lock
now selects fixed x/net v0.56.0 and the compatible x/crypto, x/sys, and x/term
versions listed above.

The passing receipt retains two binary locations per architecture for
`GO-2026-5932`, currently severity `Unknown` with no published fix. It is not
suppressed. A later database classification or fix will be evaluated on every
new run; the present gate would reject it immediately if it becomes
High/Critical or gains a published fix.

## Residual release work

This gate does not sign the executables or SBOMs, scan the completed native node
package, prove installer/origin content, publish an attestation, enforce
registry admission, inspect repository history, or inspect an installed or
running host. Threshold release signing, native package policy, origin
verification, external review, deployment admission, patch response, and
runtime monitoring remain independent release obligations.

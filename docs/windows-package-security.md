# Final signed Windows bundle security baseline

This gate produces create-only local security evidence for one exact current
`mesh-windows-node-bundle-v3` candidate. It covers the final uncompressed
USTAR, signed production-identity `meshctl.exe`, signed source-authenticated and
security-patched `nebula.exe` and `nebula-cert.exe`, the architecture-selected
locked signed Wintun DLL and notices, the Nebula license, and `package.json`
together.

Portable inspection checks the exact PE envelopes and reconstructs both Nebula
executables to their locked unsigned outputs. Native Windows verification is a
separate required input: `mesh-authenticode-verify` checks all four PEs against
the compiled role-separated certificate policy and emits a fresh canonical
receipt. This gate is not an installer, Windows Service, DACL, or installed-host
claim.

The final artifact is assembled without giving the Linux host signing
authority:

1. Build the reproducible unsigned v2 staging bundle with
   `mesh-package build-windows`.
2. Sign only `meshctl.exe`, `nebula.exe`, and `nebula-cert.exe` with the
   authorized Mesh certificate. The locked upstream Wintun DLL is retained.
3. On Windows, run `mesh-authenticode-verify --arch ... --meshctl ... --nebula
   ... --nebula-cert ... --wintun ...` and retain its canonical receipt.
4. On Linux, run `mesh-package build-windows-signed` with the unsigned v2
   bundle, three signed PEs, native receipt, independently recorded policy
   SHA-256, and a new output path. It reconstructs every replaced PE to the
   exact unsigned member, matches all four final file identities to the fresh
   receipt, and publishes the canonical v3 artifact without replacement. Use
   `mesh-release windows-authenticode-policy --print-sha256` with the same
   reviewed role pins to emit the canonical policy JSON digest without changing
   the default linker-frame output.

Run it separately for every Windows architecture after building the exact
candidate and before creating threshold-signed release metadata:

```sh
make windows-package-security-baseline BUNDLE=/absolute/path/mesh-windows-amd64.tar
make windows-package-security-baseline BUNDLE=/absolute/path/mesh-windows-arm64.tar
```

The path must be clean, absolute, real, and stable. The command accepts one
candidate per run and fails closed on a missing scanner/database, unexpected
archive byte, legacy schema, altered build or dependency identity,
vulnerability-policy failure, or secret finding.

## Production-policy inspection

The gate first builds the current `mesh-package` verifier and invokes its
read-only `inspect-windows` command. The verifier snapshots one bounded,
single-link candidate and requires:

- exact canonical USTAR order, headers, padding, terminator, size, and SHA-256;
- canonical final signed bundle-v3 metadata, Go `1.26.5`, Mesh build identity, target, state
  contract, and security floor;
- exact Slack Nebula `v1.10.3` source, patch-set, security-module, toolchain,
  reproducible-output, and Windows build-lock provenance;
- exact upstream archive provenance only for the selected Wintun DLL and
  notices; and
- one exact DER PKCS#7 certificate-table overlay per PE, with the two signed
  Nebula images reconstructing byte-for-byte to their reviewed output locks;
  and
- an exact sealed 8-file/9-directory staged tree with no links, extra paths,
  writable payloads, or replacement.

The two Nebula PEs are reproducibly built twice from the same authenticated
patched tree used by the Linux observer build. Windows intentionally compiles
the observer endpoint as a reviewed no-I/O stub, so the staging bundle makes no
Windows runtime-telemetry claim. The separate Windows output lock binds both
architectures' exact PE sizes and SHA-256 values without changing the Linux
observer output lock.

Candidate inspection derives fields only for analysis and grants no release
authority. Version, target, floor, and artifact identity still come from
threshold-authenticated release metadata.

## SBOM, vulnerabilities, and secrets

Syft `1.44.0` must report exactly 59 admitted package locations and SPDX `2.3`
exactly 60 package records. The inventory binds every Go package to its exact
PE location, identifies the three Go executables and selected Wintun DLL as
binaries. The locked runtime and Mesh controller require `x/crypto v0.53.0`
and `x/sys v0.46.0`; the runtime also requires fixed `x/net v0.56.0` and
`x/term v0.44.0`, while the Mesh controller requires `x/text v0.39.0`.

Grype `0.112.0` updates only an isolated private database cache, requires a
valid database no more than 72 hours old, and scans the bound SBOM offline.
Every High/Critical match and every match with a published fix is rejected. The
passing bundles retain three locations for the same nonfixed severity-Unknown
`GO-2026-5932` advisory without suppression.

Gitleaks `v8.30.1` scans exact package metadata, Wintun notices, the Nebula
license, and printable strings from `meshctl.exe`, both Nebula PEs, and the
selected Wintun DLL. Both reports must be empty under the one exact public
Go-checksum exception shared with the other artifact gates.

All candidate and scan steps except the database refresh run networkless,
read-only, non-root, capability-free, without a Docker socket, and with bounded
memory and processes.

## Evidence and release binding

Each pass publishes a new mode-private create-only directory:

```text
bin/windows-package-security/<artifact-sha256>-<verification-UTC>/
```

It retains the production-policy inspection, Syft/SPDX inventories, Grype
database/report, both Gitleaks reports, and canonical
`mesh-windows-package-security-receipt-v2`. The receipt binds artifact
size/SHA-256, architecture, version/floor/build identity, runtime and upstream
locks, every shipped file, verifier, scanner versions, isolation boundary,
policies, exact admitted result, and UTC completion time.

Pass both the matching package-security receipt and the fresh native
Authenticode receipt per Windows artifact into release creation:

```sh
mesh-release create-release-manifest \
  --output release.json \
  --root root-v1.json \
  --version 1.2.3 \
  --sequence 42 \
  --security-floor 1 \
  --issued 2026-07-21T16:00:00Z \
  --expires 2026-07-22T16:00:00Z \
  --os windows \
  --arch amd64 \
  --artifact-url https://releases.example/mesh/1.2.3/windows-amd64.tar \
  --artifact /absolute/path/mesh-windows-amd64.tar \
  --windows-package-security-receipt \
    /absolute/evidence/<artifact-sha256>-<UTC>/receipt.json \
  --windows-authenticode-receipt \
    /absolute/evidence/windows-amd64-authenticode.json
```

The release preflight strictly reparses both canonical receipts and requires
its architecture, version, security floor, artifact size, and artifact SHA-256
to equal the selected release artifact. It also requires the receipt to be no
more than 24 hours old with at most five minutes of future clock skew, and
rechecks that the bound Grype database was no more than 72 hours old when the
scan completed. It reopens the exact artifact previously hashed for the
manifest, requires signed bundle-v3, derives all four PE identities, and matches
them to the native receipt under the release binary's compiled Authenticode
policy. Missing, duplicate, noncanonical, stale, future, or mismatched receipts
fail before output creation. The explicit
`--test-only-allow-unscanned-windows-artifact` bypass exists solely for
synthetic fixtures and must never appear in a production signing workflow.

The signed manifest authenticates the artifact itself; the local scanner does
not become a new installer trust root. Retain the full evidence with signing
records in append-only storage.

## Residual risk

This remains point-in-time local pipeline evidence, not remotely attestable
evidence. It does not prove Windows DACLs, service identity or lifecycle,
SCM/Job Object integration, native installation/upgrade/rollback, post-install
state, registry/deployment stores, signed SBOM attestation, continuous
admission, or a running host. The Windows verification host, Linux
build/scanner host, signing operation, and current vulnerability database remain
trust inputs. Repeat native verification and this gate for every changed PE or
candidate and whenever vulnerability data changes before signing.

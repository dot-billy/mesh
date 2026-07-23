# Darwin staging-bundle security baseline

This gate produces create-only local security evidence for one exact current
`mesh-darwin-node-staging-bundle-v1` candidate. It covers the final
uncompressed USTAR, production-identity `meshctl`, source-authenticated and
security-patched `nebula` and `nebula-cert`, the reviewed launchd assets,
Nebula license, and `package.json` together.

This is a Linux-verifiable release-staging boundary. It is not a native macOS
installer, launchd activation, extended-ACL policy, codesigning/notarization
decision, installed-host verification, or lifecycle-support claim.

Run it separately for each architecture after building the exact candidate and
before creating threshold-signed release metadata:

```sh
make darwin-package-security-baseline BUNDLE=/absolute/path/mesh-darwin-amd64.tar
make darwin-package-security-baseline BUNDLE=/absolute/path/mesh-darwin-arm64.tar
```

The candidate path must be clean, absolute, real, and stable. Scanner or
database unavailability, unexpected archive bytes, legacy metadata, altered
build/dependency identity, a vulnerability-policy failure, or a secret finding
fails the run closed.

## Production-policy inspection

The gate builds the current `mesh-package` verifier and invokes its read-only
`inspect-darwin` command. The verifier snapshots one bounded single-link
candidate and requires:

- exact canonical USTAR order, headers, padding, terminator, size, and SHA-256;
- canonical bundle-v1 metadata, Go 1.26.5, Mesh build identity, target,
  agent-state contract, and security floor;
- the exact Slack Nebula v1.10.3 source, ordered security patch set, dependency
  floor, Go toolchain, common source-policy lock, and layered Darwin output lock;
- exact thin 64-bit PIE Mach-O executables for the selected architecture, with
  no executable-stack flag and the expected Go main/build settings;
- the reviewed embedded launchd plist/README and Nebula license; and
- an exact sealed 7-file/9-directory staged tree with no links, extra paths,
  writable payloads, or replacement.

Both Nebula executables are built twice from clean caches and must be
byte-identical to the selected output lock. The patched observer endpoint is a
reviewed no-I/O Darwin stub, so this bundle makes no native telemetry claim.
Candidate inspection derives analysis fields only; release selection and
authority still come from threshold-authenticated metadata.

## SBOM, vulnerabilities, and secrets

Syft 1.44.0 must report exactly 52 admitted Go-package locations and SPDX 2.3
exactly 53 package records. The inventory binds every module to its exact
Mach-O location and requires Go 1.26.5 plus the locked security dependency
versions. The locked runtime and Mesh controller require `x/crypto v0.53.0`
and `x/sys v0.46.0`; the runtime also requires fixed `x/net v0.56.0` and
`x/term v0.44.0`, while Mesh controller locations require `x/text v0.39.0`.

Grype 0.112.0 updates only an isolated private database cache, requires a valid
database no more than 72 hours old, and scans the bound SBOM offline. Every
High/Critical match and every match with a published fix is rejected. The
passing candidates retain three locations for the same nonfixed
severity-Unknown `GO-2026-5932` advisory without suppression.

Gitleaks v8.30.1 scans exact package metadata, launchd assets, the Nebula
license, and printable strings from all three Mach-O executables. Both reports
must be empty under the one exact public Go-checksum exception shared with the
other artifact gates.

All candidate and scan steps except the database refresh run networkless,
read-only, non-root, capability-free, without a Docker socket, and with bounded
memory and processes.

## Evidence and release binding

Each pass publishes a new mode-private create-only directory:

```text
bin/darwin-package-security/<artifact-sha256>-<verification-UTC>/
```

It retains the production inspection, Syft/SPDX inventories, Grype database
status/report, both Gitleaks reports, and canonical
`mesh-darwin-package-security-receipt-v1`. The receipt binds the artifact,
architecture, version/floor/build identity, source/output locks, every shipped
file, verifier/scanner versions, isolation boundary, policies, exact admitted
result, and UTC completion time.

Pass one matching receipt per Darwin artifact into release creation:

```sh
mesh-release create-release-manifest \
  --output release.json \
  --root root-v1.json \
  --version 1.2.3 \
  --sequence 42 \
  --security-floor 1 \
  --issued 2026-07-21T16:00:00Z \
  --expires 2026-07-22T16:00:00Z \
  --os darwin \
  --arch amd64 \
  --artifact-url https://releases.example/mesh/1.2.3/darwin-amd64.tar \
  --artifact /absolute/path/mesh-darwin-amd64.tar \
  --darwin-package-security-receipt \
    /absolute/evidence/<artifact-sha256>-<UTC>/receipt.json
```

Release preflight strictly reparses the full canonical receipt and requires
architecture, version, security floor, artifact size, and SHA-256 to match the
selected artifact. The receipt may be at most 24 hours old and five minutes in
the future; its bound Grype database must have been at most 72 hours old when
verification completed. Missing, duplicate, noncanonical, stale, future, or
mismatched receipts fail before output. The explicit
`--test-only-allow-unscanned-darwin-artifact` bypass exists solely for synthetic
fixtures and must never enter a production signing workflow.

The signed manifest authenticates the artifact; the local scanner is not a new
installer trust root. Preserve the evidence with release records, but do not
describe it as native installation, launchd ownership, ACL enforcement,
codesigning, notarization, runtime telemetry, or installed-host evidence.

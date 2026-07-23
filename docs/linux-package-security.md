# Linux node-package security baseline

This gate produces create-only local security evidence for one exact current
`mesh-linux-node-bundle-v3` candidate. It covers the final uncompressed USTAR,
`mesh-install`, `meshctl`, the locked observer-enabled `nebula` and
`nebula-cert`, all shipped systemd units/drop-ins, operator documentation,
license, and `package.json` together.

Run it separately for every Linux architecture after building the exact
candidate and before creating threshold-signed release metadata:

```sh
make linux-package-security-baseline BUNDLE=/absolute/path/mesh-linux-amd64.tar
make linux-package-security-baseline BUNDLE=/absolute/path/mesh-linux-arm64.tar
```

The path must be clean, absolute, real, and stable. The command accepts one
candidate per run and fails closed on a missing scanner/database, unexpected
package or archive byte, altered build identity, stale dependency, vulnerability
policy failure, or secret finding.

## Production-policy inspection

The gate first builds the current `mesh-package` verifier and invokes its
read-only `inspect-linux` command. That command stably hashes the original
artifact before and after inspection, derives only non-authoritative selection
fields from the candidate, and sends the archive through the same compiled
policy used by installation:

- exact canonical USTAR order, headers, padding, two-block trailer, size, and
  SHA-256;
- canonical bundle-v3 metadata, Go `1.26.5`, build identity, state compatibility,
  security floor, and installer bootstrap-root binding;
- exact locked Slack Nebula `v1.10.3` source/patch/toolchain provenance and
  binary identities;
- byte-exact embedded systemd units, timeout-abort drop-ins, documentation, and
  license; and
- an exact sealed 11-file/12-directory staged tree with no links, extra paths,
  writable payloads, or replacement.

This candidate-derived inspection grants no release authority. The installer
continues to select version, platform, floor, root, and artifact identity only
from threshold-authenticated release metadata.

## SBOM, vulnerabilities, and secrets

Syft `1.44.0` must report exactly 59 admitted Go package locations and SPDX
`2.3` exactly 60 package records across the four executables. The allowlist
requires, among other exact dependencies, Go `1.26.5`; the locked observer and
Mesh controller graphs on `x/crypto v0.53.0`, `x/net v0.56.0`, and
`x/sys v0.46.0`; the observer on `x/term v0.44.0`; and Mesh controller
locations on `x/text v0.39.0`.

Grype `0.112.0` updates only an isolated private database cache, verifies the
database is valid and no more than 72 hours old, and then scans the bound SBOM
offline. Every High/Critical match and every match with a published fix is
rejected. The first complete-bundle run caught `meshctl` carrying
`x/net v0.54.0`: one High and six other fix-available findings. The root module
was upgraded to fixed `v0.55.0`; the root graph then advanced to `v0.56.0`.
A later fresh scan caught `GO-2026-5942` in the observer's remaining v0.55.0
graph, so the locked observer now also requires fixed v0.56.0. The passing
bundles retain three locations for
the same nonfixed severity-Unknown `GO-2026-5932` advisory without suppression.

Gitleaks `v8.30.1` scans exact package metadata, shipped text, and printable
strings from all four executables. Both reports must be empty under the one
exact public Go-checksum exception shared with the other artifact gates.

All candidate and scan steps except the database refresh run networkless,
read-only, non-root, capability-free, without a Docker socket, and with bounded
memory/PIDs.

## Evidence and release binding

Each pass publishes a new mode-private create-only directory:

```text
bin/linux-package-security/<artifact-sha256>-<verification-UTC>/
```

It retains the production-policy inspection, Syft/SPDX inventories, Grype
database/report, both Gitleaks reports, and canonical
`mesh-linux-package-security-receipt-v1`. The receipt binds the artifact
size/SHA-256, architecture, release/build identity, installer root, every
shipped file, verifier, scanner versions, isolation boundary, policies, and
UTC completion time.

Pass the matching receipt into release-manifest creation:

```sh
mesh-release create-release-manifest \
  --output release.json \
  --root root-v1.json \
  --version 1.2.3 \
  --sequence 42 \
  --security-floor 1 \
  --issued 2026-07-21T16:00:00Z \
  --expires 2026-07-22T16:00:00Z \
  --os linux \
  --arch amd64 \
  --artifact-url https://releases.example/mesh/1.2.3/linux-amd64.tar \
  --artifact /absolute/path/mesh-linux-amd64.tar \
  --linux-package-security-receipt \
    /absolute/evidence/<artifact-sha256>-<UTC>/receipt.json
```

Every Linux artifact now requires exactly one canonical matching receipt by
default. The preflight strictly reparses the full receipt and requires its
architecture, version, security floor, artifact size, and artifact SHA-256 to
equal the release selection. It also requires the receipt to be no more than 24
hours old with at most five minutes of future clock skew, and rechecks that the
bound Grype database was no more than 72 hours old at completion.
Multi-architecture manifests require one receipt per Linux artifact. The explicit
`--test-only-allow-unscanned-linux-artifact` bypass exists solely for synthetic
fixtures that do not contain a real node bundle; it must never be used by a
production signing workflow.

The signed manifest continues to authenticate the artifact itself, not make a
local scanner a new installer trust root. Retain the full security evidence
beside signing records in append-only storage.

## Residual risk

This is unsigned, point-in-time local pipeline evidence. It does not cover
native host state after installation, runtime volumes/logs/crash data,
repository history, registry or deployment-store mutation, signed SBOM
attestation, continuous admission, remote attestation, macOS, or Windows.
Docker/build/scanner hosts and the current vulnerability database remain trust
inputs. Repeat the gate for every changed candidate and whenever vulnerability
data changes before signing.

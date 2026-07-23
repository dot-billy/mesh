# Control-plane image security baseline

Status: implemented and first verified on 2026-07-21 for the Linux amd64
control-plane image.

## Run the gate

From the repository root, as the unprivileged account that is authorized to use
the Docker daemon:

```sh
make image-security-baseline
```

The command accepts no arguments. A missing tool, unavailable registry or
vulnerability database, unexpected scanner version, image-layout difference,
scan error, disallowed finding, or evidence-publication collision fails the
gate. It never treats missing scanner data as a clean result.

Run `make security-baseline` first. The source gate checks reachable code and
the current source tree; this image gate independently checks what the
control-plane container actually ships.

## Exact build and inventory

The Dockerfile uses the digest-pinned Go 1.26.5 Bookworm index and builds the
Linux amd64 scratch image without a provenance side manifest. `mesh-server`,
`mesh-healthcheck`, `mesh-kube-init`, and `nebula-cert` are all compiled from
the repository's verified module graph. The gate requires the SBOM to prove:

- Go standard library 1.26.5 in all four binaries;
- Slack Nebula v1.10.3 in `mesh-server` and `nebula-cert`;
- `golang.org/x/crypto` v0.53.0 and `golang.org/x/sys` v0.46.0 in both
  `mesh-server` and the root-module-built `nebula-cert`, plus
  `golang.org/x/text` v0.39.0 in `mesh-server` and `x/term` v0.44.0 in
  `nebula-cert`
  that use them; and
- no package type other than Go modules and no package location outside the
  four exact binaries.

The gate saves the frozen Docker image ID rather than rescanning a mutable tag.
Before trusting a scanner, a bounded Python verifier checks every
content-addressed archive object, config digest, runtime user, entrypoint,
environment, labels, exposed port, three-layer shape, and the complete 23-entry
scratch-filesystem allowlist. It rejects links, devices, overwrites, unexpected
paths, nonempty credential/TLS placeholders, ownership or mode changes, and
oversized layers or binaries.

Syft v1.44.0 then reads that archive in a networkless, read-only, non-root,
capability-free container without a Docker socket. One invocation creates both
the native Syft 16.1.3 JSON inventory and SPDX 2.3 JSON. The verifier binds the
SBOM image-config digest to the exact saved archive and cross-checks the SPDX
package purls against the Syft inventory.

## Vulnerability policy

Grype v0.112.0 updates an otherwise empty private database cache while seeing
neither the source nor image archive. The actual SBOM scan then runs with no
network and a read-only database. The database must report schema v6, valid
state, a nonfuture build time, and an age no greater than 72 hours.

The gate rejects:

- every High or Critical match, whether or not a fix exists;
- every match at any severity for which the database publishes a fixed
  version; and
- every ignored/suppressed match or finding that cannot be bound back to a
  package purl in the exact SBOM.

The first implementation pass caught fixed component-level findings in
`x/crypto` v0.50.0 that source reachability analysis did not report, plus a
fixed Low `x/sys` finding. The module graph and independently built
`nebula-cert` now use the versions above.

The first passing report retains two location-specific matches for the same
nonfixed, severity-Unknown advisory `GO-2026-5932`, one in `mesh-server` and one
in `nebula-cert`. Retention is not suppression and is not a clean-vulnerability
claim: it remains in `vulnerabilities.json` and the receipt until upstream data
assigns a severity or fix, at which point the gate policy is reevaluated.

## Secret policy

Gitleaks v8.30.1 scans two final-image projections with its default rules:

- every nonbinary regular file admitted by the exact rootfs allowlist; and
- printable strings of length eight or more extracted from each of the four
  shipped binaries.

Both scans run networkless, read-only, non-root, capability-free, resource
bounded, and fully redacted. The only image-scan exception is the exact public
Go checksum for `golang.org/x/oauth2` v0.36.0 embedded in Go build information;
the value is already authenticated by `go.sum`. The exception is scoped to the
`generic-api-key` rule and exact checksum bytes. A dependency change must
remove or deliberately update it under security review.

This improves coverage of build-time embedding but is not proof that arbitrary
binary encodings contain no secret. Runtime volumes, environment supplied at
deployment, core dumps, the Docker daemon/store, registry metadata, deployment
stores, and repository history remain separate scan domains.

## Evidence

Every pass publishes a new mode-private, create-only directory under:

```text
bin/image-security/<docker-image-digest>-<verification-UTC>/
```

It contains:

- `image-metadata.json`, binding the Docker ID, archive digest, exact rootfs,
  config digest, and shipped file hashes;
- `mesh-control-plane.syft.json` and `mesh-control-plane.spdx.json`;
- `grype-db-status.json` and the complete `vulnerabilities.json`;
- empty `rootfs-secrets.json` and `binary-secrets.json` finding arrays; and
- `receipt.json`, which hashes every retained artifact and records the policy,
  scanner versions, database build, counts, remaining nonfixed IDs, and scanner
  isolation boundary.

The evidence is local and unsigned. Release automation must move it to durable
storage, authenticate it with the release/image identity, and retain it with
the signed image and deployment receipts.

## Scope that remains open

This gate covers only the Linux amd64 control-plane image built from
`packaging/container/Dockerfile`. The
[release-origin image](origin-image-security.md),
[Linux observer runtime](observer-security.md), and
[final Linux node packages](linux-package-security.md), plus the non-installing
[Windows staging bundles](windows-package-security.md) and
[Darwin staging bundles](darwin-package-security.md), have separate exact
gates and do not inherit this result. Native macOS and Windows package
and host state, other image architectures, registry objects, deployment stores,
installed hosts, and running containers remain separate boundaries. Image signing, SBOM
attestation, registry publication, continuous admission/remote attestation,
and independent verification remain required production operations.

The Docker daemon, build host, pinned builder/scanner image publishers, and
live vulnerability database are trust inputs. Scanner containers themselves
are isolated but are not recursively scanned or independently rebuilt by this
gate.

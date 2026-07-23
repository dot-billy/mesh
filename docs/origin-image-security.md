# Release-origin image security baseline

The release-origin gate produces create-only local security evidence for the
exact Linux `amd64` scratch image that serves public release objects. It is
separate from the control-plane image gate because the origin has a smaller
filesystem, a different dependency inventory, and an independent deployment
and custody path.

## Run the gate

From the repository root, as the unprivileged account authorized to use the
Docker daemon:

```sh
make origin-image-security-baseline
```

The command accepts no arguments. It fails closed if Docker, a scanner, the
vulnerability database, the image layout, the exact package inventory, or any
policy result differs from the pinned contract. It never changes a host
security setting.

## Exact boundary

The gate:

1. builds `packaging/origin/Dockerfile` for `linux/amd64` with provenance
   disabled and freezes the exact Docker image ID;
2. saves and authenticates every content-addressed archive object, then
   requires the exact three-layer, 18-path scratch filesystem, metadata,
   non-root runtime identity, entrypoint, labels, CA bundle, empty mount
   placeholders, and two bounded executables;
3. generates Syft `1.44.0` and SPDX `2.3` inventories offline and requires the
   exact five Syft package locations and six SPDX package records, including Go
   `1.26.5` and `golang.org/x/sys` `v0.46.0`;
4. updates an isolated Grype `0.112.0` database, then scans the bound SBOM
   offline and rejects every High or Critical match and every match with a
   published fix; and
5. runs Gitleaks `v8.30.1` over the admitted rootfs text plus printable strings
   from both binaries, requiring empty redacted reports under the exact
   allowlist.

Archive validation and all scans run in networkless, read-only, non-root,
capability-free containers without a Docker socket. Only the isolated Grype
database refresh has network access, and it receives only an empty private
cache.

## Evidence

Each pass publishes a new mode-private directory without replacing an existing
path:

```text
bin/origin-image-security/<docker-image-id>-<verification-UTC>/
```

It contains the archive metadata, Syft and SPDX documents, Grype database
status and report, both Gitleaks reports, and canonical
`mesh-origin-image-security-receipt-v1` JSON. The receipt binds every evidence
file hash, the exact Docker and config identities, the complete admitted file
evidence, scanner versions and isolation boundary, policy, counts, and UTC
completion time.

Retain the full directory in append-only release evidence. The receipt is
unsigned local pipeline evidence; it does not replace registry signing,
independent public-key custody, admission control, remote attestation, or the
external origin audit.

## Runtime custody chain

The exact image that passed this gate must be the image pushed and signed for
deployment. Pass its `receipt.json` together with the independent Cosign image
receipt to the read-only runtime verifier:

```sh
mesh-origin-runtime-verify \
  --image-receipt /secure/evidence/origin-image-verification.json \
  --security-receipt /secure/evidence/origin-image-security/receipt.json \
  --compose-config /secure/evidence/production-compose.json \
  --generation /srv/mesh-release/generations/<index-sha256> \
  --container-id <exact-64-character-id> \
  --docker /usr/bin/docker \
  --docker-socket /run/docker.sock \
  --output /secure/evidence/origin-runtime.json
```

The verifier strictly reparses the complete canonical security receipt,
requires its `linux/amd64` Docker image ID to equal the running container's
exact local image ID, and writes both input-receipt hashes into canonical
`mesh-origin-runtime-verification-v2` evidence. A rebuilt image is acceptable
only if it reproduces the same exact ID; otherwise rerun the security gate and
retain the new evidence before deployment.

## Residual risk

The evidence is a point-in-time local observation. A host or Docker authority
can lie to the verifier or replace the runtime afterward, and newly disclosed
vulnerabilities can make older evidence stale. Production still requires
signed digest publication, protected evidence retention, deployment admission
and monitoring, a post-start runtime receipt, and independent external HTTPS
auditing before traffic cutover.

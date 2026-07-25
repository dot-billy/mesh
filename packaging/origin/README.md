# Immutable HTTPS release origin

`mesh-origin` is an untrusted, read-only courier for Mesh installer releases.
It holds no root, release signing, administrator, node, or CA private key. The
independently authenticated `mesh-install` binary still verifies the complete
root chain, threshold signatures, release epoch/sequence, platform, exact
artifact size, and SHA-256 before installing anything.

The service publishes no directory tree. `mesh-release create-origin-index`
opens and hashes one explicit path allowlist, writes a canonical create-only
index, and requires each `/channels/...` object to be a canonical online
release bundle. At startup the origin opens every indexed object without
accepting symlinked directory components, rejects hard links, verifies exact
size/digest, and keeps those descriptors. Its container mounts the repository
and index read-only, runs without capabilities under an explicit non-root
UID/GID, and serves native TLS from a read-only scratch image.

`mesh-release publish-origin-generation` turns the reviewed staging repository
and index into one content-addressed deployment directory. It copies only
indexed objects through exact stable-read size and SHA-256 checks, writes a
canonical operational receipt, fsyncs the complete tree, validates it through
the production origin store, seals files `0444` and directories `0555`, and
publishes by Linux `renameat2(RENAME_NOREPLACE)`. The index SHA-256 is the
generation directory name. `mesh-release inspect-origin-generation` repeats
the receipt, exact-tree, mode, digest, and production-store validation without
mutation. Neither command grants release authority.

## Author the public index

First publish release artifacts and immutable metadata into a staging
repository. Assemble the signed online bundle last, but do not change the
stable channel yet. Build an index that names every public object:

```bash
mesh-release create-origin-index \
  --root /srv/mesh-release/repository \
  --output /srv/mesh-release/origin-index.json \
  --object /bootstrap/stable/bootstrap-handoff.json \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar \
  --object /bootstrap/stable/mesh-install-linux-amd64 \
  --object /bootstrap/stable/mesh-install.bootstrap.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-a.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-b.json \
  --object /bootstrap/stable/root-v1.json \
  --object /releases/1.2.3/mesh-linux-bundle.tar \
  --object /releases/1.2.3/release.json \
  --object /channels/stable/bundle.json
```

Never add `bootstrap-anchor.json` to this index. Create it from the canonical
handoff with `mesh-release create-bootstrap-anchor` and move it through a
separately controlled channel; a copy served by this origin has no authority.

The output is never overwritten. Publish it and its exact objects into the
existing operator-controlled generations root:

```bash
install -d -m 0755 /srv/mesh-release/generations

mesh-release publish-origin-generation \
  --source-root /srv/mesh-release/repository \
  --index /srv/mesh-release/origin-index.json \
  --generations-root /srv/mesh-release/generations

GENERATION_ID="$(sha256sum /srv/mesh-release/origin-index.json | awk '{print $1}')"
GENERATION="/srv/mesh-release/generations/${GENERATION_ID}"
mesh-release inspect-origin-generation --generation "${GENERATION}"
```

The generations root must be a clean absolute real directory with no
group/other write permission. Publication is Linux-only because the final
directory transition is atomic and no-replace. Normal failure cleans its exact
hidden staging directory; after a host crash, inspect any hidden staging
residue before explicitly removing it.

For a release change, create a new staging repository and index, publish a new
generation, inspect it, and verify it through a separate origin instance or
staging hostname. Do not edit files in place. Retain old generations for audit
and rollback according to an explicit external policy.

## Authenticate the production image

Production `compose.yaml` has no build stanza, mutable tag, or local default.
It constructs exactly
`MESH_ORIGIN_IMAGE_REPOSITORY@sha256:MESH_ORIGIN_IMAGE_SHA256`. The separately
named `compose.build.yaml` is only for the disposable smoke and deliberate local
development; never include it in a production command.

Before publication, run the separate exact Linux `amd64`
[release-origin image security gate](../../docs/origin-image-security.md):

```bash
make origin-image-security-baseline
```

Retain the resulting `receipt.json` and full evidence directory, and publish
only the exact Docker image ID named by that receipt. Rebuilding is acceptable
only if it reproduces the same ID; otherwise rerun the gate. This local
SBOM/vulnerability/secret evidence complements, but does not replace, the
independent registry-signature verification below.

Build the scratch image once in a controlled pipeline, push it, resolve its
registry manifest digest, and sign that exact digest. Keep the signing private
key outside the registry and origin host. Provision the corresponding public
key to the production operator through an independent path. The repository does
not perform that custody ceremony or install
[Cosign](https://docs.sigstore.dev/cosign/verifying/verify/).

Before every new or rolled-back image deployment, verify the exact reference:

```bash
IMAGE_REPOSITORY=registry.example.com/mesh/mesh-release-origin
IMAGE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
IMAGE="${IMAGE_REPOSITORY}@sha256:${IMAGE_SHA256}"
IMAGE_RECEIPT="/srv/mesh-release/image-audit/${IMAGE_SHA256}-$(date -u +%Y%m%dT%H%M%SZ).json"
SECURITY_RECEIPT="/srv/mesh-release/image-audit/origin-image-security-receipt.json"

mesh-origin-image-verify \
  --image "${IMAGE}" \
  --key /srv/mesh-release/trust/mesh-origin-cosign.pub \
  --cosign /usr/local/bin/cosign \
  --timeout 5m \
  --output "${IMAGE_RECEIPT}"
```

The command explicitly enables Cosign claim checking, requires every verified
payload to bind `sha256:${IMAGE_SHA256}`, snapshots the public key, and rechecks
the Cosign executable. Success writes a create-only, fsynced canonical
`mesh-origin-image-verification-v1` receipt containing the exact image, key
SHA-256, Cosign SHA-256, verification time, and signature count. Store it in an
append-only evidence system. It is image-custody evidence, not release
authority.

Set the exact same repository and digest in the protected Compose environment
file. Do not use a tag alongside them, and do not copy a digest reported only
by the untrusted origin host. Review the rendered `services.origin.image` and
confirm there is no `build` field before pulling.

## Run

Copy `.env.example` outside source control, set `MESH_ORIGIN_GENERATION` to the
exact inspected content-addressed generation, set the runtime UID/GID to its
owner and the TLS-key owner, and install a real certificate, private key, and
verification CA. The private key must be a single-link file with no group/other
permissions. Repository and index cannot be selected independently. The image
repository/digest must exactly match the successful image-verification receipt.

```bash
ROLLOUT_ID="${IMAGE_SHA256}-$(date -u +%Y%m%dT%H%M%SZ)"
COMPOSE_EVIDENCE="/srv/mesh-release/runtime-audit/${ROLLOUT_ID}-compose.json"
RUNTIME_RECEIPT="/srv/mesh-release/runtime-audit/${ROLLOUT_ID}-runtime.json"

docker compose --env-file /secure/path/origin.env config --quiet
set -o noclobber
docker compose --env-file /secure/path/origin.env config --format json > "${COMPOSE_EVIDENCE}"
set +o noclobber
docker compose --env-file /secure/path/origin.env pull
docker compose --env-file /secure/path/origin.env up -d --no-build --pull never
docker compose --env-file /secure/path/origin.env ps

CONTAINER_ID="$(docker compose --env-file /secure/path/origin.env ps --quiet origin)"
mesh-origin-runtime-verify \
  --image-receipt "${IMAGE_RECEIPT}" \
  --security-receipt "${SECURITY_RECEIPT}" \
  --compose-config "${COMPOSE_EVIDENCE}" \
  --generation "${GENERATION}" \
  --container-id "${CONTAINER_ID}" \
  --docker /usr/bin/docker \
  --docker-socket /run/docker.sock \
  --timeout 30s \
  --output "${RUNTIME_RECEIPT}"
```

Treat the rendered configuration as rollout input and confirm it names the
receipt's exact `repository@sha256:digest` and contains no build. After start,
the runtime verifier stably reparses both the complete canonical image-security
receipt and that render, reinspects the immutable generation, queries only the
exact 64-character container ID through the explicit real Unix socket, and
requires the security receipt's Docker ID, platform, local repository digest,
runtime command/user/hardening, and all five read-only mounts to agree. Success
writes a create-only canonical `mesh-origin-runtime-verification-v2` receipt
binding both input-receipt SHA-256 values.
Use `/run/docker.sock` when `/var/run` is a symlink; linked path components are
rejected.

Store the image, rendered-Compose, runtime, and external-audit evidence together
in an append-only system, then run the external deployment audit below before
traffic cutover. A generation-only rollout keeps the verified image digest
fixed but still requires a new render, container ID, runtime receipt, and public
audit. An image change or rollback requires a current exact image-security
receipt and a new image-verification receipt before pull/start as well.

For an intentional local build only, provide the placeholder production image
variables required by `.env.example` and opt into both files:

```bash
docker compose --env-file ./local-origin.env \
  --file packaging/origin/compose.yaml \
  --file packaging/origin/compose.build.yaml build
docker compose --env-file ./local-origin.env \
  --file packaging/origin/compose.yaml \
  --file packaging/origin/compose.build.yaml up -d --no-build
```

For rollout, change only `MESH_ORIGIN_GENERATION`, recreate the service, wait
for exact health, and verify the candidate's public objects. For rollback,
first inspect the retained prior generation, select its exact path, recreate,
and repeat public verification. Never rebuild an old generation or copy a
channel file backward. Retention deletion is deliberately not automated: an
external policy must prove a generation is not selected and is no longer
required for installer rollback, audit, or incident response.

## External deployment audit and monitoring

Run `mesh-origin-audit` from an operator or monitoring host outside the origin
container. It begins with the selected local generation, not an origin-supplied
index, then checks the public TLS route's exact readiness response, security
headers, certificate identity, unlisted-path and write rejection, plus HEAD and
full digest-checked GET behavior for every indexed object:

```bash
AUDIT_RECEIPT="/srv/mesh-release/audit/${GENERATION_ID}-$(date -u +%Y%m%dT%H%M%SZ).json"

mesh-origin-audit \
  --generation "${GENERATION}" \
  --origin https://releases.example.com:8444 \
  --timeout 10m \
  --output "${AUDIT_RECEIPT}"
```

Omit `--ca-file` for a public certificate rooted in the host's system trust.
For a private staging PKI, add one clean absolute bounded PEM bundle. The
command does not use environment proxies, cookies, redirects, compression, or
HTTP/2. Success writes a create-only, fsynced canonical
`mesh-release-origin-audit-v1` receipt and prints those exact bytes to stdout.
It binds the generation, public origin, observed leaf-certificate SHA-256 and
expiry, check time, object count, total bytes, and request count. It remains
courier evidence, not release authority.

Require a successful runtime receipt and full audit before traffic cutover,
then repeat the full audit after cutover and after rollback. Run it periodically
at a cadence appropriate for the complete
generation size; every run downloads every object, so it is intentionally not
a lightweight liveness probe. Use `/readyz` for high-frequency availability
monitoring and the full auditor for integrity. Alert on any nonzero exit,
missing receipt, unexpected generation/origin, certificate change or impending
expiry, and stale last-success time. Store receipts in an append-only evidence
location with external retention and alert delivery; this repository does not
provision that monitoring system.

Run `make release-origin-smoke` before changing the production image or
generation. The proof first requires production Compose to fail without image
identity and to render one exact digest reference with no build. It opts into
the separate local-only override only to build, pushes that one image to a
disposable registry, resolves its real manifest digest, runs the image preflight
through a clearly test-only Cosign subprocess, and starts through production
Compose alone. A clearly test-only image-security schema fixture exercises the
custody wiring; a mismatched Docker ID must fail without a receipt. Candidate
and rollback each require a distinct v2 runtime receipt binding both custody
receipts before external auditing. The remaining
proof creates fresh independent root and release signers, publishes a complete
bootstrap courier set for both Linux architectures plus a 2-of-2 online
channel, publishes two immutable generations, switches to a candidate, and
selects the retained prior generation again. The production external auditor
checks all public objects and writes exact receipts at both stages before the
proof continues through explicit header and unlisted-path checks. It retains a
canonical create-only bootstrap anchor outside the origin, requires the anchor
path to remain publicly absent, authenticates the fetched handoff from that
anchor, derives the selected verifier-package and root digests, validates the
fetched USTAR, and extracts only its narrow executable. The standalone and
compatibility v3 receipts must match exactly, while direct-digest v2 remains
compatible. Changed or linked anchors, changed handoffs or roots, mixed
authorities, and exact-expiry handoffs fail closed without executing the
installer. Mutating that indexed installer makes local
inspection, external auditing, readiness, and retrieval fail closed without a
success receipt. The proof removes every exact container, network, image tag,
key, generation, and repository file.

After the service is healthy, independently fetch and verify every exact
object and header before updating the dashboard's
`--linux-install-bundle-url`. The origin may courier the first `mesh-install`,
its root-authorized manifest and signatures, canonical root, and deterministic
standalone-verifier package, but it authenticates none of them. The root digest
and verifier-package digest may be bound by `bootstrap-handoff.json`; the
preferred authority is a canonical bootstrap anchor transferred independently
of this origin, its DNS/TLS, the browser, and the control plane. The exact
handoff digest remains a supported lower-level authority.

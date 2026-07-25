# Release-origin runtime deployment verification

**Status:** Implemented mechanism; production runtime attestation remains
external deployment work.

## Problem

An image-signature receipt proves a point-in-time registry check, while the
separate image-security receipt proves an exact local SBOM, vulnerability, and
secret-scan result. Neither alone proves that production Compose rendered that
image, that the running container uses it, or that its immutable-generation
mounts match the intended rollout.
The external origin audit proves public bytes and TLS behavior but deliberately
does not trust Docker metadata. Operators need a read-only bridge across those
two evidence domains before traffic cutover.

## Boundary

`mesh-origin-runtime-verify` performs no pull, build, start, restart, stop, or
network request. It accepts one prior canonical image-verification receipt, one
complete canonical `mesh-origin-image-security-receipt-v1`, one captured
production `docker compose config --format json` document, one exact
inspected origin generation, one 64-character container ID, one clean absolute
Docker executable, and one clean absolute local Docker Unix socket.

Docker and host authority can lie about or replace the runtime. The receipt is
point-in-time operator evidence, not remote attestation, release authority, or
an installer trust anchor. The subsequent external origin audit remains
mandatory because it observes the public route independently.

## Verification

The command must:

1. stably read and strictly parse both create-only image receipts and production
   Compose JSON, rejecting symlink components, linked files, unstable or
   noncanonical bytes, duplicate/unknown JSON fields, changed scanner versions,
   weakened scan policy/isolation, build configuration, extra services, mutable
   image identity, or hardened-service drift;
2. fully inspect the selected content-addressed generation before runtime
   inspection;
3. hash the exact Docker executable, reject a linked/non-executable or writable
   program and a linked/non-socket Docker endpoint, and invoke Docker without a
   shell against that explicit Unix socket;
4. require the exact container ID, healthy/running state, image reference,
   non-root user, command, read-only root, dropped capabilities, no-new-
   privileges, init, resource bounds, and five read-only bind mounts to match
   the rendered production service;
5. inspect the container's local image ID, require it and its platform to equal
   the security receipt, and require its repository digests to contain the
   signature receipt's exact `repository@sha256:digest`;
6. rehash Docker and re-inspect the generation before success; and
7. emit nothing on any mismatch or timeout.

## Receipt

Success emits canonical `mesh-origin-runtime-verification-v2` JSON plus one LF.
It binds both prior receipt SHA-256 values, exact image and manifest digest,
rendered-Compose SHA-256, generation/index digest, container ID, local image ID,
Docker-executable SHA-256, public URL, non-root runtime user, and UTC completion
time. File output is clean absolute, create-only, fsynced, and never replaced.

## Proof

Focused tests cover the exact successful chain and reject a Compose build,
image/reference mismatch, extra service, mount drift, mutable generation,
unhealthy/stopped container, weakened runtime controls, wrong local image ID,
missing repository digest, linked inputs, ambiguous Docker output, executable
change, and receipt replacement. The release-origin smoke will build through
the explicit local override, push into an exact disposable local registry,
start through production Compose by digest, create the prior image receipt with
its test-only Cosign subprocess, exercise the security schema with a clearly
test-only fixture, reject a mismatched security image ID without output, and
require v2 runtime evidence before public origin auditing. This exercises the
wiring but is not a production signature, scan, or registry-custody claim.

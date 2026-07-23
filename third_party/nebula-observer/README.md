# Slack Nebula v1.10.3 runtime-observer source/build lock

This directory is the bounded fork input used by Mesh's observer-enabled Linux
Nebula builder and, through a separate layered output lock, the non-listening
Windows runtime builder. It does not replace the reviewed upstream
release-archive lock and, by itself, makes no signing, deployment, rollout, or
rollback claim.

The patch series targets Slack Nebula v1.10.3 at commit
f573e8a26695278f9d71587390fbfe0d0933aa21:

1. 0001 adds process-local snapshot state, bounded per-configured-lighthouse RX
   retention across host-map eviction, and authenticated-RX hooks only after
   successful AEAD decryption and replay-window commit.
2. 0002 adds the fixed /run/mesh-nebula/runtime-observer.sock Linux server,
   SO_PEERCRED UID 0 enforcement, root-private path checks, bounded handlers and
   deadlines, inode-safe unlink, and observer-before-tunnels shutdown ordering.
3. 0003 adds protocol, saturation, race, socket lifecycle, ownership, peer
   credential, replacement-path, and receive call-site regression tests.
4. 0004 upgrades the security-sensitive Go module graph to x/crypto v0.53.0,
   x/net v0.56.0, x/sys v0.46.0, and x/term v0.44.0.

The patches modify only a private copy of the locked upstream source. The
source-controlled `v1.10.3-build.lock.json` additionally binds the complete
upstream and patched trees, exact patch order and bytes, Go 1.26.5 build flags,
the exact security dependency versions/checksums, the explicit
`main.Build=1.10.3` runtime identity, and exact amd64/arm64
`nebula` and `nebula-cert` outputs. `mesh-deps
build-nebula-observer` builds each output twice with clean caches and publishes
only matching locked bytes. Linux bundle schema v3 consumes that stage and the
packaged systemd unit creates the required root-owned mode-0700
`RuntimeDirectory=mesh-nebula`.

`third_party/nebula-windows-runtime/v1.10.3-build.lock.json` binds this base
policy digest to the exact reproducible amd64/arm64 Windows `nebula.exe` and
`nebula-cert.exe` outputs. `mesh-deps build-nebula-windows-runtime` builds each
target twice with clean caches and rejects output that differs from that
layered lock. Windows uses the patch series' reviewed no-I/O observer stub, so
this path supplies the patched dependency floor without exposing a fallback
listener or claiming Windows runtime telemetry. Windows bundle schema v2
records both provenance layers; the upstream Windows archive contributes only
the exact Wintun tree and notices.

## Provenance and smoke

Run:

    ./scripts/nebula-observer-prototype-smoke.sh

Then create the source, SBOM, vulnerability, and binary-secret evidence:

    make observer-security-baseline

The detailed scope and residual limits are in
`docs/observer-security.md`.

Then run the privileged two-node behavior proof on a Linux host with network,
mount, veth, and TUN namespace support:

    ./scripts/nebula-observer-overlay-smoke.sh

Run the focused two-live-lighthouse degradation/recovery and nine-configured
overflow proof with the same prerequisites:

    ./scripts/nebula-observer-multilighthouse-smoke.sh

The smoke is deliberately offline. The exact module and its dependencies must
already be in the Go module cache; GOPROXY=off prevents the smoke from
populating it. The script verifies all of these before patching:

- Mesh go.sum selects github.com/slackhq/nebula v1.10.3 with the reviewed
  checksum.
- v1.10.3.lock.json records the expected repository, tag, module, version, and
  upstream commit.
- every upstream file touched by the series matches base-files.sha256.

It fingerprints the cached source, copies it with preserved metadata to a
mode-0700 temporary directory, makes only the copy writable, applies each patch
with git apply --check and whitespace checking, runs the full fork unit suite,
runs focused race tests, and invokes the production builder for static Linux
amd64 and arm64 `nebula` plus `nebula-cert` stages. The temporary source, build
caches, binaries, and manifests are removed on every exit. A final fingerprint
check proves the cached source content and metadata were not changed.

The overlay smoke builds that same locked stage, creates two isolated Nebula
peers with a private `/run` mount for each fixed observer endpoint, and passes
every response through Mesh's production Unix client and strict parser. It
proves completed Noise-handshake and authenticated-RX evidence, the exact
lighthouse aggregate, retained lighthouse RX age after host-map eviction,
sequence continuity within one process, a new process
identity and sequence after restart, and zero retained peers on a freshly
restarted lighthouse after signed revocation. It also severs only the underlay,
observes Nebula actively evict the dead tunnel while the retained age advances,
waits for the observer's handshake-timeout counter to advance, then restores
the link and proves a fresh handshake plus authenticated RX in the same process. It exits 77 rather than
claiming coverage when the required Linux capabilities are unavailable.

The focused multi-lighthouse smoke uses two independent underlays, proves both
authenticated lighthouse tunnels in one member snapshot, removes only one path
until that tunnel is evicted and times out while the other stays current, and
recovers both in the same process. It then uses Mesh enrollment and signed
configuration to activate seven additional non-running lighthouse records,
restarts only the member, and proves `configured=9`, `overflow=true`, and exactly
the two real live entries through the strict production client.

The module checksum, full-tree hash, upstream lock hash, and touched-file hashes
bind the local source bytes to the source-controlled review lock. Because the
Go module extraction has no `.git` directory, this is not presented as an
independent Git ancestry proof.

## Protocol fixtures

fixtures contains one canonical positive request and v2 empty snapshot plus
adversarial request and response cases. Mesh tests consume the same files as
the fork tests, keeping canonical field order, nonce rules, strict v1 fallback,
strict v2 emission, numeric bounds, and response allowlisting on one review surface.

## Remaining limits and TODO

- The bad-AEAD, replay, CloseTunnel, and relay-wrapper regressions inspect the
  exact production receive control flow: the only two RX hooks must remain
  after DecryptDanger and replay-window Update, and readOutsidePackets may not
  call them. Add encrypted packet-injection and terminal/forwarding relay tests
  to the upstream e2e harness before a release claim.
- Extend the existing hardened-service install proof with unprivileged and
  alternate service UIDs, adversarial replaced parents, crash recovery, and an
  explicit proof that no new network listener exists.
- Perform upstream review, release signing, staged rollout, and rollback drills
  as separately reviewed changes before a production rollout claim.
- Darwin and Windows intentionally expose no fallback listener. Native
  credential and ACL designs remain required before those platforms can report
  runtime telemetry.

# Slack Nebula dependency intake and observer build

`mesh-deps` is a bounded dependency tool, not an installer. `fetch-nebula` downloads one exact Slack Nebula v1.10.3 release archive selected by `--os` and `--arch`, authenticates and structurally verifies it, and atomically publishes its files into a new directory. `build-nebula-observer` constructs the exact observer-enabled Linux runtime from already cached source. `build-nebula-windows-runtime` uses that same authenticated patched source and a separate layered output lock to construct exact Windows PEs. None chooses `latest`, accepts trust overrides, installs outside its output directory, or creates, starts, stops, or updates a service.

The authoritative runtime trust input is [`third_party/nebula/v1.10.3.lock.json`](../third_party/nebula/v1.10.3.lock.json) as embedded in the reviewed Mesh binary. GitHub's release API `digest` values and `SHASUM256.txt` were used to corroborate the source review; they are not fetched or trusted at runtime. This distinction matters because the v1.10.3 GitHub release was recorded as mutable when the lock was constructed. A tag, release URL, or TLS connection alone is not artifact authenticity.

The lock pins:

- release ID `283875123`, annotated tag object `afe3e8c52cd4b91e8c5f946bf2e624df6d311c13`, tag `v1.10.3`, and peeled commit `f573e8a26695278f9d71587390fbfe0d0933aa21`;
- exact GitHub asset ID, name, initial URL, byte length, and SHA-256 for Linux amd64/arm64, the Darwin universal archive, and Windows amd64/arm64;
- every archive member's canonical name, regular-file/directory type, archive mode, output mode, size, and SHA-256, plus ZIP compressed size, CRC-32, and method; and
- expected executable container, machine or universal slices, main package, module `github.com/slackhq/nebula` at `v1.10.3`, target `GOOS`/`GOARCH`, VCS revision, and unmodified VCS state.

Both upstream Windows locks enumerate the complete 18-entry archive: `nebula.exe`, `nebula-cert.exe`, and every directory/file in the bundled Wintun tree, including its four DLL architectures. Nothing unlisted is extracted. Current bundle schema v2 deliberately discards the two upstream Nebula executables after verification and uses only the selected Wintun DLL and notices; the runtime PEs come from the source-build path below.

## Operator workflow

Dependency intake is currently enabled only on a Linux amd64 or arm64 host. The complete absolute ancestor chain must contain no symlinks or extended POSIX ACLs, every component must be owned by root or the effective user, non-sticky group/world-writable ancestors are rejected, and the immediate parent must be effective-user-owned with no group/other write bits. This closes pathname and staging-name races and permits durable, no-replace publication; root and the effective user are the trusted local principals. Any target can be cross-staged from that host.

```sh
install -d -m 0700 ./dependency-intake
mesh-deps fetch-nebula \
  --os linux \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-v1.10.3-linux-amd64
```

Supported target pairs are `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, and `windows/{amd64,arm64}`. Both Darwin selections intentionally resolve to the same universal archive, and both slices must pass independently.

The supported Linux node bundle does not consume that upstream Linux release
stage. Build its observer-enabled input offline instead. Build the Windows
runtime from the same authenticated patched source through its layered target
lock:

```sh
mesh-deps build-nebula-observer \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-observer-v1.10.3-linux-amd64

mesh-deps build-nebula-windows-runtime \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-runtime-v1.10.3-windows-amd64
```

The source-build commands accept no source, patch, flag, version, hash,
toolchain, or network
override. It requires Go 1.26.5 and the exact v1.10.3 module plus dependencies
to be present in the local module cache. The embedded observer build lock binds
the upstream release lock, module checksums, complete upstream source tree,
complete patched tree, ordered patch names and bytes, build flags, targets,
security-sensitive module versions and checksums, and exact `nebula` and
`nebula-cert` sizes and SHA-256 values. The current locked security floor is
`x/crypto v0.53.0`, `x/net v0.56.0`, `x/sys v0.46.0`, and `x/term v0.44.0`.
Each executable is
built twice with separate clean build caches; nonidentical or unlocked output
is rejected. The locked linker input sets `main.Build=1.10.3` in both commands,
so the source-built runtime passes the same minimum-version gate as the pinned
release executable instead of reporting an empty development version.
Publication contains exactly the two mode-0555 executables and a
canonical mode-0444 `observer-build.json` manifest in a new mode-0555
directory.

The tree digest is domain-separated and path-sorted. Each record binds its
slash-relative path, directory/regular-file type, executable bits, regular-file
length, and bytes. It deliberately excludes owner, timestamps, and ordinary
read/write bits so the authenticated read-only module-cache tree and its
private writable patch copy have one portable identity.

Linux node-bundle schema v3 independently re-verifies that exact stage and
records the upstream commit/lock, source-tree, patched-tree, patch-set,
observer-lock, and Go-toolchain identities in `package.json`. The outer
threshold-signed release artifact then authenticates both those provenance
fields and the packaged executable hashes. Before that release metadata can be
created, the [final Linux package security gate](linux-package-security.md)
revalidates the stage inside the complete canonical bundle, binds the exact
four-executable SBOM plus shipped assets to current vulnerability and secret
evidence, and emits the required artifact-matching receipt.

The Windows builder authenticates the same upstream source, patch order and
bytes, patched tree, Go 1.26.5 toolchain, and security-module floor. On Windows
the observer endpoint is a reviewed no-I/O stub, so this reuse does not claim a
Windows telemetry transport. The layered
`third_party/nebula-windows-runtime/v1.10.3-build.lock.json` binds the base
observer policy digest plus exact amd64/arm64 `nebula.exe` and
`nebula-cert.exe` sizes, hashes, and main packages. Each target is built twice
with isolated caches; only byte-identical output matching that lock is
published. Windows bundle schema v2 requires this stage for the two Nebula PEs
and independently requires the exact upstream Windows archive solely for the
target Wintun DLL and notices. The [Windows staging-bundle security
gate](windows-package-security.md) revalidates both provenance chains inside
the final canonical artifact and emits the receipt required for release
creation.

The Darwin builder authenticates that same source, patch order and bytes,
patched tree, Go 1.26.5 toolchain, and security-module floor. The observer
endpoint is likewise a reviewed no-I/O stub rather than a macOS telemetry
transport. The layered
`third_party/nebula-darwin-runtime/v1.10.3-build.lock.json` binds the base
observer policy digest plus exact thin amd64/arm64 `nebula` and `nebula-cert`
Mach-O sizes, hashes, and main packages. Each target is built twice with
isolated caches and only byte-identical locked output is published. Darwin
bundle schema v1 packages that source-built stage with production-identity
Mesh and reviewed launchd assets; it does not consume the upstream universal
archive. The [Darwin staging-bundle security gate](darwin-package-security.md)
revalidates the full chain inside the canonical artifact and emits the receipt
required for release creation.

The output path must not exist. Download and extraction failures remove the private temporary archive and staging directory and leave no output. Publication uses Linux `renameat2(RENAME_NOREPLACE)` followed by a parent-directory sync. The archive and every staged regular file are synced, and nested directories are synced deepest-first before publication.

## Network and archive policy

The production network path is intentionally not configurable:

1. request the exact locked `https://github.com/slackhq/nebula/releases/download/v1.10.3/...` URL;
2. accept exactly one manual redirect;
3. require the final HTTPS host to be exactly `release-assets.githubusercontent.com` on the standard port, with no user information; and
4. stream exactly the source-locked size plus at most one detection byte into a private `O_EXCL` file while hashing it.

The client has no proxy, cookie jar, credentials, retries, automatic redirect, or automatic decompression. Connection, TLS handshake, response-header, total-time, and header-size bounds are compiled in. Non-identity content encoding, size disagreement, truncation, appended bytes, or digest disagreement fails before archive parsing. The verified temporary pathname is never reopened: extraction consumes the same synced file descriptor that was hashed.

After outer authentication, the tar.gz/ZIP parser requires the exact locked entry set. It rejects absolute, non-canonical, traversal, backslash, drive-like, duplicate, and unlisted paths; links, devices, FIFOs, sockets, special mode bits, encrypted/unsupported ZIP flags, unsupported compression, CRC errors, size/count/aggregate/ratio violations, second gzip members, and trailing data. Staged destinations are lock-derived and created through `os.OpenRoot` with `O_EXCL`.

## Native-signing boundary

The intake path preserves the upstream Darwin archive exactly and proves both
universal Mach-O slices; the staging bundle instead uses the separately locked
source-built thin outputs described above. Neither path performs native
`codesign`/notarization validation. A native packaging pipeline must perform
and record that policy, launchd/ACL installation behavior, and installed-host
verification before claiming macOS support.

Do not claim Authenticode for either the upstream or current source-built Nebula v1.10.3 Windows executables: those PEs are unsigned. The bundled Wintun DLLs are distributed with upstream Windows signatures, but this intake and staging slice proves only their exact locked bytes and PE inventory; it does not establish, evaluate, or replace Windows certificate-chain policy. Native Windows CI and packaging must validate the applicable signatures separately.

This intake lock is Mesh source/release provenance over a pinned upstream dependency. It is not a substitute for Mesh's threshold-signed release manifests, production bootstrap keys, OS-native Mesh packages, service integration, upgrade/rollback state, or an independently authenticated upstream artifact signature.

## Go certificate-library boundary

The offline recovery validator separately imports `github.com/slackhq/nebula/cert` from Go module `github.com/slackhq/nebula v1.10.3`. It uses upstream certificate v1/v2 parsing, CA self-signature validation, Curve25519/P256 private-key parsing, and public/private pair verification rather than maintaining a second Nebula certificate decoder. `go.mod` pins the same release version and `go.sum` authenticates the module bytes through the configured Go module trust path.

That library path is distinct from `mesh-deps fetch-nebula`: the
release-archive lock authenticates upstream runtime executables, not the module
source compiled into `mesh-server` and `mesh-backup`. The Linux observer builder
uses the same version but separately authenticates the complete cached tree and
its own exact patched outputs. Release signing remains the independent
authority over distributable Mesh artifacts.

## Reproducible verification

Normal unit tests synthesize adversarial HTTP, tar, and ZIP inputs. Maintainers with all five reviewed archives can run the real offline golden proof:

```sh
MESH_NEBULA_GOLDEN_DIR=/secure/review/nebula-v1.10.3 \
  go test -run TestGoldenPinnedArchives -v ./internal/nebulaartifact
```

That test checks every locked archive hash, exact staged tree and file hash/mode, both Darwin slices, every Linux/Windows machine, and embedded Go build/VCS information. The live production fetch path is separately opt-in:

```sh
MESH_TEST_NEBULA_FETCH=1 \
  go test -run TestGoldenNetworkFetchLinuxAMD64 -v ./internal/nebulaartifact
```

The complete offline observer proof runs the upstream unit suite, focused race
tests, source-cache immutability check, and both reproducible target builds:

```sh
./scripts/nebula-observer-prototype-smoke.sh
```

The separate [observer artifact security gate](observer-security.md) rebuilds
both locked architectures, scans the exact patched command graphs with
`govulncheck`, binds Syft and SPDX inventories, applies current Grype policy,
and scans all four binaries' printable strings. Its create-only receipt is
release evidence:

```sh
make observer-security-baseline
```

The separate privileged behavior proof builds the locked local stage and runs
two real peers with independent network and mount namespaces:

```sh
./scripts/nebula-observer-overlay-smoke.sh
```

It sends accepted snapshots through Mesh's production root-private Unix client
and parser, then proves handshake and authenticated-RX evidence, sequence and
process-instance continuity rules, revoked-peer exclusion, active tunnel
eviction, handshake timeout, and fresh same-process rehandshake recovery. Hosts
without the required namespace, veth, TUN, or privilege capabilities exit with
status 77 rather than claiming coverage.

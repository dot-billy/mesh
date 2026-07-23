# Bootstrap verifier distribution contract

`mesh-bootstrap-verify` is the deliberately narrow verifier for the first
Linux `mesh-install` or Windows `mesh-install-windows.exe` binary. `make build` creates a development copy at
`bin/mesh-bootstrap-verify`; `make bootstrap-verifier-smoke` builds a
production-identity copy and proves its package, positive behavior, and
fail-closed behavior without a container or host installation. That gate also
rejects packaging, subprocess, network-client, installer, and signing symbols
or source dependencies from the narrow verifier boundary.

The executable accepts only local anchor, handoff, root, manifest,
detached-signature, installer, independent-digest, and optional
verification-time inputs. Exactly one authority mode is required: an
independently transferred canonical anchor, an independently authenticated
handoff digest, or the lower-level root digest. It has no key generation,
signing, network retrieval, extraction, execution, or installation command.
Anchor success is one `mesh-bootstrap-verification-v3` JSON receipt binding the
anchor, authenticated handoff, and selected verifier package. Direct handoff
and root success remain v2 and v1 respectively. Failure emits no receipt.

`mesh-package build-bootstrap-verifier` accepts only a production-identity
Linux or Windows `amd64` or `arm64` verifier whose compiled version, commit, build time,
security floor, platform, Go build settings, and main package match the
requested artifact. It rejects installer trust/compatibility frames and
publishes without replacement. The deterministic uncompressed USTAR contains
exactly canonical `package.json` and `bin/mesh-bootstrap-verify` on Linux or
`bin/mesh-bootstrap-verify.exe` on Windows; its receipt
prints both the package metadata digest and complete artifact digest.

For example, after deriving the standard canonical build-identity frame as
`VERIFIER_IDENTITY`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -buildvcs=false \
  "-ldflags=-buildid= -X mesh/internal/buildinfo.Identity=${VERIFIER_IDENTITY}" \
  -o mesh-bootstrap-verify ./cmd/mesh-bootstrap-verify

mesh-package build-bootstrap-verifier \
  --version 1.2.3 \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --source-date-epoch 1784649600 \
  --security-floor 1 \
  --os linux \
  --arch amd64 \
  --verifier ./mesh-bootstrap-verify \
  --output ./mesh-bootstrap-verifier-linux-amd64.tar
```

The build identity's canonical UTC time must equal `SOURCE_DATE_EPOCH`, and
all other identity arguments must match too. Build the same artifact twice
from isolated reviewed inputs and require byte equality before publication.

Build the Linux `arm64` and Windows `amd64`/`arm64` packages from the same
identity and toolchain, then bind all four packages and the canonical root into
one expiring handoff:

```sh
mesh-release create-bootstrap-handoff \
  --root ./root-v1.json \
  --verifier-package ./mesh-bootstrap-verifier-linux-amd64.tar \
  --verifier-package ./mesh-bootstrap-verifier-linux-arm64.tar \
  --verifier-package ./mesh-bootstrap-verifier-windows-amd64.tar \
  --verifier-package ./mesh-bootstrap-verifier-windows-arm64.tar \
  --issued 2026-07-21T12:00:00Z \
  --expires 2026-08-20T12:00:00Z \
  --output ./bootstrap-handoff.json
```

The command statically revalidates all four complete USTAR representations and
their embedded ELF or PE files. It requires exactly one package per supported
OS/architecture pair, one production build identity and Go version, a verifier
security floor at least as high as root version 1, and a handoff validity
window no longer than 31 days and wholly inside the root validity. The output
is canonical, create-only `mesh-bootstrap-handoff-v2` JSON. Legacy v1 Linux-only
handoffs remain readable but cannot select a Windows verifier. The handoff is deliberately
unsigned because a root cannot authenticate its own digest.

Turn that handoff into the preferred file-shaped authority outside the public
origin staging tree:

```sh
mesh-release create-bootstrap-anchor \
  --handoff ./bootstrap-handoff.json \
  --output /independent-transfer/bootstrap-anchor.json
```

The create-only `mesh-bootstrap-anchor-v2` file repeats the reviewable channel,
handoff, root, build, and ordered Linux/Windows verifier-package facts and binds the
handoff's exact size and SHA-256. It is also deliberately unsigned: custody
through the separately controlled transfer channel is its authority. Do not
add it to the origin index, serve it from the dashboard, or place it beside the
courier files.

This directory and bundle format are distribution mechanisms, not a trust
channel. Production must transfer the anchor through an operator channel
already trusted and independent of the installer origin, TLS endpoint, Mesh
control plane, and browser. Review its public facts and use its selected package
digest to authenticate the verifier USTAR before extraction. The verifier can
then authenticate the courier handoff from that same anchor and derive the root
digest itself. Directly transferring the exact handoff digest, or each USTAR
and root digest, remains supported. Fetching the anchor from the origin would
be circular and provides no bootstrap security.

After the verifier itself is trusted, authenticate a candidate without running
it:

```sh
mesh-bootstrap-verify \
  --handoff bootstrap-handoff.json \
  --handoff-anchor /independent-transfer/bootstrap-anchor.json \
  --root root-v1.json \
  --manifest mesh-install.bootstrap.json \
  --signature mesh-install.bootstrap.root-a.json \
  --signature mesh-install.bootstrap.root-b.json \
  --installer ./mesh-install
```

The independent anchor is stably read first. Its validity and canonical form
must pass before the handoff is opened; the handoff's exact size, digest, and
duplicated review fields must pass before the root is opened. The authenticated
root and selected platform must then match before the larger manifest,
signatures, or installer are opened. Every file except the independently
transferred anchor may arrive through an untrusted courier. On Linux, each
verifier input must be a stable, single-link regular file rather than a symlink.
The Windows reader rejects symlinks and detects identity, size, mode, and
timestamp drift across its bounded read; clean-host DACL, extraction, and
execution receipts remain required before the Windows path is supported.

Direct-handoff compatibility replaces `--handoff-anchor` with
`--expected-handoff-sha256` and emits v2. The lower-level direct-root mode omits
`--handoff`, uses `--expected-root-sha256`, and emits v1. Mixed, incomplete, or
missing authority arguments fail closed.

`mesh-release verify-bootstrap` is retained for compatibility and calls the
same internal verifier. New operator packages should contain only the narrow
`mesh-bootstrap-verify` binary, not the release-authoring utility.

For native Windows evidence, use
`scripts/windows-bootstrap-verifier-smoke.ps1` only after deriving the selected
package digest from the independently transferred anchor on a trusted operator
workstation. The harness authenticates the USTAR before extraction, uses a
private LocalSystem/Administrators staging DACL, executes only the extracted
verifier, and emits a create-only source-bound receipt. It never executes the
installer. Passing receipts from clean `amd64` and `arm64` hosts remain required.

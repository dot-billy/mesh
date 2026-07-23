# Versioned release trust and the Linux installer

Mesh has operator-invoked, threshold-authenticated online and offline Linux
installation for `amd64` and `arm64`. The first `mesh-install` binary is the
bootstrap trust decision: obtain and authenticate it through a channel that is
independent of the release URL, object store, TLS endpoint, and Mesh control
plane. None of those systems can supply or replace installer trust.

No production private signing key belongs in this repository, an installer,
an image, an artifact store, or control-plane state.

## Trust model

The separately authenticated installer contains exactly one canonical
`mesh-linux-installer-bootstrap-v2` frame. That frame carries canonical root
version 1, release epoch 1, and its digest. It has no runtime file, flag, URL,
environment, or API override. `meshctl` and other packaged executables must
carry no installer-trust frame.

The root document separates two roles:

- the **root role** authorizes the immediate next root and controls rotation,
  revocation, expiry, thresholds, replay floors, and release epochs;
- the **release role** signs exact channel and release manifests for the epoch
  declared by the current root.

Every root transition needs the threshold of the previous root role and the
threshold of the new root role. Root and release signatures use the same
domain-separated, length-bound detached-envelope format, but a release-role
signature never counts as a root vote. Duplicate or malformed envelopes do not
increase a threshold.

New channel and release metadata uses `mesh-channel-manifest-v2` and
`mesh-release-manifest-v2`. Both bind a positive release epoch. The channel
pins the exact release-manifest length and SHA-256; the release pins the exact
artifact URL, platform, length, and SHA-256. Legacy v1 channel/release data is
accepted only under the untouched version-1, epoch-1 root.

The installer persists accepted transitions as exact, append-only root-update
envelopes under `/var/lib/mesh-installer/trust/roots`. Current trust is always
derived by replaying that history from the compiled root. Installer state v3
binds accepted releases to epoch, root version, root digest, compiled
bootstrap-root digest, exact metadata/artifact/package digests, and the
original verification time.

## Key custody and initial root

Generate keys on separate secured POSIX signing systems. At minimum, keep two
independently controlled root keys and two independently controlled release
keys. Root keys should normally remain offline and must not share release-key
custody. Private files are create-only mode `0600`; signing accepts only
owner-controlled regular files at mode `0400` or `0600`.

```sh
mesh-release generate-key --private root-a.private.json
mesh-release export-public \
  --private root-a.private.json --public root-a.public.json
# Repeat on an independent host for root B and for release A and B.

mesh-release create-root \
  --output root-v1.json \
  --channel stable \
  --release-epoch 1 \
  --minimum-release-sequence 1 \
  --minimum-security-floor 1 \
  --issued 2026-07-20T12:00:00Z \
  --expires 2027-07-20T12:00:00Z \
  --root-threshold 2 \
  --root-public root-a.public.json \
  --root-public root-b.public.json \
  --release-threshold 2 \
  --release-public release-a.public.json \
  --release-public release-b.public.json

mesh-release inspect-root --root root-v1.json
```

Independently compare the printed root digest on the signing systems and build
host. Create the compiled public bootstrap from that exact root:

```sh
MESH_INSTALLER_TRUST="$(mesh-release installer-policy --root root-v1.json)"

go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= \
    -X mesh/internal/buildinfo.Identity=$MESH_BUILD_IDENTITY \
    -X mesh/internal/installtrust.Identity=$MESH_INSTALLER_TRUST" \
  ./cmd/mesh-install
```

`installer-policy` is retained as the command name for compatibility; it now
emits the versioned-root bootstrap, not a replaceable static key list. The
inner Linux `package.json` retains its established installer-trust JSON field
name but binds the compiled initial-root digest. Package metadata is checked
against the installer binary and can never become an authority itself.

Linux bundle v3 also carries `installer_state_read_min`,
`installer_state_read_max`, and `installer_state_write_version`. `mesh-install`
contains one canonical installer-only compatibility frame in a read-only ELF
section. Release assembly requires that frame to match bundle metadata, and
staging requires the candidate range to include the exact installer-state
schema it will inherit before publishing any release directory or switching a
managed link. The frame is authenticated by the threshold-signed outer
artifact digest; it is not a new trust root. Existing bundle v2 has one fixed
bridge for state v3 because that implementation is already known to read v2
and v3 and write v3. It is rejected for any future state version, which forces
the next schema migration to carry an explicit authenticated contract.

Authorize the exact first binary with the root role after the build host has
statically proved that its sole compiled bootstrap is this root:

```sh
mesh-release create-bootstrap-manifest \
  --output mesh-install.bootstrap.json \
  --root root-v1.json \
  --installer ./mesh-install \
  --arch amd64 \
  --issued 2026-07-20T12:05:00Z \
  --expires 2026-08-20T12:05:00Z

mesh-release sign \
  --private root-a.private.json \
  --manifest mesh-install.bootstrap.json \
  --signature mesh-install.bootstrap.root-a.json
# Repeat the exact-byte signature independently with root B.
```

The canonical, maximum-31-day bootstrap manifest contains no URL. It binds the
exact root, compiled bootstrap, production build identity, Go version,
platform, installer length, and installer SHA-256. It uses a distinct
`bootstrap` signature domain. Release-role keys cannot authorize it.

After reproducibly building the four supported standalone-verifier packages,
bind them and root version 1 into one unsigned canonical handoff:

```sh
mesh-release create-bootstrap-handoff \
  --root root-v1.json \
  --verifier-package mesh-bootstrap-verifier-linux-amd64.tar \
  --verifier-package mesh-bootstrap-verifier-linux-arm64.tar \
  --verifier-package mesh-bootstrap-verifier-windows-amd64.tar \
  --verifier-package mesh-bootstrap-verifier-windows-arm64.tar \
  --issued 2026-07-20T12:05:00Z \
  --expires 2026-08-20T12:05:00Z \
  --output bootstrap-handoff.json

mesh-release create-bootstrap-anchor \
  --handoff bootstrap-handoff.json \
  --output /independent-transfer/bootstrap-anchor.json
```

The anchor is canonical, unsigned, and create-only. Carry that exact file over
a channel independent of the handoff, installer, manifest, signatures, release
origin, TLS endpoint, control plane, and browser; its independent custody is
the authority. Keep it outside the origin generation. Review its channel,
handoff, root, build, and ordered package facts, then use its selected package
digest to authenticate the verifier USTAR before extraction. Directly carrying
the handoff SHA-256 or the root plus selected package digest remains equivalent.
On a host where the narrow verifier has been authenticated this way, verify
without executing the candidate:

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

The standalone executable has no signing, key-generation, download,
extraction, or installation command. It reads the independent anchor before
the courier handoff, authenticates the handoff's exact bytes and repeated
review fields before opening the root, requires that root and the exact host OS/architecture
to match the handoff, and only then opens the larger manifest, signatures, and installer.
It checks root-role threshold signatures, validity, and the downloaded ELF or
PE's exact bytes, build identity, platform, sole v2 bootstrap frame,
installer-state compatibility frame, and embedded root. On Linux it
rejects symlinked or multiply linked inputs and checks file identity through
the complete bounded read. It never runs or installs the candidate and emits
a bounded v3 JSON receipt containing the anchor, handoff, selected package, and
root digests. Direct-handoff mode accepts `--expected-handoff-sha256` and emits
v2; direct-root mode accepts `--expected-root-sha256` and emits v1. Exactly one
authority mode is permitted. `mesh-release verify-bootstrap` remains a
compatibility entry point backed by the exact same implementation.

A verifier downloaded beside the installer is not independently trusted and
could fake success. Build its deterministic packages under the
[verifier distribution contract](../packaging/bootstrap-verifier/README.md)
and independently transfer the exact anchor before selecting one, or publish the
installer SHA-256 itself over the independent channel and check it with the
host's already trusted `sha256sum`.

The URL shown by Mesh is location guidance, not evidence that the binary,
manifest, verifier, or root is authentic. The production origin image has an
exact image-security gate, a digest-only Compose contract, a Cosign/public-key
verification command, and a read-only runtime gate binding both receipts to the
running local image, rendered service, selected generation, and exact
container. Publishing the real scanned and signed image, independently
provisioning its public key, retaining its security/signature/runtime/audit
evidence, provisioning the origin, operating the independent bootstrap-anchor
channel, and performing the real root-custodian ceremony remain external
deployment work.

## Create and sign a release

For Linux, build `mesh-install` and `meshctl` with the same canonical build
identity, then build the deterministic bundle with `mesh-package build-linux`.
Run the [final Linux package security gate](linux-package-security.md) against
that exact candidate and retain its canonical receipt. For Windows, build the
locked source-authenticated runtime with `mesh-deps
build-nebula-windows-runtime`, build the deterministic staging artifact with
`mesh-package build-windows`, externally sign and natively verify the selected
PEs, assemble with `mesh-package build-windows-signed`, and run the [final
signed Windows bundle security gate](windows-package-security.md) against the
exact result. For Darwin, build
the locked runtime with `mesh-deps build-nebula-darwin-runtime`, build the
deterministic staging artifact with `mesh-package build-darwin`, and run the
[Darwin staging-bundle security gate](darwin-package-security.md) against the
exact result. Create root-derived
v2 metadata; channel, epoch, thresholds, and minimum floors cannot be
contradicted by command-line input:

```sh
mesh-release create-release-manifest \
  --output release.json \
  --root root-v1.json \
  --version 1.2.3 \
  --sequence 42 \
  --security-floor 1 \
  --issued 2026-07-20T12:00:00Z \
  --expires 2026-07-22T12:00:00Z \
  --os linux \
  --arch amd64 \
  --artifact-url https://releases.example/mesh/1.2.3/linux-amd64.tar \
  --artifact ./mesh-linux-bundle.tar \
  --linux-package-security-receipt \
    ./linux-package-security/<artifact-sha256>-<UTC>/receipt.json

mesh-release create-channel-manifest \
  --output channel.json \
  --root root-v1.json \
  --release-manifest release.json \
  --manifest-url https://releases.example/mesh/1.2.3/release.json \
  --issued 2026-07-20T12:00:00Z \
  --expires 2026-07-22T12:00:00Z

mesh-release sign \
  --private release-a.private.json \
  --manifest release.json \
  --signature release.signer-a.json
mesh-release sign \
  --private release-a.private.json \
  --manifest channel.json \
  --signature channel.signer-a.json
# Repeat both exact signatures with release signer B.
```

Signing never re-encodes the manifest. A whitespace or newline change produces
different signed bytes. All authoring and assembly outputs are create-only and
read back before success is reported.

Every Linux and Darwin artifact requires exactly one canonical package-security
receipt whose platform architecture, version, security floor, size, and
SHA-256 match that artifact. Every Windows artifact requires both that package
receipt and a fresh native Authenticode receipt for all four exact PEs under
the compiled signer policy. Multi-architecture manifests repeat the applicable
receipt flags once per candidate. Each receipt must be no more than 24 hours
old with at most five minutes of future clock skew, and each package receipt's
bound Grype database must have been no more than 72 hours old at verification.
A missing, duplicate, noncanonical, stale, future, policy-drifted, or mismatched
receipt fails before the output is created.
`--test-only-allow-unscanned-linux-artifact` and
`--test-only-allow-unscanned-windows-artifact` and
`--test-only-allow-unscanned-darwin-artifact` exist only for synthetic
fixtures and must never appear in a production signing workflow. Receipts are
release-authoring evidence; the threshold-signed manifest remains artifact
authority.

## Rotate or revoke keys

To revoke or replace release keys, create successor root `N+1` with a new
release role and normally increment the release epoch. Root-only rotation may
keep the release epoch unchanged and does not require re-signing otherwise
valid release metadata.

```sh
# Generate/export new release C and D keys on independent hosts first.
mesh-release create-root \
  --output root-v2.json \
  --previous-root root-v1.json \
  --release-epoch 2 \
  --issued 2026-08-01T12:00:00Z \
  --expires 2027-08-01T12:00:00Z \
  --root-public root-a.public.json \
  --root-public root-b.public.json \
  --release-public release-c.public.json \
  --release-public release-d.public.json

mesh-release sign \
  --private root-a.private.json \
  --manifest root-v2.json \
  --signature root-v2.old-a.json
mesh-release sign \
  --private root-b.private.json \
  --manifest root-v2.json \
  --signature root-v2.old-b.json

mesh-release assemble-root-update \
  --output root-v1-to-v2.update.json \
  --previous-root root-v1.json \
  --root root-v2.json \
  --signature root-v2.old-a.json \
  --signature root-v2.old-b.json
```

Because this example retains the same root-role keys, those signatures satisfy
both old and new root thresholds. When rotating root keys, also sign exact
`root-v2.json` with the new root-role threshold and include those envelopes.
`assemble-root-update` verifies both thresholds and the immediate-successor
rules before publishing.

Create epoch-2 release/channel manifests with `--root root-v2.json` and sign
them only with release C and D. Omitting a compromised release key from the new
root revokes it for every new decision. An artifact downloaded after preflight
is reverified at the privileged apply boundary, so a root accepted during the
download can still revoke its signer.

## Offline snapshots

The v2 snapshot carries an ordered root chain followed by the exact signed
release data and artifact. The assembler sorts root updates by decoded version
and rejects duplicates, gaps, unstable inputs, and unknown output entries.

```sh
mesh-release assemble-snapshot \
  --output ./mesh-1.2.3-linux-amd64.snapshot \
  --root-update ./root-v1-to-v2.update.json \
  --channel-manifest ./channel.json \
  --channel-signature ./channel.signer-c.json \
  --channel-signature ./channel.signer-d.json \
  --release-manifest ./release.json \
  --release-signature ./release.signer-c.json \
  --release-signature ./release.signer-d.json \
  --artifact ./mesh-linux-bundle.tar

sudo /path/to/authenticated/mesh-install install \
  /absolute/path/to/mesh-1.2.3-linux-amd64.snapshot
```

Repeat `--root-update` for every required successor. It is safe to include an
already accepted byte-identical prefix. A v2 snapshot with no rotation still
contains an empty `root_updates` array.

## Online bundles

The online bundle v2 carries the same exact root chain, channel/release bytes,
and detached signatures. It carries no artifact and no alternative trust
input. The bounded HTTPS response is a courier only.

```sh
mesh-release assemble-online-bundle \
  --output ./mesh-1.2.3-online-bundle.json \
  --root-update ./root-v1-to-v2.update.json \
  --channel-manifest ./channel.json \
  --channel-signature ./channel.signer-c.json \
  --channel-signature ./channel.signer-d.json \
  --release-manifest ./release.json \
  --release-signature ./release.signer-c.json \
  --release-signature ./release.signer-d.json
```

Publish in this order:

1. the exact artifact at its immutable signed URL;
2. every immutable root-update object needed for audit/reassembly;
3. the immutable release and online bundle;
4. the stable channel object only after exact readback succeeds.

The repository may be served by the hardened [release-origin container](../packaging/origin/README.md). Create a new canonical object allowlist with `mesh-release create-origin-index`; never edit an indexed file in place. `mesh-release publish-origin-generation` copies only those exact objects into a create-only content-addressed tree, fsyncs and seals it, and publishes through Linux no-replace rename. `inspect-origin-generation` checks its canonical receipt, exact tree/modes, index digest, every object, and production-store readiness. Compose selects that one directory, preventing repository/index mismatch and making rollback an exact retained-generation selection rather than a channel rewrite. Before image publication, the [origin image security gate](origin-image-security.md) freezes the exact Linux amd64 Docker ID and binds its complete scratch filesystem, SBOM, vulnerability policy, and secret results. The post-start v2 runtime receipt requires that canonical evidence plus the independent signature receipt and proves the running local image ID/platform agrees with it. `mesh-origin` verifies every indexed size and SHA-256 before startup, retains the opened descriptors, serves no unlisted path, disables redirects and content transformation, applies a 30-second revalidating cache policy to `/channels/...`, and applies a one-year immutable policy to every release object. A changed open file fails `/readyz` and that object's request closed. From an independent operator or monitor host, `mesh-origin-audit` compares the public HTTPS route to the selected local generation, verifies TLS and exact readiness/security behavior, performs HEAD and full digest-checked GET requests for every object, verifies negative route/write behavior, and emits one create-only canonical external-audit receipt. Run `make release-origin-smoke` to build a disposable native-TLS origin, author a fresh 2-of-2 release, prove the two-receipt runtime custody chain and mismatch failure, publish and inspect two generations, select and externally audit the candidate and retained prior generation in turn, publish the complete two-architecture bootstrap courier set while retaining a create-only anchor outside both generations, authenticate the fetched handoff from that anchor, derive and verify the selected package and root, verify the fetched installer without execution, verify v3 and v2 bootstrap-receipt compatibility, verify the online release through the production client, and prove mutation detection, no-receipt failure, and cleanup.

This origin is still only a public courier. Its index, generation receipt, and external-audit receipt are not a new trust root, and their SHA-256 values do not replace signed release metadata. Production deployment still requires separately controlled signing systems, authenticated image publication, public DNS/TLS, a real durable storage and retention policy for the implemented immutable generations, deployment of the implemented auditor into an alerting/receipt-retention system, and an independently administered bootstrap-anchor transfer channel.

Then, using the independently authenticated bootstrap binary:

```sh
sudo /path/to/authenticated/mesh-install install-online \
  'https://releases.example/channels/stable/bundle.json'
```

One fixed UTC start time governs root and release expiry for the attempt. The
installer fetches and strictly decodes the bounded bundle, replays compiled and
persisted trust, verifies and fsyncs each root transition, requires the final
root to be current, and authenticates the release before requesting an
artifact. It accepts no trust flags, redirects, proxy environment, cookies,
credentials, compression, or URL normalization. TLS protects transport; the
compiled root chain authorizes the release.

The web install guide may display this exact public bundle URL and the
configured `bootstrap-handoff.json` courier URL. Both are location hints only.
The guide never receives or displays the bootstrap anchor or expected handoff
digest. It explicitly requires independently transferred authority before
trusting the selected verifier, root, or `mesh-install`.

## Expiry and recovery

A root may authenticate only its exact immediate successor. An expired current
or intermediate root may authorize a catch-up transition, but after the
supplied chain is processed the final root must be unexpired at the attempt's
fixed start time. Publish and distribute successors well before expiry.

Each verified root transition is persisted before the next is evaluated. If a
later transition, release signature, artifact transfer, cancellation,
materialization, or activation fails, earlier accepted roots remain durable;
installer state and managed runtime do not advance. Retry with the corrected
contiguous chain. Re-supplying accepted byte-identical updates is idempotent;
different bytes at an accepted version are root equivocation and fail closed.

If installer state v2 exists, its one-time migration to v3 is allowed only
under the exact compiled version-1 root, with empty root history and no pending
transaction. Finish `mesh-install recover` before attempting new trust input.
An already fsynced v3 pending transaction may recover under its recorded
historical root and original verification time; new candidates use only the
latest root.

Compromise of a release key is handled by a threshold-authorized successor
root that removes it. Compromise of one root key remains bounded while the root
threshold is intact. If an attacker controls a root threshold, or if the first
bootstrap binary/root was compromised, the in-band chain cannot repair that
trust decision: stop distribution, establish a new independently authenticated
bootstrap/root through an out-of-band incident ceremony, and treat affected
installations as requiring explicit rebootstrap or replacement.

## Release verification gate

The versioned-root implementation completed its release-quality gate on
2026-07-20. Before distributing a later installer change, rerun the full Go
suite and vet, the targeted release/installer race suites, browser and shell
syntax tests, Linux `amd64`/`arm64` builds, non-Linux fail-closed builds, and
production binary-frame/privacy inspection. Finish with
`make linux-install-smoke`; its final `PASS` proves online and offline root
rotation, revocation, expired-intermediate catch-up, exact v2 migration,
activation, rollback, recovery, races, runtime gates, process provenance, and
cleanup against an isolated privileged systemd host.

## Remaining platform work

The Linux privileged installer has native installation receipts. The Windows
privileged installer and runtime foundation now cross-build with protected
DACLs, no-reparse traversal, exact SCM configuration, durable metadata and
activation/rollback journals, offline snapshot intake, and canonical operator
commands. Direct-root and v2 handoff/anchor bootstrap tooling statically package,
select, and verify both Windows verifier and installer architectures. Clean-host
native install, interruption/reboot, upgrade/rollback, enrollment/packet,
uninstall, and resolver receipts plus signed-bundle Authenticode production
evidence remain separate gates before support.
Bootstrap binary distribution/authentication also remains an operator-owned
external process; Mesh intentionally does not claim to self-bootstrap.

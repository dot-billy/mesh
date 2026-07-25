# Authenticated Online Release Retrieval Design

**Date:** 2026-07-20

**Status:** Approved for implementation

## Purpose

Mesh already has a threshold-authenticated, rollback-resistant offline Linux
installer. The missing link is a safe online courier that can retrieve the
same release metadata and artifact from a static HTTPS repository, then feed
their exact bytes into that existing offline boundary.

This slice also connects the installer to the administrator web experience.
After an administrator creates a node, the enrollment dialog will show the
three real host-side transitions: install an authenticated Mesh release,
enroll with the one-time credential through standard input, and activate the
installer-managed services.

The online layer is not a new release authority. HTTPS provides transport and
availability. Release authenticity continues to come exclusively from the
threshold policy compiled into the separately authenticated `mesh-install`
bootstrap binary, together with the installer's persisted anti-replay state.

## Scope

This design adds:

- a bounded online metadata-bundle format containing exact existing manifest
  and detached-signature bytes;
- deterministic offline release tooling that assembles that bundle;
- hardened HTTPS metadata and artifact retrieval in `mesh-install`;
- a new `mesh-install install-online EXACT_BUNDLE_URL` command that ends at the
  existing `ApplySnapshot` boundary;
- root-private online intake, cleanup, cancellation, and crash semantics;
- optional control-plane configuration for the public bundle URL;
- an authenticated install-configuration API and an accurate three-step
  enrollment dialog;
- unit, browser, subprocess, and real systemd-container proofs.

This design does not add:

- bootstrap-binary distribution or authentication;
- release signing-key rotation or revocation;
- private-repository credentials, custom certificate authorities, proxy
  configuration, redirect following, or resumable HTTP range downloads;
- automatic polling or unattended upgrades;
- a control-plane metadata or artifact proxy;
- native macOS or Windows installation and code signing;
- installer-state schema compatibility changes;
- promotion of runtime observations into lifecycle health.

Those remain separate milestones. Until bootstrap distribution is implemented,
the UI must say that `mesh-install` itself must be obtained and authenticated
independently.

## Security invariants

1. Candidate files, command-line values, environment variables, HTTP headers,
   TLS peers, the control plane, and the online bundle cannot replace or extend
   the compiled release keys, threshold, channel, replay floor, security floor,
   platform, supported semantics, or current verification time.
2. No unsigned top-level URL or locator from the online bundle is dereferenced.
   The only artifact URL used by the online installer is selected from the
   threshold-authenticated inner release manifest after the channel-to-release
   binding is proved.
3. The online bundle is an unsigned transport container. Its decoded inner
   bytes are passed unchanged to the existing release verifier. Re-encoding a
   manifest before verification is forbidden.
4. The artifact body must have the exact authenticated byte length and SHA-256
   before it can enter release extraction or installation.
5. A candidate is authenticated against installer state before its artifact is
   requested and is authenticated again against current state immediately
   before installation. State advancement during a download causes safe
   rejection, never stale installation.
6. No online failure commits installer state or changes managed binaries,
   links, units, service state, or runtime gates. Creating and cleaning the
   dedicated private intake surface is allowed.
7. Once the existing installer writes a prepared transaction, its journal,
   rollback, completion-proof, and `recover` rules remain the only authority.
8. Enrollment tokens never appear in command arguments, URLs, generated install
   commands, or exported environment variables.
9. The Mesh control plane may display a configured bundle URL but never fetches
   a release, receives a signing key, verifies a release on the installer's
   behalf, or claims that the URL itself is trusted.

## Online metadata bundle

The new format is `mesh-online-release-bundle-v1`. It is canonical compact JSON
followed by exactly one LF byte:

```json
{
  "schema": "mesh-online-release-bundle-v1",
  "channel_manifest": "BASE64URL_EXACT_BYTES",
  "channel_signatures": ["BASE64URL_EXACT_BYTES"],
  "release_manifest": "BASE64URL_EXACT_BYTES",
  "release_signatures": ["BASE64URL_EXACT_BYTES"]
}
```

The example is expanded for readability; the encoded form has no insignificant
whitespace. Every byte field uses canonical unpadded base64url. Decoding and
encoding it again must produce the same string.

The top-level object has exactly the five fields shown. It deliberately has no
URL, path, artifact, key, policy, threshold, platform, version, sequence,
clock, expiry, or security-floor override.

The encoded document is limited to 6 MiB. After decoding:

- each manifest is between 1 byte and `release.MaxManifestSize`;
- each signature array has between 1 and
  `release.MaxSignatureEnvelopes` entries;
- each signature envelope is between 1 byte and `release.MaxEnvelopeSize`;
- byte-identical envelopes within or across roles are rejected;
- the complete document must round-trip to the one canonical JSON encoding.

The 6 MiB outer bound accommodates both current maximum-sized manifests and
both current maximum signature sets after base64url expansion, with 698,708
bytes left for bounded JSON overhead. Any future increase to an inner release
limit requires an explicit transport-schema and outer-bound review; it must not
silently weaken or bypass either bound.

The bundle is intentionally small and contains no artifact bytes. Removing or
reordering valid signatures can cause denial of service but cannot create
authority. The existing threshold verifier rejects missing, duplicate,
untrusted, malformed, or invalid signatures.

## Release publication

`mesh-release` gains:

```text
mesh-release assemble-online-bundle \
  --output BUNDLE \
  --channel-manifest CHANNEL \
  --channel-signature SIGNATURE ... \
  --release-manifest RELEASE \
  --release-signature SIGNATURE ...
```

The command remains non-trusting. It has no key flags and does not bless its
inputs. It reuses the release tool's stable-input protections: canonical
absolute resolution where required, no symlink inputs, bounded regular files,
anchored descriptors, identity checks before and after reads, deterministic
signature ordering by exact-byte SHA-256, duplicate rejection, create-only
output, fsync, and exact readback.

The output is a public mode-0644 regular file because it contains no secret.
Normal failures remove only the exact temporary output created by the
invocation. Publication tooling never overwrites an existing output.

Operators publish in this order:

1. Upload immutable, versioned artifacts referenced by the release manifest.
2. Upload the immutable, versioned online bundle.
3. Verify both public objects from a separate reader.
4. Atomically replace or switch the stable channel object, such as
   `/channels/stable/bundle.json`, only after the immutable objects exist.

The stable channel response should use cache controls that require
revalidation. A stale cache can create a bounded freeze within the signed
manifest's validity window; expiry and the installer's persisted sequence floor
reject older or expired releases. The client also requests revalidation, but
HTTP cache behavior is never treated as rollback protection.

## Hardened network transport

Online retrieval uses a dedicated production HTTP client derived from the
existing hardened dependency downloader rather than `http.DefaultClient`.

It has:

- system certificate roots and TLS 1.2 or newer;
- no proxy from environment variables;
- no redirects, cookies, compression, connection reuse, or authentication
  forwarding;
- one connection per request;
- bounded dial, TLS handshake, response-header, and whole-request timeouts;
- bounded response headers;
- `Accept-Encoding: identity` and a versioned Mesh installer user agent;
- context cancellation on every request.

The configured bundle URL must be one canonical absolute HTTPS URL with a
nonempty host and clean absolute path, no user information, fragment, query,
opaque form, whitespace, dot segments, or explicit default port. There is no
`--insecure`, key, threshold, channel, clock, platform, proxy, CA-file, or
redirect override.

The metadata response must be HTTP 200 with an absent or identity content
encoding. A declared content length greater than the outer limit is rejected
before reading. The body is read through an outer-limit-plus-one reader so
unknown-length or dishonest responses remain bounded.

After metadata authentication selects the platform artifact, the signed
artifact URL is requested directly with redirects disabled. The response must
be HTTP 200, have absent or identity content encoding, declare the exact signed
content length, and stream exactly that many bytes plus an overrun check while
computing SHA-256. The destination is synchronized only after both length and
digest match. No redirect target can inherit the authority of a signed URL.

## Installer orchestration

`mesh-install` gains the exact command:

```text
mesh-install install-online EXACT_BUNDLE_URL
```

It accepts exactly one positional URL and no online trust flags. Existing
`version`, `install`, `recover`, `activate`, and `rollback` behavior remains
unchanged. Success emits the existing `InstallResult` JSON so online and
offline callers share one durable result contract.

The command performs these phases:

1. Verify the production bootstrap build identity and compiled trust policy.
2. Establish and validate `/var/lib/mesh-installer` and the dedicated
   root-owned mode-0700 online-intake root.
3. Acquire a separate nonblocking mode-0600 online-intake lock. This prevents
   two downloads without holding the installer transaction lock across network
   I/O.
4. Reconcile only recognized stale children of the dedicated intake root.
   Unknown names, object types, ownership, modes, links, or entries fail closed
   and are not deleted.
5. Download, strictly decode, and snapshot the metadata bundle into a newly
   allocated root-owned mode-0700 intake child.
6. Briefly acquire the existing installer state lock, load and validate current
   state, reject an unfinished transaction, and run `VerifySignedCandidate`
   against that exact snapshot. Release the state lock.
7. Download the selected artifact into the private intake child, enforcing its
   authenticated size and SHA-256 while streaming and synchronizing it.
8. Materialize the existing `mesh-linux-install-snapshot-v1` layout in that
   same private child: exact decoded metadata bytes, deterministic signature
   names, authenticated artifact bytes, and canonical `install.json`. Files
   become mode 0400 before the directory is consumed.
9. Call the existing `ApplySnapshot` with that absolute snapshot directory.
   `ApplySnapshot` reacquires current state, re-verifies the same metadata,
   recaptures the artifact into its anonymous inode, validates the archive, and
   executes the existing crash-durable transaction.
10. Return the existing result and remove only the exact online intake child.

The state-lock acquisition in phase 6 is deliberately short. If another
offline install, online install, rollback, or recovery advances or journals
state while the artifact downloads, phase 9 observes current state and rejects
the stale or conflicting candidate. No result from phase 6 is used to skip the
second verification.

The online-intake lock is separate from `state.lock`. Offline `recover` and
rollback therefore remain available during an interrupted or slow download.
The final `ApplySnapshot` uses the existing nonblocking transaction lock and
fails clearly if another transaction is active.

## Cleanup, cancellation, and crash behavior

The intake root is a dedicated installer-owned namespace, not an
operator-selected directory. Each invocation creates one random child and
remembers its anchored identity. Normal success, transport failure,
authentication failure, artifact mismatch, or cancellation removes only that
exact child and synchronizes the parent.

An abrupt process death before `ApplySnapshot` can leave one recognized partial
child. The next `install-online` invocation, while holding the intake lock,
may remove it only after rooted inspection proves the exact allowed name,
ownership, mode, link, entry, and size bounds. Unexpected content fails closed
for operator inspection. Version 1 does not resume a partial HTTP body.

If process death occurs after `ApplySnapshot` has committed a prepared
transaction, the existing `state.json` pending journal is authoritative. The
next install refuses a new candidate and tells the operator to run
`mesh-install recover`. Cleanup of online courier bytes cannot clear or alter
that transaction.

Cancellation is honored during metadata and artifact transfer. Once the
existing installer detaches cancellation to complete rollback or final proof,
the online wrapper does not impose a competing recovery rule.

## Error contract

Errors identify their stage without exposing response bodies, credentials,
private filesystem content, or attacker-controlled multiline headers. Stable
stage prefixes distinguish:

- bundle URL validation;
- metadata request or bounded read;
- online-bundle decoding;
- first candidate authentication;
- artifact request, length, or digest;
- offline snapshot materialization;
- final candidate authentication or installer transaction;
- intake cleanup or recovery-required state.

The command uses a nonzero exit status for every failure. It does not emit a
success-shaped `InstallResult` until the existing installer completion proof
succeeds.

## Control-plane configuration and API

`mesh-server` gains optional configuration:

```text
--linux-install-bundle-url EXACT_BUNDLE_URL
```

Startup applies the same canonical HTTPS URL rules as the installer. The value
is nonsecret and does not become part of persisted network state. It is passed
to `httpapi.Options`, whose constructor validates that the supplied value is
already canonical.

An authenticated administrator endpoint returns one strict response:

```json
{
  "schema": "mesh-install-guide-v1",
  "linux": {
    "online_available": true,
    "bundle_url": "https://releases.example/channels/stable/bundle.json"
  }
}
```

When the flag is absent, `online_available` is false and `bundle_url` is
omitted. The endpoint is informational: the server does not request the URL or
claim that it matches the bootstrap binary's compiled trust policy.

## Web enrollment experience

The browser loads and strictly validates the install guide after administrator
authentication. When online installation is configured, the node enrollment
dialog shows three numbered actions:

1. **Install Mesh.** Explain that the bootstrap binary must be independently
   authenticated, then offer a copy button for:

   ```sh
   sudo ./mesh-install install-online 'EXACT_BUNDLE_URL'
   ```

2. **Enroll this node.** Prompt in the local shell and send the one-time token
   only through `meshctl enroll --token-file -`. The token is held in a
   non-exported shell variable only long enough to write standard input and is
   unset afterward. The command keeps the current exact server, state, output,
   Nebula, and Nebula-cert paths.
3. **Activate managed services.** Offer:

   ```sh
   sudo /usr/local/bin/mesh-install activate
   ```

The activation step replaces the current direct
`systemctl enable --now mesh-agent.service` instruction, which bypasses the
installer's runtime-gate contract.

When no online URL is configured, the first step remains an honest external
installation prerequisite. The enrollment and activation commands still use
stdin and `mesh-install activate`; absence of online retrieval must not retain
the unsafe or inaccurate instructions.

The browser constructs commands with DOM text APIs, never HTML interpolation.
The configured URL is validated again before display. Enrollment token text is
never concatenated into a command.

## Compatibility

- Existing release, channel, signature, public-key, installer-policy, build,
  offline-snapshot, Linux-bundle, and installer-state schemas do not change.
- Existing offline release tooling and `mesh-install install` remain supported.
- Old control planes omit the install-guide endpoint; the browser treats that
  as online installation unavailable rather than inventing a URL.
- New control planes with no configured URL preserve the external-install
  workflow.
- The online bundle is a transport schema and cannot migrate or authorize
  installer state.
- The feature is Linux-only because `mesh-install` and the complete privileged
  installer boundary are Linux-only.

## Verification plan

Implementation is test-driven. Required proof includes:

### Bundle model and publisher

- exact schema, field set, canonical encoding, base64url round-trip, inner and
  outer size limits, signature counts, duplicate bytes, and malformed UTF-8;
- deterministic output independent of signature flag order;
- symlink, FIFO, directory, hard-link substitution, concurrent mutation,
  truncation, growth, output collision, fsync, and exact readback cases;
- proof that no private-key or trust-policy input is accepted.

### Transport and orchestration

- HTTPS-only canonical URL parsing and rejection of userinfo, fragments,
  queries, dot segments, whitespace, opaque URLs, and noncanonical ports;
- no redirects, proxy environment, cookies, compression, or credential
  forwarding;
- status, header, timeout, cancellation, absent body, declared-size, truncation,
  overrun, and digest cases;
- threshold failure, unknown signer, insufficient signatures, expiry, replay,
  same-sequence equivocation, unsupported floor, platform absence, and wrong
  channel;
- no artifact request before successful metadata authentication;
- state advancement between the two verification passes;
- pending-transaction and lock-contention behavior;
- normal cleanup, recognized crash-leftover cleanup, unknown-entry refusal,
  and no partial-download resume;
- CLI argument, output, cancellation, and existing-command regression tests.

### Server and browser

- configuration parsing, HTTPS normalization, unset behavior, and constructor
  parity;
- endpoint authentication, exact response fields, content type, and absence of
  trust claims;
- strict browser validation and old-server fallback;
- install, stdin enrollment, and activation command rendering;
- copy controls, URL text safety, token noninterpolation, focus, labels, and
  keyboard behavior;
- regression coverage for network, node, policy, recovery, health, and runtime
  telemetry views.

### Real Linux proof

Extend the existing systemd container smoke harness with a local static HTTPS
repository whose CA is installed into the container's system roots. Using the
production `mesh-release`, `mesh-install`, bundle, systemd units, and binaries,
prove:

- a first online install from a clean host;
- enrollment followed by installer activation;
- an online upgrade preserving managed service intent;
- exact rollback and recovery;
- corrupt outer metadata, invalid threshold, expired/replayed metadata, HTTP
  redirect, truncated/oversized artifact, and wrong digest leave no committed
  candidate or managed-runtime change;
- cancellation and a killed partial download are safely cleaned or reconciled;
- a state advance during download rejects the stale candidate;
- offline installation still succeeds through the unchanged command.

All Go tests, race-focused installer tests, `go vet`, browser tests, shell
syntax checks, cross-platform non-Linux build checks, privacy searches, and
temporary-resource cleanup audits must pass before this slice is described as
complete.

## Acceptance criteria

This slice is complete only when:

1. A production-policy `mesh-install` can retrieve a valid static HTTPS bundle
   and artifact and successfully traverse the existing offline installer
   boundary on a clean Linux systemd host.
2. The exact same candidate still passes the offline command, proving that the
   online layer did not create a second install authority.
3. Every untrusted transport or metadata failure is proved unable to commit
   installer state or mutate the managed runtime.
4. Replay, expiry, same-sequence equivocation, floor, platform, and concurrent
   state protections remain effective across both verification passes.
5. The control plane merely exposes a validated informational URL and never
   handles signing keys or release bytes.
6. The enrollment dialog accurately guides install, stdin-only enrollment, and
   installer activation, with secrets absent from generated commands.
7. Documentation states that bootstrap authentication, key rotation, native
   packages, and automatic updates remain outstanding.
8. The complete verification plan passes from a clean checkout and leaves no
   installer intake, container, process, or other smoke resource behind.

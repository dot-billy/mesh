# Mesh

Mesh is a security-first control plane for [Slack Nebula](https://github.com/slackhq/nebula). It turns CA creation, node enrollment, signed configuration rollout, certificate renewal, health reporting, credential rotation, and revocation into one managed lifecycle.

The current build is a working lifecycle foundation. JSON remains the default single-process backend; an explicit PostgreSQL exact-document preview supports multiple application replicas without claiming production database HA:

- A dedicated Nebula CA and Ed25519 configuration-signing key per network, encrypted at rest with AES-256-GCM.
- Safe IPv4 allocation, lighthouse discovery, node inventory, and deterministic Nebula configuration.
- Conservative routed-subnet ownership declared when a node is created: canonical IPv4 prefixes are reserved across the complete live control graph, embedded as exact Nebula certificate unsafe networks at enrollment, and propagated only after the owner activates. Crash-durable transfer and active-owner route-profile workflows move or edit exact prefixes with certificate-first additions and route-first removals. Multiple active enrolled gateways may safely own one exact same-network prefix; a strict route-policy API and dashboard render one deterministic weighted-ECMP route with bounded per-gateway weights, MTU, and metric controls.
- Explicit per-node site and failure-domain placement, kept separate from Nebula authorization groups, with editable dashboard metadata and diversity-aware readiness. Existing nodes migrate conservatively to `unassigned` instead of receiving invented placement.
- Thirty-minute one-time enrollment. The node generates its Nebula keypair and 256-bit agent credential locally; only the public key and credential hash reach the server.
- A fail-closed runtime prerequisite before enrollment reads a token or touches node state. Both `nebula` and `nebula-cert` must resolve and execute immediately, report one supported semantic version, and, in a production build, sit beside `meshctl` in the same authenticated installed release. Missing or split runtimes direct the operator to the signed online or offline installer instead of downloading an upstream moving `latest`.
- A token-scoped, no-store enrollment preflight. Before generating keys, writing the crash journal, or consuming the token, `meshctl` retrieves only the target role, Mesh CIDR, bounded lighthouse endpoint set, and token expiry; on Linux it rejects an intersecting non-default route and on every platform it requires every lighthouse DNS name to resolve from the future host. This point-in-time check does not dial or claim public UDP reachability.
- Crash-safe enrollment recovery through a private, fsynced node-side journal.
- Administrator-authorized recovery of an expired or unusable agent credential without replacing the node's Nebula identity, with a pinned signed recovery receipt and crash-safe exact retries.
- Signed, monotonic configuration revisions installed as complete immutable bundles behind an atomic `current` symlink.
- Scoped agent authentication, proactive certificate renewal, 90-day agent-credential rotation, and exact revision/digest/fingerprint heartbeats.
- Immediate administrator-driven same-key host-certificate rotation. The operation blocklists the old certificate through its expiry, invalidates outstanding agent-recovery tokens, advances one signed revision, and returns an idempotent audit receipt that the dashboard can replay safely after response loss or a same-tab reload.
- A secret-free authenticated fleet-health snapshot and dashboard, derived from one authoritative control-state read every 15 seconds, with setup grace, two-/five-minute heartbeat thresholds, typed lifecycle alerts, lighthouse redundancy, revocation-staleness detection, and exact per-network/fleet rollout convergence.
- A resumable per-network setup guide derived from that same authenticated snapshot. It keeps the network, first operational lighthouse, first operational member, and required lighthouse count visible after **Finish later**, selects one exact next action, and sends enrolled-but-nonoperational machines to diagnosis instead of counting them as progress. Pending credentials are never redisplayed, revoked inventory does not satisfy a stage, and the guide explicitly does not infer peer reachability.
- An on-demand authenticated deployment-readiness report and dashboard dialog. It proves managed-CIDR collision status, groups the fleet by declared site, requires every active node to have explicit placement and at least two active-lighthouse failure domains, counts active lighthouse redundancy, resolves bounded lighthouse DNS names from the control-plane vantage, requires fresh aggregate member-side DNS and all-lighthouse public-UDP evidence from every current active member, and accepts a privacy-preserving no-overlap result only after every current active node reports its bounded kernel route check. Raw routes, resolved addresses, and resolver diagnostics never leave the node.
- A separate authenticated aggregate-only runtime-observation projection and per-node dashboard line, bound to the exact displayed lifecycle heartbeat and explicitly classified as observational rather than healthy or end-to-end reachable. Consecutive attempted lighthouse probes are compared only under the same heartbeat-authenticated signed-config digest, so the UI can distinguish stable, recovered, degraded, changed, and unclassified evidence without exposing the digest or inventing history across a policy change or heartbeat gap. Missing, stale, invalid, or unsupported telemetry cannot clear or reclassify lifecycle health.
- Full issuance history and revocation of every still-valid certificate issued to a node. The dashboard's exact-name-, revision-, and idempotency-bound trust cutoff removes enrollment/recovery records, disables agent credentials, releases route ownership, advances one signed revision, and survives response loss or a same-tab reload; online managed peers receive the updated Nebula blocklist.
- Safe revoked-node archival after certificate authority has ended. Enrolled records remain non-removable until five minutes after the latest expiry across every issuance and revocation; the atomic cleanup removes expired blocklist/history records, writes a strict tombstone, and advances signed configuration once. Never-enrolled legacy revoked rows can be removed immediately without changing signed state.
- Per-network, least-privilege Nebula firewall policy with rules installed on every node, one certificate group, or one named node; peer selectors for any peer, a group, a named node, or an in-network IPv4/CIDR; exact per-node effective-policy preview; and crash-durable canary, convergence, rollback, and audit workflows.
- Managed per-network lighthouse DNS with a guided dashboard editor, explicit resolver addresses, optimistic revision checks, and signed rollout. Each active lighthouse binds the configured UDP port only on its own overlay IP; members never serve DNS, and enabling is rejected unless the inbound firewall covers that port. A separate explicit split-DNS option signs a per-node `mesh-native-dns-v1` policy and runs a bounded local suffix adapter; Linux registers only that domain on the Mesh-owned interface through systemd-resolved, while Windows owns one exact local-machine NRPT suffix rule pointing to the adapter on the node's overlay IP. Unrelated DNS is never forwarded. Linux has live proof; the Windows adapter has portable fault coverage and a gated native packet/cleanup harness but still needs clean-host receipts.
- Managed per-network Slack Nebula relays with a guided dashboard selector for 1 to 8 pending or active nodes, optimistic revision checks, exact active-relay addresses, and signed rollout. Selected nodes receive server-only relay configuration; every other node advertises only active selections. Revoking a selected relay removes it automatically. Relay support is experimental upstream, and each relay still needs direct underlay reachability from both peers.
- Guided zero-downtime per-network CA rotation. The dashboard prepares dual trust, waits for every active agent to acknowledge it, forces same-key host-certificate renewal under a replacement CA, gates removal of the old root on exact certificate/revision/fingerprint evidence, and then clears transition metadata. Optimistic revisions, recovery-replay fencing, actor-attributed audits, and a real two-node zero-packet-loss proof cover the complete staged lifecycle.
- A fail-closed systemd runtime contract: Nebula is stopped before startup sync, configuration freshness is bounded to five minutes by default, and a stale peer remains quarantined until signed state recovers.
- A Linux network-namespace proof that real Nebula peers exchange authenticated overlay packets before revocation and stop exchanging them after the signed peer blocklist is applied.
- A versioned release-root chain: separately controlled root and release roles authorize threshold-signed epoch-bound metadata, append-only signing-key rotation/revocation, exact online/offline root-chain carriage, and artifact size/SHA-256 verification.
- An explicit immutable HTTPS release-origin mechanism. `mesh-release create-origin-index` hashes one canonical object allowlist; Linux generation publication copies only those objects into a content-addressed, fsynced, sealed, no-replace tree with a canonical operational receipt. Inspection repeats the exact tree, mode, digest, and production-store checks, while Compose derives repository and index from one selected generation. Production Compose has no build or mutable-tag default and requires one registry repository plus manifest SHA-256; the local build is a separate opt-in override. The release-origin image gate freezes the exact Linux amd64 scratch Docker ID, validates all 18 paths, binds exact Syft/SPDX inventories, rejects High/Critical or fix-available Grype findings, and requires empty rootfs/binary-string Gitleaks reports. `mesh-origin-image-verify` independently authenticates the published registry digest with a provisioned Cosign public key. After start, read-only `mesh-origin-runtime-verify` chains both receipt hashes to the exact local Docker ID/platform, production Compose render, immutable generation, 64-character container ID, repository digest, Docker executable/socket, runtime hardening, and mounts. `mesh-origin-audit` then starts from the selected local generation and verifies the external TLS identity, exact readiness/security contract, every indexed HEAD and full digest-checked GET, and negative route/write behavior before writing a canonical external receipt. The read-only `mesh-origin` service opens and verifies every indexed object before serving, exposes no directory tree, distinguishes short-lived channel caching from immutable release objects, and fails readiness closed on in-place mutation. Its hardened scratch-container proof externally audits a candidate generation and the retained prior generation in turn, couriers the complete four-package Linux/Windows bootstrap verifier set while retaining the create-only authority anchor outside both generations, authenticates the fetched handoff from that anchor, derives and verifies the selected verifier package and root, verifies the root-authorized installer without execution, and then uses the production online client to verify a fresh 2-of-2 signed channel and exact artifact over native TLS. The origin remains untrusted and cannot authenticate the anchor, handoff, or first installer.
- A narrow standalone `mesh-bootstrap-verify` executable for the first-installer ceremony. It shares one verification implementation with the compatibility command in `mesh-release`, has no signing/install/download subcommands, reads an independently transferred canonical anchor before any courier file, or accepts the lower-level handoff/root digest modes, reads bounded regular-file snapshots, and never executes a candidate. Direct-root v1 authorization statically verifies either the Linux `mesh-install` ELF or Windows `mesh-install-windows.exe` PE, including exact platform build identity, compiled root, and the platform-specific installer-state frame. `mesh-package build-bootstrap-verifier` now packages exact Linux and Windows verifier executables for both architectures; the v2 handoff and v2 anchor require and select the complete four-package set by exact host OS/architecture while retaining read-only compatibility for Linux-only v1 handoffs. The release-origin proof exercises the four-package ceremony and Linux selection; clean-host Windows extraction/execution receipts remain outstanding.
- A lock-driven Slack Nebula dependency intake path that authenticates exact v1.10.3 archives, proves every member and executable build identity, and atomically stages any supported target from a secure Linux host without installing it.
- A complete Linux `amd64`/`arm64` install boundary: deterministic exact bundles, an independently authenticated compiled version-1 root, crash-durable root rotation/revocation, bounded online retrieval or root-private offline snapshots, durable epoch/sequence anti-rollback state, immutable releases, crash recovery, explicit rollback, exact systemd provenance, and separate installer and post-validation runtime gates. Bundle v3 also binds the installer-only state read/write contract found in the candidate `mesh-install` ELF and rejects a package before publication when it cannot read the inherited installer state; legacy bundle v2 has one exact state-v3 bridge and cannot cross a future schema boundary.
- A two-stage Windows `amd64`/`arm64` release boundary: deterministic unsigned v2 staging USTARs bind a production-identity `meshctl.exe`, reproducible security-patched Nebula PEs, and exact upstream Wintun bytes; `build-windows-signed` then accepts only three signed PEs that reconstruct to those unsigned members plus a fresh native receipt covering all four PEs and publishes final signed bundle-v3. Production-policy inspection seals the exact final tree; Syft/SPDX/Grype/Gitleaks emits a strict v2 package receipt, and release authoring fails closed without both matching package-security and native Authenticode receipts. Clean-host lifecycle proof remains separate.
- A cross-built [Windows installer/runtime foundation](docs/windows-path-security.md): a separate narrow `mesh-install-windows.exe` now drives canonical online or root-private offline intake, exact snapshot preparation, deterministic publication, crash recovery, runtime activation, authority-bound rollback, and recovery-safe runtime uninstall over compiled-root threshold metadata, append-only root history, durable release high water, exact signed-byte recovery, protected DACLs, no-reparse traversal, full-artifact selection, exact SCM service dispatch, and suspended Job Object containment. Uninstall removes only the gate, exact service, exact selector, and active/previous runtime state while retaining release trees, enrollment state, trusted-root history, and anti-rollback high water. Direct-root bootstrap manifests plus the four-package v2 handoff/anchor authorize, package, select, and statically inspect exact `amd64`/`arm64` verifier and installer PEs without execution. A compiled role-separated Authenticode policy enforces one SHA-256 signer, online whole-chain revocation, policy continuity between verifier and installer, and Mesh-versus-Wintun SPKI pins before activation; signed-bundle authoring and release preflight preserve that native proof. The Windows agent also owns a response-loss-safe NRPT split-DNS rule with exact effective-policy readback. Portable fault tests and both architecture builds pass. Clean-host bootstrap/lifecycle/uninstall/resolver receipts, real enrollment/packet proof, and installed-host review remain required before Windows support.
- A non-installing Darwin `amd64`/`arm64` staging boundary: deterministic exact USTARs bind a production-identity `meshctl`, reproducible security-patched thin Nebula Mach-O executables from the authenticated source/patch/toolchain lock and layered Darwin output lock, plus reviewed launchd assets. Production-policy inspection reconstructs every archive byte and seals the exact tree; a Syft/SPDX/Grype/Gitleaks gate emits one strict canonical receipt per architecture, and release authoring fails closed without matching receipts. This does not claim native installation, launchd activation, extended-ACL enforcement, codesigning, notarization, runtime telemetry, or installed-host support.
- An authenticated dashboard with persistent opaque browser sessions, separate CSRF credentials, live node state, drift visibility, and a merged view of local control and identity-session audit events. Production deployments can add hybrid OIDC login with IdP-claim-enforced MFA while retaining the full-privilege administrator bearer for recovery from IdP outages.
- A preview [Flutter desktop console](desktop/README.md) for Linux and Windows. It uses system TLS, browser-approved OIDC, operating-system credential storage, server-enforced RBAC, one-time enrollment and recovery custody, and reviewed flows for network creation, node enrollment, certificate rotation, permanent revocation, and session management. It remains an unprivileged remote console and does not install Nebula or run a local tunnel.
- An offline encrypted recovery path that coordinates both stores, proves every CA/signing/OIDC secret relationship, publishes without replacement, restores only into a new fenced directory, and preserves browser sessions. A self-cleaning drill proves source immutability and a fresh real-Nebula enrollment after restore.
- Production-shaped HTTPS container deployment contracts for Compose and Kubernetes. The scratch image contains the static control plane, TLS readiness verifier, narrow Kubernetes private-file materializer, exact Nebula 1.10.3 certificate tool, and public CA roots. Compose runs one JSON replica under an explicit non-root UID/GID with a read-only root, no capabilities, owner-only file-mounted recovery credentials, bounded resources/logs, and TLS-verified durable-store readiness. The strict Helm chart requires an exact image digest, validates projected Secrets into memory-backed regular files, fixes JSON to one `Recreate` replica, and permits rolling application replicas only with external PostgreSQL. Disposable Compose, pod-shaped container, and native RKE2 proofs preserve authoritative state and exercise projected-secret materialization through verified readiness and pod replacement on one proof-owned node-local PVC. Image publication/signing, production Secret/storage/ingress proof, production HA, ingress automation, and the independent node-installer origin ceremony remain separate milestones.
- A PostgreSQL preview that stores the exact control and identity documents as two authoritative checksummed `BYTEA` rows plus a separate reconstructible runtime-telemetry document in a dedicated `mesh` schema. It preserves one-callback/no-op/receipt semantics, keeps recovery `ReadPair` and authenticated backups control/identity-only, loads role-specific DSNs from private files, and requires `--storage-backend=postgres` with no JSON fallback. PostgreSQL 17 integration, two-application-replica, bounded synchronous promotion, deterministic ambiguous-commit, bounded archived-WAL recovery, isolated Linux role/system-trust-path TLS, a fixed intended-workload micro-soak, and an audited maximum-valid-document run are automated. Sustained mixed-write failover, long-duration retention, production recovery operations, and target-platform trust/secret/certificate deployment remain unproved.

Production publication of a signed origin image plus independent public-key custody and receipt retention; deployment of the root-authorized bootstrap manifest and canonical handoff through the immutable origin plus operation of the real independent bootstrap-anchor channel; native macOS/Windows packages and services, including native receipts for the implemented Windows resolver; production multi-operator exercise of the implemented OIDC-only break-glass custody/replacement path; native WebAuthn; subordinate/offline-root CA mode and compromise-recovery ceremonies; production router health/SLA and broader routed-prefix failure drills; general recursive DNS forwarding; production relay placement, capacity, Internet-edge reachability, and failure drills; placement-aware multi-site failure injection and broader multi-site public-UDP verification; production [PostgreSQL HA/PITR proof](docs/ha-storage.md); and cross-platform packet-level five-minute proof are still outstanding. [The roadmap](docs/roadmap.md) separates the working lifecycle from those production milestones.

## Quick start

Requirements:

- Go 1.26 or newer
- One independently authenticated Mesh runtime release per managed node, containing the matched `meshctl`, `nebula`, and `nebula-cert` executables selected for that host OS and architecture
- Nebula 1.10.3 or newer within that authenticated release

Nebula 1.10.3 is the minimum because it contains the fix for the [P256 certificate blocklist bypass](https://github.com/slackhq/nebula/security/advisories/GHSA-69x3-g4r3-p962).

```bash
make test
make build
make dev
```

For a native-HTTPS container deployment, use the hardened [Compose contract](packaging/compose/README.md) and run `make compose-smoke` before adapting it to a real image registry and certificate authority.

For the preview desktop console, read the [desktop security and build guide](desktop/README.md), then run `make desktop-check`. Linux packaging is available through `make desktop-linux-package`; Windows packaging uses the documented unsigned MSIX boundary on a Windows build host.

Development mode creates private `admin.token`, `master.key`, and state files under `./data`. Open <http://127.0.0.1:8080> and sign in with:

```bash
cat data/admin.token
```

The token is exchanged for an opaque browser session; it is not stored in the browser cookie. Development uses loopback-only HTTP cookies. Cookies are scoped to a host rather than a TCP port, so this development mode assumes every HTTP service on the same loopback address is trusted not to capture and replay them. Production uses Secure `__Host-` cookies and must use HTTPS.

In the dashboard:

1. Create a network, for example `production` on `10.42.0.0/24`. The successful response immediately advances to step 2 without making you rediscover the new network card.
2. Add the first lighthouse with its real site, failure domain, and public `host:port` UDP endpoint. If it will route a private LAN, declare those canonical routed subnets now; Mesh binds them into that node's certificate. Later, use **Transfer routes** to move exact prefixes to another active gateway through the staged certificate-convergence workflow. You can choose **Finish later** without losing the newly created network.
3. Save the one-time lighthouse credential and run the displayed enrollment command on that machine. Choose **I saved this**, followed by **add first member**, to continue to the locked member step for the same network.
4. Save the member credential and run its command. Choose **I saved this**, followed by **check readiness**, to open the network's deployment checks. They refresh every 10 seconds while visible so activation can converge in place. If redundancy is insufficient, the dialog offers **Add second lighthouse**. Closing a disclosure clears its token and install, enrollment, and activation commands from the page. If a machine will not use an enrollment, choose **Cancel enrollment** while it is still pending instead of revoking an identity that never existed.
5. For a packaged Linux node, use the enrollment dialog's bootstrap-handoff link only as a courier location, authenticate it with the operator's independently transferred bootstrap anchor (preferred) or exact handoff digest, authenticate the selected verifier/root and bootstrap `mesh-install`, install the threshold-signed online bundle or offline snapshot, enroll, and run `mesh-install activate`. The dashboard supplies neither independent authority, and units must not be copied or enabled manually.
6. Every 15 seconds the dashboard replaces its inventory and health view from one authenticated server snapshot, then independently reads aggregate runtime observations. It reports lifecycle heartbeat/process/config/certificate/credential evidence and rollout convergence; a separately labeled observation is shown only for an exact heartbeat match and explicitly does not claim health, peer reachability, or UDP reachability.
7. Open **Firewall policy**, choose where each rule is installed and which peers it authorizes, review the exact compiled policy for every active node, then stage it on selected canaries. Use a node's **Security & access** action to review its final rules or safely replace certificate-bound group membership.
8. Open **Network DNS** to enable the Nebula lighthouse responder on a UDP port different from the network's Nebula port. The dialog requires firewall coverage and lists only active lighthouse overlay resolver addresses. Packaged nodes may also opt into one canonical search domain. Linux registers a transient non-default per-link resolver through systemd-resolved; Windows uses one exact Mesh-owned NRPT suffix rule and a local adapter on the overlay address. Either platform quarantines Nebula if the signed resolver state cannot be reconciled. Leave the option off when resolver changes are managed separately. Windows remains receipt-gated and macOS integration is not implemented.
9. Open **Network relays** when direct peer tunnels are unreliable. Select 1 to 8 managed machines with underlay reachability from both sides of the difficult path. Pending selections begin relaying only after enrollment; Mesh configures Nebula but does not prove public-edge reachability or relay capacity.
10. Open **Rotate CA** for a planned root replacement. Choose **Prepare dual trust**, leave the dialog open while every active agent applies it, then **Activate replacement CA**. Mesh renews old-root certificates early and enables **Finalize** only after every active node reports the replacement certificate. After replacement-only trust converges, choose **Complete**. Do not revoke, stop, or bypass the managed agent during this sequence; offline, stale, PID/HUP, and no-reload peers cannot satisfy the gates.
11. Use **Rotate certificate** when an active node should receive an immediate replacement while keeping its current Nebula private key. Mesh invalidates its outstanding recovery tokens, blocklists the old certificate through expiry, and deploys one signed revision. A brief reconnect may occur. If the outcome is ambiguous, use **Verify rotation** in the same browser tab; the exact idempotency request survives a reload. This is not a private-key compromise remedy.
12. If an active machine loses its Nebula private key, use **Replace identity**. Mesh immediately revokes and blocklists the old identity, removes its recovery and relay/canary assignments, advances one signed network revision, and creates one pending replacement carrying the same name, role, groups, placement, endpoint, and routed subnets but a new node ID and IP. Save and run the displayed one-time enrollment to restore connectivity.
13. Use **Revoke** to permanently cut an active node out of the network. The confirmation invalidates every enrollment, agent, and recovery credential; blocklists applicable certificate history; removes relay/canary assignments safely; releases routed-subnet ownership; and deploys one signed revision. If the response is ambiguous, **Verify revocation** replays the exact persisted request even after a same-tab reload.
14. After a revoked node's complete certificate history has expired, use **Archive record** to remove its expired issuance/blocklist history and inventory row. The control plane enforces a five-minute safety margin after the latest recorded expiry. The name, IP, and routed subnets become reusable only through a fresh node ID and one-time enrollment; archival does not undo or substitute for revocation.
15. To move one or more routed subnets without rebuilding the network, use **Transfer routes**. Select the active source, active replacement, and exact prefixes. Mesh keeps peers routed through the source while the target agent renews and proves an expanded certificate, then exposes **Promote target**. Promotion moves durable ownership and peer routes atomically; **Complete transfer** remains gated until the source proves a cleaned certificate. Cancellation before issuance is immediate, while cancellation after issuance similarly waits for target cleanup.
15. To permanently decommission a network, first stop any fail-open or unmanaged Nebula processes, then use **Retire network** and type the exact network name. The revision-bound operation atomically removes the encrypted CA/signing material, nodes, certificate history, and every node credential. Managed fail-closed agents become unauthorized immediately and stop Nebula by their configured maximum signed-state staleness deadline (five minutes by default). The retired name and every overlapping CIDR remain permanently reserved.

The equivalent admin CLI flow is:

```bash
export MESH_ADMIN_TOKEN="$(cat data/admin.token)"
./bin/meshctl create-network --name production --cidr 10.42.0.0/24

# Use the returned network ID.
./bin/meshctl create-node \
  --network NETWORK_ID \
  --name lighthouse-01 \
  --role lighthouse \
  --site aws-use1 \
  --failure-domain aws-use1a \
  --endpoint vpn.example.com:4242
```

Run enrollment on the target node only after the signed online installer or
signed offline snapshot has installed the complete runtime. Keep agent state
outside the managed bundle directory:

```bash
(
  IFS= read -rsp 'Enrollment token: ' MESH_ENROLL_TOKEN && printf '\n' >&2
  trap 'unset MESH_ENROLL_TOKEN' EXIT HUP INT TERM
  printf '%s\n' "$MESH_ENROLL_TOKEN" | ./bin/meshctl enroll \
    --server https://mesh.example.com \
    --token-file - \
    --state /var/lib/mesh-agent/state.json \
    --output /var/lib/mesh-agent/nebula
)
```

Enrollment validates the complete bundle with both `nebula-cert verify` and `nebula -test`. It leaves the live config at `/var/lib/mesh-agent/nebula/current/config.yml`.
Before reading the token, creating either target directory, generating a key,
or making an HTTP request, `meshctl` resolves both executables, checks both
reported versions, and requires an exact match at 1.10.3 or newer. A production
`meshctl` also requires both executables to resolve beside itself in
one authenticated installed release. If the prerequisite fails, authenticate
`mesh-install` independently and run either `install-online EXACT_BUNDLE_URL`
or `install ABSOLUTE_SNAPSHOT_DIR`; do not substitute GitHub's moving latest
Nebula release. Air-gapped hosts use the same signed offline snapshot path.

For authoritative runtime acknowledgment, point the Nebula systemd unit at that exact config and run:

```bash
./bin/meshctl agent \
  --state /var/lib/mesh-agent/state.json \
  --max-config-staleness 5m \
  --restart-service nebula.service
```

The agent quarantines Nebula before its first control-plane poll, verifies the unit's effective `ExecStart`, restarts it only after signed state is current, confirms the managed process is running, and only then acknowledges the revision. Subsequent control-plane failures stop Nebula once the persisted freshness deadline is reached. Poll intervals must be no more than half the staleness bound.

[`packaging/systemd`](packaging/systemd/README.md) documents the signed installer, enrollment, activation, recovery, and boot-gate contract. Only `mesh-install activate` establishes the agent's canonical boot link; the Nebula child intentionally has no independent boot target.

`--reload-pid-file` supports SIGHUP-based environments but deliberately reports no healthy acknowledgment because signal delivery cannot prove that Nebula accepted new PKI or blocklist state. `--no-reload` is validation-only and cannot quarantine a runtime, so it requires the explicit `--fail-open` acknowledgement:

```bash
./bin/meshctl agent --once --no-reload --fail-open \
  --state /var/lib/mesh-agent/state.json
```

`--fail-open` is an availability override: it permits Nebula to keep running when fresh signed state cannot be confirmed and therefore removes the bounded revocation guarantee.

Only one `meshctl enroll` or agent process may own a state/output pair. If enrollment is interrupted after its one-time request, rerun the same command: the private provisional journal resumes the exact request or recovers the committed bundle through the node-scoped bootstrap API.

If a never-enrolled node's token expires or is lost, use its dashboard **Reissue enrollment** action or replace every prior token atomically from the admin CLI:

```bash
./bin/meshctl reissue-enrollment \
  --server https://mesh.example.com \
  --node NODE_ID
```

The replacement is displayed once and expires after 30 minutes. Active and revoked nodes cannot use this flow.

Use **Cancel enrollment** for a never-enrolled pending node that should be removed. The exact-name-bound operation atomically invalidates every issued token, removes the pending inventory record, releases its IP and routed-subnet reservations, and removes any pending relay selection. An enrollment already signing concurrently either loses its final commit and returns unauthorized, or commits first and changes the node to active so cancellation is rejected. If the response is interrupted, the dashboard refreshes authoritative inventory before claiming that the node is gone.

Use **Archive record** only after a node is already revoked. The exact-name- and revision-bound operation refuses an enrolled identity until five minutes after the latest expiry across its current certificate, every issuance, and every revocation entry. A legacy revocation without an expiry blocks archival permanently. When eligible, one transaction removes the node and all of its enrollment, recovery, issuance, and revocation records; removing expired blocklist entries advances signed configuration exactly once. A never-enrolled legacy revoked row has no certificate authority and can archive immediately without a revision change. The strict `node.archived` tombstone preserves cleanup evidence but deliberately does not reserve the name, IP, or routed subnets: reuse creates a fresh node ID and credential. Runtime telemetry is deleted separately after commit and its status is reported honestly.

Use an active node's **Rotate certificate** action for an immediate same-key replacement. The exact-name-, revision-, and idempotency-bound operation signs the already pinned public key, blocklists the previous fingerprint through its exact expiry, invalidates every outstanding agent-recovery record, adds one issuance, advances certificate generation and signed configuration exactly once, and returns a non-secret durable receipt. It is fenced during CA and firewall rollouts and while a current renewal claim is in flight. The dashboard stores the request binding in same-tab session storage before sending it, retries an ambiguous outcome with the exact request, and exposes **Verify rotation** until a receipt is recovered. A different binding cannot reuse that request ID. Use **Replace identity**, not certificate rotation, when the private key is missing or may be compromised.

If an active node loses its Nebula private key, use its dashboard **Replace identity** action instead of agent recovery. The confirmation is intentionally disruptive: one atomic revision revokes and blocklists the old certificate identity and creates a pending replacement with a fresh node ID, address, and one-time enrollment token. Connectivity and any published routed subnets remain unavailable until the replacement enrolls. If the HTTP response is interrupted after commit, refresh the dashboard and use **Reissue enrollment** on the same-name pending identity; repeating replacement against the now-revoked source is rejected and cannot create a second replacement.

To remove an entire trust domain, use the dashboard **Retire network** action. Retirement requires the exact current configuration revision plus the exact typed network name, and returns a no-store cleanup receipt. It removes the network and all of its control-plane key, node, enrollment, recovery, issuance, and revocation records in one atomic write. Runtime observations live in a separate reconstructible store and are removed immediately after that commit; their cleanup status is reported independently. If the response is interrupted, the dashboard refreshes authoritative inventory and reports success only when the network is absent. A retirement tombstone permanently prevents reuse of the name or any overlapping CIDR.

If an active node was offline until its agent credential expired, issue a separate recovery token from the dashboard or admin CLI:

```bash
./bin/meshctl issue-agent-recovery \
  --server https://mesh.example.com \
  --node NODE_ID
```

The token is shown once and expires after 30 minutes. Issuing it does not disturb the current credential. On the affected node, stop the lifecycle agent, stage the recovered signed state while proving that Nebula stays quarantined, and start the agent only after recovery succeeds:

```bash
sudo systemctl stop mesh-agent.service
(
  read -rsp 'Agent recovery token: ' MESH_AGENT_RECOVERY_TOKEN && printf '\n'
  trap 'unset MESH_AGENT_RECOVERY_TOKEN' EXIT
  printf '%s\n' "$MESH_AGENT_RECOVERY_TOKEN" | sudo /usr/local/bin/meshctl recover-agent \
    --token-file - \
    --state /var/lib/mesh-agent/state.json \
    --nebula /usr/local/bin/nebula \
    --nebula-cert /usr/local/bin/nebula-cert \
    --quarantine-service mesh-nebula.service &&
  sudo systemctl start mesh-agent.service
)
```

The packaged recovery path never starts Nebula directly: it verifies the managed unit, stops it, validates and stages the signed bundle, and confirms that it remains stopped. The normal agent then performs a fresh signed-state poll before starting Nebula. If a response is interrupted after the private journal is written, first rerun the command with `--resume` and no token source; the state file supplies the exact pending token and bearer. If the CLI instead proves that the pending token or credential is no longer authorized, issue a replacement recovery token and rerun the prompted command with that new token. Before replacing its journal, the client verifies that the old pending bearer is rejected; an authenticated old bearer forces exact resume instead. If the CLI says the reset is durably committed but activation or renewal failed, start `mesh-agent.service` to retry under the ordinary fail-closed loop; do not run recovery again.

The recovery token is the reset authority. Matching the existing Nebula X25519 public key binds recovery to the same node identity but is not proof that the requester possesses the private key. Protect recovery tokens like temporary administrator credentials; the detailed trust and replay rules are in [the security model](docs/security.md#agent-credential-recovery).

## Production control plane

Before a release or production-shaped deployment, run `make security-baseline`,
`make image-security-baseline`, `make observer-security-baseline`, and
`make origin-image-security-baseline`, plus
`make linux-package-security-baseline BUNDLE=/absolute/candidate.tar` for each
Linux candidate and
`make windows-package-security-baseline BUNDLE=/absolute/candidate.tar` for
each Windows staging candidate and
`make darwin-package-security-baseline BUNDLE=/absolute/candidate.tar` for
each Darwin staging candidate, then review the
[threat model](docs/threat-model.md), [control-plane image security
gate](docs/image-security.md), [observer artifact security
gate](docs/observer-security.md), [release-origin image security
gate](docs/origin-image-security.md), [Linux node-package security
gate](docs/linux-package-security.md), [final signed Windows bundle security
gate](docs/windows-package-security.md), [Darwin staging-bundle security
gate](docs/darwin-package-security.md), and
[production hardening guide](docs/production-hardening.md). The source gate pins
a patched Go toolchain, verifies module integrity, runs tests/vet and reachable
dependency analysis, and performs a redacted source secret scan. The image gate
binds Syft/SPDX, current Grype policy, and final-image secret evidence to one
exact Linux amd64 control-plane Docker ID. The observer gate independently binds
the exact patched source and both Linux binary architectures to current
vulnerability and secret evidence. The origin gate independently binds the
smaller courier scratch image and feeds its receipt into runtime verification.
The Linux node-package gate revalidates each final canonical bundle, binds the
complete four-executable and shipped-asset inventory to current vulnerability
and secret evidence, and makes its exact receipt mandatory before release
manifest creation. The Windows staging gate applies the corresponding exact
inventory, scanner, candidate, and receipt boundary without claiming a native
installer. The Darwin staging gate does the same for exact Mach-O and launchd
assets without claiming native installation, activation, signing, or
notarization. None replaces external review, penetration testing, native macOS
package or Windows installer/host validation, signed attestation/admission,
installed-host validation, or deployment-specific validation.

Without `--dev`, both secrets are mandatory. Generate them once, place them in a secret manager, and load the same values on every restart. `MESH_MASTER_KEY` must remain 256 bits of CSPRNG output; a padded or passphrase-derived 32-byte value is not supported. The exports below are first-deployment generation examples, not a startup script. Replacing the master key is rejected because it makes existing encrypted CA and signing state unreadable. To rotate only the administrator bearer, update its secret-manager value while keeping the exact master key, start once with `--rotate-admin-token`, verify the `admin.credential_rotated` audit event and bearer, then remove the flag from the service definition. Leaving that flag enabled turns a later secret-manager typo into an authorized rotation. Session effects are described in [the identity guide](docs/identity.md#cookies-and-sessions).

Serve TLS directly:

```bash
export MESH_ADMIN_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"
export MESH_MASTER_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
./bin/mesh-server \
  --listen 0.0.0.0:8443 \
  --public-url https://mesh.example.com:8443 \
  --data-dir /var/lib/mesh \
  --tls-cert /etc/mesh/tls.crt \
  --tls-key /etc/mesh/tls.key
```

Or bind behind a trusted TLS reverse proxy:

```bash
./bin/mesh-server \
  --listen 127.0.0.1:8080 \
  --public-url https://mesh.example.com \
  --behind-tls-proxy \
  --data-dir /var/lib/mesh
```

Proxy mode requires a numeric loopback backend listener such as `127.0.0.1:8080` or `[::1]:8080`; hostnames, wildcard binds, and network-reachable `--behind-tls-proxy` binds are rejected because name resolution or direct clients could otherwise bypass the trusted TLS edge. Cleartext HTTP is accepted only on an explicit numeric loopback origin; `--allow-insecure-http` is rejected. Mesh deliberately ignores forwarded client-IP headers. Consequently, every proxied OIDC request shares the proxy's loopback rate-limit key; the trusted edge must enforce distributed limits using its verified client address or identity. Keep `MESH_MASTER_KEY` in a secret manager. Use the coordinated encrypted recovery workflow rather than copying either JSON store independently; losing both the live key and a recoverable archive makes every managed CA and signing private key unrecoverable.

For Kubernetes 1.29+, the [Helm chart](packaging/helm/mesh-control-plane/README.md)
deploys the same native-TLS scratch image by exact registry digest with JSON or
external PostgreSQL state. It fixes JSON mode at one `Recreate` replica and
permits rolling application replicas only with PostgreSQL. A narrow init command
materializes only the fixed projected Secret keys into owner-private regular
files after validating the credentials and TLS identity; the server remains
UID/GID 65532, capability-free, read-only-root, and service-account-token-free.
Run `make helm-chart-smoke` before using a release candidate. The chart does
not publish or sign the image, deploy PostgreSQL, authenticate an ingress
controller, perform backups, or provision the independent installer origin.
`make helm-kubernetes-smoke` is the opt-in native cluster proof; it requires
cluster-administrator authority because its short-lived loader imports the
already security-gated digest directly into one selected RKE2 node.

### PostgreSQL storage preview

The repository includes `mesh-storage` for offline migration, authenticated backup import, and exact post-import verification. Build the operator binary explicitly:

```bash
go build -buildvcs=false -trimpath -o bin/mesh-storage ./cmd/mesh-storage
```

PostgreSQL mode requires a separately provisioned fresh database and distinct migration/import/runtime roles. Its DSN must be held in an owner-private, single-link mode-`0400` or mode-`0600` file at a clean absolute path. Production requires `sslmode=verify-full`, `sslrootcert=system`, `target_session_attrs=read-write`, and bounded connection/pool settings; install any private database CA into the operating-system trust store. PostgreSQL 17's trusted `pgcrypto` installation also requires the documented cluster-admin transfer of only its member-function ownership before `mesh_migrate` can revoke PUBLIC execution and apply explicit grants. Custom root files and PostgreSQL client-certificate/mTLS settings are not supported. The plaintext exception is only for an explicit numeric-loopback or absolute-Unix-socket development/test route.

The cutover is stopped-server, one-way, and archive-driven: create and catalog a fresh current control-v13 JSON backup, run `mesh-storage migrate` with the migration-role DSN, complete the required cluster-admin function-ownership transfer and `mesh_migrate` grant audit, run `import-backup` and `verify` with the import-role DSN and exact catalog-selected backup ID, then start one canary using the runtime-role DSN. The importer also accepts authenticated bound control-v2 through control-v13 archives and preserves older documents exactly so the first upgraded server startup can perform any remaining ordered topology, managed-DNS, managed-relay, CA-rotation, firewall-rollout, firewall-pause, route-transfer, route-profile, route-policy, native-DNS, and firewall-scope migrations. A fresh import initializes the separate empty telemetry document automatically. An already-imported database upgraded to migration 002 must run `initialize-runtime-telemetry` once with the temporarily enabled import role before verification:

```bash
./bin/mesh-storage migrate \
  --postgres-dsn-file /etc/mesh/postgres-migrate.dsn

./bin/mesh-storage import-backup \
  --postgres-dsn-file /etc/mesh/postgres-import.dsn \
  --backup-key-file /secure/mesh-backup-keys/mesh.key \
  --backup-archive /secure/mesh-backups/mesh.meshbackup \
  --expect-backup-id BACKUP_ID

# Upgrade-only, before verify, when the imported pair predates migration 002:
./bin/mesh-storage initialize-runtime-telemetry \
  --postgres-dsn-file /etc/mesh/postgres-import.dsn

./bin/mesh-storage verify \
  --postgres-dsn-file /etc/mesh/postgres-import.dsn \
  --backup-key-file /secure/mesh-backup-keys/mesh.key \
  --backup-archive /secure/mesh-backups/mesh.meshbackup \
  --expect-backup-id BACKUP_ID

./bin/mesh-server \
  --storage-backend=postgres \
  --postgres-dsn-file /etc/mesh/postgres-runtime.dsn \
  --listen 127.0.0.1:8080 \
  --public-url https://mesh.example.com \
  --behind-tls-proxy
```

Keep every Mesh writer stopped during `verify`. If import reports that its commit may be durable, or a post-import validation fails, run offline `verify`; do not blindly retry the create-only import. Every replica must receive the same external `MESH_MASTER_KEY`, `MESH_ADMIN_TOKEN`, canonical public URL, and identity policy. PostgreSQL mode rejects `--dev`, an explicit `--data-dir`, and silent fallback to JSON. See the [complete role grants, DSN contract, one-way cutover, and remaining production gates](docs/ha-storage.md).

To enable production single sign-on and provision one-use recovery, copy [`config/mesh-identity.example.json`](config/mesh-identity.example.json) to a service-user-owned, mode-0600, single-link absolute path, provision the OIDC client secret at the separate absolute path named in that file, and add:

```bash
./bin/mesh-server \
  --listen 127.0.0.1:8080 \
  --public-url https://mesh.example.com \
  --behind-tls-proxy \
  --identity-config /etc/mesh/identity.json \
  --data-dir /var/lib/mesh
```

The example starts in hybrid mode with the browser admin-token form hidden and recovery-code management enabled. Create and independently custody at least two codes from **Activity**, then stop the server and change `mode` to `oidc` for cutover. OIDC-only startup proves the configured usable-code floor and rejects the administrator bearer over HTTP, while retaining that token as the offline control/backup recovery binding. See [browser identity and OIDC operations](docs/identity.md) for the exact cutover, one-use failure boundary, IdP registration, MFA claims, session expiry/revocation, file requirements, audit limits, and proxy controls.

See [the security model](docs/security.md) before exposing a control plane.

## Backup and recovery

`mesh-backup` creates one authenticated archive containing exact coordinated control and identity state plus canonical master/admin credentials. It requires a stopped server, takes both store locks in server order, proves the bound control-v2 through control-v13 master/admin credentials, validates every active or staged CA, host certificate, issuance, signing key, and sealed identity value, and creates the archive without overwriting any path. The current server writes control v13, where topology, per-network DNS and optional Linux native-resolver settings, relay settings, node issuing-CA identity, crash-durable CA rotation and firewall canaries, explicit firewall pause state, routed-subnet transfer and route-profile receipts, weighted route policies, and node/group-scoped firewall selectors are represented. Existing v2 nodes migrate to `unassigned`, existing v3 networks migrate to disabled DNS on canonical port 53, existing v4 networks migrate to disabled relays with an exact empty selection, existing v5 certificates are bound to their current CA, existing v6 networks migrate to stable firewall rollout state, existing v7 stable or in-flight canaries gain an unpaused zero value, existing v8 networks gain an empty route-transfer receipt, existing v9 networks gain an empty route-profile edit receipt, existing v10 networks gain empty route-policy state, existing v11 networks gain disabled native resolver state with an empty search domain, and existing v12 networks gain no scoped firewall fields. None of these compatibility migrations change signed configuration bytes, revisions, or timestamps. The 256-bit backup key is generated and held separately. A live version-1 control store must complete one successful upgraded server startup before capture; unbound version-1 archives are deliberately rejected by the verifier and restore path.

```bash
./bin/mesh-backup keygen --output /secure/mesh-backup-keys/mesh.key

# Load the exact production values from their secret manager. These file reads
# apply only to a development-mode data directory that persisted both secrets.
export MESH_MASTER_KEY="$(cat /var/lib/mesh/master.key)"
export MESH_ADMIN_TOKEN="$(cat /var/lib/mesh/admin.token)"
./bin/mesh-backup create \
  --data-dir /var/lib/mesh \
  --key-file /secure/mesh-backup-keys/mesh.key \
  --output /secure/mesh-backups/mesh.meshbackup
unset MESH_MASTER_KEY MESH_ADMIN_TOKEN

./bin/mesh-backup verify \
  --key-file /secure/mesh-backup-keys/mesh.key \
  --archive /secure/mesh-backups/mesh.meshbackup
```

Backup/restore filesystem mutations currently run only on Linux; macOS and Windows fail closed as unsupported until their ACL, case-folding/DACL, locking, and directory-durability contracts are proven. Restore requires an authenticated backup ID selected from an external monotonic catalog and a nonexistent target directory. An interrupted restore leaves a sibling marker that makes `mesh-server` fail closed until `finalize-restore` revalidates and synchronizes the exact recovered file set. Linux restore and server startup also share a parent-directory advisory fence, and existing targets receive an alias-aware bounded sibling-marker scan. Local validation cannot distinguish a valid older archive from the authorized recovery point, so the external catalog remains mandatory. See [backup and recovery](docs/backup-recovery.md) for key custody, filesystem requirements, the complete restore ceremony, external configuration, and the live drill.

That same authenticated bound control-v2 through control-v13 archive is the only supported JSON-to-PostgreSQL import source. `mesh-storage` does not scrape a live data directory and never takes a DSN on its command line.

## Versioned release trust

`mesh-release` generates separate offline Ed25519 root and release-role keys, creates canonical versioned roots, assembles dual-threshold root updates, and signs the exact bytes of strict channel or release manifests. `meshctl verify-release` remains a local release-signature diagnostic; `mesh-install` also starts from its separately authenticated compiled root and durably replays root rotation and revocation before accepting release metadata. Changing even manifest whitespace invalidates its signatures.

```bash
./bin/mesh-release generate-key --private signer-a.private.json
./bin/mesh-release export-public \
  --private signer-a.private.json \
  --public signer-a.public.json
./bin/mesh-release sign \
  --private signer-a.private.json \
  --manifest release.json \
  --signature release.signer-a.json

# Repeat signing with an independently controlled signer, then verify local files.
./bin/meshctl verify-release \
  --manifest release.json \
  --signature release.signer-a.json \
  --signature release.signer-b.json \
  --trusted-public-key signer-a.public.json \
  --trusted-public-key signer-b.public.json \
  --channel stable \
  --artifact ./meshctl
```

`meshctl verify-release` remains a non-installing local diagnostic. The Linux release path also builds a deterministic node bundle and lets a separately authenticated `mesh-install` replay its compiled-plus-persisted root chain, consume either a bounded online bundle or a private offline snapshot, verify the artifact through a pinned anonymous descriptor, install atomically, recover interrupted transactions, and roll back to an exact recorded release. Online URLs are untrusted locators and candidate files cannot replace the compiled initial root. See [the release-trust design and operator workflow](docs/release-trust.md).

## Locked Nebula dependency intake

`mesh-deps` provides separate non-installing dependency paths. `fetch-nebula` authenticates Slack's exact v1.10.3 release archives for six target pairs. `build-nebula-observer` is the Linux node-bundle input: it authenticates the complete cached upstream source tree, applies the exact embedded observer patch series, builds both executables twice with isolated caches and the locked Go toolchain/flags, and publishes only byte-identical outputs matching the embedded Linux build lock. `build-nebula-windows-runtime` uses that same authenticated patched tree and a separate layered Windows output lock to reproducibly publish exact `amd64` or `arm64` PEs; the observer endpoint is a reviewed no-I/O stub on Windows.

Run it from a private parent on a Linux amd64 or arm64 intake host; it can cross-stage any supported target:

```bash
install -d -m 0700 ./dependency-intake
./bin/mesh-deps fetch-nebula \
  --os linux \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-v1.10.3-linux-amd64

./bin/mesh-deps build-nebula-observer \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-observer-v1.10.3-linux-amd64

./bin/mesh-deps build-nebula-windows-runtime \
  --arch amd64 \
  --output-dir ./dependency-intake/nebula-runtime-v1.10.3-windows-amd64
```

There is intentionally no `latest`, URL, hash, source, patch, toolchain, alternate-lock, proxy, or install override. None of these commands mutates services. Linux bundle schema v3 accepts only the observer stage and carries its source, patch-set, toolchain, output provenance, and installer-state compatibility. Windows staging schema v2 accepts only the separate locked source-built runtime stage for Nebula PEs while retaining the exact upstream archive lock solely for Wintun and notices; final signed schema v3 also requires exact PE reconstruction and a fresh native Authenticode receipt. macOS native code-signing validation remains a separate packaging responsibility. See [the dependency trust boundary and exact verification flow](docs/nebula-dependency-trust.md).

## Development

```bash
make build
make test
make vet
make security-baseline
make image-security-baseline
make observer-security-baseline
make origin-image-security-baseline
# After building each exact Linux candidate:
make linux-package-security-baseline BUNDLE=/absolute/path/mesh-linux-bundle.tar
make smoke
make packet-smoke
make ui-guided-packet-smoke
make network-dns-smoke
make native-dns-smoke
make network-relay-smoke
make network-ca-rotation-smoke
make network-firewall-rollout-smoke
make routed-subnet-smoke
make route-transfer-smoke
make route-profile-smoke
make ui-guided-linux-package-smoke
make backup-restore-smoke
make nebula-observer-smoke
make nebula-observer-overlay-smoke
make nebula-public-endpoint-smoke
make postgres-multi-replica-smoke
make postgres-load-soak-smoke
make postgres-max-document-smoke
make postgres-sync-failover-smoke
make postgres-ambiguous-commit-smoke
make postgres-pitr-smoke
make postgres-roles-tls-smoke
make linux-install-smoke
make windows-bundle-smoke
go build -buildvcs=false -trimpath -o bin/mesh-storage ./cmd/mesh-storage
./bin/meshctl version --json
go test ./internal/release ./cmd/mesh-release ./cmd/meshctl
go test ./internal/nebulaartifact ./internal/nebulaobserverartifact ./cmd/mesh-deps
```

`make smoke` creates an isolated loopback control plane, enrolls a lighthouse and member with real Nebula, cancels an abandoned pending enrollment and proves its token is dead without changing the signed revision, archives a never-enrolled revoked row and proves exact tombstone/credential cleanup without changing the post-revocation signed revision, exercises signed agent recovery, atomically replaces the member's lost-key identity, proves a repeated replace cannot create a duplicate, and recovers the committed pending identity through enrollment reissue. It then immediately rotates that active identity's real certificate with the same public key, proves exact response-loss replay writes no state, verifies the old fingerprint remains blocklisted through expiry, rejects the invalidated recovery token, converges both signed real-Nebula bundles, and proves generation/revision advance exactly once. A separate real-Nebula node then exercises the idempotent revocation endpoint, proves exact receipt replay is write-free, proves enrollment/recovery/agent credentials are dead, and converges its fingerprint blocklist onto both surviving peers. Focused control tests separately cover concurrency and archival expiry boundaries. The harness then retires the complete network, verifies removal of its encrypted trust material and every credential-bearing record, rejects both old active agents and a pending enrollment token, proves permanent name/overlapping-CIDR reservation while allowing an unrelated network, checks that raw credentials were never persisted, and removes its temporary secrets.

`make packet-smoke` is the stronger Linux-only network proof. With root or non-interactive sudo, network namespaces, veth, TUN, and exact-version Nebula 1.10.3 binaries available, it builds an isolated underlay, proves packets route over both Nebula interfaces, deploys a signed restrictive policy, proves its explicitly allowed TCP/443 exchange in each direction, and then proves ICMP is denied from a clean conntrack state. It restores connectivity with a second signed revision, then applies a signed revocation blocklist and proves bidirectional samples fail while both peer processes and overlay routes remain alive. Unsupported hosts exit with status 77 rather than claiming coverage.

`make ui-guided-packet-smoke` adds real headless Firefox interaction through the W3C WebDriver protocol before that packet proof. It signs in through the browser form, creates the network, requires the successful submit to open the locked first-lighthouse step automatically, creates the lighthouse, requires its saved-credential action to open the locked first-member step for the same network, then requires the saved member credential to open deployment readiness directly. It requires a one-shot 10-second refresh to be scheduled after each validated readiness result and canceled when the dialog closes. From the single-lighthouse warning it follows **Add second lighthouse**, requires a locked lighthouse role and distinct failure domain, creates the pending backup, returns from its saved credential to refreshed readiness, and proves the pending node neither counts as active redundancy nor leaves the remediation button visible. It validates the displayed install/enroll/activate guidance, requires every transition to remove the one-time token and commands from the DOM, and passes the original browser-authored lighthouse/member identities into the existing enrollment and network-namespace harness. Its latest audited run on 2026-07-21 reached authenticated lighthouse/member overlay traffic in 4 seconds, then passed signed policy deployment/restoration, revocation, and exact cleanup. Firefox and geckodriver are prerequisites. This is the measured UI-to-packet mechanism gate; it deliberately does not claim that the pending backup was activated or that native package installation or cross-platform host preparation occurred inside that four-second interval.

`make network-dns-smoke` extends that browser-authored path by enabling a managed resolver on UDP 5353, requiring the strict UI and API readback to show no resolver before activation and exactly the active lighthouse afterward, and checking that only the lighthouse's signed config binds DNS to its own overlay IP. A raw UDP DNS client then runs from the member namespace, validates the response endpoint and DNS wire structure, and requires `packet-member.` to return exactly that authenticated member's overlay address. The restrictive-policy stage must retain only the explicit UDP resolver rule or the control plane rejects it. The latest audited run on 2026-07-21 reached authenticated overlay traffic in 5 seconds and completed policy restoration, revocation, and exact cleanup. This proves Nebula's raw overlay DNS responder on Linux; it does not exercise host resolver integration.

`make native-dns-smoke` adds the explicit Linux split-DNS option with search domain `packet.mesh`. It starts the production node-local adapter from the exact signed member configuration inside the real network namespace, resolves `packet-member.packet.mesh.` through the authenticated lighthouse to the exact overlay address, and requires an unrelated `example.com.` query to fail instead of being forwarded recursively. The audited 2026-07-21 run then completed the ordinary signed firewall, restoration, revocation, and cleanup stages. Unit and lifecycle tests separately prove strict signed-policy parsing, local-source enforcement, upstream failover, systemd-resolved command ordering and reassertion, partial-apply rollback, disable/revert, quarantine, and exact heartbeat gating. This is Linux/systemd-resolved mechanism proof; macOS, Windows, and general recursive DNS service remain separate work.

`make network-relay-smoke` uses the real browser to select the pending lighthouse as the managed relay, verifies the strict pending and active API documents, enrolls that relay plus two members, and checks the exact server/client relay blocks in all three signed configurations. Each member lives on a different point-to-point underlay, can reach only the relay endpoint, and has no route to the other member; IPv4 forwarding is explicitly disabled in the relay namespace. Bidirectional member-to-member overlay ICMP then passes through real Nebula 1.10.3 while all three processes remain alive. The latest audited run on 2026-07-21 reached the browser-authored overlay in 5 seconds and completed exact namespace/process cleanup. This is a forced Linux mechanism proof, not production relay placement, capacity, public-edge reachability, or an upstream stability guarantee.

`make network-ca-rotation-smoke` starts from the same browser-authored lighthouse/member network and drives the exact strict API lifecycle through prepare, activate, finalize, and complete. Both agents install dual trust, renew their same-key host certificates under a distinct replacement CA, converge on replacement-only trust, and persist the completed revision. The harness retains both original Nebula process identities, reloads each trust stage with SIGHUP, validates every immutable bundle and certificate issuer, and requires one continuous authenticated member-to-lighthouse ICMP stream to lose zero packets. The audited 2026-07-21 run passed all four stages and exact cleanup. The smoke helper submits an ordinary unprivileged node-agent heartbeat only after process identity and packet delivery are proven; production convergence still requires the packaged systemd runtime acknowledgment, not PID/HUP or no-reload mode.

`make network-firewall-rollout-smoke` starts from the same browser-authored lighthouse/member network and stages a TCP/443-only target policy to the member canary while the lighthouse retains the known-good policy. Before applying that first target, an unprivileged agent helper reports its exact signed revision and per-node digest as a local activation failure; the server independently re-renders the selected canary, automatically restores the retained policy in one revision, and the harness proves authenticated ICMP and both original Nebula processes survived. It then re-stages and injects a fresh exact-target heartbeat with the authoritative certificate generation, explicit degraded status, and stopped managed runtime; this second closed guard also restores the retained policy while missing, stale, prior-bundle, generation-free, healthy-contradictory, and generic running-degraded evidence remain non-destructive. The harness re-stages again, requires exact convergence, proves TCP/443 passes while canary ICMP is denied, pauses so a new signed retained-policy revision restores ICMP without discarding the target or cohort, resumes into another signed target revision with fresh convergence required, then rolls back and re-stages for final promotion. The audited 2026-07-21 run completed every stage and exact cleanup. Production convergence still requires the packaged systemd runtime acknowledgment.

`make routed-subnet-smoke` drives the same browser-authored lifecycle with an exact `172.31.250.0/24` routed-subnet declaration. It requires the owner certificate to contain that exact unsafe network, requires signed peer configuration to point the route at the owner while the owner's own configuration omits it, and requires the managed inbound firewall rules to be repeated for that exact local CIDR. A separate Linux namespace then acts as a non-Nebula host behind the gateway, and the member must reach it through the Nebula TUN route. Revocation removes the route from signed peer configuration. The latest audited run on 2026-07-21 reached the routed host and completed the existing signed policy/revocation lifecycle in 5 seconds before exact cleanup. This is the declaration/revocation mechanism proof.

`make route-transfer-smoke` adds a self-cleaning three-node gateway-cutover drill around that routed LAN. It starts with the replacement gateway's forwarding disabled, proves the member still reaches the non-Nebula host through the source during target prepare, installs and reloads the target's exact expanded certificate, verifies target-to-LAN reachability, and submits the exact healthy generation/fingerprint/revision/digest heartbeat before promotion. It then atomically promotes ownership, reloads the member's target route and the source's cleaned certificate, switches the LAN return route, disables source forwarding, and requires packets to keep reaching the host through the target. Completion remains unavailable until the source heartbeat converges, and an exact completed advance replay must be byte-identical and write-free. The audited 2026-07-21 run passed every stage with the original three Nebula processes and exact cleanup. This is one exact IPv4 prefix and one active gateway at a time; it is not ECMP or a production router deployment.

`make route-profile-smoke` adds a self-cleaning active-gateway prefix-set drill around the same routed LAN. It first replaces the complete set with empty: peer routing is withdrawn in one signed revision, the gateway installs a cleaned certificate, real routed-host packets stop, and completion remains unavailable until the exact healthy generation/fingerprint/revision/digest heartbeat converges. It then restores the prefix certificate-first: the gateway installs and reloads the expanded certificate while the member remains unable to route the prefix, promotion stays unavailable until exact convergence, and one signed promotion publishes the peer route and restores real packets. Both terminal advances replay byte-identically without another write, and both original Nebula processes remain in place. The audited 2026-07-21 run passed every stage and exact cleanup. Overlapping old/new prefixes and a staged union above eight prefixes fail closed and must be split into completed removal and addition edits.

`make route-ecmp-smoke` adds a self-cleaning four-namespace weighted-ECMP drill. A second active gateway joins the exact prefix certificate-first, the authenticated route-policy API binds a 3:1 owner set plus MTU and metric, and 160 distinct UDP source-port flows must reach a receiver behind both gateways within a bounded distribution. Taking the lower-weight gateway's underlay down without replacing its Nebula process exercises Nebula 1.10.3 passive/active tunnel-death detection; the next sample must arrive entirely through the survivor. Restoring the underlay and overlay tunnel must restore weighted selection. Finally, route-first membership removal collapses the route to the surviving scalar gateway while every packet still arrives, and completion waits for the departing certificate heartbeat. Exact policy and terminal lifecycle replays are byte-identical. The audited 2026-07-21 run passed with all three Nebula process identities preserved. This is a bounded mechanism proof, not a production router health SLA.

`make ui-guided-linux-package-smoke` is the package-inclusive Linux clean-host gate. It preserves the full versioned-root install regression, adds an isolated private TLS release/control underlay, and starts two additional pinned Fedora systemd hosts with no Mesh install state or installed Mesh binaries. After separately placing the authenticated bootstrap and the fixture CA, its measured interval uses real headless Firefox to create the network, lighthouse, and member with explicit site/failure-domain placement; executes the exact displayed `install-online`, prompted stdin enrollment, and `activate` commands on both hosts; waits for both managed services; and proves an authenticated overlay packet from member to lighthouse. It first injects a real route collision on the future lighthouse and broken DNS on the future member, requires both enrollments to fail without a state journal or consumed token, restores the hosts, and reuses the same one-time credentials successfully. The latest audited run on 2026-07-20 continued through readiness-v6 placement grouping plus fresh route, member-DNS, and all-member UDP evidence, injected post-enrollment route and DNS failures, recovered, and cleaned every exact resource in 121 seconds. Build/repository/control-plane provisioning, bootstrap distribution/authentication, and generic host preparation remain outside the interval; this is a Linux systemd mechanism proof, not native macOS/Windows or production distribution proof.

`make nebula-observer-overlay-smoke` builds the exact reproducible observer stage and reruns that two-peer lifecycle with one private mount namespace and `/run` per Nebula process. It passes snapshots through the production root-private Unix client and strict parser, proving completed handshake and authenticated-RX evidence, exact lighthouse aggregation, monotonic sample sequencing, process-instance discontinuity after restart, and no retained peer on the newly restarted lighthouse after signed revocation. An underlay-only outage also proves default Nebula tunnel eviction, an incremented handshake-timeout counter, and a fresh same-process handshake/RX recovery. Its combined multi-site mode enrolls two real members and two real lighthouses across three declared sites and two lighthouse failure domains; proves a same-domain labeling mistake warns without changing signed state or any live tunnel; requires every zero-capability member to publish `attempted=2/replied=2` before readiness verifies both active lighthouses; isolates both nodes in one site while the unaffected member stays authenticated through the other lighthouse; requires degraded active-probe evidence to return public-UDP readiness to unverified; recovers both unchanged member processes and all-member readiness; and retains the bounded nine-configured-lighthouse overflow proof.

`make nebula-public-endpoint-smoke` runs that complete multi-site proof through two independent routed edge namespaces. Each lighthouse uses a private point-to-point address and production-shaped default gateway while Mesh publishes a distinct public test-net UDP endpoint; an nftables edge accepts only bounded UDP forwarding to Nebula 4242 and records DNAT counters. The proof requires authenticated overlay traffic, not a UDP `Dial`, through both counters. It takes the site-A edge-to-lighthouse path and both site-A member paths down, proves site-B continuity and readiness withdrawal, then restores the same processes, tunnels, and all-member readiness before the nine-lighthouse overflow check. It remains a self-contained Linux mechanism proof, not evidence from an externally routed production deployment or native macOS/Windows transports.

`make backup-restore-smoke` stops an isolated live control plane at the coordinated boundary, proves online capture is rejected, verifies a create-only encrypted archive, restores it into a new directory, exercises the incomplete-restore startup fence and receipt finalization, proves the prior opaque browser session and network revision survived, and enrolls a pending lighthouse with real Nebula before validating both its certificate and configuration.

`make postgres-multi-replica-smoke` uses one self-cleaning `postgres:17-alpine` container and two independent application processes to prove shared control mutations/inventory/audits, cross-replica session and CSRF revocation, surviving-replica mutation, and restart convergence. It does not fail over PostgreSQL or prove synchronous replication, WAL restore, or PITR.

`make postgres-load-soak-smoke` is the first bounded [intended-workload PostgreSQL gate](docs/postgres-load-soak.md). Against one capped local PostgreSQL 17 primary and two real application replicas it performs exactly 256 dependency-ordered, no-retry control/identity writes plus 108 reads in a fixed 30-second mixed stage. It gates nearest-rank latency, load throughput, post-import revision/audit/receipt deltas, complete receipt sequences, WAL and database growth, deadlocks/conflicts/temp files, explicit vacuum pressure, per-app RSS, PostgreSQL memory, restart readiness, exact terminal state, and diagnostic credential disclosure. It does not test failover, production TLS/roles, maximum-size documents, long-duration receipt retention, or production autovacuum tuning.

`make postgres-max-document-smoke` is the separate [maximum-valid-document boundary gate](docs/postgres-max-document.md). Its test-only builders create a validator-approved v3 62-63 MiB control graph from one real `/16`, bounded pending nodes with explicit topology and exactly 64 groups, matching enrollments/audits, and a 7-7.5 MiB identity graph whose maximum-width OIDC claims stay below the hardened 64 KiB aggregate limit with at most 64 groups. The identity fixture includes one purpose-sealed login attempt and one expired session for the first cleanup rewrite. Legal JSON whitespace reaches the exact 64/8 MiB storage limits. The target authenticates a backup before PostgreSQL exists, validated-imports it into one exact labeled 1-GiB-capped PostgreSQL 17 container, checks revision-1 receipts/provenance and repeated authoritative reads, performs shrink-first control and identity mutations through production paths, and restarts a real server under explicit time/memory/WAL/database/disk budgets. The audited 2026-07-20 run passed at both exact document limits with exact transition/receipt proof and clean resource removal.

`make postgres-sync-failover-smoke` creates one uniquely labeled disposable PostgreSQL 17 primary/physical-standby pair, proves the named standby is synchronously streaming with `remote_apply` before the first Mesh database write, then exercises migration, authenticated import, verification, and two application replicas through multi-host read-write routing. It records the acknowledged state and receipt ledger, hard-terminates the primary, explicitly promotes the standby, proves every pre-failure inventory item, browser session, audit event, document revision, and receipt survived, commits fresh control and identity mutations, restarts an app replica, proves convergence, and removes only exact ID/label-verified resources. It does not inject ambiguous commits, restore PITR, use production TLS/roles, or establish load/soak budgets.

`make postgres-ambiguous-commit-smoke` uses real PostgreSQL 17 transactions plus a package-internal one-shot fault wrapper that is absent from production construction. It proves callback cancellation before receipt SQL is a definite noncommit; a transport loss before `COMMIT` physically rolls back but remains process-uncertain; and a lost commit acknowledgment resolves exact success without replay only when the receipt survives `remote_apply`, hard primary loss, and explicit standby promotion. It then permits one fresh write. A second lost acknowledgment resolves against a writable PostgreSQL authority with a distinct system identifier and missing receipt, returns `ErrUncertainCommit`, and gates readiness, reads, and writes. Exact labels, IDs, PIDs, private credentials, and cleanup are enforced. This bounded deterministic drill does not prove sustained mixed-write failover, automatic election/fencing, production TLS/roles, or load/soak behavior.

`make postgres-pitr-smoke` creates an authenticated current control-v13 import, one exact PostgreSQL 17 primary with a private continuously archived WAL volume, and one immutable physical base backup. With the sole app writer stopped at each boundary, it writes create-only, fsynced same-workspace evidence binding the primary system identifier, source timeline 1, named restore point, LSN, WAL filename/size/SHA-256, immutable base-backup SHA-256, exact API snapshot, authoritative-pair plus telemetry revisions, and the full receipt/import ledger. Two fresh volumes independently recover to the selected early and later points through read-only inputs and advance timelines: each exact manifest matches before any fresh write, early recovery excludes both later sessions, later recovery includes its selected session but excludes an archived post-point mutation, and the validated early authority completes a real Nebula create/enroll/sign/verify/revoke lifecycle. Cleanup is exact ID/name/label guarded. The evidence is neither authenticated nor externally custodied; this bounded local drill also does not prove WAL retention/timeline-history operations, concurrent-write/failover coverage, production TLS/roles, or load/soak budgets.

`make postgres-roles-tls-smoke` uses cached exact labeled PostgreSQL 17 and Ubuntu 24.04 containers without network pulls. The real Mesh binaries migrate, import, verify, become ready, and commit mutations through separate roles using hostname-verified TLS, `sslrootcert=system`, the conventional isolated Linux trust paths, and an unavailable-first fallback route. The drill transfers only `pgcrypto` member-function ownership through the cluster-admin channel; audits the exact ACL; denies import/runtime DDL, privilege, delete, forbidden insert/update, and forbidden-column operations; rejects plaintext and a reachable uncovered hostname; disables import login; rotates the runtime password; rejects the old password; scans diagnostics for database secrets; and removes exact resources. It is not a package-managed host trust installation, managed-database deployment, certificate lifecycle, secret-manager integration, crash-collector proof, or cross-platform claim.

`make linux-install-smoke` builds the pinned Fedora 42 systemd fixture when it is absent, reproducibly authenticates the observer-enabled Nebula stage, and creates independent ephemeral 2-of-2 root and release roles. It proves online/offline first install, same-epoch upgrade, root-only rotation, epoch-2 release-key rotation with sequence reset, revoked/old-epoch rejection, expired-intermediate multi-root catch-up, exact installer-state v2 migration, activation, rollback/recovery, state races, cleanup, runtime gates, stable unit bytes, and `/proc` executable provenance. Before expensive release builds it now reserves 32 root-owned inotify instances in an exact disposable probe and exits with prerequisite status 77 rather than changing a host sysctl when the per-UID quota is exhausted. Its separate UI-guided target enables the package-inclusive two-host extension described above. Both paths remove their exact labeled resources and private credential workspace on a normal run. Native macOS/Windows service proof remains a production milestone.

`make bootstrap-verifier-smoke` is the fast container-free first-installer gate. It builds a production-identity standalone verifier, packages it twice into byte-identical canonical USTARs, validates the exact two-member archive, proves create-only publication and narrow source/link dependencies, and rejects development, identity-mismatched, symlinked, or multiply linked package inputs. It then builds one production installer under fresh 2-of-2 root/release roles, requires receipt parity with the compatibility verifier, and rejects a wrong independent digest, a distinct root, release-role signatures, one-of-two approval, changed installer bytes, expiry, and a symlinked root. The longer Linux installation smoke uses that same standalone executable before installation. These validate the [bootstrap authorization mechanism and its non-circular trust boundary](docs/release-trust.md); they do not provision the production artifact origin, publish its real signed image or public-key custody, operate the independent handoff channel, or perform root-key custody.

`make release-origin-smoke` joins the two independently tested release paths. It first proves production Compose fails without image identity and renders one exact digest-pinned image with no build, then opts into the local-only override only to build. It pushes that image into a disposable registry, resolves the real manifest digest, passes it through the image-preflight command with a clearly test-only Cosign subprocess, and starts only through production Compose by digest. A clearly test-only security-receipt fixture exercises the production schema, and a different Docker ID fails closed without output. It publishes two exact content-addressed, read-only origin generations, rejects replacement and staging residue, selects the candidate through the single Compose generation path, requires a v2 runtime receipt binding both custody receipts, render, generation, container, exact local image/platform, Docker, hardening, and mounts, then externally audits every candidate object. It selects the retained prior generation, requires a second runtime receipt for the distinct recreated container, proves the candidate object is gone, and writes the rollback public-audit receipt. One hardened native-TLS scratch origin then serves the exact v2 handoff, root, all four Linux/Windows verifier USTARs, two root-role bootstrap signatures, bootstrap manifest, native installer, signed online bundle, release manifest, and release artifact from that generation's explicit allowlist. The proof keeps the complete create-only v2 bootstrap anchor outside that origin, authenticates the downloaded handoff from the anchor, derives and checks the selected Linux package before extracting its narrow verifier, and passes that same independent anchor directly to both verifier entry points. It requires byte-identical v3 receipts, rejects a wrong anchor or changed handoff/root, and rejects the exact-expiry handoff, verifies the downloaded installer without execution, then verifies the 2-of-2 online release through the production client. An in-place bootstrap-installer mutation makes generation inspection, runtime verification, external auditing, readiness, and retrieval fail closed without a success receipt. This proves four-package courier authoring and Linux host selection plus the digest-only deployment, runtime-binding, external-audit, and retained-generation rollback contracts; clean-host Windows extraction/execution remains a native proof gate.

The Linux install proof exits with status 77 when Docker, TUN, or a root
inotify instance is unavailable. It detects root inotify-quota exhaustion with
an isolated probe and never changes host sysctls to force the fixture to boot.

`make windows-bundle-smoke` is the narrower unsigned cross-staging proof that can run on Linux without a Windows host. It authenticates the pinned upstream archives for Wintun, reproducibly builds both security-patched Windows Nebula runtimes from the layered source/output locks, cross-builds production-identity Mesh PEs, builds each staging USTAR twice, requires byte equality, canonicalizes both targets into one release manifest under the explicit synthetic-only security-receipt bypass, signs it with ephemeral 2-of-2 roots, verifies each exact artifact, and removes all temporary keys and workspaces. After real signing and native verification, run the separate [final signed Windows bundle security gate](docs/windows-package-security.md); production authoring requires both matching package-security and Authenticode receipts. The staging smoke makes no Windows lifecycle or native-signature claim.

The separate [Windows path-security foundation](docs/windows-path-security.md)
now cross-builds authenticated single-link bundle intake, exact protected
staging, crash-resumable write-through no-replace publication, full-artifact
selection, SCM service-object protection, Windows Service dispatch, and Job
Object containment for both production architectures. Its target descriptor is
now derived from compiled-root threshold metadata, exact persisted signed
bytes, append-only root history, durable anti-rollback state, and bounded
restart-safe artifact capture. A separate cross-built privileged command now
wires canonical online/offline install, exact private snapshot preparation,
recovery, post-enrollment runtime activation, persisted-previous rollback, and
recovery-safe runtime uninstall to those mechanisms. Runtime uninstall retains
release trees, agent enrollment, root history, and anti-rollback high water. No clean
Windows native receipt exists yet; this does not establish Windows support.

`make darwin-bundle-smoke` is the corresponding Linux-host Darwin proof. It
reproducibly builds both locked thin Nebula runtime stages, cross-builds
production-identity Mesh Mach-O executables, builds and production-inspects
each canonical staging USTAR twice, rejects an appended candidate without
partial staging, threshold-verifies both artifacts under ephemeral 2-of-2
roles, and removes all private workspaces. Run the separate [Darwin
staging-bundle security gate](docs/darwin-package-security.md) for release
candidates; it makes matching receipts mandatory in production authoring.
Neither path installs or activates launchd, applies extended ACLs, performs
codesigning/notarization, or makes a native macOS lifecycle claim.

`make darwin-path-security-smoke` separately exercises the exact packed-ACL,
descriptor-walk, persistent-gate, packaged-executable, process-argument,
installer gate crash-ordering, immutable-release publication and expected-prior
current-switch ordering, exact launchd-plist replacement, canonical
compiled-root intake, append-only root history, publication/activation/rollback-journal and high-water/active/previous-state transitions, Darwin-host bundle staging,
supervisor-ordering, and
cycle-ordering logic;
validates the physical
`/private/var/db/...` launchd state paths; and reproducibly cross-builds the
native path and direct-child adapters into `darwin/amd64` and `darwin/arm64`
Mach-O executables. See the [Darwin path-security boundary](docs/darwin-path-security.md)
for its exact policy and mandatory real-Mac syscall, ACL, process, signal,
orphan, race, durability, and launchd matrix. Cross-building these adapters
does not satisfy that native-host gate.

On an approved disposable Mac, `sudo make darwin-native-runtime-smoke` runs the
opt-in self-cleaning first native subset. It injects real path, ACL, executable,
and persistent-gate faults, exercises release-layout creation, and proves exact child identity/argv, cycle-context
detachment, ordinary and forced process-group termination, exact reap, and no
residual group. It publishes hash-bound local evidence and must pass separately
on Intel and Apple Silicon; the v3 evidence is accepted by
`mesh-release verify-darwin-native-evidence` only when the full system launchctl
gate ran and all retained host, test, and source digests match. With
`MESH_DARWIN_NATIVE_BUNDLE`, it also
proves journaled release/current/plist recovery and explicit active/previous rollback in a disposable plist directory
through a fake service controller. By default it does not write
`/Library/LaunchDaemons` or invoke launchctl; the separately gated
`MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST=1` proof creates and removes only its unique
proof plist and label. It does not satisfy reboot, codesigning/notarization,
real service-controller upgrade/rollback, adversarial race, or packet proof.

The Go server embeds the dashboard into `mesh-server`; the reviewed, pinned module graph is declared in `go.mod`. There is no frontend package installation. The default JSON quick start needs no separate database process; the PostgreSQL preview requires an operator-provisioned database that satisfies the documented security and recovery gates.

## License

Mesh's original source is available under the [MIT License](LICENSE).
Vendored and bundled third-party components retain their upstream licenses; see
[Third-party notices](THIRD_PARTY_NOTICES.md) for the applicable boundaries.
The license grant does not change the documented production-readiness,
platform-support, or security-evidence limits.

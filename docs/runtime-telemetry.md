# Nebula runtime telemetry decision and contract

## Decision

Mesh does not enable Nebula's Prometheus listener, SSH server, or log parsing to
claim runtime connectivity. Slack Nebula v1.10.3 has useful in-process state,
but its upstream released binary has no least-privilege local transport for
that state. Mesh therefore packages a source-locked Linux observer fork while
keeping process/config acknowledgment separate from handshake and reachability
evidence.

The packaged Linux path is a narrowly scoped, read-only runtime snapshot added to
Nebula and exposed only over a root-private Unix-domain socket. Mesh may retain
it only in the separate nonauthoritative observation plane described below and
must not display it as authoritative health. An optional active overlay
probe can supplement the snapshot, but firewall or host capability policy must
never turn an unattempted ICMP probe into a node failure.

## Current Mesh implementation status

The isolated Mesh client/parser foundation is implemented in
`internal/runtimeobserver`. The agent-side adapter in `internal/nodeagent`
reloads and
revalidates the active immutable signed bundle, extracts exactly one IPv4
overlay prefix from the canonical host certificate, strictly extracts the
signed `lighthouse.hosts` set, performs one bounded observer request, repeats
the complete snapshot validation at the adapter boundary, and returns only the
fixed aggregate allowlist or explicit `unknown`. The adapter has no cache and
does not write agent lifecycle state.

After an accepted lifecycle heartbeat, the normal agent cycle now takes one
passive sample, resolves the independent active probe, route-overlap result,
and member-side endpoint-DNS result, and posts all four to the separate, optional
`POST /api/v1/agent/runtime-telemetry` endpoint. The report is bound to the
exact accepted heartbeat sequence. A missing endpoint on an older server and
all telemetry transport/storage failures are nonfatal to lifecycle health;
observer failures send a fresh `unknown` with no cached snapshot. The client
generates the canonical nonce-bound request, strictly validates the response
allowlist against the verified overlay prefix and exact configured lighthouse
set, and on Linux uses only the fixed root-private Unix socket with bounded
deadlines and filesystem/peer-credential checks.

The separately versioned `mesh-runtime-telemetry-state-v7` persistence plane is
also implemented. Every record contains independent passive `observation` and
fixed-shape `active_probe`, `route_overlap`, and `endpoint_dns` values, plus the
heartbeat-authenticated applied-config digest and its server-derived probe
transition. The route sibling is
limited to state, retained age, and one overlap boolean; it contains no raw
route or interface data. The DNS sibling contains only state, retained age,
configured-name count, and resolved-name count; it contains no queried name,
address, resolver configuration, or error. Process continuity is derived only from the
transition between passive observations; changing only the probe on a higher
heartbeat cannot create a process restart. A first observation, or one
immediately following `unknown`, is `unclassified`; the same process with
monotonic sample sequence, uptime, and cumulative handshake counters is
`continuous`; a changed process is `restarted`; and `unknown` is `unavailable`
and deliberately breaks the comparison chain. Probe transitions compare only
consecutive heartbeats with attempted results, the same nonempty applied-config
digest, and the same attempted count; a gap or config change is `unclassified`,
and attempted-count ambiguity is rejected. An exact same-heartbeat retry must
match all four sibling values and the private digest, while equivocation, same-process replay,
version rollback, uptime rollback, or cumulative-counter rollback leaves the
previous record intact. Canonical v1 through v6 documents migrate strictly
to v7, assigning `unsupported` missing sibling evidence and a current-only
probe transition without inventing retained age, configuration identity, or
transition history. JSON mode uses a private crash-durable
file store;
PostgreSQL migration 002 permits one bounded `runtime_telemetry` exact document
that remains outside `ReadPair` and the authenticated two-document backup
format. Authenticated reports are replay/equivocation checked and persisted
with server receive time. PostgreSQL import initializes this reconstructible
document only after the authoritative imported pair and provenance pass.

Administrators can now read a strict, no-store
`GET /api/v1/fleet/runtime-telemetry` projection when the optional telemetry
store is configured. The versioned `mesh-runtime-telemetry-fleet-v5` response
contains only node ID, exact lifecycle-heartbeat sequence, server receive time,
observation version/state, derived process-continuity enum, bounded passive
aggregates, the six fixed active-probe result fields, and a bounded
`probe_transition` enum. It omits the private applied-config digest, observer
process identity, local and target addresses, plan hashes, nonces, packet
bytes, and socket errors, and explicitly declares `aggregate_only: true` and
`end_to_end_reachability_proven: false`. The endpoint is authenticated,
query-free, concurrency-bounded with the fleet projections, read-only, and
fails with a generic server error for unreadable or invalid repository state.
The fleet-v5 projection deliberately continues to omit the route and DNS
siblings; they are consumed only by the stricter per-network readiness
correlation.

The separate network-readiness v5 projection may consume these aggregate
siblings under narrower correlation rules without changing that fleet-API
declaration. Public UDP requires every active operational member, exact current
heartbeat and signed-config convergence for each, a complete control-plane recomputation
of every active policy-eligible lighthouse, exact all-target replies, and at
most 30 seconds of effective server-derived age. Route safety requires every
current active node to be operational and exact-heartbeat matched and to report
no intersecting non-default route within 90 seconds; one current observed
conflict blocks. Member-side DNS additionally requires every current active
member to report the exact active-lighthouse DNS-name count within 90 seconds;
one observed unresolved result blocks. Anything partial, stale, replayed,
duplicated, unsupported, policy-ineligible, over the probe ceiling, or
unavailable remains `unknown`.
Readiness exposes only aggregate counts, booleans, and time; it does not add
identities, addresses, interfaces, routes, plans, or packet details and does not
claim general end-to-end application reachability.

The dashboard fetches that projection independently of the authoritative
fleet-health snapshot. It attaches a record only when node ID and heartbeat
sequence exactly match the displayed lifecycle snapshot, advances freshness
from server time plus local elapsed time, and labels evidence only as
`observed`, `unknown`, `not current`, `stale`, or `unavailable`. For an observed
v5 record it additionally explains whether the immediately prior passive
observation was continuous, crossed a restart, or was unavailable for
comparison, and whether a consecutive same-policy attempted probe was stable,
recovered, degraded, or changed. The strict browser parser also accepts exact
fleet v2 through v4 records and derives only a current-record probe state; it
never fabricates a historical transition. Old strict clients reject v5 and
fail closed. Servers accept an exact old-agent envelope with no probe, route,
or DNS result and normalize missing siblings to `unsupported`, so server rolls
remain compatible with older agents. A telemetry
request, validation, clock, or rendering failure clears only observational
evidence; it cannot clear or reclassify verified lifecycle health. The UI does
not call any aggregate healthy or reachable. Passive and active sentences are
rendered independently, so a sound ICMP result remains visible when the
observer is `unknown`, and an observer sample remains visible when the ping
socket is unavailable. Attempted samples report only replied/attempted
lighthouse ICMP counts, an elapsed lower bound, and only a same-signed-policy
comparison when the immediately previous heartbeat supplies comparable
evidence. Passive v2 renders retained
lighthouse receive age as an elapsed lower bound; passive v1 says retained
history is unavailable. Neither is presented as general end-to-end
reachability.

Linux bundle schema v2 now requires the reproducibly built observer stage,
records its complete source/patch/toolchain provenance, and installs a systemd
unit that owns the mode-0700 `/run/mesh-nebula` lifecycle. The isolated Linux
install smoke requires the root-owned mode-0600 socket while Nebula is active
and its runtime directory to be absent while stopped.

The Linux namespace/TUN overlay smoke now builds that exact stage and runs two
observer-enabled peers with separate private `/run` mounts. Accepted snapshots
pass through Mesh's production socket validation and strict parser. The live
proof covers completed Noise handshakes, authenticated receive freshness,
exact lighthouse aggregation, within-process sample sequencing, restart
process-instance discontinuity, and revoked-peer exclusion after a signed
blocklist revision. Its underlay-only failure phase also proves the actual
default Nebula transition: active tunnel testing evicts the dead host-map
entry before two minutes while the process-retained lighthouse receive age
continues to advance, a later handshake attempt increments `timed_out_total`,
and restoring the link completes a fresh handshake and authenticated receive
in the same process.

A separate opt-in namespace/TUN proof drives the same authenticated Mesh
lifecycle with two live lighthouses and one member on independent point-to-point
underlays. It proves exact two-lighthouse aggregation, keeps one authenticated
lighthouse current while the other is evicted and times out, restores both in
the original member process, then advances the member to a signed configuration
with nine active lighthouse records. Seven are deliberately not started; the
strict observer still reports `configured=9`, `overflow=true`, complete
aggregates for the two live tunnels, and only those two bounded entries.

The opt-in active-probe namespace/TUN mode now exercises the production signed
planner, crash-durable cadence journal, Linux datagram-ping executor, lifecycle
heartbeat, telemetry report, v4 persistence, fleet projection, and independent
health projection. Under an exact signed TCP-only policy it records
`not_eligible` and a root-only cooked AF_PACKET capture on the member TUN sees
zero echo requests. Restoring signed ICMP permission produces a validated
lighthouse reply from a zero-capability process; an immediate restarted cycle
reuses the sample and emits no packet; and changing to a different eligible
lighthouse plan inside the 30-second window returns `unavailable` with no
packet. Excluding the service group from namespace `ping_group_range` yields
`capability_unavailable` while passive observation remains sound. Hiding the
observer mount yields passive `unknown` while the independent probe still
receives an exact reply. Every case remains outside authoritative lifecycle
health, exposes no private plan or packet fields, and the cleanup audit removes
all temporary processes, namespaces, mounts, journals, and workspaces.

This still does **not** make overlay telemetry an authoritative health feature.
Health-alert promotion, release rollout/rollback drills, and native
macOS/Windows transports remain outstanding. Unsupported or failed observers
persist `unknown`; an exact v1 observer remains labeled as a legacy observation
with retained history unavailable. The observation UI never infers health from
lifecycle data.

## Evidence from the pinned dependency

This decision is based on the source and released binaries pinned by
`third_party/nebula/v1.10.3.lock.json`: tag `v1.10.3`, commit
`f573e8a26695278f9d71587390fbfe0d0933aa21`.

- `stats.go` starts Prometheus with `http.ListenAndServe` on a configured TCP
  address and the default HTTP handler. It provides no authentication, TLS,
  Unix-socket mode, peer-credential check, or response allowlist.
- `hostmap.go` and `handshake_manager.go` publish process-local aggregate
  gauges and counters such as main/pending host counts and initiated/timed-out
  handshakes. `interface.go` also records a successful-handshake-duration
  histogram. These values do not identify freshness for a particular peer or
  prove that an established tunnel still carries authenticated traffic.
- `control.go` can copy host-map state safely when Nebula is embedded as a Go
  library. The released `nebula` process does not expose that `Control` object
  over a narrow local IPC boundary.
- `ssh.go` exposes host-map reads, but the same server registers commands that
  reload configuration, create/close tunnels, change remotes, change logging,
  and write CPU, heap, and mutex profiles. Enabling it would introduce a broad
  administrative interface and a new SSH host/user-key lifecycle.
- Successful-handshake log messages are event records, not a snapshot. Even a
  bounded journal window loses long-lived tunnels, cannot prove recent
  authenticated traffic, and couples Mesh to log text/format and retention.

Consequently:

- A loopback bind does not make the unauthenticated Prometheus TCP listener an
  acceptable agent protocol.
- Restricting which SSH commands Mesh invokes does not remove the other commands
  from the listening server.
- Host-map presence is evidence of local runtime state, not peer reachability.
- Current Mesh heartbeat fields prove the managed process and exact signed
  bundle path are active. They must not be relabeled as handshake freshness.

## Packaged observer snapshot

### Transport and ownership

The Linux implementation exposes exactly one `AF_UNIX` stream socket at
`/run/mesh-nebula/runtime-observer.sock` while the managed Nebula process is
running.

- The Nebula systemd unit creates the real, root-owned mode-`0700`
  `RuntimeDirectory=mesh-nebula`, does not preserve it across stops, and grants
  the otherwise hardened service write access only there. No TCP, UDP, HTTP,
  SSH, abstract Unix socket, or fallback listener is permitted.
- Nebula binds with umask `0077`; the final socket must be root-owned and
  mode-`0600`. An unexpected existing path, symlink, hard link, non-socket, or
  ownership/mode mismatch fails startup instead of being removed blindly.
- Linux accepts only a peer whose `SO_PEERCRED` effective UID is `0`. File mode
  is not a substitute for the peer-credential check.
- The listener serves at most one request per connection, at most two
  simultaneous connections, and a small fixed request rate. Accept, read,
  write, and total connection deadlines are mandatory.
- The socket disappears with the runtime directory. Nebula must close it before
  dropping live tunnel state during shutdown.

Darwin needs a separately proved Unix-socket parent/ACL boundary and
`getpeereid` check. Windows needs a named pipe with a service-account-only DACL
and verified client token. Neither platform may emulate the contract with a
loopback network listener; unsupported builds report telemetry unavailable.

### Request framing

The protocol is deliberately not a general RPC or debug command set.

- The request is one newline-terminated JSON object no larger than 256 bytes:

  ```json
  {"schema":"nebula.runtime-observer.request.v1","operation":"snapshot","nonce":"<32 lowercase hex>"}
  ```

- Unknown, duplicate, missing, non-canonical, or trailing fields are rejected.
  `snapshot` is the only operation and takes no peer, path, address, or command
  argument.
- The response is one newline-terminated JSON object no larger than 16 KiB.
  It repeats the nonce, uses canonical field types, and closes the connection.
- Malformed, oversized, slow, or concurrent clients receive a bounded generic
  error. No parser or transport error includes configuration, peer, key, path,
  or packet data.

### Response allowlist

The snapshot contains raw observations, not an upstream `healthy` verdict:

```json
{
  "schema": "nebula.runtime-observer.snapshot.v2",
  "nonce": "<request nonce>",
  "process_instance_id": "<32 lowercase hex>",
  "sample_sequence": 42,
  "process_uptime_ms": 123456,
  "handshakes": {
    "completed_total": 8,
    "timed_out_total": 1,
    "pending": 0,
    "most_recent_completion_age_ms": 2200
  },
  "peers": {
    "established": 3,
    "authenticated_rx_within_2m": 3,
    "authenticated_rx_within_5m": 3,
    "oldest_authenticated_rx_age_ms": 17000
  },
  "lighthouses": {
    "configured": 2,
    "established": 2,
    "authenticated_rx_within_2m": 2,
    "authenticated_rx_within_5m": 2,
    "most_recent_authenticated_rx_age_ms": 900,
    "overflow": false,
    "entries": [
      {
        "vpn_ip": "10.42.0.1",
        "established": true,
        "last_handshake_age_ms": 2200,
        "last_authenticated_rx_age_ms": 900
      }
    ]
  }
}
```

Contract details:

- `process_instance_id` is a nonsecret random identifier generated at process
  start. `sample_sequence` increases within that instance. A consumer computes
  counter deltas only when both values form a continuous series.
- Ages are calculated from Nebula's monotonic clock. `null` means the event has
  not occurred in this process instance. Values are nonnegative and saturated
  at an explicit protocol maximum rather than wrapping.
- Counter, sequence, uptime, and age integers saturate at
  `9,007,199,254,740,991` (`2^53-1`) so every accepted JSON integer remains
  exact across consumers. Host/count aggregates, including pending handshakes,
  saturate at `4,294,967,295` (`2^32-1`). Every non-null age must be no greater
  than `process_uptime_ms`.
- `completed_total` increments only after the Noise handshake is accepted and
  the tunnel enters the main host map. `timed_out_total` follows the existing
  handshake-manager timeout point.
- `authenticated_rx` advances only after a packet from that tunnel passes
  Nebula authentication/decryption and replay checks. Socket receipt, an
  underlay datagram, host-map presence, an outbound send, or a pending handshake
  cannot advance it.
- Lighthouse entries are the deterministic, numerically sorted intersection of
  configured lighthouse overlay addresses and current host-map observations.
  The response is capped at eight entries; a larger configured set returns a
  bounded `overflow` indicator and aggregates all entries without truncating
  the counts.
- Mesh supplies the parser an exact lighthouse set from the active signed
  configuration and rejects entries outside that set or its canonical IPv4
  overlay prefix. The client-side expected set is capped at 64 addresses; its
  size must exactly match `lighthouses.configured`. `overflow` is true exactly
  when that configured size exceeds eight.
- V2 retains one bounded, process-local authenticated-RX mark per configured
  lighthouse overlay address (at most 64) independently of the host map.
  `most_recent_authenticated_rx_age_ms` is the youngest retained mark across
  the currently configured set. It may remain non-null when `established` and
  both recent-established counts are zero after Nebula evicts a dead tunnel;
  it resets on Nebula restart and does not assert a current tunnel or
  reachability. Removed configured addresses are excluded and pruned.
- A new client also accepts the exact canonical v1 response allowlist. It
  preserves that sample as observation version 1 with retained history
  unavailable; it never synthesizes an exact age from v1 bucket counts. An old
  strict client rejects a v2 response and therefore fails closed to `unknown`.
- `established` alone never means reachable. Mesh applies separately versioned
  warning/offline thresholds to the ages.

The response must not include certificates, fingerprints, groups, unsafe
routes, firewall rules, private/public keys, packet payloads, local or remote
underlay addresses, relay paths, log records, process environment, file paths,
or arbitrary metric names/labels. The fixed allowlist prevents a future global
metrics registry addition from silently expanding this trust boundary.

### Failure semantics

- Missing socket, refused connection, credential rejection, timeout, malformed
  response, impossible numeric
  overflow, or unsupported platform produces `runtime_telemetry=unknown`. A
  canonical v1 observer is accepted as legacy evidence with no retained age. The
  explicit bounded lighthouse-entry `overflow` flag is a valid snapshot, not a
  transport failure; its aggregate counts remain complete.
- `unknown` does not become `healthy`, and stale prior samples are not extended.
- The current ephemeral adapter returns a new `unknown` for every topology,
  transport, or snapshot-validation failure and never returns an earlier
  sample. It deliberately keeps no cross-sample history. The versioned
  persistence gate compares only the immediately previous accepted record:
  same-process sample replay and monotonic-field rollback are rejected without
  replacing it, a process change is accepted as `restarted`, and an accepted
  `unknown` replaces the prior observation and breaks the continuity chain.
- Telemetry failure does not authorize configuration, acknowledge a reload,
  restart Nebula, stop Nebula, or change the five-minute signed-state freshness
  gate. It is a separate observation plane.
- The agent sends no new heartbeat fields. Runtime observations use a separate
  versioned endpoint and persistence document, preserving exact control
  backup/restore and rollback compatibility. Existing `status` and
  `last_error` fields are not overloaded with encoded counters.
- Local root controls both processes and can spoof the observation. This is
  operational evidence, not an independent security attestation.

## Optional policy-aware active probe

The implemented active probe answers a narrower question than the passive
observer: did this host exchange one specifically permitted ICMP packet with a
configured lighthouse through the overlay? It does not replace the runtime
snapshot or prove general application reachability.

From the revalidated active signed bundle the no-I/O planner strictly parses
Mesh's rendered `static_host_map`, remote `lighthouse.hosts`, and outbound
firewall rules; requires every candidate in both topology sections and the
verified certificate network; and returns at most eight numerically ordered
targets only when an exact ICMP/any rule proves egress permission. Inbound-only
permission, nonmatching selectors, and policy denial produce no targets.
Malformed, duplicate, alternate-YAML, or incomplete signed topology fails
closed before the executor is reached.

Linux then performs a bounded ICMP echo to eligible lighthouse overlay
addresses with all of these preconditions:

- The targets come only from the already signature-verified
  `lighthouse.hosts` set, also exist in `static_host_map`, and are contained by
  the local verified Nebula certificate network.
- Analysis of the exact active signed firewall policy proves the request and
  its stateful reply are permitted under Nebula's firewall/conntrack semantics.
  A policy that denies ICMP makes the probe `not_eligible`; it does not make the
  node degraded or unreachable.
- Linux uses a datagram ping socket from the local overlay address under the
  actual `mesh-agent` service sandbox. The current empty capability bounding
  set is retained. If the host `ping_group_range` policy does not permit the
  socket, the result is `capability_unavailable`; Mesh must not add
  `CAP_NET_RAW` to force telemetry.
- No shell or external `ping` process is used. Requests contain a fresh random
  nonce, are at most 64 bytes, validate the exact reply source/type/nonce, and
  expose no persistent secret.
- At most eight targets are probed once per execution, no more often than every
  30 seconds across agent restarts and `--once` cycles, with at most 750 ms per
  target and six seconds total. A canceled agent cycle promptly closes the one
  socket and cancels outstanding work.

The cadence is a separate adjacent
`mesh-agent-active-probe-journal-v1` file. It stores only a domain-separated
SHA-256 of the ordered private plan, a UTC reservation instant, and the last
fixed public result. It is a canonical root-private mode-`0600` regular file
written by atomic replace with file and parent-directory sync. Mesh durably
reserves the window before opening a socket; a crash therefore cannot create a
restart burst. An unchanged completed plan inside the window reuses its result
and advances `sample_age_ms`; a changed eligible plan, future timestamp, clock
regression, unreadable/corrupt journal, failed reservation, or failed final
write returns `unavailable` without early packet I/O. A missing journal is the
only create-new case, and `not_eligible` or non-Linux `unsupported` does not
touch a prior packet reservation.

Probe results use explicit states:

- `not_eligible`: policy denies ICMP or there is no remote lighthouse.
- `unsupported`: the operating-system implementation has not passed its native
  proof.
- `capability_unavailable`: the sandbox/host cannot create the ping socket.
- `attempted`: includes attempted and replied counts plus a bounded sample time.
- `unavailable`: policy/topology, cadence, clock, journal, entropy, or execution
  state could not produce sound evidence.

The fleet projection separately classifies only the current result or one
comparison with the immediately previous heartbeat:

- `unavailable`: the current probe has no attempted packet evidence;
- `not_eligible`: the current signed policy does not permit an attempt;
- `unclassified`: the current probe was attempted, but the preceding heartbeat
  is missing, was not attempted, or has a missing or different applied-config
  digest;
- `stable`: consecutive same-config attempts used the same target count and
  produced the same reply count;
- `recovered`: a partial same-config result became complete;
- `degraded`: a complete same-config result became partial;
- `changed`: two partial same-config results have different reply counts.

The server rejects a changed target count under one digest, never compares
across a heartbeat gap, persists the digest only in the private observation
document, and exposes only the derived enum. These labels describe bounded
ICMP-to-lighthouse evidence; none is lifecycle health or general application
reachability.

Only `attempted` with a missing reply is negative reachability evidence, and it
must be labeled as ICMP-to-lighthouse evidence rather than handshake failure.
The server-first rolling-upgrade contract accepts old reports with no probe as
`unsupported`; a new strict fleet-v5 projection always includes the fixed
result object and its current or config-bound transition. Darwin and Windows compile a no-I/O executor and fail closed as
`unsupported` until native socket, privilege, firewall, and packaging tests
pass.

## Phased acceptance proof

### Phase 1: upstream unit and adversarial tests

- Race-test snapshots while handshakes complete, tunnels rehandshake/close, the
  lighthouse list reloads, and authenticated packets update timestamps.
- Prove counters are monotonic/saturating, ages use a monotonic clock, entries
  sort deterministically, and snapshots copy data without retaining internal
  pointers.
- Fuzz strict request decoding and bounded canonical response encoding.
- Reject oversized, duplicate-field, unknown-operation, trailing-data,
  slow-reader, slow-writer, and excess-concurrency clients.
- Assert the response key allowlist so secrets and newly registered metrics
  cannot appear accidentally.

### Phase 2: Linux transport and sandbox proof

- Start the exact packaged services and prove the only observer is a
  root-owned mode-`0600` filesystem Unix socket beneath the mode-`0700` runtime
  directory; prove no new TCP/UDP listener exists.
- Prove an unprivileged UID, a different service UID, a symlinked parent, a
  preexisting regular file/socket, and wrong ownership/mode all fail closed.
- Prove peer credentials are checked even if test setup temporarily relaxes
  socket mode.
- Crash/restart Nebula and prove the socket is cleaned without unlinking an
  attacker-controlled path and `process_instance_id` changes.

### Phase 3: real overlay behavior

- Done: in isolated Linux network and mount namespaces with exact locked Nebula
  binaries, a permitted packet completes a handshake and advances accepted
  authenticated-receive evidence; repeated samples advance exactly within one
  process, restart creates a new instance/sequence, and signed revocation leaves
  the restarted lighthouse with no established peer.
- Done: severing only the underlay causes active tunnel-test eviction while the
  v2 snapshot reports zero established/current entries and retains an advancing
  authenticated lighthouse RX age. A later handshake times out; restoring the
  underlay causes a fresh handshake and authenticated RX without a process
  restart, resetting the retained age to fresh evidence.
- Done: exercise two live lighthouses on independent underlays and prove exact
  two-of-two aggregation, one-of-two partial failure and recovery, and bounded
  overflow at nine configured lighthouses without exposing underlay addresses.
- Done: persist consumer-side process continuity across file and PostgreSQL
  stores. The first accepted observation and the first observation after an
  accepted `unknown` are baselines, same-process monotonic advances are
  `continuous`, and Nebula process-instance changes are `restarted` without
  comparing process-local counters across that boundary.
- Make the socket absent, malformed, slow, and permission-denied. Mesh must
  report telemetry unknown while leaving existing runtime/config enforcement
  semantics unchanged.

### Phase 4: active probe and control-plane integration

- Done: signed ICMP denial emits no TUN request and records `not_eligible`
  without changing lifecycle health.
- Done: signed ICMP permission proves request size/target/cardinality, fresh
  nonce and exact reply validation, bounded timeouts, and a real lighthouse
  reply. An immediate restart reuses the durable result with no packet, and a
  changed eligible target plan inside the window returns `unavailable` with no
  packet.
- Done: a disallowed Linux ping socket records `capability_unavailable` with an
  empty effective/bounding capability set and no subprocess. Separately, a
  missing observer preserves the sound probe and probe capability denial
  preserves the sound passive observation.
- Done: Mesh uses the separate bounded telemetry-store alternative. State v4,
  fleet v4, exact v1/v2/v3 migrations, old-agent normalization, PostgreSQL
  migration identity, strict browser fallback, privacy allowlists, and
  server-first mixed-version rollout are covered without changing control
  schema v2 or its authenticated two-document backup.
- Only after those proofs may the observational UI be promoted into health
  alert codes for handshake age, authenticated traffic,
  runtime/overlay-derived lighthouse reachability, probe eligibility/result,
  and telemetry unknown. The existing lifecycle-health lighthouse alerts count
  recently proven managed processes; they do not claim handshake reachability.

### Phase 5: native platforms

- Repeat the transport, identity, service lifecycle, firewall, and packet proof
  on native macOS and Windows packages. Unsupported or partially proved builds
  continue to report telemetry unavailable and do not open a loopback listener.

## Completion gate

Runtime handshake telemetry is complete only when a locked Nebula build with
the read-only local observer passes Phases 1 through 4 on packaged Linux, Mesh
persists it through an explicit compatible schema, and the dashboard labels
unknown, established, recently authenticated, and actively probed states
without conflating them. Cross-platform completion additionally requires Phase
5; process-running heartbeats and Prometheus/SSH workarounds do not satisfy this
gate.

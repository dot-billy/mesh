# Runtime Observer Multi-Lighthouse Proof Design

## Purpose

Prove that Mesh's signed lifecycle and strict runtime-observer path behave
correctly with more than one configured Nebula lighthouse. The proof must use
real Mesh-created nodes, real signed bundles, the exact source-locked Nebula
observer binary, Linux network namespaces, TUN devices, authenticated overlay
traffic, and Mesh's production observer client.

This is an evidence slice. It does not change the observer schema, persistence
schema, administrator API, dashboard, or lifecycle-health classification.

## Scope

The proof has two phases:

1. Three active nodes: two lighthouses and one member. The member establishes
   authenticated tunnels to both lighthouses. One lighthouse's underlay is
   removed while the other stays usable, then restored.
2. Nine configured lighthouses: the two live lighthouses plus seven Mesh-enrolled
   lighthouses that are intentionally not started. The member consumes the new
   signed revision and restarts its Nebula process. The observer must report the
   exact configured count and bounded overflow semantics while retaining only
   the two real live entries.

The existing single-lighthouse outage, policy, rollback, and revocation smoke
remains the authority for those behaviors. This proof does not duplicate or
replace it.

## Approaches considered

### Extend every packet smoke run

Running the full policy/revocation lifecycle with ten nodes would maximize
coverage in one invocation, but would make the existing gate much slower and
couple unrelated assertions to a more complicated topology.

### Hand-write a standalone Nebula topology

A small raw-Nebula script would be simpler, but it would bypass Mesh network
creation, enrollment, signed configuration generation, immutable bundle
activation, and the strict production observer client. It would not prove the
product path in the goal.

### Add an opt-in mode to the existing harness

This is the selected approach. A dedicated wrapper builds the exact observer
stage and invokes `scripts/packet-smoke.sh` with a new explicit mode. The mode
reuses the hardened setup, enrollment, process-launch, capture, and cleanup
functions, then exits after its focused assertions. Default behavior stays
unchanged.

## Topology

The member namespace has two independent underlay interfaces:

- `underlay0`: `192.0.2.2/30`, directly paired with lighthouse A at
  `192.0.2.1/30`.
- `underlay1`: `198.51.100.2/30`, directly paired with lighthouse B at
  `198.51.100.1/30`.

There is no host address, route, bridge, NAT, or external network dependency.
Taking `underlay0` down cannot disturb the member-to-lighthouse-B path.

Mesh allocates overlay addresses from `10.88.0.0/24`. The observer client gets
the exact configured overlay lighthouse set from the signed member bundle, not
from smoke-script assumptions.

## Harness interface

`MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE=1` selects this proof. It requires
`MESH_RUNTIME_OBSERVER_SMOKE=1` and rejects combination with the existing
all-underlay outage mode because that mode has deliberately different aggregate
expectations.

`scripts/nebula-observer-multilighthouse-smoke.sh` is the supported entrypoint.
It builds the same exact locked observer stage and isolated Mesh binaries as the
existing observer overlay wrapper, sets the required mode flags, and delegates
to `scripts/packet-smoke.sh`.

## Evidence phases

### Dual-lighthouse active state

The control plane creates and enrolls both lighthouse nodes before the member
performs its final initial agent poll. All three nodes must converge on the same
signed revision. Both lighthouses run in separate network and private mount
namespaces, and the member sends authenticated ICMP through each tunnel.

Two consecutive member snapshots must have one process identity and adjacent
sample sequences. The second must report:

- `lighthouses.configured=2`
- `lighthouses.established=2`
- both recent authenticated-RX counters equal to `2`
- a non-null retained authenticated-RX age
- `overflow=false`
- exactly two numerically sorted entries, each established with non-null
  handshake and authenticated-RX ages

### One-lighthouse underlay loss and recovery

The harness takes only member `underlay0` down and continually proves ICMP to
lighthouse B. It polls until lighthouse A has been evicted and a handshake to it
has timed out. In the same member process, the observer must report two
configured lighthouses, one established/recent entry for lighthouse B, and no
entry for lighthouse A. The aggregate remains observational and makes no
reachability or health claim.

After restoring `underlay0`, authenticated ICMP to lighthouse A must complete a
fresh handshake. The next snapshot, still from the same process, must return to
two established/recent lighthouse entries without counter rollback.

### Overflow state

The control plane creates and enrolls seven more lighthouse nodes with distinct
reserved documentation endpoints. These processes are not started. The member
agent accepts the latest signed bundle, whose exact `lighthouse.hosts` and
`static_host_map` sets contain nine lighthouses, and the harness explicitly
restarts the member so Nebula consumes that configuration.

After authenticated ICMP to the two real lighthouses, the strict production
observer client receives all nine expected overlay addresses. The accepted
snapshot must report:

- `configured=9`
- `overflow=true`
- `established=2`
- both recent authenticated-RX counters equal to `2`
- exactly two numerically sorted live entries for the running lighthouses
- no entry or evidence synthesized for the seven non-running lighthouses

This proves the first value beyond the eight-entry response cap without starting
unnecessary processes. Existing unit and adversarial tests remain responsible
for the 64-address client bound, canonical response parsing, malformed overflow,
and duplicate-tunnel accounting.

## Failure handling and cleanup

Every namespace, veth, launcher, private runtime mount, token, node state, and
diagnostic remains under the existing guarded temporary workspace and cleanup
trap. Cleanup gains explicit second-lighthouse state and refuses unexpected
paths just as the existing harness does. A failed assertion prints only a short
public error; private diagnostics are removed.

The mode fails closed when its flags are inconsistent, any active node revision
does not converge, a process exits, an observer snapshot is rejected, the
surviving path stops passing authenticated traffic, ordering differs from the
canonical IPv4 order, or any exact count differs.

## Security and product semantics

- All nodes and configurations originate from Mesh's authenticated control
  plane and signed lifecycle.
- The observer socket stays mode `0600` under a root-private `/run` mount.
- The smoke client receives the exact signed lighthouse set and network prefix.
- Private keys, certificates, process identity, underlay addresses, and entry
  details remain outside the administrator runtime-telemetry projection.
- The proof establishes bounded operational evidence only. It does not label a
  node, tunnel, lighthouse, or network healthy or generally reachable.

## Acceptance evidence

The slice is accepted only when all of these pass freshly:

1. `bash -n` for the packet harness and both observer wrappers.
2. The existing single-lighthouse observer overlay smoke.
3. The new multi-lighthouse smoke, including partial underlay loss/recovery and
   the nine-configured overflow state.
4. `go test ./...`, `go vet ./...`, observer/runtime telemetry race tests, and
   the runtime-telemetry browser tests.
5. Cleanup checks showing no Mesh temporary workspaces or Mesh-created network
   namespaces remain.


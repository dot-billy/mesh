# Runtime Observer Multi-Lighthouse Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-cleaning live proof that Mesh configures two working Nebula lighthouses, preserves one during isolated failure of the other, and emits strict bounded overflow evidence with nine configured lighthouses.

**Architecture:** Add a dedicated wrapper that selects a new opt-in branch in the existing hardened packet harness. The branch uses two independent point-to-point underlays, Mesh's real create/enroll/agent flow, the exact locked observer binary, and the production smoke client. It exits after focused multi-lighthouse assertions so the existing policy/revocation path remains unchanged.

**Tech Stack:** Bash 4+, Linux network namespaces/veth/TUN, Mesh Go binaries, Slack Nebula v1.10.3 observer fork, Python 3 standard library assertions.

---

### Task 1: Add an explicit, fail-closed harness mode

**Files:**
- Create: `scripts/nebula-observer-multilighthouse-smoke.sh`
- Modify: `scripts/nebula-observer-overlay-smoke.sh`
- Modify: `scripts/packet-smoke.sh`

- [ ] **Step 1: Verify the new supported entrypoint is absent**

Run:

```bash
test -x scripts/nebula-observer-multilighthouse-smoke.sh
```

Expected: nonzero because the supported entrypoint does not exist.

- [ ] **Step 2: Add mode parsing before any capability mutation**

Add the exact packet-harness input:

```bash
observer_multilighthouse_smoke="${MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE:-0}"
```

Validate it with the existing `0 | 1` convention. Require observer mode and
reject combination with `MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE=1`:

```bash
case "${observer_multilighthouse_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE must be exactly 0 or 1" ;;
esac
if [[ "${observer_multilighthouse_smoke}" == "1" && "${observer_smoke}" != "1" ]]; then
  die "MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE requires MESH_RUNTIME_OBSERVER_SMOKE=1"
fi
if [[ "${observer_multilighthouse_smoke}" == "1" && "${observer_outage_smoke}" == "1" ]]; then
  die "multi-lighthouse and single-lighthouse outage modes are mutually exclusive"
fi
```

- [ ] **Step 3: Parameterize the existing observer wrapper without changing its defaults**

In `scripts/nebula-observer-overlay-smoke.sh`, default outage mode to `1` and
multi-lighthouse mode to `0`, validate both, and pass them to
`scripts/packet-smoke.sh`. A no-environment invocation must keep running the
existing outage proof.

- [ ] **Step 4: Add the dedicated wrapper**

Create a guarded Bash script that resolves its own directory and executes:

```bash
MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE=0 \
MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE=1 \
  exec "${script_dir}/nebula-observer-overlay-smoke.sh"
```

Use `set -Eeuo pipefail`, `umask 077`, and an absolute physical script directory.

- [ ] **Step 5: Verify parsing and syntax**

Run:

```bash
bash -n scripts/packet-smoke.sh scripts/nebula-observer-overlay-smoke.sh scripts/nebula-observer-multilighthouse-smoke.sh
env MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE=1 MESH_RUNTIME_OBSERVER_SMOKE=0 scripts/packet-smoke.sh
```

Expected: syntax exits zero; the second command exits nonzero with the exact
observer-mode dependency error before creating a temporary workspace.

### Task 2: Build and clean a three-namespace underlay

**Files:**
- Modify: `scripts/packet-smoke.sh`

- [ ] **Step 1: Add second-lighthouse lifecycle variables**

Add separate namespace, launcher PID, Nebula PID, created flag, and veth names:

```bash
second_lighthouse_launcher_pid=""
second_lighthouse_nebula_pid=""
second_lighthouse_ns=""
second_lighthouse_ns_created=0
second_lighthouse_veth=""
second_member_veth=""
```

- [ ] **Step 2: Extend cleanup before creating the namespace**

Delete the second-lighthouse namespace before the first lighthouse, wait for its
launcher, and include both new veth names in the guarded link cleanup loop. This
must be present before any code can set `second_lighthouse_ns_created=1`.

- [ ] **Step 3: Assign collision-resistant names**

When multi-lighthouse mode is enabled, derive a second namespace and link names
from the existing hexadecimal PID suffix. Keep every Linux interface name at or
below 15 bytes.

- [ ] **Step 4: Create the independent underlay**

After the existing pair is up, create a second lighthouse namespace and direct
veth pair. Configure:

```text
second lighthouse underlay0 = 198.51.100.1/30
member underlay1            = 198.51.100.2/30
```

Bring loopback and both new interfaces up. Namespace deletion must remove the
pair without leaving host links.

- [ ] **Step 5: Run a capability-level live attempt**

Run the new wrapper. Expected at this checkpoint: it advances through namespace
creation and fails later because the second Mesh lighthouse lifecycle and
assertions have not yet been implemented. Confirm cleanup leaves no namespace
whose name starts with `meshps-`.

### Task 3: Enroll and prove two active lighthouses

**Files:**
- Modify: `scripts/packet-smoke.sh`

- [ ] **Step 1: Create a second lighthouse through the authenticated API**

In multi-lighthouse mode, post this node before the member is enrolled:

```json
{"name":"packet-lighthouse-b","role":"lighthouse","public_endpoint":"198.51.100.1:4242"}
```

Validate its node ID, overlay IP, enrollment bearer, and uniqueness against both
existing nodes.

- [ ] **Step 2: Enroll and validate the second immutable bundle**

Use the existing `enroll_node`, `validate_bundle`, and `run_validation_agent`
helpers. Require lighthouse A, lighthouse B, and the member to converge on one
positive signed revision before starting Nebula.

- [ ] **Step 3: Start the second observer-enabled Nebula process**

Use `start_nebula` in the second namespace and require its overlay address on a
non-underlay interface. Send authenticated ICMP from the member to both
lighthouse overlay addresses.

- [ ] **Step 4: Add an exact dual-lighthouse assertion**

Capture two member snapshots with both expected lighthouse IPs. Inline Python
must require one process identity, adjacent sequences, two established peers,
two recent authenticated peers, and this lighthouse aggregate:

```json
{
  "configured": 2,
  "established": 2,
  "authenticated_rx_within_2m": 2,
  "authenticated_rx_within_5m": 2,
  "overflow": false
}
```

Require a non-null retained age and exactly two established entries in numeric
IPv4 order, each with non-null handshake and authenticated-RX ages.

- [ ] **Step 5: Run the live proof to its next intentional failure**

Run:

```bash
./scripts/nebula-observer-multilighthouse-smoke.sh
```

Expected: the dual-active assertion passes; the invocation fails later because
the partial outage/recovery phase has not yet been added. Confirm both
lighthouse processes remained running through the assertion and cleanup removed
all `meshps-` namespaces.

### Task 4: Prove isolated loss and same-process recovery

**Files:**
- Modify: `scripts/packet-smoke.sh`

- [ ] **Step 1: Add the degraded-state predicate**

The predicate must accept only a snapshot with:

```text
configured=2
established=1
authenticated_rx_within_2m=1
authenticated_rx_within_5m=1
overflow=false
entries=[the surviving lighthouse]
timed_out_total>=1
```

It must also require a non-null retained aggregate and one live peer with recent
authenticated RX.

- [ ] **Step 2: Poll while continuously proving the surviving path**

Take member `underlay0` down. In each bounded polling cycle, send authenticated
ICMP to lighthouse B before capturing a snapshot with both expected lighthouse
addresses. Emit a bounded aggregate summary every sixth attempt and fail after
36 five-second attempts.

- [ ] **Step 3: Assert continuity and recovery**

Restore `underlay0`, prove authenticated ICMP to lighthouse A, and capture the
immediate next member sample. Require the baseline, degraded, and recovered
samples to share a process identity; sequences and uptime must increase;
handshake and timeout counters cannot roll back; completed handshakes must
increase; and the recovered aggregate must again show two established/recent
lighthouses.

- [ ] **Step 4: Run the live degraded/recovered proof**

Run the dedicated wrapper. Expected at this checkpoint: both active and
partial-failure phases pass in one member process. Proceed to the overflow task
before treating the wrapper as a release gate.

### Task 5: Prove the first overflow cardinality

**Files:**
- Modify: `scripts/packet-smoke.sh`

- [ ] **Step 1: Activate seven non-running lighthouses**

For indices `3` through `9`, create and enroll one lighthouse using the endpoint
`203.0.113.<index>:4242`. Validate and retain each allocated overlay IP. Do not
start Nebula for these nodes.

- [ ] **Step 2: Refresh and inspect the member's signed bundle**

Run the member validation agent after all seven enrollments. Parse the signed
config with bounded Python/YAML-safe line checks already used by the smoke and
require exactly nine unique `lighthouse.hosts` values and matching
`static_host_map` keys. Require the member revision to advance.

- [ ] **Step 3: Restart only the member and establish the two real tunnels**

Stop member-namespace processes, reap its launcher, start Nebula from the new
current bundle, and send authenticated ICMP to both live lighthouses. Leave both
lighthouse processes running.

- [ ] **Step 4: Assert strict bounded overflow**

Capture a member snapshot with all nine expected overlay addresses. Require:

```text
configured=9
overflow=true
established=2
authenticated_rx_within_2m=2
authenticated_rx_within_5m=2
```

Require exactly the two live entries, numeric ordering, a non-null retained
aggregate, and no entry for any of the seven inactive lighthouse IPs.

- [ ] **Step 5: Emit a focused success result**

Print three explicit PASS lines for dual-active aggregation, isolated
loss/recovery, and bounded overflow. Exit zero from the multi-lighthouse branch
before the existing restrictive-policy section.

### Task 6: Document and verify the slice

**Files:**
- Modify: `docs/runtime-telemetry.md`
- Modify: `docs/roadmap.md`
- Modify: `third_party/nebula-observer/README.md`

- [ ] **Step 1: Run both live observer proofs**

Run:

```bash
./scripts/nebula-observer-overlay-smoke.sh
./scripts/nebula-observer-multilighthouse-smoke.sh
```

Expected: the existing single-lighthouse lifecycle passes unchanged; the new
proof passes all three multi-lighthouse phases.

- [ ] **Step 2: Run static and repository gates**

Run:

```bash
bash -n scripts/packet-smoke.sh scripts/nebula-observer-overlay-smoke.sh scripts/nebula-observer-multilighthouse-smoke.sh scripts/nebula-observer-prototype-smoke.sh
go test ./...
go vet ./...
go test -race -count=1 ./internal/runtimeobserver ./internal/runtimetelemetry ./internal/nodeagent
node --test internal/httpapi/webtest/health.test.js internal/httpapi/webtest/runtime-telemetry.test.js
```

Expected: every command exits zero with no test failures or race reports.

- [ ] **Step 3: Verify exact cleanup**

Run:

```bash
find /tmp -maxdepth 1 -type d -name 'mesh-*smoke*' -print
ip netns list | awk '$1 ~ /^meshps-/ {print}'
```

Expected: no output from either command. Pre-existing CNI namespaces are outside
the smoke's ownership and must not be changed.

- [ ] **Step 4: Update evidence and remaining limits**

Document the two-live, one-degraded, recovered, and nine-configured overflow
results. Remove multi-lighthouse redundancy/overflow from the outstanding
runtime-observer list, while retaining consumer process-continuity
classification, policy-aware probes, health promotion, native transports, and
release rollout/rollback as explicit remaining work.

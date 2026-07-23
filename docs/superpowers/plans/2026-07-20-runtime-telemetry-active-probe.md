# Runtime Telemetry Active Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This workspace is not a Git repository, so test checkpoints replace commit steps; do not initialize a repository or manufacture commit history.

**Goal:** Add a restart-rate-limited, policy-aware Linux ICMP-to-lighthouse probe to the separate runtime-observation plane, persist and render its exact result without exposing topology or changing lifecycle health, and prove the real packet paths.

**Architecture:** Keep `active_probe` as a sibling of passive `observation`, advance private state and fleet projections to v4, and normalize legacy or missing results to `unsupported`. The agent uses the existing verified no-I/O planner, a separate durable cadence journal, and build-tagged executors; Linux uses an unprivileged datagram ping socket while other platforms return `unsupported`.

**Tech Stack:** Go 1.26, canonical JSON exact-document stores, PostgreSQL document repository, `golang.org/x/sys/unix`, vanilla JavaScript/Node tests, Linux network/TUN namespaces, systemd sandboxing.

---

## File map

- Create `internal/runtimetelemetry/active_probe.go` for the public result model and strict invariants.
- Modify runtime-telemetry model/store/document/projection files for state v4, transition parity, migrations, and fleet v4.
- Create `internal/nodeagent/active_probe_journal.go` for the private canonical cadence journal.
- Create `internal/nodeagent/active_probe_executor.go`, `_linux.go`, and `_other.go` for the executor boundary and platform implementations.
- Modify node-agent reporting, HTTP ingestion, and browser assets for independent passive/probe evidence.
- Extend `scripts/packet-smoke.sh` only through a fail-closed opt-in active-probe mode.

### Task 1: Define the fixed active-probe result contract

**Files:**
- Create: `internal/runtimetelemetry/active_probe.go`
- Create: `internal/runtimetelemetry/active_probe_test.go`
- Modify: `internal/runtimetelemetry/model.go`

- [x] **Step 1: Write table-driven failing validation tests**

Use these wished-for fixtures:

```go
func unsupportedProbe() ActiveProbeResult {
	return ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeUnsupported}
}

func attemptedProbe() ActiveProbeResult {
	age := uint64(0)
	return ActiveProbeResult{
		Version: ActiveProbeVersionV1, State: ProbeAttempted,
		SampleAgeMS: &age, Attempted: 2, Replied: 1, DurationMS: 14,
	}
}
```

Require valid fixtures for all five states. Require failures for an unknown version/state, non-null unsupported/unavailable age, missing eligible-state age, age above 30,000, attempted count 0 or 9, replies above attempts, duration above 6,000, and nonzero counts in every non-attempted state. Prove `CloneActiveProbe` detaches `SampleAgeMS`.

- [x] **Step 2: Run the focused test and verify RED**

```bash
go test ./internal/runtimetelemetry -run '^TestActiveProbe' -count=1
```

Expected: build failure for undefined `ActiveProbeResult` and `ValidateActiveProbe`.

- [x] **Step 3: Implement the minimal exact model**

```go
const (
	ActiveProbeVersionV1 = 1
	MaxActiveProbeTargets = 8
	MaxActiveProbeSampleAgeMS uint64 = 30_000
	MaxActiveProbeDurationMS uint64 = 6_000
)

type ActiveProbeState string

const (
	ProbeNotEligible ActiveProbeState = "not_eligible"
	ProbeUnsupported ActiveProbeState = "unsupported"
	ProbeCapabilityUnavailable ActiveProbeState = "capability_unavailable"
	ProbeAttempted ActiveProbeState = "attempted"
	ProbeUnavailable ActiveProbeState = "unavailable"
)

type ActiveProbeResult struct {
	Version int `json:"version"`
	State ActiveProbeState `json:"state"`
	SampleAgeMS *uint64 `json:"sample_age_ms"`
	Attempted uint64 `json:"attempted"`
	Replied uint64 `json:"replied"`
	DurationMS uint64 `json:"duration_ms"`
}
```

Implement `ValidateActiveProbe`, `CloneActiveProbe`, `UnsupportedActiveProbe`, `UnavailableActiveProbe`, and `NotEligibleActiveProbe`. Keep the fixed JSON shape; do not add `omitempty`.

- [x] **Step 4: Verify GREEN**

```bash
gofmt -w internal/runtimetelemetry/active_probe.go internal/runtimetelemetry/active_probe_test.go internal/runtimetelemetry/model.go
go test ./internal/runtimetelemetry -count=1
```

### Task 2: Advance persistence to state v4 without changing continuity semantics

**Files:**
- Modify: `internal/runtimetelemetry/model.go`
- Modify: `internal/runtimetelemetry/store.go`
- Modify: `internal/runtimetelemetry/document.go`
- Modify: `internal/runtimetelemetry/file_store.go`
- Modify: `internal/runtimetelemetry/postgres_store.go`
- Modify: corresponding `*_test.go` files in `internal/runtimetelemetry`

- [x] **Step 1: Write failing transition tests**

Update record fixtures to include `ActiveProbe: unsupportedProbe()`. Change the wished-for Store call to:

```go
record, changed, err := store.Put(nodeID, heartbeat, receivedAt, observation, activeProbe)
```

Require exact same-heartbeat idempotency across both observation and probe, probe-only same-heartbeat `ErrConflict`, pointer cloning, and higher-heartbeat `continuous` classification when only the probe changes.

- [x] **Step 2: Write failing strict v3 migration tests**

Add canonical `mesh-runtime-telemetry-state-v3` fixtures with continuity and observation but no probe. Require state-v4 decoding with `UnsupportedActiveProbe()`, exact re-encoding, unknown/noncanonical rejection, durable file rewrite, and PostgreSQL initialization operation `runtime_telemetry.state.migrate_v4`.

- [x] **Step 3: Verify RED**

```bash
go test ./internal/runtimetelemetry -run 'Test.*(Probe|V3|Continuity)' -count=1
```

- [x] **Step 4: Implement state-v4 records and shared transitions**

Add `StateSchemaV4`, make it current, and add the required field:

```go
ActiveProbe ActiveProbeResult `json:"active_probe"`
```

Extend `newCandidateRecord` and every Store `Put` with the value argument. At the same heartbeat compare both `Observation` and `ActiveProbe`; for higher heartbeats leave process identity, version, sequence, uptime, and cumulative-counter rules restricted to `Observation`.

- [x] **Step 5: Implement exact legacy v3 decoding**

Define `stateV3`/`recordV3` matching the old exact shape. Decode current v4, v3, v2, then v1. Assign `UnsupportedActiveProbe()` on every legacy path without changing retained-age or continuity migration rules.

- [x] **Step 6: Refactor file/PostgreSQL backends and verify GREEN**

```bash
gofmt -w internal/runtimetelemetry/*.go
go test ./internal/runtimetelemetry -count=1
```

### Task 3: Accept old agents and emit fleet v4

**Files:**
- Modify: `internal/runtimetelemetry/model.go`
- Modify: `internal/runtimetelemetry/projection.go`
- Modify: `internal/runtimetelemetry/projection_test.go`
- Modify: `internal/httpapi/server.go`
- Modify: `internal/httpapi/server_test.go`
- Modify: `internal/nodeagent/client_test.go`

- [x] **Step 1: Write failing API compatibility tests**

Require a new server to accept an exact old envelope with no `active_probe` and store `unsupported`, accept a supplied valid result, reject unknown/invalid fields with no-store, and return 409 for same-heartbeat probe equivocation without replacing the accepted record.

- [x] **Step 2: Write failing fleet-v4 tests**

Require `mesh-runtime-telemetry-fleet-v4`, a fixed `active_probe` object on every record, and absence of target/local IP, plan hash, nonce, packet, socket error, and process identity. Keep `aggregate_only: true` and `end_to_end_reachability_proven: false`.

- [x] **Step 3: Verify RED**

```bash
go test ./internal/httpapi ./internal/runtimetelemetry -run 'Test.*RuntimeTelemetry' -count=1
```

- [x] **Step 4: Implement optional input and required stored output**

```go
type ReportInput struct {
	HeartbeatSequence int64 `json:"heartbeat_sequence"`
	Observation Observation `json:"observation"`
	ActiveProbe *ActiveProbeResult `json:"active_probe,omitempty"`
}
```

Normalize nil to `UnsupportedActiveProbe()` in `agentRuntimeTelemetry`, validate and clone supplied values, and keep persisted/projection fields required values.

- [x] **Step 5: Implement fleet v4 and verify GREEN**

```bash
gofmt -w internal/runtimetelemetry internal/httpapi
go test ./internal/runtimetelemetry ./internal/httpapi ./internal/nodeagent -count=1
```

### Task 4: Parse and render fleet v4 observationally

**Files:**
- Modify: `internal/httpapi/web/runtime-telemetry.js`
- Modify: `internal/httpapi/webtest/runtime-telemetry.test.js`
- Modify: `internal/httpapi/web_health_test.go`

- [x] **Step 1: Write failing strict-parser tests**

Add fleet-v4 fixtures for every state. Require exact fields `version,state,sample_age_ms,attempted,replied,duration_ms`; reject missing/extra fields and every Go-side invariant violation. Require exact fleet v2/v3 to map to:

```js
Object.freeze({version: 1, state: 'unsupported', sampleAgeMS: null, attempted: 0, replied: 0, durationMS: 0})
```

- [x] **Step 2: Write failing presentation tests**

Test every sentence in the design. Attempted age is `sampleAgeMS + nowMS - receivedAtMS`. Prove passive `unknown` still displays sound attempted evidence. Forbid `healthy`, `reachable`, `online`, `connected`, `failed`, `down`, process identity, IP patterns, plan hashes, and nonces.

- [x] **Step 3: Verify RED**

```bash
node --test internal/httpapi/webtest/runtime-telemetry.test.js
```

- [x] **Step 4: Implement v4 parsing and independent presentation**

Add `SCHEMA_V4` as current while retaining exact v2/v3 branches. Run heartbeat/freshness checks once, construct passive wording and probe wording independently, then combine them without changing lifecycle health.

- [x] **Step 5: Verify browser and asset tests**

```bash
node --test internal/httpapi/webtest/health.test.js internal/httpapi/webtest/runtime-telemetry.test.js
go test ./internal/httpapi -run '^TestDashboard' -count=1
```

### Task 5: Build the crash-durable cadence journal

**Files:**
- Create: `internal/nodeagent/active_probe_journal.go`
- Create: `internal/nodeagent/active_probe_journal_test.go`
- Modify: `internal/nodeagent/state.go`

- [x] **Step 1: Write failing shape/filesystem tests**

Use `StateStore.Path()+".runtime-probe.json"` and this shape:

```go
type activeProbeJournal struct {
	Schema string `json:"schema"`
	PlanSHA256 string `json:"plan_sha256"`
	ReservedAt time.Time `json:"reserved_at"`
	Result runtimetelemetry.ActiveProbeResult `json:"result"`
}
```

Require schema `mesh-agent-active-probe-journal-v1`, exact compact JSON plus newline, maximum 4 KiB, UTC time, lowercase 64-hex hash, valid result, mode 0600, private real parent, no symlink/nonregular file, duplicate/unknown/trailing/noncanonical rejection, atomic replace, file and parent sync, missing-file `os.ErrNotExist`, and preservation of invalid existing bytes.

- [x] **Step 2: Verify RED**

```bash
go test ./internal/nodeagent -run '^TestActiveProbeJournal' -count=1
```

- [x] **Step 3: Implement strict StateStore journal methods**

```go
func (s *StateStore) LoadActiveProbeJournal() (activeProbeJournal, error)
func (s *StateStore) SaveActiveProbeJournal(activeProbeJournal) error
```

Reuse `validatePrivateParent`, `privateRegularFile`, `writeAtomicPrivateFile`, and `syncDir`, but validate any existing journal before replacement. Re-encode and byte-compare during decode.

- [x] **Step 4: Verify GREEN and races**

```bash
gofmt -w internal/nodeagent/active_probe_journal*.go internal/nodeagent/state.go
go test -race -count=1 ./internal/nodeagent -run '^TestActiveProbeJournal'
```

### Task 6: Implement the bounded Linux ping-socket executor

**Files:**
- Create: `internal/nodeagent/active_probe_executor.go`
- Create: `internal/nodeagent/active_probe_executor_linux.go`
- Create: `internal/nodeagent/active_probe_executor_linux_test.go`
- Create: `internal/nodeagent/active_probe_executor_other.go`
- Create: `internal/nodeagent/active_probe_executor_other_test.go`

- [x] **Step 1: Write failing protocol tests around a syscall seam**

Use a private socket interface so tests inject packets while production alone calls `unix.Socket`. Require one socket, eight-target cap, fresh 16-byte nonce per target, request length at most 64, exact source/type-0/code-0/sequence/nonce acceptance, rejection of malformed/wrong/duplicate/late replies, 750 ms per target, six-second total deadline, prompt cancellation, EACCES/EPERM capability classification, other setup/entropy unavailable classification, and attempted increment once send is called even if send errors.

- [x] **Step 2: Verify RED**

```bash
go test ./internal/nodeagent -run '^TestLinuxActiveProbe' -count=1
```

- [x] **Step 3: Implement common interface and codec**

```go
type activeProbeExecutor interface {
	Supported() bool
	Probe(context.Context, activeProbePlan) runtimetelemetry.ActiveProbeResult
}
```

Implement checksum-safe echo encoding and exact reply decoding without `os/exec`, `net/http`, or a new ICMP package.

- [x] **Step 4: Implement build-tagged adapters**

Linux opens `AF_INET`, `SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK`, `IPPROTO_ICMP`, binds the verified local IPv4, polls within bounded deadlines, and closes on every path. `!linux` returns unsupported without a syscall.

- [x] **Step 5: Verify GREEN and portability**

```bash
gofmt -w internal/nodeagent/active_probe_executor*.go
go test ./internal/nodeagent -run 'Test(Linux|Unsupported)ActiveProbe' -count=1
GOOS=darwin GOARCH=amd64 go test ./internal/nodeagent -run '^TestUnsupportedActiveProbe' -c -o /tmp/mesh-nodeagent-darwin.test
GOOS=windows GOARCH=amd64 go test ./internal/nodeagent -run '^TestUnsupportedActiveProbe' -c -o /tmp/mesh-nodeagent-windows.test.exe
```

Then require this scan to return no hits:

```bash
rg -n 'os/exec|exec.Command|/bin/ping' internal/nodeagent/active_probe_executor*.go
```

### Task 7: Orchestrate eligibility, durable rate limiting, and reporting

**Files:**
- Modify: `internal/nodeagent/agent.go`
- Modify: `internal/nodeagent/runtime_telemetry.go`
- Modify: `internal/nodeagent/runtime_telemetry_test.go`
- Modify: `cmd/meshctl/agent_test.go`

- [x] **Step 1: Write failing orchestration tests**

With a fake executor and real temp journal, cover: denied/no-target zero calls; unsupported no journal; reservation visible before executor entry; saved final result; same-plan +10s cached age; changed-plan +10s unavailable; due execution at +30s; new Agent process honoring the journal; future time/clock regression; corrupt journal; reservation/final-write failures; cancellation; observer/probe independence; and exact outgoing JSON.

- [x] **Step 2: Verify RED**

```bash
go test ./internal/nodeagent -run 'TestAgent.*ActiveProbe|TestReportRuntimeTelemetry.*Probe' -count=1
```

- [x] **Step 3: Implement plan hashing and journal resolution**

Hash a domain-separated canonical local-address/ordered-target byte sequence, but persist/project only lowercase SHA-256. Use `a.currentTime()` for deterministic UTC tests. Reserve unavailable before `Probe`, save after it, and return unavailable on every ambiguous journal/time path.

- [x] **Step 4: Combine passive and active results**

Keep `ObserveRuntimeTelemetry` passive-only. In `ReportRuntimeTelemetry`, derive both independently from the same bundle and send:

```go
runtimetelemetry.ReportInput{
	HeartbeatSequence: heartbeatSequence,
	Observation: observation,
	ActiveProbe: &activeProbe,
}
```

Do not alter `Heartbeat`, `Health`, runner quarantine, service state, or control schema v2.

- [x] **Step 5: Verify GREEN and races**

```bash
gofmt -w internal/nodeagent cmd/meshctl
go test ./internal/nodeagent ./cmd/meshctl -count=1
go test -race -count=1 ./internal/nodeagent
```

### Task 8: Prove packaging retains least privilege

**Files:**
- Modify: `packaging/systemd/assets_test.go`
- Modify: `scripts/linux-install-smoke.sh`

- [x] **Step 1: Strengthen unit tests before any packaging change**

Require exactly one empty `CapabilityBoundingSet=`, exactly one `NoNewPrivileges=yes`, no `AmbientCapabilities`, no `CAP_NET_RAW`, and no writable-path expansion. The journal stays beneath `/var/lib/mesh-agent` through the existing state path.

- [x] **Step 2: Extend the Linux install smoke assertions**

When an eligible probe creates the journal, require root ownership, mode 0600, regular-file type, and an empty effective/bounding capability set for the live agent. Do not weaken the unit to satisfy the smoke.

- [x] **Step 3: Verify packaging**

```bash
go test ./packaging/systemd ./internal/linuxbundle -count=1
bash -n scripts/linux-install-smoke.sh scripts/packet-smoke.sh
```

### Task 9: Add the end-to-end namespace/TUN active-probe proof

**Files:**
- Modify: `scripts/packet-smoke.sh`
- Modify: `scripts/nebula-observer-overlay-smoke.sh`
- Create only if required: `internal/nodeagent/probecapture/smoke_linux.go`

- [x] **Step 1: Add fail-closed opt-in mode**

Introduce `MESH_RUNTIME_ACTIVE_PROBE_SMOKE=1`, require observer mode and production agent/server binaries, reject incompatible modes, preserve default behavior, and exit 77 before resource creation when capture prerequisites are absent.

- [x] **Step 2: Prove signed denial emits no TUN ICMP**

Deploy TCP-only policy, run a real telemetry cycle, and use bounded root-only AF_PACKET/TUN capture to assert zero member-to-lighthouse echo requests. Fetch fleet v4 and require not-eligible with unchanged lifecycle health.

- [x] **Step 3: Prove allowed reply and cadence reuse**

Deploy outbound ICMP permission, wait until globally due, capture bounded requests, and require attempted with at least one validated reply. Run again inside 30 seconds and require zero new packets plus advancing sample age. Change to a different eligible target plan inside the window and require unavailable plus zero packet.

- [x] **Step 4: Prove capability and independence paths**

Exclude the service group through namespace `net.ipv4.ping_group_range`, retain empty capabilities, and require capability unavailable. Separately prove observer failure preserves a sound probe and probe failure preserves passive observation.

- [x] **Step 5: Run proof and cleanup audit**

```bash
MESH_RUNTIME_ACTIVE_PROBE_SMOKE=1 ./scripts/nebula-observer-overlay-smoke.sh
find /tmp -maxdepth 1 -type d -name 'mesh-nebula-observer-overlay.*' -print
ip netns list | rg 'meshps-' || true
ps -eo pid,args | rg 'mesh-nebula-observer-overlay|meshps-' || true
```

Expected: all PASS lines and no Mesh-owned leftover directory, namespace, or process.

### Task 10: Documentation and full verification

**Files:**
- Modify: `docs/runtime-telemetry.md`
- Modify: `docs/roadmap.md`
- Modify: this plan's checkboxes only as evidence is produced

- [x] **Step 1: Update documentation from observed behavior**

Document v4 fields, legacy fallback, server-first rollout, journal recovery, Linux proof, and UI semantics. Remove only Linux policy-aware probing from remaining work; retain health promotion and native platforms.

- [x] **Step 2: Run all automated gates**

```bash
gofmt -w internal/runtimetelemetry internal/nodeagent internal/httpapi cmd/meshctl packaging/systemd
go test ./...
go vet ./...
go test -race -count=1 ./internal/runtimeobserver ./internal/runtimetelemetry ./internal/nodeagent
node --test internal/httpapi/webtest/health.test.js internal/httpapi/webtest/runtime-telemetry.test.js
bash -n scripts/*.sh
```

- [x] **Step 3: Rerun observer regressions**

```bash
./scripts/nebula-observer-overlay-smoke.sh
./scripts/nebula-observer-multilighthouse-smoke.sh
```

- [x] **Step 4: Audit the completed plan and privacy boundary**

```bash
rg -n '^- \[ \]' docs/superpowers/plans/2026-07-20-runtime-telemetry-active-probe.md
rg -n 'StateSchema\s*=.*V3|FleetProjectionSchema\s*=.*V3' internal
rg -n 'process_instance_id|plan_sha256|nonce|socket_error|private_key|agent_token' internal/httpapi/web internal/runtimetelemetry/projection.go
rg -ni '\b(healthy|reachable|online|connected|failed|down)\b' internal/httpapi/web/runtime-telemetry.js
```

Review every hit as an intentional legacy/test reference or remove it. Keep the thread goal active after this slice unless the entire product objective separately passes its completion audit.

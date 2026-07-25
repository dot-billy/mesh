# Runtime Telemetry Process Continuity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derive, persist, and render fail-closed Nebula observer process continuity without exposing process identity or creating a health claim.

**Architecture:** Add a required derived enum to the private current record, centralize all backend transitions in one function, migrate state documents to v3, and project only the enum through fleet v3. The browser accepts exact fleet v2 as unclassified legacy evidence and exact fleet v3 as classified evidence.

**Tech Stack:** Go 1.26, canonical JSON exact-document stores, PostgreSQL document repository, Node.js strict browser tests, vanilla JavaScript.

---

### Task 1: Specify the shared transition contract in failing tests

**Files:**
- Modify: `internal/runtimetelemetry/model.go`
- Modify: `internal/runtimetelemetry/store_test.go`
- Modify: `internal/runtimetelemetry/model_test.go`

- [x] Add `ProcessContinuity` with exact values `unavailable`, `unclassified`,
  `continuous`, and `restarted`, plus a required `process_continuity` field on
  `Record`.
- [x] Add table-driven memory-store tests for first observed, same-process
  advance, process change, observed-to-unknown, unknown-to-observed, and exact
  same-heartbeat retry.
- [x] Add rejection tests proving same-process repeated/decreased sample
  sequence returns `ErrReplay`, and same-process version switch, uptime rollback,
  completed-counter rollback, and timeout-counter rollback return `ErrConflict`
  without replacing the prior record.
- [x] Run `go test ./internal/runtimetelemetry -run 'TestMemoryStore.*Continuity' -count=1` and confirm the tests fail because stores do not derive the enum.

### Task 2: Centralize transition derivation and refactor memory/file stores

**Files:**
- Modify: `internal/runtimetelemetry/model.go`
- Modify: `internal/runtimetelemetry/store.go`
- Modify: `internal/runtimetelemetry/file_store.go`
- Modify: `internal/runtimetelemetry/file_store_test.go`

- [x] Add `newCandidateRecord` to clone/validate the report with
  `unavailable` for unknown and `unclassified` for observed.
- [x] Add `transitionRecord(existing *Record, candidate Record)` that applies
  heartbeat idempotency first, then derives continuity and validates the final
  record. Only observation bytes participate in same-heartbeat equivocation;
  receive time and derived classification come from the stored record.
- [x] Replace duplicated memory and file transition switches with the shared
  helper while preserving ordering, capacity, durability, and clone behavior.
- [x] Add a file reopen test proving a persisted `continuous` or `restarted`
  enum survives exact round-trip and rejected rollback leaves bytes unchanged.
- [x] Run focused memory/file tests and then the complete runtime-telemetry package.

### Task 3: Advance state persistence to v3 with strict migration

**Files:**
- Modify: `internal/runtimetelemetry/model.go`
- Modify: `internal/runtimetelemetry/document.go`
- Modify: `internal/runtimetelemetry/document_test.go`
- Modify: `internal/runtimetelemetry/file_store_test.go`

- [x] Set current state schema to `mesh-runtime-telemetry-state-v3` while
  retaining named v1 and v2 constants.
- [x] Add an exact legacy-v2 document type matching the old record shape and a
  strict canonical decoder. Migrate observed records to `unclassified` and
  unknown records to `unavailable`.
- [x] Make the existing v1 decoder produce state v3 with the same conservative
  classifications; never synthesize retained v2 lighthouse history.
- [x] Add canonical v2 migration, noncanonical/unknown-field rejection, and
  durable file rewrite tests. Update v1 expectations to v3.
- [x] Run document and file migration tests and inspect the rewritten bytes for
  the exact schema and enum fields.

### Task 4: Enforce parity in PostgreSQL and HTTP reporting

**Files:**
- Modify: `internal/runtimetelemetry/postgres_store.go`
- Modify: `internal/runtimetelemetry/postgres_store_test.go`
- Modify: `internal/httpapi/server_test.go`

- [x] Change the PostgreSQL migration operation identity to
  `runtime_telemetry.state.migrate_v3`.
- [x] Use `newCandidateRecord` and `transitionRecord` inside the exact-document
  update callback. Preserve callback retry/idempotency and return the already
  accepted record on a no-op receipt.
- [x] Add PostgreSQL tests for continuous, restarted, unknown-gap, replay, and
  rollback outcomes, plus canonical v2-to-v3 initialization migration.
- [x] Add an HTTP test proving a same-process rollback maps to `409 Conflict`,
  returns `Cache-Control: no-store`, and leaves the accepted projection intact.
- [x] Run PostgreSQL adapter and HTTP package tests.

### Task 5: Project fleet v3 and render continuity observationally

**Files:**
- Modify: `internal/runtimetelemetry/projection.go`
- Modify: `internal/runtimetelemetry/projection_test.go`
- Modify: `internal/httpapi/server_test.go`
- Modify: `internal/httpapi/web/runtime-telemetry.js`
- Modify: `internal/httpapi/webtest/runtime-telemetry.test.js`
- Modify: `internal/httpapi/web_health_test.go`

- [x] Advance the emitted fleet schema to `mesh-runtime-telemetry-fleet-v3`
  and require `process_continuity` on every projected record.
- [x] Prove Go projection emits only the enum, continues to omit process
  identity, and rejects invalid state/continuity combinations.
- [x] Update the strict browser parser to accept exact v3 records with the
  required enum and exact v2 records without it. Map legacy observed to
  `unclassified` and legacy unknown to `unavailable`; reject all other schemas,
  fields, and enum values.
- [x] Add presentation tests for continuous, restarted, unclassified, and
  unavailable/unknown paths. Require explicit observational wording and reject
  `healthy`, `reachable`, and process identifiers.
- [x] Run both browser suites and Go HTTP/projection tests.

### Task 6: Document and verify the complete continuity slice

**Files:**
- Modify: `docs/runtime-telemetry.md`
- Modify: `docs/roadmap.md`

- [x] Document the immediately-previous-record boundary, monotonic fields,
  unknown gap reset, strict v2 migrations/fallbacks, and non-health semantics.
- [x] Remove consumer process-continuity classification from the remaining
  roadmap list while retaining policy-aware probes and health-alert promotion.
- [x] Run `gofmt` on all changed Go files.
- [x] Run `go test ./...`, `go vet ./...`, targeted runtime telemetry races,
  both browser suites, and shell syntax.
- [x] Rerun both privileged observer namespace proofs and confirm no Mesh-owned
  temporary workspace or `meshps-` namespace remains.

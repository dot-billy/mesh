# PostgreSQL intended-workload micro-soak gate

`make postgres-load-soak-smoke` is the first fixed-count intended-workload gate for the PostgreSQL exact-document preview. It builds clean-room test binaries, imports one authenticated current control-v13 JSON backup, starts one exact labeled `postgres:17-alpine` primary capped at two CPUs and 512 MiB, and starts two real PostgreSQL-backed `mesh-server` replicas with eight connections each. Cached Docker and exact Nebula 1.10.3 prerequisites are required; an unavailable prerequisite exits with status 77.

This is deliberately a reproducible micro-soak, not an open-ended benchmark. The operation counts, concurrency, duration, percentile definition, and budgets are constants in `internal/postgresloadgate`. The HTTP driver does not retry. Mutation bodies are not transport-replayable, environment proxies are disabled, redirects are rejected, and every logical operation ID has exactly one response record containing only status, duration, response size/SHA-256, and a non-secret resource ID.

## Fixed workload

The dependency phases keep every mutation valid while control and identity writes contend independently on their two exact document rows.

| Stage | Operations | Count |
| --- | --- | ---: |
| Load phase 1 | create pending nodes | 48 |
| Load phase 1 | create browser sessions | 68 |
| Load phase 2 | reissue every pending-node enrollment | 48 |
| Load phase 2 | revoke the first sessions | 56 |
| 30-second paced stage | revoke pending nodes | 24 |
| 30-second paced stage | revoke the remaining sessions | 12 |
| 30-second paced stage | readiness, network, node, and revoked-session reads | 108 |

The load stage therefore commits 220 writes and the paced stage commits 36 writes plus 108 reads. Global write concurrency is eight; writes are split exactly 128/128 across the two application replicas. The paced schedule interleaves one write with three reads and must finish in 25–45 seconds.

## Exact correctness gates

The driver warms both replicas and then crosses an explicit PostgreSQL-statistics visibility barrier before capturing the post-import baseline. After every workload writer has joined, it repeats that barrier and captures the terminal snapshot. On PostgreSQL 17 the barrier waits beyond the cumulative-statistics publication interval, drives seven simultaneous readiness transactions through each eight-connection application pool while retaining one connection of defensive headroom, calls `pg_stat_force_next_flush()` and `pg_stat_clear_snapshot()` for the measurement connection, and reads with no writer active. Global writer concurrency is eight and writes alternate replicas before finishing at an exact 128/128 split, so the seven probes per replica cover the recently active writer backends. Concurrent readiness transactions coexist through a shared migration advisory lock; migration retains the exclusive form of that same lock and therefore makes readiness fail closed until migration completes.

All revision, audit, receipt, operation-class, database-statistic, and WAL assertions are terminal-minus-baseline deltas:

- control revision and audit: +120;
- identity revision and audit: +136;
- receipt headers and receipt document items: +256 each;
- operation classes: 120 `control.state.update`, 136 `identity.state.update`, and no new import or unexpected class;
- exactly 48 workload nodes, with 24 revoked and 24 still pending;
- exactly 68 workload sessions, all revoked;
- 48 node-created, 48 enrollment-reissued, 24 node-revoked, 68 session-created, and 68 session-revoked audit events;
- contiguous receipt item revisions from 1 through each current document revision, correct base/committed relationships, complete header/domain cardinality, and an exact current document/receipt SHA-256 binding; and
- zero unexpected HTTP/network errors, timeouts, 429s, 5xx responses, PostgreSQL conflicts, deadlocks, temporary files, or temporary bytes.

Both applications are then stopped and restarted. Each must become ready, return the same terminal inventories, and preserve exact document revisions/SHA-256 values, audit counts, receipt counts/classes, and receipt integrity without a new mutation.

## Measurement budgets

Latency uses the non-interpolated nearest-rank definition: sort observations ascending and select the value at one-based rank `ceil(percentile / 100 * N)`.

| Measurement | Pass budget |
| --- | ---: |
| Write p95 / p99 / maximum | ≤2 s / ≤5 s / ≤10 s |
| Read p95 / p99 / maximum | ≤750 ms / ≤2 s / ≤5 s |
| Dependency-load throughput | ≥8 successful writes/s |
| Total workload WAL | ≤128 MiB |
| Average WAL per committed write | ≤512 KiB |
| `wal_buffers_full` delta | ≤8 |
| Final database size | ≤128 MiB |
| Each exact document | ≤2 MiB |
| Explicit `VACUUM (ANALYZE)` | ≤10 s |
| Document-table dead tuples after vacuum | ≤4 |
| Each application peak RSS | ≤192 MiB |
| PostgreSQL peak container memory | ≤384 MiB under the 512-MiB cap |

The report also records transaction/block/tuple counters, full-page images, sampled lock/transaction/tuple waits, vacuum/autovacuum/analyze counters, and resource sample counts even where this first gate has no independent budget for the value. Explicit vacuum proves the bounded two-row table can be reclaimed; it is not evidence that production autovacuum settings or a pruning policy are sufficient.

## Credential and cleanup boundary

The workspace is mode 0700. DSNs and credential inputs are stable private files; the driver accepts the administrator token through an `O_NOFOLLOW`/`O_CLOEXEC` descriptor with owner, link-count, exact 0400/0600 mode, size, and stable-inode checks. It captures every session cookie, CSRF cookie, initial enrollment credential, and reissued enrollment credential into one excluded private scan source. The shell adds the administrator token, master key, backup key, full DSN, database password, randomized database role, and randomized database name, then scans the saved application/PostgreSQL/build/storage/driver logs, reports, and process arguments for every exact value.

Cleanup signals only verified child PIDs and removes only the exact ID/name/label-verified container and expected private workspace. `KEEP_MESH_SMOKE=1 make postgres-load-soak-smoke` retains both for debugging and prints a warning that they contain live disposable credentials.

## Honest limits

This gate is local, single-primary, and short. It does not establish maximum-size document behavior, sustained/burst fleet rates, heartbeat load, long-duration receipt/WAL retention or pruning, production autovacuum tuning, failover behavior, recovery while loaded, automatic fencing, managed-database behavior, deployed roles/TLS/trust/secret rotation, or production observability. Maximum stored valid bytes have a separate [pre-live boundary harness](postgres-max-document.md); the remaining claims stay separate PostgreSQL production gates.

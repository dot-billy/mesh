# PostgreSQL maximum-valid-document gate

`make postgres-max-document-smoke` is the dedicated storage-boundary gate for the PostgreSQL exact-document preview. It is separate from the intended-workload micro-soak: this gate proves that maximum **valid** application documents can pass recovery validation, authenticated backup, create-only import, authoritative reads, bounded mutations, canonical rewrites, and a real server restart. It does not manufacture an invalid graph merely to consume bytes.

The harness and its driver are implemented. A successful live proof is claimed only when the target itself prints both `PASS` lines; implementation or static tests alone are not a passing maximum-document result.

## Accepted live evidence

The audited 2026-07-20 v3 run printed both terminal `PASS` lines and completed in 171 seconds. It imported and reread the exact 67,108,864-byte control document and 8,388,608-byte identity document, authenticated their backup provenance, verified every import and mutation receipt, proved exact shrink-first transitions, restarted the real server, and found no disposable credential in bounded diagnostics. Measured peaks were 1,157,021,696 bytes of application RSS and 112,512,204 bytes of PostgreSQL memory; the physical PostgreSQL directory was 71,323,648 bytes, `pg_database_size` was 14,079,667 bytes, WAL growth was 6,602,306 bytes, and the private workspace was 294,026,132 bytes. The cleanup audit found no labeled container, volume, workspace, or gate process afterward.

## Validator-created fixtures

The test-only builders use the same private canonicalizers, graph validators, persistence encoders, recovery validators, and credential checks as production code. They report canonical bytes, exact bytes, padding bytes, SHA-256, OIDC aggregate-claim bytes, and record cardinalities in `fixture-metadata.json`.

| Domain | Canonical structured state | Exact imported document |
| --- | --- | --- |
| Control | 62-63 MiB | 67,108,864 bytes |
| Identity | 7-7.5 MiB | 8,388,608 bytes |

The control graph is a current version-13 document containing exactly one valid `10.240.0.0/16` network with a real Nebula CA and encrypted signing material. It installs 128 bounded firewall rules in each direction, then adds as many valid pending nodes as necessary to enter the canonical band without exceeding the `/16` capacity. Every node has explicit `unassigned` topology, exactly 64 canonical groups including `all`, one valid enrollment, and one `node.created` audit; network DNS, native resolver state, and relays are explicitly disabled, firewall rollout is stably unpaused, and route transfer/profile/policy state is empty. Names, identifiers, hashes, addresses, placement, groups, audit details, and cardinalities remain inside the production validators. The old unbounded-group construction is not part of this gate.

The identity graph uses production-reachable maximum-width OIDC principals: 2,048-byte issuer, 512-byte subject, 256-byte display name, 254-byte email, a conservative 64 groups of 256 bytes, a 256-byte ACR, and 16 AMR values of 64 bytes. A representative complete claims object is encoded and parsed through the hardened OIDC field parsers and must remain below the aggregate 64 KiB claims limit and the 128 KiB signed-token envelope. Document size comes from legitimate session and creation-audit cardinality rather than an unreachable oversized claim. The graph also contains exactly one valid purpose-sealed OIDC login attempt. That attempt and exactly one session are expired at the recorded cleanup boundary; all other sessions are live there.

After canonical encoding, the builders append only JSON space characters. JSON permits that trailing whitespace, so the exact documents exercise the storage ceilings without bypassing the application graph limits. The builders then repeat full control recovery and master/admin credential validation and full identity recovery validation on the exact padded bytes. Identity recovery must open the sealed login payload with the purpose-bound sealer, and a wrong sealer is explicitly rejected. Static tests also require each domain's hard limit plus one byte to fail.

## Live sequence

The script exits with status 77 when a required local prerequisite is unavailable. It requires Linux, Go, Python, curl, Docker daemon access, a cached `postgres:17-alpine` image, and the real local Nebula certificate binary. It never pulls an image.

The sequence is deliberately ordered:

1. Run tagged static tests and build untagged production binaries plus the separately tagged test-only driver. The fixture helpers, driver, and package are excluded from normal release builds.
2. Generate and validate both canonical graphs, the bounded OIDC claim intake, the purpose-sealed login payload, exact padded documents, hashes, credential bindings, and recovery snapshots before creating any Docker resource.
3. Create, reopen, and authenticate a current control-v13 backup before PostgreSQL exists.
4. Resolve the cached PostgreSQL image to one content ID and create from that immutable ID; create one uniquely named and labeled volume and one uniquely named and labeled container capped at two CPUs and 1 GiB; verify its exact identity and PostgreSQL 17 major version.
5. Migrate a fresh database, import only through `mesh-storage import-backup` with the exact expected backup ID, and run offline `mesh-storage verify`.
6. Read the pair twice, require byte-identical revisions/hashes/write IDs, require revision-1 bytes to equal the authenticated source files, repeat full recovery and credential validation, run both production-shaped readiness adapters, and verify revision-1 import receipts plus immutable provenance.
7. Start one real PostgreSQL-backed `mesh-server`. First replace the maximum firewall through the authenticated API so the 64 MiB control document shrinks on its first mutation. Run identity `CleanupExpired` under its own 15-second context to remove exactly one named sealed login attempt and one named session in the first identity rewrite. Before revocation, read identity revision 2 and bind its exact source-derived canonical bytes and SHA-256 to its one-document write receipt. Then revoke one remaining session through the bearer-authenticated API.
8. Require control revision 2 and identity revision 3; prove that only the exact firewall fields and one audit changed in control, cleanup removed only the two named records, and terminal identity changed only the named session revocation fields plus one exact audit. Bind every import and mutation receipt hash, operation class, domain, and revision pair to those independently derived documents, then require canonical documents smaller than their original structured sizes and no remaining whitespace padding.
9. Restart the real server, repeat readiness and terminal database verification, then enforce resources and scan saved diagnostics/results for every disposable credential.

## Budgets and cleanup

A behavior-probed GNU coreutils or uutils `timeout` enforces a 15-minute wall-clock limit around the complete inner gate and gives its exact cleanup trap 30 seconds before a forced kill. Its inner marker is bound to the supervisor PID and resolved executable, so caller environment cannot bypass supervision. Each measured application process has a 1.5 GiB RSS budget, sampled during high-memory operations and checked again through server `VmHWM`; RSS is a measured failure threshold rather than a cgroup memory cap. The remaining hard local budgets are 15 seconds for each measured application operation/readiness check, 1 GiB PostgreSQL memory, 512 MiB for the physical PostgreSQL data directory, 256 MiB for `pg_database_size`, 256 MiB WAL growth, and 2 GiB for the private workspace. Docker readiness, sampling, diagnostics, and cleanup calls have their own short wall-clock bounds. The container itself is capped at two CPUs, 1 GiB memory/swap, 256 PIDs, and 128 MiB shared memory.

Cleanup is guarded by the generated run ID, full container ID, resolved image ID, exact resource names, and labels for kind, instance, and role. Container identity is read in one inspection by immutable ID, and all later container operations use that ID rather than its reusable name. The script refuses to signal an unexpected PID or remove a mismatched container, volume, or workspace. `KEEP_MESH_SMOKE=1` retains only the private workspace for diagnosis and warns that it contains disposable credentials; the exact Docker resources are still removed.

This is a single-authority boundary mechanism proof. It does not establish sustained workload behavior, heartbeat rewrite cost, long-duration receipt/WAL retention, autovacuum or pruning policy, failover, PITR, production roles/TLS, managed-service behavior, or fleet-scale suitability. Use [the intended-workload micro-soak](postgres-load-soak.md) and the remaining [PostgreSQL production gates](ha-storage.md#production-hold-and-required-gates) for those separate claims.

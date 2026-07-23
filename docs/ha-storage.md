# PostgreSQL exact-document storage preview

Status: the exact-document PostgreSQL backend, authenticated JSON-backup import, secure DSN loader, explicit server backend, application-level multi-replica path, bounded synchronous-promotion and archived-WAL recovery gates, and a bounded isolated Linux role/system-trust-path TLS gate are implemented. This is a production-preview storage path, **not a completed PostgreSQL HA, production PITR, or deployed platform claim**. Production remains on hold until sustained mixed-write failover fault injection, production recovery-point catalog/retention/timeline operations, concurrent-write and failover-adjacent recovery drills, load and soak, target-platform role/TLS/trust deployment proof, and trusted-edge distributed rate limiting all pass the gates below.

## Implemented boundary

PostgreSQL stores exactly two authoritative application documents:

- the exact encoded control document that was `state.json`; and
- the exact encoded identity document that was `identity-state.json`.

It also stores one independently versioned, reconstructible
`runtime_telemetry` document. This third document is not part of recovery
`ReadPair`, authenticated backup import source data, or the control document schema.

The control document remains bounded at 64 MiB, identity at 8 MiB, and runtime
telemetry at 32 MiB. All are stored as `BYTEA`, not `JSONB`, with a monotonic
storage revision, SHA-256 checksum, last-write receipt, and timestamp. The
database schema is fully qualified under `mesh`; every application transaction
forces `search_path=pg_catalog`.

The checked-in, checksummed migrations are
[`001_documents.sql`](../internal/postgresstore/migrations/001_documents.sql),
[`002_runtime_telemetry.sql`](../internal/postgresstore/migrations/002_runtime_telemetry.sql),
and [`003_control_topology_import.sql`](../internal/postgresstore/migrations/003_control_topology_import.sql). They create and extend:

| Table | Purpose |
| --- | --- |
| `mesh.mesh_schema_migrations` | Exact migration version, compiled SHA-256, build, and application time. |
| `mesh.mesh_state_documents` | The two authoritative exact documents, the reconstructible telemetry document, and their current receipt references. |
| `mesh.mesh_write_receipts` | One immutable header for each changed commit. |
| `mesh.mesh_write_receipt_documents` | Revision and SHA-256 binding for each document changed by a receipt. |
| `mesh.mesh_import_metadata` | One immutable import record bound to the authenticated backup and its two revision-1 documents. |

Migration creates `pgcrypto` in the dedicated `mesh` schema, revokes public schema/table privileges, and verifies that the schema, five tables, and extension share the migration owner. Base schema readiness deliberately permits the trusted-extension pre-transfer stage. Before any import write and during full runtime readiness, a stricter operational check requires every `pgcrypto` function member to be in `mesh` and owned by the schema/extension owner, denies PUBLIC execution, requires the current role to execute `mesh.digest(bytea,text)`, and rejects a non-owner role (including a superuser) that can execute any other member. Migration checksums still reject a database that is behind or unexpectedly ahead. Import metadata stores `source_backup_id` as exactly 32 lowercase hexadecimal characters; there is no catalog-sequence field in the database. Rollback authorization remains the responsibility of the external monotonic backup catalog.

Exact bytes preserve the existing strict duplicate-name/unknown-field/UTF-8/trailing-data checks and full Go graph validators. A database checksum detects corruption but does not make a database owner untrusted: a privileged database operator can replace a document and its checksum. The encrypted CA/signing material, hash-only credentials, access control, audit custody, and database backup controls remain necessary.

## Transaction semantics

For a mutation, the backend locks the authoritative row, clones and strictly decodes the current document, calls the application callback **exactly once**, validates and encodes the result, and commits the new bytes and receipt together.

- A callback or validation failure writes nothing.
- Byte-identical output is a semantic no-op: it creates no receipt and advances no revision.
- A changed commit advances the document revision exactly once.
- Control mutations and their control audit/claim state remain one control-document transaction. Identity-session mutations and their identity audit remain one identity-document transaction.
- All operations that lock both domains use `control`, then `identity` order.

The storage layer never replays a callback to hide a deadlock, disconnect, serialization error, or competing write. Callbacks can allocate one-time bearer material, so replay could return a value that is not the value persisted.

Cancellation observed after the callback but before `tx.Commit` is invoked, or PostgreSQL/pgx's explicit `ErrTxCommitRollback`, is a definite noncommit. Once `tx.Commit` is invoked, every other commit error is uncertain: the process opens a fresh transaction against a confirmed writable, non-recovery endpoint and authenticates the attempted receipt. An exact receipt proves success, including when a promoted synchronous standby is now authoritative. A missing or mismatched receipt, unavailable resolution route, or authority change that cannot return that exact receipt produces `ErrUncertainCommit`; without a separately bound authority/timeline-continuity proof, receipt absence is not enough to classify the attempt as uncommitted. That process then gates reads, writes, and readiness rather than replaying the callback. The gate is sticky for that process. Restarting it may reconstruct ordinary database readiness, but does not retroactively resolve the original client's outcome; operator/client reconciliation still has to use authoritative state and audit evidence. This depends on the database service preserving acknowledged receipts across promotion. An asynchronous promotion that loses an acknowledged receipt is an infrastructure RPO violation that Mesh cannot repair.

There is currently no revision-probe cache in the control or identity adapters. Each request reads, checksum-verifies, strictly decodes, and validates its complete document. This is conservative and correct, but it reinforces the current small-deployment and load-test limits.

## Secure PostgreSQL connection files

`mesh-server` and `mesh-storage` accept a PostgreSQL secret only through `--postgres-dsn-file`; a DSN value is not accepted as a flag or environment variable. On Linux and macOS the loader requires a clean absolute path whose components contain no symlink, and an effective-user-owned, single-link regular file with exact mode `0400` or `0600`. It performs two stable reads of the same bounded inode. Windows fails closed at this loader boundary.

Production DSNs must explicitly provide `host`, `user`, `database`, `connect_timeout`, `sslmode=verify-full`, `sslrootcert=system`, and `target_session_attrs=read-write`. Every primary and fallback hostname is verified. Connection and pool values are bounded; arbitrary runtime parameters and ambient `PG*` settings are rejected. Client-certificate/mTLS settings and custom root-certificate files are currently unsupported. When a private CA signs PostgreSQL, install that CA in the operating-system trust store used by the Mesh service before using `sslrootcert=system`.

Example production file contents (one line):

```text
postgres://mesh_runtime:REDACTED@db-rw.example.com:5432/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=16&pool_min_conns=2
```

Create separate private DSN files for the migration, import, and runtime roles. Do not put the password in service arguments or logs.

`--allow-local-plaintext-postgres` is an explicit development/test exception. With `sslmode=disable`, **every** parsed route must be a numeric loopback address such as `127.0.0.1` or `::1`, or a clean absolute Unix-socket directory. `localhost`, private-network addresses, and mixed local/nonlocal fallback lists are rejected. Never enable this flag for production.

## Least-privilege roles

Use a fresh database dedicated to Mesh. The following is a reference role layout; provision passwords through the database platform rather than checking them into this SQL. Run the first block through a separately controlled cluster-administration channel:

```sql
CREATE ROLE mesh_migrate LOGIN NOINHERIT;
CREATE ROLE mesh_import  LOGIN NOINHERIT;
CREATE ROLE mesh_runtime LOGIN NOINHERIT;

CREATE DATABASE mesh OWNER mesh_migrate TEMPLATE template0;
REVOKE ALL ON DATABASE mesh FROM PUBLIC;
GRANT CONNECT ON DATABASE mesh TO mesh_migrate, mesh_import, mesh_runtime;
```

Before migration, connect to that fresh database as `mesh_migrate` and secure the default namespace:

```sql
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

Run `mesh-storage migrate` with the migration-role DSN. On PostgreSQL 17, `pgcrypto` is a trusted extension: the extension itself is owned by `mesh_migrate`, but its member functions are initially owned by the bootstrap superuser. A non-owner `REVOKE` only warns and leaves PUBLIC `EXECUTE` in place. Before applying grants, use the separately controlled cluster-administration channel to transfer **only** the `pgcrypto` function members in the dedicated `mesh` schema:

```sql
DO $ownership$
DECLARE
    function_signature pg_catalog.regprocedure;
    transferred integer := 0;
BEGIN
    FOR function_signature IN
        SELECT p.oid::pg_catalog.regprocedure
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_depend AS dependency
          ON dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
         AND dependency.objid = p.oid
         AND dependency.deptype = 'e'
        JOIN pg_catalog.pg_extension AS extension
          ON extension.oid = dependency.refobjid
         AND dependency.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
        WHERE n.nspname = 'mesh'
          AND p.prokind = 'f'
          AND extension.extname = 'pgcrypto'
        ORDER BY p.oid
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %s OWNER TO mesh_migrate',
            function_signature
        );
        transferred := transferred + 1;
    END LOOP;
    IF transferred = 0 THEN
        RAISE EXCEPTION 'pgcrypto has no function members in schema mesh';
    END IF;
END
$ownership$;
```

Then apply the post-migration grants below as `mesh_migrate`. Treat any warning as a failed ceremony, and independently prove that every `pgcrypto` function member is `mesh_migrate`-owned, PUBLIC has no function `EXECUTE`, and only `mesh.digest(bytea,text)` is granted to the import/runtime roles. `mesh-storage import-backup` enforces this before touching an application row, and full server readiness continuously enforces it. Repeat the member transfer and complete ACL audit after any `pgcrypto` extension update before returning Mesh to readiness:

```sql
REVOKE ALL ON SCHEMA mesh FROM PUBLIC, mesh_import, mesh_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA mesh
    FROM PUBLIC, mesh_import, mesh_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE mesh_migrate IN SCHEMA mesh
    REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA mesh FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE mesh_migrate IN SCHEMA mesh
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA mesh TO mesh_import, mesh_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA mesh TO mesh_import, mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh.digest(bytea, text) TO mesh_import, mesh_runtime;

GRANT INSERT ON
    mesh.mesh_write_receipts,
    mesh.mesh_state_documents,
    mesh.mesh_write_receipt_documents,
    mesh.mesh_import_metadata
TO mesh_import;

GRANT INSERT ON
    mesh.mesh_write_receipts,
    mesh.mesh_write_receipt_documents
TO mesh_runtime;
GRANT UPDATE (
    revision,
    document_bytes,
    document_sha256,
    last_write_receipt,
    updated_at
) ON mesh.mesh_state_documents TO mesh_runtime;
```

The resulting intent is exact:

| Role | Permitted | Not permitted |
| --- | --- | --- |
| `mesh_migrate` | Own the database/schema/extension/tables and, after the mandatory admin transfer, the extension's function members; run checksummed DDL and grants. | Application serving or ordinary import/runtime use. |
| `mesh_import` | Read schema/state/provenance; insert the initial authoritative pair, its import receipt/provenance, and the separate initial telemetry document/receipt. | Update, delete, DDL, or overwrite an existing document. |
| `mesh_runtime` | Read readiness/state/provenance; insert new receipt rows; update only the five mutable state-document columns. | Insert state/import metadata, update import metadata, delete, DDL, or prune receipts. |

After a successful import and offline verification, disable the import role's login until another controlled recovery ceremony. Receipt pruning is not granted to any of these roles; it needs a separately designed maintenance policy after ambiguity and incident-retention budgets are measured. Prove the actual grants from each DSN in the deployment environment—this example is not a substitute for that gate.

## One-way JSON-to-PostgreSQL cutover

Cutover is offline and one-way. Never dual-write and never place multiple servers on the JSON directory.

1. Upgrade the JSON server, start it once with the authoritative `MESH_MASTER_KEY` and `MESH_ADMIN_TOKEN` so control schema v13 and identity v2 are durable, then stop it. Existing control-v2 nodes migrate to explicit `unassigned` placement, existing control-v3 networks migrate to explicit disabled DNS settings on port 53, existing control-v4 networks migrate to disabled relays with an exact empty selection, existing control-v5 certificates are bound to the active CA, existing control-v6 networks migrate to stable firewall-rollout state, existing control-v7 rollouts gain explicit unpaused state, existing control-v8 networks gain an empty route-transfer receipt, existing control-v9 networks gain an empty route-profile edit receipt, existing control-v10 networks gain empty route-policy state, existing control-v11 networks gain disabled native resolver state with an empty search domain, and existing control-v12 networks gain the firewall-scope compatibility boundary without scoped rules. These migrations do not change signed config bytes, revisions, or timestamps. Prove the service is stopped.
2. Create and verify a fresh control-v13 encrypted backup. The importer also accepts authenticated bound v2 through v12 archives for ordered one-way migration after import. Record the returned 32-character backup ID, archive SHA-256, sequence, location, and key-custody reference in the external catalog. Select that ID independently for import.
3. Provision the empty dedicated database and three roles above. Put each DSN in a separate owner-private file. Use the migration-role DSN only for schema setup:

   ```bash
   ./bin/mesh-storage migrate \
     --postgres-dsn-file /etc/mesh/postgres-migrate.dsn
   ```

4. Through the cluster-administration channel, transfer only the `pgcrypto` member functions as documented above; then apply and independently inspect the `mesh_migrate` grants. With every JSON and PostgreSQL Mesh writer still stopped, use only the import-role DSN to authenticate the catalog-selected archive. The command atomically installs both authoritative revision-1 documents, one two-document receipt, and import provenance; only after that succeeds, it idempotently creates a separate empty revision-1 telemetry document and receipt before reporting success:

   ```bash
   ./bin/mesh-storage import-backup \
     --postgres-dsn-file /etc/mesh/postgres-import.dsn \
     --backup-key-file /secure/mesh-backup-keys/control-plane-2026.key \
     --backup-archive /secure/mesh-backups/mesh-cutover.meshbackup \
     --expect-backup-id BACKUP_ID \
     > /secure/mesh-backups/mesh-cutover.import.json
   ```

   For a database that was imported before migration 002, temporarily enable
   only the import role after applying the migration and initialize the third
   document without changing the authoritative pair:

   ```bash
   ./bin/mesh-storage initialize-runtime-telemetry \
     --postgres-dsn-file /etc/mesh/postgres-import.dsn
   ```

5. Keep all writers stopped and verify the exact database pair against the same authenticated archive. Verification reads both authoritative documents twice, requires them not to change, repeats recovery-grade cryptographic validation, checks immutable import provenance/receipt, and strictly validates the separate telemetry document:

   ```bash
   ./bin/mesh-storage verify \
     --postgres-dsn-file /etc/mesh/postgres-import.dsn \
     --backup-key-file /secure/mesh-backup-keys/control-plane-2026.key \
     --backup-archive /secure/mesh-backups/mesh-cutover.meshbackup \
     --expect-backup-id BACKUP_ID \
     > /secure/mesh-backups/mesh-cutover.verify.json
   ```

   If `import-backup` reports that the import may be durable, or any post-import reread/validation/close step fails, **do not blindly retry import**. The authoritative pair import is create-only and may already have committed. Leave writers stopped and run `mesh-storage verify`. If the pair verifies but the reconstructible document is absent, run the idempotent `initialize-runtime-telemetry` command with the import role, then repeat verification.

6. Load the same external `MESH_MASTER_KEY` and `MESH_ADMIN_TOKEN` values used by the JSON source on every replica. These credentials are not stored in the DSN and remain external service secrets. Configure one canary with the runtime-role DSN and an explicit backend:

   ```bash
   export MESH_MASTER_KEY="$(secret-manager-read mesh/master-key)"
   export MESH_ADMIN_TOKEN="$(secret-manager-read mesh/admin-token)"
   ./bin/mesh-server \
     --storage-backend=postgres \
     --postgres-dsn-file /etc/mesh/postgres-runtime.dsn \
     --listen 127.0.0.1:8080 \
     --public-url https://mesh.example.com \
     --behind-tls-proxy
   ```

   PostgreSQL mode rejects `--dev`, an explicit `--data-dir`, an absent DSN file, and silent JSON fallback. Pass `/readyz`, authentication, inventory, mutation, session-revocation, enrollment, signed-config, and revocation checks before adding replicas behind the edge.

7. Make the old JSON directory immutable and retain it with the cutover evidence. Before the first PostgreSQL application mutation, the byte-identical import can be abandoned in favor of the untouched JSON source. After the first PostgreSQL mutation, returning to the JSON files would discard committed state and create split-brain authority; recovery must move PostgreSQL forward from its database backups/WAL.

All replicas must use the same canonical `--public-url`, identity policy, master key, and administrator credential, but separate process listeners are expected. `--rotate-admin-token` remains a one-start authorization and must not be left enabled on multiple replicas.

## Readiness and current proof

`/healthz` proves only that the process and HTTP loop are alive. In PostgreSQL mode, `/readyz` fails closed unless the endpoint is writable, the exact migration/schema/ACL contract passes, both authoritative documents and their current receipts are consistent, the import provenance is valid, both strict application graphs decode, the separate telemetry document strictly decodes, credential binding succeeds, recovery-grade cryptographic material has been validated for the observed revisions, and the process has no unresolved commit. Readiness takes a shared transaction-level migration advisory lock, so concurrent probes from many replicas coexist. Migration keeps the exclusive form of the same lock; while it is held, every readiness probe returns not-ready and resumes succeeding only after the migration transaction releases it.

The implemented repository proofs include:

- a PostgreSQL 17 single-node integration test for migration, checksums, exact no-ops, concurrent stores, import/provenance, corruption rejection, schema-security drift, concurrent two-pool shared readiness, and exclusive migration-lock exclusion; and
- `make postgres-multi-replica-smoke`, which uses one disposable `postgres:17-alpine` database and two independent `mesh-server` processes to prove shared concurrent control writes/inventory/audit, cross-replica session and CSRF revocation, surviving-replica mutation, and restarted-replica convergence; and
- `make postgres-sync-failover-smoke`, which builds a uniquely labeled disposable PostgreSQL 17 primary and physical standby, enables `synchronous_commit=remote_apply` with one named synchronous standby only after streaming replay is proven, exercises migration/import/verification and two application replicas through a primary-first multi-host `target_session_attrs=read-write` DSN, records the exact acknowledged document revisions and receipt ledger, hard-terminates the primary, explicitly promotes the standby, proves every pre-failover inventory item, session, audit event, revision, and receipt survived, commits fresh control and identity mutations, and proves restarted-replica convergence. Cleanup removes only exact ID/label-verified containers, network, volumes, processes, and workspace; and
- `make postgres-ambiguous-commit-smoke`, which uses a package-internal test-only transaction wrapper around real PostgreSQL operations. It proves definite callback cancellation before receipt SQL, strict uncertainty after a rolled-back pre-`COMMIT` transport error with no callback replay, exact receipt resolution after a real `remote_apply` commit plus hard primary loss and explicit standby promotion, and one fresh post-resolution write. It then routes a real committed write's resolution to a writable authority with a distinct system identifier and missing receipt, proves `ErrUncertainCommit`, and gates readiness, reads, and writes. Exact labeled resource and private-workspace cleanup is enforced; and
- `make postgres-pitr-smoke`, which builds one exact labeled PostgreSQL 17 primary with continuous WAL archiving and an immutable physical base backup. At three no-writer boundaries it writes create-only, fsynced same-workspace evidence binding the source system identifier, timeline 1, point/LSN/WAL filename, WAL size/SHA-256, base-backup SHA-256, exact API digests, both document revisions, every receipt item, and complete import provenance. Two isolated volumes recover independently through read-only inputs to the selected early and later points and advance to new timelines; both exact database/API manifests match before fresh writes, later sessions and mutations are excluded or included exactly by point selection, and the validated early authority completes a real Nebula create/enroll/sign/verify/revoke lifecycle. Cleanup removes only exact ID/name/label-verified containers, network, volumes, processes, and workspace.
- `make postgres-roles-tls-smoke`, which uses exact labeled cached PostgreSQL 17 and Ubuntu 24.04 containers without network pulls. It runs migration, authenticated import/offline verification, and real server mutations as three isolated login roles over hostname-verified TLS with `sslrootcert=system`, an ephemeral CA at the conventional Linux trust paths, and unavailable-first verified fallback routing. It transfers only `pgcrypto` member-function ownership through the cluster-admin channel, audits the exact ACL, denies import/runtime DDL/privilege/delete/forbidden insert/update/column operations, rejects plaintext and an uncovered reachable hostname, disables import login, rotates the runtime password, rejects the old credential, scans saved arguments/environment/logs/failure diagnostics for database secrets, and removes exact resources.

The separate [`make postgres-max-document-smoke`](postgres-max-document.md) target is implemented as a pre-live boundary harness. It creates validator-approved structured state near each ceiling, keeps maximum-width OIDC claims within the aggregate 64 KiB hardened intake limit, includes one purpose-sealed login attempt so identity recovery is key-sensitive, and uses only legal JSON whitespace to hit exact 64/8 MiB documents. It validates recovery and credentials before backup, then gates authenticated import, repeated reads, receipts/provenance, shrink-first cleanup/production mutations, restart readiness, resources, and cleanup. It becomes an implemented proof only after an audited live run prints its terminal `PASS` evidence; static validation alone does not satisfy the maximum-document production gate.

The multi-application proof remains application replication over one database. The clean promotion and deterministic ambiguous-commit proofs are bounded drills; they do **not** sustain concurrent mixed writes across repeated failure boundaries, automate election/fencing, or establish recovery budgets. The recovery proof is a bounded single-primary, no-concurrent-writer local drill; its create-only evidence is neither authenticated nor independently custodied. The role/TLS proof uses a minimal isolated Linux system trust path, not a package-managed host trust installation, managed database, deployed secret manager, certificate lifecycle, or crash collector. None of these proves production retention, failover-adjacent recovery, or load/soak budgets.

## Production hold and required gates

PostgreSQL HA is not production-complete until all of these are automated and repeatable:

- **Synchronous failover completion:** extend the passing clean-promotion and deterministic receipt-resolution drills to sustained mixed control/identity writes, real transport/controller failures before/during/after commit, repeated failovers with automated election and fencing, and explicit recovery budgets while retaining monotonic revisions and replica convergence on the authoritative timeline.
- **Backup and PITR completion:** extend the passing bounded base-backup/archived-WAL drill to points around concurrent mutations and failover; operate independently protected monotonic recovery authorization, archive retention, timeline history, backup/WAL integrity monitoring, and measured RPO/RTO; then repeat full session/enrollment/signed-state/revocation validation under those production conditions.
- **Load and soak:** exercise intended node/session/heartbeat rates and both document bounds while measuring row-lock waits, latency, WAL/receipt growth, vacuum pressure, recovery time, and memory against explicit budgets.
- **Production-deployed role and TLS proof:** repeat the passing isolated mechanism drill against the target database and every fallback route; install/rotate the private CA through that platform's real OS trust-management path, source role secrets from the deployed secret manager, exercise the actual certificate/password lifecycle and crash collector, and re-confirm that no DSN or credential enters arguments, logs, diagnostics, or ambient `PG*` state.
- **Distributed edge controls:** enforce trusted-edge distributed login/OIDC limits. PostgreSQL storage does not make the current in-process pre-authentication budgets distributed, and Mesh does not trust forwarded client-IP headers.
- **Observability and fault injection:** alert on database authority/readiness loss, receipt uncertainty, pool saturation, lock wait, revision drift, WAL/backup health, and recovery objectives; inject disconnects before/during/after commit and receipt resolution.

The local single-database, bounded synchronous-promotion/commit-injection, archived-WAL recovery, and isolated role/system-trust-path TLS drills are necessary foundation proofs, not production HA, zero-RPO under every failure mode, a production trust deployment, or a production PITR program.

## Explicit limits

- Every control writer contends on one row; every identity writer contends on the other. More application replicas improve availability around process loss, not write throughput.
- Each changed heartbeat rewrites and WAL-logs the complete control document.
- Records inside `BYTEA` are not independently queryable or SQL-indexable. Reporting and immutable audit export need a non-authoritative projection or a later normalized schema.
- This design targets one authoritative database timeline. It does not support multi-primary PostgreSQL, disconnected writes, active-active multi-region writes, or asynchronous-promotion zero-RPO claims.
- Receipts currently grow with write rate and have no production-proven pruning policy.
- PostgreSQL storage does not itself provide packaging, ingress, KMS/HSM custody, runtime handshake telemetry, staged/canary rollout control, automatic rollback, or the cross-platform five-minute network proof tracked in the [product roadmap](roadmap.md). The application-level fleet health and rollout snapshot works over either backend.

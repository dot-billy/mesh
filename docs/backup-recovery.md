# Backup and recovery

Mesh provides a strictly offline, encrypted backup and create-only restore path for the single-writer JSON backend. The same authenticated bound control-v2 through control-v13 archive is also the only supported source for the one-way PostgreSQL import preview. Fresh current servers persist control v13. The filesystem restore remains a disaster-recovery boundary, not high availability: only one JSON-backed `mesh-server` may own a data directory, and restoring an archive does not make JSON safe for multiple replicas.

## What the archive contains

Each authenticated archive contains exactly four mode-0600 file bodies, in this order:

1. the exact durable `state.json` bytes;
2. the exact durable `identity-state.json` bytes;
3. the canonical 32-byte master key encoded as unpadded base64url plus LF;
4. the administrator token as printable ASCII plus LF.

The manifest binds each name, mode, size, and SHA-256 digest, the control and identity schema versions, a random 128-bit backup ID, and a whole-second UTC capture time. The binary envelope starts with `MESH-BACKUP-V1` plus two zero bytes, carries a random 32-byte salt and authenticated ciphertext length, and authenticates the complete header as additional data. HKDF-SHA-256 derives an archive-specific AES-256-GCM key from the separately held backup key. The archive is one bounded message with no compression, password mode, streaming partial-success state, or unauthenticated metadata.

The following are deliberately external and appear in every manifest as recovery requirements:

- backup-key custody;
- identity policy and the exact public URL;
- the OIDC client secret when configured;
- native TLS or trusted reverse-proxy configuration;
- the service definition and authenticated binaries;
- an external monotonic backup catalog.

Keep copies of those items in independently protected systems. In particular, an archive is useless without its backup key, while possession of both grants the recovered master key, administrator bearer, every managed network CA, and all persisted browser sessions.

## Filesystem and operator requirements

`mesh-backup` currently performs every filesystem-mutating operation only on Linux, where this implementation proves effective-user ownership, private modes, single-link regular files, advisory locks, and directory durability. macOS and Windows operations fail closed as unsupported. A future macOS implementation must additionally prove ACL and case-folding behavior rather than treating Unix mode bits as the whole access-control boundary.

Run it as the same effective user that owns the Mesh data directory, on a local Linux filesystem that supports directory-FD `flock` and file/directory `fsync`. Network and userspace filesystems need separate proof before use. All paths must be clean absolute paths with no symbolic-link component. The data directory, backup-output parent, backup-key parent, and restore-target parent must be real owner-only mode-0700 directories. Keys, archives, state, credentials, markers, and receipts must be private, non-executable, single-link regular files. The key and archive must live outside the Mesh data directory.

The command never accepts the Mesh master key or administrator token as flags and never prints secret material. `create` reads them only from `MESH_MASTER_KEY` and `MESH_ADMIN_TOKEN`. Supply the production values from the same secret manager used by the service. For a development-only data directory, their canonical values can be loaded from `master.key` and `admin.token`.

## Credential binding and state compatibility

A successful current `mesh-server` startup advances each older authority in order through native DNS v12 and then firewall scopes v13 before the API begins serving. Version 13 creates the compatibility boundary for local node/group targets and named peer-node selectors; existing policies contain none, so the v12-to-v13 migration changes no signed configuration bytes, revisions, or timestamps. Startup checks credentials read-only before any migration, authenticates every existing or staged CA ciphertext before writes, and commits each one-way transition atomically. `create`, `verify`, `restore`, and `finalize-restore` accept bound version 2 through version 13 snapshots and recompute both verifiers from the recovered credentials; restored older authorities perform any remaining ordered migrations on current-server startup.

The master-key verifier is deliberately an offline oracle for a candidate master key to anyone who can read `state.json`. Its safety therefore depends on `MESH_MASTER_KEY` being the documented 32 bytes of CSPRNG output. Do not pad, truncate, hash, or directly use a password or other low-entropy string to satisfy the length check.

Changing a bound administrator token without an explicit ceremony fails startup before state migration. For production, keep the exact master key, update only the administrator-token secret, start once with `--rotate-admin-token`, verify the `admin.credential_rotated` audit event and both intended authentication paths, then remove the flag. The flag never authorizes a master-key change and must not remain in a unit, container argument list, or chart. In `--dev`, do not use a one-run `MESH_ADMIN_TOKEN` override for rotation: stop the service, replace the private `data-dir/admin.token` file with the intended durable value, then perform the one-shot flagged startup.

Version 1 is accepted only as live input for the one-way startup migrations. First run the current server successfully with the authoritative credentials, stop it, and create a fresh version-13 backup. The current backup verifier will not verify or restore an older unbound version-1 archive, and an older server binary will not decode the newer fields. If a pre-binding archive is the only remaining copy, preserve it and its creating binary in isolation; do not weaken the current verifier or edit the archived state to bypass the binding.

## Generate and protect a backup key

Create a private key directory once, using a storage location separate from both the live host and archive retention location:

```bash
install -d -m 0700 /secure/mesh-backup-keys
./bin/mesh-backup keygen \
  --output /secure/mesh-backup-keys/control-plane-2026.key
```

The command creates one mode-0600 file without replacement. Copy that key into independently controlled, tested custody before relying on it. Do not put it beside the archive in the same failure or access domain.

Generating a new key does not re-encrypt old archives. Keep every retained archive's corresponding key, or create and verify a new archive under the new key before retiring prior material.

## Create and verify an offline backup

1. Prove the upgraded server has completed at least one successful startup and the control store is version 13.
2. Stop `mesh-server` and prove it exited. Do not take filesystem snapshots of a running process and call them coordinated backups.
3. Create a private mode-0700 archive directory outside the data directory.
4. Load the exact service secrets into the environment.
5. Create a new archive path, then verify it.

```bash
sudo systemctl stop mesh-server.service
sudo systemctl is-active --quiet mesh-server.service && exit 1

install -d -m 0700 /secure/mesh-backups
export MESH_MASTER_KEY="$(secret-manager-read mesh/master-key)"
export MESH_ADMIN_TOKEN="$(secret-manager-read mesh/admin-token)"
trap 'unset MESH_MASTER_KEY MESH_ADMIN_TOKEN' EXIT HUP INT TERM

./bin/mesh-backup create \
  --data-dir /var/lib/mesh \
  --key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --output /secure/mesh-backups/mesh-2026-07-19.meshbackup \
  > /secure/mesh-backups/mesh-2026-07-19.create.json

./bin/mesh-backup verify \
  --key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --archive /secure/mesh-backups/mesh-2026-07-19.meshbackup \
  > /secure/mesh-backups/mesh-2026-07-19.verify.json
```

`create` refuses an incomplete-restore marker before locking, acquires `.mesh.lock` and then `.identity-state.json.lock` nonblocking, and repeats the alias-aware marker check before it reads either store. A running or starting server therefore makes the backup fail rather than race, and a fenced recovery target cannot be captured as a valid source. It synchronizes both source files and their directory, validates strict state graphs and both credential verifiers, opens every sealed OIDC payload, proves each decrypted Nebula CA certificate/self-signature/private-key pair and configuration-signing pair, and validates every stored Nebula host certificate against its CA, node name/address/groups/public key, validity, fingerprint, renewal metadata, and current issuance record. It compares stable reads after validation, immediately before publication, and after publication before it releases the locks.

A source-stability failure is reported as an unsafe snapshot, not as a publication-durability failure. If it occurs before publication, no final archive is created. If it occurs after publication, quarantine the observed archive and investigate the source; ordinary `verify` can authenticate that archive's bytes but cannot retroactively prove the source was stable at capture time. Do not catalog it as a successful recovery point.

Archive publication is create-only: an existing output is never replaced. A private sibling temporary file is synchronized, reopened, authenticated, and hard-linked to the final name; the directory is synchronized before and after removal of the temporary link. If the process dies after the hard link, the final and canonical random temporary name may still reference one inode. If publication reports that verification is required, do not retry `create` against the same path. Run `verify` on the observed final archive. It authenticates the final bytes with the selected key before repair, requires exactly one canonical temporary candidate that is the same inode, removes only that name, synchronizes the directory, rechecks a single-link final, and then performs complete semantic validation plus the archive file and parent-directory durability barriers. Missing, ambiguous, or nonmatching candidates fail without repair.

`inspect` also requires the backup key and authenticates the complete envelope, manifest, entry digests, and canonical credential encodings, but it does not prove the recovered control/identity semantics. Use `verify`, not only `inspect`, before cataloging a backup.

Record at least the returned backup ID, capture time, archive SHA-256, storage location, key-custody identifier, and an independently monotonic sequence in an external catalog. Restart the service only after the archive and catalog entry are confirmed.

## Import one backup into PostgreSQL

PostgreSQL cutover consumes the catalog-selected encrypted archive; it does not scrape or lock a live JSON directory. The Linux-only import reader performs stable owner-private reads of the archive and backup key, authenticates the complete envelope and exact expected backup ID, requires bound control schema version 2 through 6 plus `identity-state-v2`, validates every recovered credential and cryptographic relationship including staged CA state, and clears its in-process document/credential buffers after use. Import and offline verification preserve the selected control bytes exactly; older sources perform any remaining ordered topology, managed-DNS, managed-relay, and CA-rotation migrations only when the current application server starts.

Provision a fresh dedicated database with the separate migration, import, and runtime roles and secure DSN files described in the [PostgreSQL storage guide](ha-storage.md). After migration, complete its mandatory cluster-admin transfer of only the trusted `pgcrypto` member functions, apply the `mesh_migrate` revokes/grants, and inspect the resulting ACL before import. Stop the JSON server before the backup and leave every JSON and PostgreSQL Mesh writer stopped through migration, transfer/grants, import, and verification:

```bash
./bin/mesh-storage migrate \
  --postgres-dsn-file /etc/mesh/postgres-migrate.dsn

./bin/mesh-storage import-backup \
  --postgres-dsn-file /etc/mesh/postgres-import.dsn \
  --backup-key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --backup-archive /secure/mesh-backups/mesh-2026-07-19.meshbackup \
  --expect-backup-id BACKUP_ID \
  > /secure/mesh-backups/mesh-2026-07-19.import.json

./bin/mesh-storage verify \
  --postgres-dsn-file /etc/mesh/postgres-import.dsn \
  --backup-key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --backup-archive /secure/mesh-backups/mesh-2026-07-19.meshbackup \
  --expect-backup-id BACKUP_ID \
  > /secure/mesh-backups/mesh-2026-07-19.postgres-verify.json
```

Import is create-only and atomically inserts exactly the two authoritative revision-1 documents, their shared receipt and two receipt items, and one immutable provenance row bound to the authenticated 32-character lowercase-hex backup ID. After that pair commits, the command idempotently creates a separate empty runtime-telemetry document and initialization receipt before reporting success. Telemetry is reconstructible and is not added to the encrypted backup or recovery `ReadPair`. Import never runs migrations, overwrites, merges, or imports into nonempty authoritative state. `verify` must run with writers stopped: it checks schema/import readiness, reads the pair twice, rejects any change between reads, proves exact equality with the archive, repeats full credential-bound recovery validation, and strictly validates the separate telemetry document.

If `import-backup` reports that the commit may be durable, or any reread, validation, readiness, or close step fails after import might have committed, do not blindly retry import. Leave writers stopped and run `mesh-storage verify`; a blind retry cannot safely distinguish a committed authoritative import from a failed one. If verification proves the pair but reports that the reconstructible telemetry document is absent, run `mesh-storage initialize-runtime-telemetry --postgres-dsn-file /etc/mesh/postgres-import.dsn` with the controlled import role, then verify again. Retain the JSON results alongside the catalog evidence.

After verification, load the same externally managed `MESH_MASTER_KEY` and `MESH_ADMIN_TOKEN` values on every PostgreSQL-backed replica and start one canary with `--storage-backend=postgres --postgres-dsn-file /etc/mesh/postgres-runtime.dsn`. The credentials remain external to PostgreSQL and the DSN. Once the first PostgreSQL application mutation commits, the import-era archive is no longer an exact verification image and the old JSON directory must not be restarted as authority.

`mesh-storage verify` is a cutover verifier, not an ongoing PostgreSQL backup command. The repository now proves one bounded local synchronous physical-standby promotion with `remote_apply`, deterministic ambiguous-commit cases, bounded local base-backup/archived-WAL recovery to two selected named points, and an isolated Linux role/system-trust-path TLS lifecycle. It does not prove production recovery-point authorization, base-backup/WAL retention or timeline-history operations, concurrent-write or failover-adjacent recovery, sustained failover, package-managed target-host trust, or deployed secret/certificate lifecycle. Those remain mandatory before PostgreSQL HA or PITR production use.

## Restore to a new directory

Restore never mutates or reuses an existing target. First retrieve the expected backup record from the external catalog. Authenticate the archive with `inspect` or `verify`, compare its ID and digest with that record, and pass the independently selected ID explicitly:

```bash
./bin/mesh-backup verify \
  --key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --archive /secure/mesh-backups/mesh-2026-07-19.meshbackup

./bin/mesh-backup restore \
  --key-file /secure/mesh-backup-keys/control-plane-2026.key \
  --archive /secure/mesh-backups/mesh-2026-07-19.meshbackup \
  --target-dir /var/lib/mesh-restored \
  --expect-backup-id BACKUP_ID
```

The expected-ID check occurs after archive authentication but before either the target or its marker is created. Before inspecting either name, restore takes an exclusive nonblocking advisory lock on an opened parent-directory file descriptor. `mesh-server` takes the same Linux fence across its precheck, control-directory creation/lock, and postcheck. A restore therefore cannot begin against a server-created target, and a server cannot pass startup while restore can still create or remove its marker. The lock is an in-process coordination contract, not protection against unrelated programs that ignore advisory locks.

With the fence held, restore creates the sibling marker `.<target-name>.mesh-restore-incomplete`, synchronizes it, creates a new mode-0700 target, writes all four files with create-only semantics, and adds `.mesh-restore-receipt.json`. It reopens and validates every byte and cryptographic relationship, synchronizes the files and directory, and removes the marker only after success. Finalization holds the same parent fence through revalidation and marker removal.

The receipt binds the backup and restore operation IDs, exact target path, restore time, both state digests, and canonical recovered credential bodies with an HMAC derived from the recovered master key. This catches accidental or partial modification during recovery; it is not an integrity defense against an attacker who can read the restored master key and rewrite the directory.

If restore is interrupted after the marker is durable, every later `mesh-server` startup against that target refuses before opening or creating state. Startup checks the exact marker even while the target is absent. Once the target exists, it also stream-scans at most 65,536 sibling entries, derives every syntactically valid restore target name, and compares resolved inode identity. This closes case-folded and same-parent alternate-path spellings; scan overflow or an I/O error fails closed. It does not discover arbitrary aliases in unrelated parent namespaces, so the symlink-free absolute-path rule remains mandatory. Leave the marker in place while investigating. When the target contains the complete exact file set, resume only through:

```bash
./bin/mesh-backup finalize-restore --target-dir /var/lib/mesh-restored
```

Finalization synchronizes every recovered file again, rejects missing or extra directory entries, verifies the receipt and all state/key relationships, synchronizes the target directory, and only then removes and synchronizes the marker. If it fails, do not start the server and do not delete the marker merely to bypass the fence. Discard the new target and begin a new create-only restore when its partial state cannot be proved.

## Bring the JSON-restored control plane online

Reinstall the authenticated service binary and restore the external identity, TLS/proxy, OIDC-secret, and service configuration before startup. Use the same canonical `--public-url` and identity policy when existing browser sessions are expected to survive; a policy fingerprint or legacy credential-binding change invalidates them by design.

Start only one server against the new directory, then prove more than `/healthz`:

1. authenticate through the intended browser/OIDC and administrator-bearer paths;
2. compare network, node, revision, issuance, revocation, and audit inventories with the cataloged drill expectations;
3. enroll a fresh pending node with real pinned-version `nebula` and `nebula-cert` tools;
4. verify its certificate and run `nebula -test` on its signed configuration;
5. confirm active agents accept later signed revisions and still enforce revocation.

Do not delete the prior data directory or last known-good archive until this validation and the applicable retention period complete.

## Rollback and HA limits

The backup ID, receipt, and `--expect-backup-id` prevent archive mix-ups; they do not prevent rollback. A self-consistent older archive contains its matching master key and can pass every local cryptographic check. Mesh has no trusted monotonic counter outside the restored state. The external catalog and operator approval process must reject a backup sequence older than the authorized recovery point.

The JSON restore workflow does not provide replication, shared rate limits, zero-downtime failover, point-in-time recovery, or multi-writer transactions; never place two servers on a shared JSON directory. The PostgreSQL exact-document backend, two-application-replica path, bounded synchronous promotion/ambiguous-commit drills, bounded no-concurrent-writer archived-WAL recovery drill, and isolated role/system-trust-path TLS drill are implemented as a preview. Sustained mixed-write failover, externally authorized recovery with production WAL retention/timeline-history operations, load/soak, target-platform trust/secret/certificate deployment proof, and distributed edge limiting remain unproved.

## Repository proof

Run the self-cleaning recovery drill on a supported Linux host with exact-version Nebula 1.10.3 binaries:

```bash
make backup-restore-smoke
```

The drill proves live-lock refusal, source immutability, create-only publication, authenticated verification, expected-ID and no-clobber restore behavior, server refusal under an interrupted-restore marker, receipt-based finalization, persisted browser-session continuity, restored network identity/revision, and a fresh real-Nebula enrollment whose certificate and configuration both validate.

The separate `make postgres-multi-replica-smoke` proof imports one authenticated archive into a disposable PostgreSQL 17 database and exercises two independent application replicas. `make postgres-sync-failover-smoke` adds a uniquely labeled PostgreSQL 17 primary/physical-standby pair, proves named-standby `remote_apply`, hard-terminates the primary, explicitly promotes the standby, and verifies survival of every acknowledged revision, receipt, session, inventory item, and audit event before fresh writes and replica convergence.

`make postgres-ambiguous-commit-smoke` is the bounded transaction-outcome companion: deterministic test-only wrappers around real commits prove definite callback cancellation before receipt SQL, strict uncertainty after a rolled-back pre-`COMMIT` transport failure, exact lost-acknowledgment receipt resolution across synchronous promotion without replay, and fail-closed behavior when resolution reaches a distinct writable authority with no receipt. It is not a sustained failover or recovery-point proof.

`make postgres-pitr-smoke` uses one exact PostgreSQL 17 primary, a private continuous WAL archive, and one immutable physical base backup. With the sole Mesh writer stopped, it writes three create-only, fsynced same-workspace point records binding the source system identifier and timeline 1 to each name/LSN/WAL filename and size/SHA-256, the immutable base-backup SHA-256, and exact API/database-manifest digests. Fresh isolated volumes recover through read-only inputs to the selected early and later points, advance to new timelines, and must match each full receipt/import ledger and API snapshot before any new write. The early point rejects both later sessions, the later point retains its selected session but rejects the archived post-point session, and only then does the early recovered authority complete real Nebula enrollment, signed-bundle verification, and revocation. The evidence is neither authenticated nor externally custodied; this remains a bounded local mechanism proof, not a production recovery catalog, retention/timeline-history program, concurrent/failover-adjacent drill, or measured RPO/RTO. See the [remaining PostgreSQL proof gates](ha-storage.md#production-hold-and-required-gates).

`make postgres-roles-tls-smoke` runs the real migration/import/verify/server lifecycle through three separate roles in exact labeled cached PostgreSQL 17 and Ubuntu 24.04 containers. It uses `sslmode=verify-full`, `sslrootcert=system`, an ephemeral CA at conventional isolated Linux trust paths, primary and unavailable-first fallback hostnames, explicit `pgcrypto` member ownership, exact grant/denial probes, import-login disablement, runtime password rotation, old-password rejection, and database-secret leak scanning. This is not a package-managed host trust installation, managed-database deployment, production secret/certificate lifecycle, crash-collector proof, or cross-platform claim.

package postgresloadgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/runtimetelemetry"
)

const (
	operationControlUpdate  = "control.state.update"
	operationIdentityUpdate = "identity.state.update"
	operationImport         = "storage.import"
)

type persistedNetwork struct {
	control.Network
	EncryptedCAKey            string `json:"encrypted_ca_key"`
	EncryptedNextCAKey        string `json:"encrypted_next_ca_key,omitempty"`
	EncryptedConfigSigningKey string `json:"encrypted_config_signing_key"`
}

type persistedNode struct {
	control.Node
	AgentTokenHash              string     `json:"agent_token_hash,omitempty"`
	PreviousAgentTokenHash      string     `json:"previous_agent_token_hash,omitempty"`
	PreviousAgentTokenExpiresAt *time.Time `json:"previous_agent_token_expires_at,omitempty"`
	PublicKeyHash               string     `json:"public_key_hash,omitempty"`
	RenewalClaimID              string     `json:"renewal_claim_id,omitempty"`
	RenewalClaimedAt            *time.Time `json:"renewal_claimed_at,omitempty"`
}

type controlDocument struct {
	Version                 int                             `json:"version"`
	MasterKeyVerifier       string                          `json:"master_key_verifier,omitempty"`
	AdminCredentialVerifier string                          `json:"admin_credential_verifier,omitempty"`
	Networks                []persistedNetwork              `json:"networks"`
	Nodes                   []persistedNode                 `json:"nodes"`
	Enrollments             []control.EnrollmentToken       `json:"enrollments"`
	AgentRecoveries         []control.AgentRecoveryToken    `json:"agent_recoveries,omitempty"`
	Issuances               []control.CertificateIssuance   `json:"issuances,omitempty"`
	Revocations             []control.CertificateRevocation `json:"revocations,omitempty"`
	Audit                   []control.AuditEvent            `json:"audit"`
}

type identityDocument struct {
	Schema          string                        `json:"schema"`
	LoginAttempts   []json.RawMessage             `json:"login_attempts"`
	Sessions        []identity.Session            `json:"sessions"`
	BreakGlassCodes []json.RawMessage             `json:"break_glass_codes"`
	Audit           []identity.IdentityAuditEvent `json:"audit"`
}

type loadedDocuments struct {
	control     controlDocument
	identity    identityDocument
	controlRaw  []byte
	identityRaw []byte
}

func decodeOneStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func readStorageSnapshot(ctx context.Context, pool *pgxpool.Pool) (StorageSnapshot, loadedDocuments, error) {
	if pool == nil {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("PostgreSQL pool is required")
	}
	var result StorageSnapshot
	loaded := loadedDocuments{}
	rows, err := pool.Query(ctx, `
SELECT document_key, revision, document_bytes, document_sha256, octet_length(document_bytes)
FROM mesh.mesh_state_documents
ORDER BY document_key`)
	if err != nil {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("read exact PostgreSQL documents failed")
	}
	defer rows.Close()
	seen := make(map[string]bool)
	for rows.Next() {
		var key string
		var revision, size int64
		var body, storedHash []byte
		if err := rows.Scan(&key, &revision, &body, &storedHash, &size); err != nil {
			return StorageSnapshot{}, loadedDocuments{}, errors.New("scan exact PostgreSQL document failed")
		}
		if seen[key] || len(storedHash) != sha256.Size {
			return StorageSnapshot{}, loadedDocuments{}, errors.New("PostgreSQL document identity or checksum is invalid")
		}
		seen[key] = true
		digest := sha256.Sum256(body)
		if !bytes.Equal(storedHash, digest[:]) {
			return StorageSnapshot{}, loadedDocuments{}, errors.New("PostgreSQL document checksum does not match exact bytes")
		}
		snapshot := DocumentSnapshot{Revision: revision, SHA256: hex.EncodeToString(digest[:]), Bytes: size}
		switch key {
		case "control":
			if err := decodeOneStrict(body, &loaded.control); err != nil {
				return StorageSnapshot{}, loadedDocuments{}, errors.New("decode exact control document failed")
			}
			loaded.controlRaw = append([]byte(nil), body...)
			snapshot.AuditRecords, snapshot.ResourceRecords = len(loaded.control.Audit), len(loaded.control.Nodes)
			result.Control = snapshot
		case "identity":
			if err := decodeOneStrict(body, &loaded.identity); err != nil {
				return StorageSnapshot{}, loadedDocuments{}, errors.New("decode exact identity document failed")
			}
			loaded.identityRaw = append([]byte(nil), body...)
			snapshot.AuditRecords, snapshot.ResourceRecords = len(loaded.identity.Audit), len(loaded.identity.Sessions)
			result.Identity = snapshot
		case "runtime_telemetry":
			if revision < 1 {
				return StorageSnapshot{}, loadedDocuments{}, errors.New("runtime telemetry document revision is invalid")
			}
			if _, err := runtimetelemetry.DecodeState(body); err != nil {
				return StorageSnapshot{}, loadedDocuments{}, errors.New("decode exact runtime telemetry document failed")
			}
		default:
			return StorageSnapshot{}, loadedDocuments{}, errors.New("unexpected PostgreSQL document domain")
		}
	}
	if err := rows.Err(); err != nil {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("iterate exact PostgreSQL documents failed")
	}
	if !seen["control"] || !seen["identity"] || !seen["runtime_telemetry"] || len(seen) != 3 {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("PostgreSQL does not contain the authoritative pair and runtime telemetry document")
	}

	if err := pool.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM mesh.mesh_write_receipts),
    (SELECT count(*) FROM mesh.mesh_write_receipt_documents),
    pg_database_size(current_database()),
    d.xact_commit, d.xact_rollback, d.blks_read, d.blks_hit,
    d.tup_returned, d.tup_fetched, d.tup_inserted, d.tup_updated, d.tup_deleted,
    d.conflicts, d.temp_files, d.temp_bytes, d.deadlocks,
    w.wal_records, w.wal_fpi, w.wal_bytes::bigint, w.wal_buffers_full
FROM pg_catalog.pg_stat_database AS d
CROSS JOIN pg_catalog.pg_stat_wal AS w
WHERE d.datname = current_database()`).Scan(
		&result.ReceiptHeaders,
		&result.ReceiptDocuments,
		&result.DatabaseBytes,
		&result.Database.XactCommit,
		&result.Database.XactRollback,
		&result.Database.BlocksRead,
		&result.Database.BlocksHit,
		&result.Database.TuplesReturned,
		&result.Database.TuplesFetched,
		&result.Database.TuplesInserted,
		&result.Database.TuplesUpdated,
		&result.Database.TuplesDeleted,
		&result.Database.Conflicts,
		&result.Database.TempFiles,
		&result.Database.TempBytes,
		&result.Database.Deadlocks,
		&result.WAL.Records,
		&result.WAL.FullPageImages,
		&result.WAL.Bytes,
		&result.WAL.BuffersFull,
	); err != nil {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("read PostgreSQL database and WAL counters failed")
	}
	operationRows, err := pool.Query(ctx, `
SELECT operation_class, count(*)
FROM mesh.mesh_write_receipts
GROUP BY operation_class
ORDER BY operation_class`)
	if err != nil {
		return StorageSnapshot{}, loadedDocuments{}, errors.New("read PostgreSQL receipt operation classes failed")
	}
	result.OperationClasses = make(map[string]int64)
	for operationRows.Next() {
		var operation string
		var count int64
		if err := operationRows.Scan(&operation, &count); err != nil {
			operationRows.Close()
			return StorageSnapshot{}, loadedDocuments{}, errors.New("scan PostgreSQL receipt operation class failed")
		}
		result.OperationClasses[operation] = count
	}
	if err := operationRows.Err(); err != nil {
		operationRows.Close()
		return StorageSnapshot{}, loadedDocuments{}, errors.New("iterate PostgreSQL receipt operation classes failed")
	}
	operationRows.Close()
	table, err := readDocumentTableCounters(ctx, pool)
	if err != nil {
		return StorageSnapshot{}, loadedDocuments{}, err
	}
	result.DocumentTable = table
	return result, loaded, nil
}

func readDocumentTableCounters(ctx context.Context, pool *pgxpool.Pool) (TableCounters, error) {
	var counters TableCounters
	err := pool.QueryRow(ctx, `
SELECT n_live_tup, n_dead_tup, vacuum_count, autovacuum_count, analyze_count, autoanalyze_count
FROM pg_catalog.pg_stat_user_tables
WHERE schemaname = 'mesh' AND relname = 'mesh_state_documents'`).Scan(
		&counters.LiveTuples,
		&counters.DeadTuples,
		&counters.VacuumCount,
		&counters.AutovacuumCount,
		&counters.AnalyzeCount,
		&counters.AutoanalyzeCount,
	)
	if err != nil {
		return TableCounters{}, errors.New("read PostgreSQL document-table counters failed")
	}
	return counters, nil
}

func subtractDatabase(after, before DatabaseCounters) DatabaseCounters {
	return DatabaseCounters{
		XactCommit:     after.XactCommit - before.XactCommit,
		XactRollback:   after.XactRollback - before.XactRollback,
		BlocksRead:     after.BlocksRead - before.BlocksRead,
		BlocksHit:      after.BlocksHit - before.BlocksHit,
		TuplesReturned: after.TuplesReturned - before.TuplesReturned,
		TuplesFetched:  after.TuplesFetched - before.TuplesFetched,
		TuplesInserted: after.TuplesInserted - before.TuplesInserted,
		TuplesUpdated:  after.TuplesUpdated - before.TuplesUpdated,
		TuplesDeleted:  after.TuplesDeleted - before.TuplesDeleted,
		Conflicts:      after.Conflicts - before.Conflicts,
		TempFiles:      after.TempFiles - before.TempFiles,
		TempBytes:      after.TempBytes - before.TempBytes,
		Deadlocks:      after.Deadlocks - before.Deadlocks,
	}
}

func subtractWAL(after, before WALCounters) WALCounters {
	return WALCounters{
		Records:        after.Records - before.Records,
		FullPageImages: after.FullPageImages - before.FullPageImages,
		Bytes:          after.Bytes - before.Bytes,
		BuffersFull:    after.BuffersFull - before.BuffersFull,
	}
}

func subtractOperations(after, before map[string]int64) map[string]int64 {
	keys := make(map[string]struct{}, len(after)+len(before))
	for key := range after {
		keys[key] = struct{}{}
	}
	for key := range before {
		keys[key] = struct{}{}
	}
	result := make(map[string]int64, len(keys))
	for key := range keys {
		result[key] = after[key] - before[key]
	}
	return result
}

func storageDelta(after, before StorageSnapshot) StorageDelta {
	return StorageDelta{
		ControlRevision:  after.Control.Revision - before.Control.Revision,
		IdentityRevision: after.Identity.Revision - before.Identity.Revision,
		ControlAudit:     after.Control.AuditRecords - before.Control.AuditRecords,
		IdentityAudit:    after.Identity.AuditRecords - before.Identity.AuditRecords,
		ReceiptHeaders:   after.ReceiptHeaders - before.ReceiptHeaders,
		ReceiptDocuments: after.ReceiptDocuments - before.ReceiptDocuments,
		OperationClasses: subtractOperations(after.OperationClasses, before.OperationClasses),
		Database:         subtractDatabase(after.Database, before.Database),
		WAL:              subtractWAL(after.WAL, before.WAL),
	}
}

func countersNonnegative(c DatabaseCounters) bool {
	return c.XactCommit >= 0 && c.XactRollback >= 0 && c.BlocksRead >= 0 && c.BlocksHit >= 0 &&
		c.TuplesReturned >= 0 && c.TuplesFetched >= 0 && c.TuplesInserted >= 0 && c.TuplesUpdated >= 0 &&
		c.TuplesDeleted >= 0 && c.Conflicts >= 0 && c.TempFiles >= 0 && c.TempBytes >= 0 && c.Deadlocks >= 0
}

func validateStorageDelta(delta StorageDelta, terminal StorageSnapshot) error {
	if delta.ControlRevision != ExpectedControlWrites || delta.IdentityRevision != ExpectedIdentityWrites {
		return fmt.Errorf("document revision deltas control=%d identity=%d, want %d and %d", delta.ControlRevision, delta.IdentityRevision, ExpectedControlWrites, ExpectedIdentityWrites)
	}
	if delta.ControlAudit != ExpectedControlWrites || delta.IdentityAudit != ExpectedIdentityWrites {
		return fmt.Errorf("audit deltas control=%d identity=%d, want %d and %d", delta.ControlAudit, delta.IdentityAudit, ExpectedControlWrites, ExpectedIdentityWrites)
	}
	if delta.ReceiptHeaders != ExpectedWrites || delta.ReceiptDocuments != ExpectedWrites {
		return fmt.Errorf("receipt deltas headers=%d documents=%d, want %d each", delta.ReceiptHeaders, delta.ReceiptDocuments, ExpectedWrites)
	}
	if delta.OperationClasses[operationControlUpdate] != ExpectedControlWrites ||
		delta.OperationClasses[operationIdentityUpdate] != ExpectedIdentityWrites ||
		delta.OperationClasses[operationImport] != 0 {
		return fmt.Errorf("receipt operation-class deltas are not exact: %#v", delta.OperationClasses)
	}
	for operation, count := range delta.OperationClasses {
		if operation != operationControlUpdate && operation != operationIdentityUpdate && operation != operationImport && count != 0 {
			return fmt.Errorf("unexpected receipt operation-class delta %q=%d", operation, count)
		}
	}
	if !countersNonnegative(delta.Database) || delta.WAL.Records < 0 || delta.WAL.FullPageImages < 0 || delta.WAL.Bytes < 0 || delta.WAL.BuffersFull < 0 {
		return errors.New("PostgreSQL statistics reset or moved backwards during the bounded run")
	}
	if delta.Database.Deadlocks != 0 || delta.Database.Conflicts != 0 || delta.Database.TempFiles != 0 || delta.Database.TempBytes != 0 {
		return fmt.Errorf("PostgreSQL error/temp deltas are nonzero: %+v", delta.Database)
	}
	if delta.WAL.Bytes > MaximumWALBytes || delta.WAL.Bytes/int64(ExpectedWrites) > MaximumAverageWALPerWrite {
		return fmt.Errorf("WAL delta=%d average=%d exceeds total=%d average=%d budgets", delta.WAL.Bytes, delta.WAL.Bytes/int64(ExpectedWrites), MaximumWALBytes, MaximumAverageWALPerWrite)
	}
	if delta.WAL.BuffersFull > MaximumWALBuffersFull {
		return fmt.Errorf("wal_buffers_full delta=%d exceeds %d", delta.WAL.BuffersFull, MaximumWALBuffersFull)
	}
	if terminal.DatabaseBytes > MaximumDatabaseBytes || terminal.Control.Bytes > MaximumDocumentBytes || terminal.Identity.Bytes > MaximumDocumentBytes {
		return fmt.Errorf("storage sizes database=%d control=%d identity=%d exceed budgets", terminal.DatabaseBytes, terminal.Control.Bytes, terminal.Identity.Bytes)
	}
	return nil
}

func validateReceiptIntegrity(ctx context.Context, pool *pgxpool.Pool, snapshot StorageSnapshot) error {
	var malformedItems, mismatchedCurrent, malformedHeaders int64
	if err := pool.QueryRow(ctx, `
SELECT count(*)
FROM mesh.mesh_write_receipt_documents
WHERE committed_revision <> base_revision + 1
   OR base_revision < 0
   OR octet_length(document_sha256) <> 32`).Scan(&malformedItems); err != nil {
		return errors.New("inspect PostgreSQL receipt items failed")
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)
FROM mesh.mesh_state_documents AS d
LEFT JOIN mesh.mesh_write_receipt_documents AS i
  ON i.receipt_id = d.last_write_receipt
 AND i.document_key = d.document_key
 AND i.committed_revision = d.revision
 AND i.document_sha256 = d.document_sha256
WHERE i.receipt_id IS NULL
   OR d.document_sha256 <> mesh.digest(d.document_bytes, 'sha256')`).Scan(&mismatchedCurrent); err != nil {
		return errors.New("inspect current PostgreSQL receipt bindings failed")
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)
FROM (
	    SELECT r.receipt_id, r.operation_class,
	           count(i.receipt_id) AS item_count,
	           count(*) FILTER (WHERE i.document_key = 'control') AS control_items,
	           count(*) FILTER (WHERE i.document_key = 'identity') AS identity_items,
	           count(*) FILTER (WHERE i.document_key = 'runtime_telemetry') AS runtime_telemetry_items
    FROM mesh.mesh_write_receipts AS r
    LEFT JOIN mesh.mesh_write_receipt_documents AS i ON i.receipt_id = r.receipt_id
    GROUP BY r.receipt_id, r.operation_class
) AS grouped
WHERE NOT (
    (operation_class = 'storage.import' AND item_count = 2 AND control_items = 1 AND identity_items = 1)
 OR (operation_class = 'control.state.update' AND item_count = 1 AND control_items = 1 AND identity_items = 0)
 OR (operation_class = 'identity.state.update' AND item_count = 1 AND control_items = 0 AND identity_items = 1)
	 OR (operation_class = 'document.initialize' AND item_count = 1 AND runtime_telemetry_items = 1)
)`).Scan(&malformedHeaders); err != nil {
		return errors.New("inspect PostgreSQL receipt headers failed")
	}
	if malformedItems != 0 || mismatchedCurrent != 0 || malformedHeaders != 0 {
		return fmt.Errorf("receipt integrity malformed_items=%d current_mismatches=%d malformed_headers=%d", malformedItems, mismatchedCurrent, malformedHeaders)
	}
	rows, err := pool.Query(ctx, `
SELECT document_key, count(*), min(committed_revision), max(committed_revision), count(DISTINCT committed_revision)
FROM mesh.mesh_write_receipt_documents
GROUP BY document_key
ORDER BY document_key`)
	if err != nil {
		return errors.New("read PostgreSQL receipt sequences failed")
	}
	defer rows.Close()
	seen := make(map[string]bool)
	for rows.Next() {
		var domain string
		var count, minimum, maximum, distinct int64
		if err := rows.Scan(&domain, &count, &minimum, &maximum, &distinct); err != nil {
			return errors.New("scan PostgreSQL receipt sequence failed")
		}
		wanted := int64(0)
		switch domain {
		case "control":
			wanted = snapshot.Control.Revision
		case "identity":
			wanted = snapshot.Identity.Revision
		case "runtime_telemetry":
			wanted = 1
		default:
			return errors.New("receipt sequence contains an unexpected domain")
		}
		seen[domain] = true
		if count != wanted || distinct != wanted || minimum != 1 || maximum != wanted {
			return fmt.Errorf("%s receipt sequence count=%d distinct=%d range=%d..%d, want exact 1..%d", domain, count, distinct, minimum, maximum, wanted)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.New("iterate PostgreSQL receipt sequences failed")
	}
	if !seen["control"] || !seen["identity"] || !seen["runtime_telemetry"] || len(seen) != 3 {
		return errors.New("receipt sequence does not contain the authoritative pair and runtime telemetry domain")
	}
	return nil
}

func runVacuum(ctx context.Context, pool *pgxpool.Pool) (VacuumResult, error) {
	before, err := readDocumentTableCounters(ctx, pool)
	if err != nil {
		return VacuumResult{}, err
	}
	started := time.Now()
	if _, err := pool.Exec(ctx, `VACUUM (ANALYZE) mesh.mesh_state_documents`); err != nil {
		return VacuumResult{}, errors.New("explicit PostgreSQL document-table vacuum failed")
	}
	duration := time.Since(started)
	if _, err := pool.Exec(ctx, `SELECT pg_catalog.pg_stat_clear_snapshot()`); err != nil {
		return VacuumResult{}, errors.New("refresh PostgreSQL statistics after vacuum failed")
	}
	after, err := readDocumentTableCounters(ctx, pool)
	if err != nil {
		return VacuumResult{}, err
	}
	result := VacuumResult{DurationMicros: duration.Microseconds(), Before: before, After: after}
	if duration > MaximumVacuumDuration {
		return result, fmt.Errorf("explicit vacuum duration=%s exceeds %s", duration, MaximumVacuumDuration)
	}
	if after.DeadTuples > MaximumDeadTuplesAfterVacuum {
		return result, fmt.Errorf("document-table dead tuples=%d after vacuum, want <=%d", after.DeadTuples, MaximumDeadTuplesAfterVacuum)
	}
	if after.VacuumCount-before.VacuumCount < 1 || after.AnalyzeCount-before.AnalyzeCount < 1 {
		return result, errors.New("explicit VACUUM ANALYZE did not advance its recorded counters")
	}
	return result, nil
}

type lockWaitSampler struct {
	mu     sync.Mutex
	result LockWaitSamples
	err    error
	cancel context.CancelFunc
	done   chan struct{}
}

func startLockWaitSampler(parent context.Context, pool *pgxpool.Pool) *lockWaitSampler {
	ctx, cancel := context.WithCancel(parent)
	sampler := &lockWaitSampler{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var waiters, transactionWaiters, tupleWaiters int64
				err := pool.QueryRow(ctx, `
SELECT
    count(*) FILTER (WHERE wait_event_type = 'Lock'),
    count(*) FILTER (WHERE wait_event = 'transactionid'),
    count(*) FILTER (WHERE wait_event = 'tuple')
FROM pg_catalog.pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&waiters, &transactionWaiters, &tupleWaiters)
				sampler.mu.Lock()
				if err != nil {
					if ctx.Err() == nil && sampler.err == nil {
						sampler.err = errors.New("sample PostgreSQL lock waits failed")
					}
					sampler.mu.Unlock()
					continue
				}
				sampler.result.Samples++
				if waiters > 0 {
					sampler.result.SamplesWithWaits++
				}
				if waiters > sampler.result.MaximumWaiters {
					sampler.result.MaximumWaiters = waiters
				}
				sampler.result.TransactionWaits += transactionWaiters
				sampler.result.TupleWaits += tupleWaiters
				sampler.mu.Unlock()
			}
		}
	}()
	return sampler
}

func (sampler *lockWaitSampler) stop() (LockWaitSamples, error) {
	if sampler == nil {
		return LockWaitSamples{}, errors.New("lock-wait sampler is nil")
	}
	sampler.cancel()
	<-sampler.done
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if sampler.err != nil {
		return sampler.result, sampler.err
	}
	if sampler.result.Samples == 0 {
		return sampler.result, errors.New("lock-wait sampler captured no samples")
	}
	return sampler.result, nil
}

func sortedNodeIDs(nodes map[string]string) []string {
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

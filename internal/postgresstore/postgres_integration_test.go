package postgresstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Set MESH_POSTGRES_TEST_DSN to a disposable PostgreSQL database. The test
// requires an empty disposable database and a provisioning superuser, creates/
// drops only its fixed Mesh schema plus one uniquely named hostile schema, and
// never manages containers.
func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("MESH_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("MESH_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to disposable postgres: %v", err)
	}
	defer admin.Close(context.Background())
	var meshSchemaExists bool
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace('mesh') IS NOT NULL`).Scan(&meshSchemaExists); err != nil {
		t.Fatalf("inspect dedicated schema: %v", err)
	}
	if meshSchemaExists {
		t.Fatal("refusing integration test because schema mesh already exists; use a disposable empty database")
	}
	uuid, err := generateUUID()
	if err != nil {
		t.Fatal(err)
	}
	attackerSchema := "mesh_attacker_test_" + strings.ReplaceAll(uuid, "-", "")
	attackerIdentifier := pgx.Identifier{attackerSchema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+attackerIdentifier); err != nil {
		t.Fatalf("create hostile search-path schema: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE FUNCTION "+attackerIdentifier+`.octet_length(bytea) RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 999999999'`); err != nil {
		t.Fatalf("create hostile shadow function: %v", err)
	}
	defer func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, `DROP SCHEMA IF EXISTS mesh CASCADE`); err != nil {
			t.Errorf("drop dedicated test schema: %v", err)
		}
		if _, err := admin.Exec(dropCtx, "DROP SCHEMA "+attackerIdentifier+" CASCADE"); err != nil {
			t.Errorf("drop hostile test schema: %v", err)
		}
	}()

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse integration DSN: %v", err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = attackerSchema + ",pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open isolated test pool: %v", err)
	}
	defer pool.Close()
	options := Options{
		MigrationBuild: "postgresstore-integration-test",
	}
	store, err := New(pool, options)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := store.CheckSchemaReadiness(ctx); err != nil {
		t.Fatalf("schema readiness before initialization: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	var currentUser string
	var currentUserSuperuser bool
	if err := pool.QueryRow(ctx, `
SELECT CURRENT_USER, r.rolsuper
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = CURRENT_USER`).Scan(&currentUser, &currentUserSuperuser); err != nil {
		t.Fatalf("inspect integration provisioning role: %v", err)
	}
	if !currentUserSuperuser {
		t.Fatal("PostgreSQL integration function-corruption proof requires a disposable provisioning superuser")
	}

	if _, err := pool.Exec(ctx, `GRANT EXECUTE ON FUNCTION mesh.digest(bytea, text) TO PUBLIC`); err != nil {
		t.Fatalf("inject public function ACL drift: %v", err)
	}
	if err := store.CheckSchemaReadiness(ctx); err != nil {
		t.Fatalf("base schema readiness rejected operational function ACL drift: %v", err)
	}
	if err := store.CheckReadiness(ctx); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("full readiness with public function ACL drift = %v, want ErrSchemaNotReady", err)
	}
	if _, err := pool.Exec(ctx, `REVOKE ALL ON FUNCTION mesh.digest(bytea, text) FROM PUBLIC`); err != nil {
		t.Fatalf("repair public function ACL drift: %v", err)
	}

	if _, err := pool.Exec(ctx, `ALTER FUNCTION mesh.crypt(text, text) OWNER TO pg_monitor`); err != nil {
		t.Fatalf("inject pgcrypto member ownership drift: %v", err)
	}
	if err := store.CheckSchemaReadiness(ctx); err != nil {
		t.Fatalf("base schema readiness rejected pre-transfer member ownership: %v", err)
	}
	rowsBeforeRejectedImport := integrationApplicationRowCount(t, ctx, pool)
	if _, err := store.Import(ctx, integrationImportSource("c")); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("pre-transfer import error = %v, want ErrSchemaNotReady", err)
	}
	if rowsAfter := integrationApplicationRowCount(t, ctx, pool); rowsAfter != rowsBeforeRejectedImport {
		t.Fatalf("pre-transfer import wrote application rows: before=%d after=%d", rowsBeforeRejectedImport, rowsAfter)
	}
	if _, err := pool.Exec(ctx, `ALTER FUNCTION mesh.crypt(text, text) OWNER TO `+pgx.Identifier{currentUser}.Sanitize()); err != nil {
		t.Fatalf("repair pgcrypto member ownership drift: %v", err)
	}
	if err := store.CheckReadiness(ctx); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("readiness after function security repair = %v, want ErrNotInitialized", err)
	}

	if _, err := pool.Exec(ctx, `GRANT USAGE, CREATE ON SCHEMA mesh TO PUBLIC`); err != nil {
		t.Fatalf("inject schema ACL drift: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT, INSERT ON mesh.mesh_state_documents TO PUBLIC`); err != nil {
		t.Fatalf("inject table ACL drift: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("repair schema ACL drift: %v", err)
	}
	if err := store.CheckSchemaReadiness(ctx); err != nil {
		t.Fatalf("schema readiness after ACL repair: %v", err)
	}
	if err := store.CheckReadiness(ctx); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("readiness before initialization = %v, want ErrNotInitialized", err)
	}

	controlBytes := []byte("0\n")
	identityBytes := []byte("{\n  \"schema\": \"identity-state-v2\"\n}\n")
	initializationPeer, err := New(pool, options)
	if err != nil {
		t.Fatal(err)
	}
	defer initializationPeer.Close()
	type initializationResult struct {
		result WriteResult
		err    error
	}
	initializations := make(chan initializationResult, 2)
	for _, candidate := range []*Store{store, initializationPeer} {
		go func(candidate *Store) {
			result, err := candidate.Initialize(ctx, DomainControl, controlBytes)
			initializations <- initializationResult{result: result, err: err}
		}(candidate)
	}
	changedInitializations := 0
	for range 2 {
		outcome := <-initializations
		if outcome.err != nil {
			t.Fatalf("concurrent identical initialize: %v", outcome.err)
		}
		if outcome.result.Changed {
			changedInitializations++
		}
		if outcome.result.Document.Revision != 1 {
			t.Fatalf("initial revision = %d, want 1", outcome.result.Document.Revision)
		}
	}
	if changedInitializations != 1 {
		t.Fatalf("changed initializations = %d, want exactly 1", changedInitializations)
	}
	if _, err := store.Initialize(ctx, DomainIdentity, identityBytes); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	runtimeTelemetryBytes := []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[]}`)
	if initialized, err := store.Initialize(ctx, DomainRuntimeTelemetry, runtimeTelemetryBytes); err != nil || !initialized.Changed {
		t.Fatalf("initialize runtime telemetry: changed=%v err=%v", initialized.Changed, err)
	}
	if initialized, err := store.Initialize(ctx, DomainRuntimeTelemetry, runtimeTelemetryBytes); err != nil || initialized.Changed {
		t.Fatalf("idempotent runtime telemetry initialize: changed=%v err=%v", initialized.Changed, err)
	}
	telemetryDocument, err := store.Read(ctx, DomainRuntimeTelemetry)
	if err != nil || !bytes.Equal(telemetryDocument.Bytes, runtimeTelemetryBytes) {
		t.Fatalf("read runtime telemetry document=%q err=%v", telemetryDocument.Bytes, err)
	}
	if err := store.CheckReadiness(ctx); err != nil {
		t.Fatalf("readiness after initialization: %v", err)
	}
	t.Run("shared readiness excludes only migration", func(t *testing.T) {
		integrationReadinessLockCompatibility(t, ctx, dsn, attackerSchema, store, admin)
	})
	pairedControl, pairedIdentity, err := store.ReadPair(ctx)
	if err != nil {
		t.Fatalf("paired read after initialization: %v", err)
	}
	if !bytes.Equal(pairedControl.Bytes, controlBytes) || !bytes.Equal(pairedIdentity.Bytes, identityBytes) {
		t.Fatal("paired read did not return both exact initialized documents")
	}

	read, err := store.Read(ctx, DomainIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Bytes) != string(identityBytes) {
		t.Fatalf("exact BYTEA changed: got %q want %q", read.Bytes, identityBytes)
	}
	read.Bytes[0] = '['
	again, err := store.Read(ctx, DomainIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Bytes) != string(identityBytes) {
		t.Fatal("caller mutation changed stored bytes")
	}

	beforeReceipts := integrationReceiptCount(t, ctx, pool)
	noOpCalls := 0
	noOp, err := store.Update(ctx, DomainControl, "control.noop", func(current []byte) ([]byte, error) {
		noOpCalls++
		return append([]byte(nil), current...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if noOp.Changed || noOp.Document.Revision != 1 || noOpCalls != 1 {
		t.Fatalf("unexpected no-op: result=%+v calls=%d", noOp, noOpCalls)
	}
	if after := integrationReceiptCount(t, ctx, pool); after != beforeReceipts {
		t.Fatalf("no-op receipt count = %d, want %d", after, beforeReceipts)
	}

	if _, err := store.Update(ctx, DomainControl, "control.increment", incrementDocument); err != nil {
		t.Fatalf("initial changed update: %v", err)
	}
	second, err := New(pool, options)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stores := []*Store{store, second}
	const concurrentUpdates = 12
	var (
		callbackCalls atomic.Int64
		waitGroup     sync.WaitGroup
	)
	errorsByUpdate := make(chan error, concurrentUpdates)
	for i := range concurrentUpdates {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_, err := stores[index%len(stores)].Update(ctx, DomainControl, "control.concurrent", func(current []byte) ([]byte, error) {
				callbackCalls.Add(1)
				return incrementDocument(current)
			})
			errorsByUpdate <- err
		}(i)
	}
	waitGroup.Wait()
	close(errorsByUpdate)
	for err := range errorsByUpdate {
		if err != nil {
			t.Fatalf("concurrent update: %v", err)
		}
	}
	if callbackCalls.Load() != concurrentUpdates {
		t.Fatalf("concurrent callback calls = %d, want %d", callbackCalls.Load(), concurrentUpdates)
	}
	final, err := store.Read(ctx, DomainControl)
	if err != nil {
		t.Fatal(err)
	}
	if final.Revision != 2+concurrentUpdates || string(final.Bytes) != strconv.Itoa(1+concurrentUpdates)+"\n" {
		t.Fatalf("lost update: revision=%d bytes=%q", final.Revision, final.Bytes)
	}
	if err := second.CheckReadiness(ctx); err != nil {
		t.Fatalf("second replica readiness: %v", err)
	}

	badHash := make([]byte, sha256.Size)
	if _, err := pool.Exec(ctx, `UPDATE mesh.mesh_state_documents SET document_sha256 = $2 WHERE document_key = $1`, DomainControl, badHash); err == nil {
		t.Fatal("database accepted bytes/hash mismatch while digest constraint was present")
	}
	corruptTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer corruptTx.Rollback(context.Background())
	if _, err := corruptTx.Exec(ctx, `ALTER TABLE mesh.mesh_state_documents DROP CONSTRAINT mesh_state_documents_sha256_check`); err != nil {
		t.Fatalf("drop checksum constraint for privileged-corruption test: %v", err)
	}
	if _, err := corruptTx.Exec(ctx, `
UPDATE mesh.mesh_write_receipt_documents
SET document_sha256 = $2
WHERE document_key = $1
  AND committed_revision = (
      SELECT revision FROM mesh.mesh_state_documents WHERE document_key = $1
  )`, DomainControl, badHash); err != nil {
		t.Fatalf("corrupt current receipt hash: %v", err)
	}
	if _, err := corruptTx.Exec(ctx, `UPDATE mesh.mesh_state_documents SET document_sha256 = $2 WHERE document_key = $1`, DomainControl, badHash); err != nil {
		t.Fatalf("inject privileged checksum corruption: %v", err)
	}
	if err := corruptTx.Commit(ctx); err != nil {
		t.Fatalf("commit privileged checksum corruption: %v", err)
	}
	if _, err := store.Read(ctx, DomainControl); !errors.Is(err, ErrCorruptDocument) {
		t.Fatalf("read after corruption = %v, want ErrCorruptDocument", err)
	}
	if err := store.CheckReadiness(ctx); !errors.Is(err, ErrCorruptDocument) {
		t.Fatalf("readiness after corruption = %v, want ErrCorruptDocument", err)
	}

	resetIntegrationSchema(t, ctx, pool, store)
	sourceA := integrationImportSource("a")
	sourceB := integrationImportSource("b")
	type importOutcome struct {
		result ImportResult
		err    error
	}
	differentOutcomes := make(chan importOutcome, 2)
	for index, candidate := range []*Store{store, second} {
		source := sourceA
		if index == 1 {
			source = sourceB
		}
		go func(candidate *Store, source ImportSource) {
			result, err := candidate.Import(ctx, source)
			differentOutcomes <- importOutcome{result: result, err: err}
		}(candidate, source)
	}
	var winningImport ImportResult
	successes, alreadyImported := 0, 0
	for range 2 {
		outcome := <-differentOutcomes
		switch {
		case outcome.err == nil:
			successes++
			winningImport = outcome.result
		case errors.Is(outcome.err, ErrAlreadyImported):
			alreadyImported++
		default:
			t.Fatalf("concurrent different import: %v", outcome.err)
		}
	}
	if successes != 1 || alreadyImported != 1 {
		t.Fatalf("concurrent different import successes=%d alreadyImported=%d", successes, alreadyImported)
	}
	if err := store.CheckImportReadiness(ctx); err != nil {
		t.Fatalf("import readiness: %v", err)
	}
	importedControl, err := store.Read(ctx, DomainControl)
	if err != nil {
		t.Fatal(err)
	}
	importedIdentity, err := store.Read(ctx, DomainIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(importedControl.Bytes, winningImport.Control.Bytes) || !bytes.Equal(importedIdentity.Bytes, winningImport.Identity.Bytes) {
		t.Fatal("import did not retain exact source bytes")
	}
	pairedControl, pairedIdentity, err = store.ReadPair(ctx)
	if err != nil || !bytes.Equal(pairedControl.Bytes, winningImport.Control.Bytes) || !bytes.Equal(pairedIdentity.Bytes, winningImport.Identity.Bytes) {
		t.Fatalf("paired read did not retain exact imported documents: %v", err)
	}
	if integrationReceiptCount(t, ctx, pool) != 1 || integrationReceiptItemCount(t, ctx, pool) != 2 {
		t.Fatal("one import did not create exactly one header and two receipt items")
	}
	if _, err := store.Import(ctx, sourceA); !errors.Is(err, ErrAlreadyImported) {
		t.Fatalf("reimport error = %v, want ErrAlreadyImported", err)
	}
	if integrationReceiptCount(t, ctx, pool) != 1 || integrationReceiptItemCount(t, ctx, pool) != 2 {
		t.Fatal("refused reimport mutated receipt tables")
	}
	importUpdateCalls := 0
	if _, err := store.Update(ctx, DomainControl, "control.after_import", func(current []byte) ([]byte, error) {
		importUpdateCalls++
		return append(current, '\n'), nil
	}); err != nil {
		t.Fatalf("post-import update: %v", err)
	}
	if importUpdateCalls != 1 || integrationReceiptCount(t, ctx, pool) != 2 || integrationReceiptItemCount(t, ctx, pool) != 3 {
		t.Fatalf("post-import callback/receipt counts calls=%d headers=%d items=%d", importUpdateCalls, integrationReceiptCount(t, ctx, pool), integrationReceiptItemCount(t, ctx, pool))
	}
	if err := store.CheckImportReadiness(ctx); err != nil {
		t.Fatalf("import readiness after later revision: %v", err)
	}
	wrongProvenanceHash := make([]byte, sha256.Size)
	if _, err := pool.Exec(ctx, `UPDATE mesh.mesh_import_metadata SET source_control_sha256 = $1`, wrongProvenanceHash); err != nil {
		t.Fatalf("inject provenance mismatch: %v", err)
	}
	if err := store.CheckImportReadiness(ctx); !errors.Is(err, ErrImportProvenance) {
		t.Fatalf("corrupt import readiness = %v, want ErrImportProvenance", err)
	}

	resetIntegrationSchema(t, ctx, pool, store)
	sameOutcomes := make(chan error, 2)
	for _, candidate := range []*Store{store, second} {
		go func(candidate *Store) {
			_, err := candidate.Import(ctx, sourceA)
			sameOutcomes <- err
		}(candidate)
	}
	successes, alreadyImported = 0, 0
	for range 2 {
		err := <-sameOutcomes
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyImported):
			alreadyImported++
		default:
			t.Fatalf("concurrent same import: %v", err)
		}
	}
	if successes != 1 || alreadyImported != 1 {
		t.Fatalf("concurrent same import successes=%d alreadyImported=%d", successes, alreadyImported)
	}
	if err := second.CheckImportReadiness(ctx); err != nil {
		t.Fatalf("same-source import readiness: %v", err)
	}

	resetIntegrationSchema(t, ctx, pool, store)
	importRace := make(chan error, 1)
	initializeRace := make(chan error, 1)
	go func() {
		_, err := store.Import(ctx, sourceA)
		importRace <- err
	}()
	go func() {
		_, err := second.Initialize(ctx, DomainControl, []byte(`{"version":1,"initializer":true}`))
		initializeRace <- err
	}()
	importErr := <-importRace
	initializeErr := <-initializeRace
	validImportWinner := importErr == nil && errors.Is(initializeErr, ErrAlreadyInitialized)
	validInitializeWinner := initializeErr == nil && errors.Is(importErr, ErrNotEmpty)
	if !validImportWinner && !validInitializeWinner {
		t.Fatalf("import/initialize race returned opaque outcome: import=%v initialize=%v", importErr, initializeErr)
	}
}

func incrementDocument(current []byte) ([]byte, error) {
	value, err := strconv.Atoi(strings.TrimSpace(string(current)))
	if err != nil {
		return nil, fmt.Errorf("parse counter: %w", err)
	}
	return []byte(strconv.Itoa(value+1) + "\n"), nil
}

func integrationReceiptCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mesh.mesh_write_receipts`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func integrationReceiptItemCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mesh.mesh_write_receipt_documents`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func integrationApplicationRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `
SELECT
    (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_state_documents)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipt_documents)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_import_metadata)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func integrationReadinessLockCompatibility(t *testing.T, parent context.Context, dsn, attackerSchema string, primary *Store, lockConnection *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()

	peerConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse peer readiness DSN: %v", err)
	}
	peerConfig.ConnConfig.RuntimeParams["search_path"] = attackerSchema + ",pg_catalog"
	peerConfig.MaxConns = 8
	peerPool, err := pgxpool.NewWithConfig(ctx, peerConfig)
	if err != nil {
		t.Fatalf("open peer readiness pool: %v", err)
	}
	defer peerPool.Close()
	peer, err := New(peerPool, Options{MigrationBuild: "postgresstore-readiness-lock-integration-test"})
	if err != nil {
		t.Fatalf("open peer readiness store: %v", err)
	}
	defer peer.Close()

	// Hold a real shared lock for the full fan-out. This makes the test
	// deterministic: the former exclusive try-lock used by readiness would make
	// every call fail, while the shared readiness lock can coexist.
	sharedLock, err := lockConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin shared migration-lock transaction: %v", err)
	}
	defer sharedLock.Rollback(context.Background())
	if _, err := sharedLock.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock_shared($1)`, migrationAdvisoryLockKey); err != nil {
		t.Fatalf("hold shared migration advisory lock: %v", err)
	}

	const readinessCalls = 16
	type readinessResult struct {
		index int
		err   error
	}
	started := make(chan struct{})
	results := make(chan readinessResult, readinessCalls)
	var wait sync.WaitGroup
	stores := []*Store{primary, peer}
	for index := range readinessCalls {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-started
			results <- readinessResult{index: index, err: stores[index%len(stores)].CheckReadiness(ctx)}
		}(index)
	}
	close(started)
	wait.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent readiness call %d through pool %d: %v", result.index+1, result.index%len(stores)+1, result.err)
		}
	}
	if err := sharedLock.Rollback(ctx); err != nil {
		t.Fatalf("release shared migration advisory lock: %v", err)
	}

	exclusiveLock, err := lockConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin exclusive migration-lock transaction: %v", err)
	}
	defer exclusiveLock.Rollback(context.Background())
	if _, err := exclusiveLock.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock($1)`, migrationAdvisoryLockKey); err != nil {
		t.Fatalf("hold exclusive migration advisory lock: %v", err)
	}
	if err := primary.CheckReadiness(ctx); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("readiness under exclusive migration lock = %v, want ErrSchemaNotReady", err)
	}
	if err := exclusiveLock.Rollback(ctx); err != nil {
		t.Fatalf("release exclusive migration advisory lock: %v", err)
	}
	if err := peer.CheckReadiness(ctx); err != nil {
		t.Fatalf("readiness after exclusive migration lock release: %v", err)
	}
}

func integrationImportSource(marker string) ImportSource {
	backupID := strings.Repeat(marker, 32)
	return ImportSource{
		ControlBytes:          []byte("{\n  \"version\": 2,\n  \"marker\": \"" + marker + "\"\n}\n"),
		IdentityBytes:         []byte("{\n  \"schema\": \"identity-state-v2\",\n  \"marker\": \"" + marker + "\"\n}\n"),
		SourceFormat:          ImportSourceFormat,
		ControlVersion:        ImportControlVersion,
		IdentitySchema:        ImportIdentitySchema,
		AuthenticatedBackupID: backupID,
		ImporterBuild:         "postgresstore-integration/v1",
	}
}

func resetIntegrationSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *Store) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP SCHEMA mesh CASCADE`); err != nil {
		t.Fatalf("reset dedicated schema: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("remigrate dedicated schema: %v", err)
	}
	if err := store.CheckSchemaReadiness(ctx); err != nil {
		t.Fatalf("schema readiness after reset: %v", err)
	}
}

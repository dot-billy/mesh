package runtimetelemetry_test

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"mesh/internal/postgresstore"
	"mesh/internal/runtimetelemetry"
)

// Set MESH_RUNTIME_TELEMETRY_POSTGRES_TEST_DSN to a dedicated disposable
// PostgreSQL database. The test refuses a pre-existing Mesh schema and drops
// only the schema it created.
func TestPostgresMobileRuntimeIntegration(t *testing.T) {
	dsn := os.Getenv("MESH_RUNTIME_TELEMETRY_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("MESH_RUNTIME_TELEMETRY_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to disposable PostgreSQL: %v", err)
	}
	defer admin.Close(context.Background())
	var meshSchemaExists bool
	if err := admin.QueryRow(
		ctx,
		`SELECT pg_catalog.to_regnamespace('mesh') IS NOT NULL`,
	).Scan(&meshSchemaExists); err != nil {
		t.Fatalf("inspect dedicated schema: %v", err)
	}
	if meshSchemaExists {
		t.Fatal("refusing integration test because schema mesh already exists")
	}
	defer func() {
		dropCtx, dropCancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer dropCancel()
		if _, err := admin.Exec(
			dropCtx,
			`DROP SCHEMA IF EXISTS mesh CASCADE`,
		); err != nil {
			t.Errorf("drop dedicated test schema: %v", err)
		}
	}()

	primaryPool := openIntegrationPool(t, ctx, dsn)
	defer primaryPool.Close()
	primaryRepository, err := postgresstore.New(
		primaryPool,
		postgresstore.Options{
			MigrationBuild: "mobile-runtime-postgres-integration-primary",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer primaryRepository.Close()
	if err := primaryRepository.Migrate(ctx); err != nil {
		t.Fatalf("migrate PostgreSQL schema: %v", err)
	}
	if _, err := primaryRepository.Import(
		ctx,
		postgresstore.ImportSource{
			ControlBytes:          []byte(`{"version":2}`),
			IdentityBytes:         []byte(`{"schema":"identity-state-v2"}`),
			SourceFormat:          postgresstore.ImportSourceFormat,
			ControlVersion:        postgresstore.ImportControlVersion,
			IdentitySchema:        postgresstore.ImportIdentitySchema,
			AuthenticatedBackupID: string(bytes.Repeat([]byte{'a'}, 32)),
			ImporterBuild:         "mobile-runtime-postgres-integration/v1",
		},
	); err != nil {
		t.Fatalf("import disposable authority documents: %v", err)
	}
	primary, err := runtimetelemetry.NewPostgresStore(
		primaryRepository,
		runtimetelemetry.PostgresStoreOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	if err := primary.EnsureInitialized(ctx); err != nil {
		t.Fatalf("initialize runtime telemetry: %v", err)
	}

	secondaryPool := openIntegrationPool(t, ctx, dsn)
	defer secondaryPool.Close()
	secondaryRepository, err := postgresstore.New(
		secondaryPool,
		postgresstore.Options{
			MigrationBuild: "mobile-runtime-postgres-integration-secondary",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer secondaryRepository.Close()
	secondary, err := runtimetelemetry.NewPostgresStore(
		secondaryRepository,
		runtimetelemetry.PostgresStoreOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer secondary.Close()
	if err := secondary.CheckReadiness(); err != nil {
		t.Fatalf("secondary runtime telemetry readiness: %v", err)
	}

	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	input := integrationMobileRuntimeInput()
	first, changed, err := primary.PutMobile("node_mobile", now, input)
	if err != nil || !changed || first.Sequence != input.Sequence {
		t.Fatalf("initial mobile report=%#v changed=%t err=%v", first, changed, err)
	}
	*input.PacketsRead = 999
	observed, found, err := secondary.GetMobile("node_mobile")
	if err != nil || !found || observed.PacketsRead == nil ||
		*observed.PacketsRead != 11 || !observed.ReceivedAt.Equal(now) {
		t.Fatalf("cross-replica mobile report=%#v found=%t err=%v", observed, found, err)
	}

	retry := integrationMobileRuntimeInput()
	accepted, changed, err := secondary.PutMobile(
		"node_mobile",
		now.Add(time.Minute),
		retry,
	)
	if err != nil || changed || !accepted.ReceivedAt.Equal(now) {
		t.Fatalf("idempotent retry=%#v changed=%t err=%v", accepted, changed, err)
	}

	next := integrationMobileRuntimeInput()
	next.Sequence++
	next.RuntimeUptimeMS++
	*next.PacketsRead = 12
	type outcome struct {
		record  runtimetelemetry.MobileRuntimeRecord
		changed bool
		err     error
	}
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for _, store := range []*runtimetelemetry.PostgresStore{
		primary,
		secondary,
	} {
		wait.Add(1)
		go func(store *runtimetelemetry.PostgresStore) {
			defer wait.Done()
			record, changed, err := store.PutMobile(
				"node_mobile",
				now.Add(2*time.Minute),
				next,
			)
			outcomes <- outcome{record: record, changed: changed, err: err}
		}(store)
	}
	wait.Wait()
	close(outcomes)
	changedCount := 0
	for result := range outcomes {
		if result.err != nil || result.record.Sequence != next.Sequence {
			t.Fatalf("concurrent transition=%#v", result)
		}
		if result.changed {
			changedCount++
		}
	}
	if changedCount != 1 {
		t.Fatalf("concurrent identical transition changed count=%d, want 1", changedCount)
	}

	document, err := secondaryRepository.Read(
		ctx,
		postgresstore.DomainRuntimeTelemetry,
	)
	if err != nil {
		t.Fatalf("read authoritative telemetry document: %v", err)
	}
	state, err := runtimetelemetry.DecodeState(document.Bytes)
	if err != nil {
		t.Fatalf("decode authoritative telemetry document: %v", err)
	}
	if document.Revision != 3 ||
		state.Schema != runtimetelemetry.StateSchemaV8 ||
		len(state.Records) != 0 ||
		len(state.MobileRecords) != 1 ||
		state.MobileRecords[0].Sequence != next.Sequence {
		t.Fatalf(
			"authoritative telemetry revision=%d state=%#v",
			document.Revision,
			state,
		)
	}
	assertRuntimeTelemetryReceipts(t, ctx, secondaryPool)

	if err := primary.Close(); err != nil {
		t.Fatalf("close primary runtime adapter: %v", err)
	}
	final, found, err := secondary.GetMobile("node_mobile")
	if err != nil || !found || final.Sequence != next.Sequence {
		t.Fatalf("surviving replica report=%#v found=%t err=%v", final, found, err)
	}
}

func openIntegrationPool(
	t *testing.T,
	ctx context.Context,
	dsn string,
) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse disposable PostgreSQL DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open disposable PostgreSQL pool: %v", err)
	}
	return pool
}

func integrationMobileRuntimeInput() runtimetelemetry.MobileRuntimeReportInput {
	read, written := uint64(11), uint64(7)
	return runtimetelemetry.MobileRuntimeReportInput{
		Version:                runtimetelemetry.MobileRuntimeVersionV1,
		InstanceGeneration:     3,
		Sequence:               4,
		State:                  runtimetelemetry.MobileStateTunnelRunning,
		ConfigRevision:         8,
		ConfigSHA256:           string(bytes.Repeat([]byte{'a'}, 64)),
		CertificateFingerprint: string(bytes.Repeat([]byte{'b'}, 64)),
		CertificateGeneration:  2,
		EngineIdentity:         string(bytes.Repeat([]byte{'c'}, 64)),
		RuntimeUptimeMS:        90_000,
		PacketsRead:            &read,
		PacketsWritten:         &written,
	}
}

func assertRuntimeTelemetryReceipts(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()
	rows, err := pool.Query(ctx, `
SELECT r.operation_class, d.base_revision, d.committed_revision
FROM mesh.mesh_write_receipts AS r
JOIN mesh.mesh_write_receipt_documents AS d
  ON d.receipt_id = r.receipt_id
WHERE d.document_key = $1
ORDER BY d.committed_revision`,
		postgresstore.DomainRuntimeTelemetry,
	)
	if err != nil {
		t.Fatalf("read runtime telemetry receipts: %v", err)
	}
	defer rows.Close()
	type receipt struct {
		operation string
		base      int64
		committed int64
	}
	var receipts []receipt
	for rows.Next() {
		var current receipt
		if err := rows.Scan(
			&current.operation,
			&current.base,
			&current.committed,
		); err != nil {
			t.Fatalf("scan runtime telemetry receipt: %v", err)
		}
		receipts = append(receipts, current)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate runtime telemetry receipts: %v", err)
	}
	expected := []receipt{
		{operation: postgresstore.OperationInitialize, base: 0, committed: 1},
		{
			operation: "runtime_telemetry.state.update",
			base:      1,
			committed: 2,
		},
		{
			operation: "runtime_telemetry.state.update",
			base:      2,
			committed: 3,
		},
	}
	if len(receipts) != len(expected) {
		t.Fatalf("runtime telemetry receipts=%#v, want %#v", receipts, expected)
	}
	for index := range expected {
		if receipts[index] != expected[index] {
			t.Fatalf("runtime telemetry receipts=%#v, want %#v", receipts, expected)
		}
	}
}

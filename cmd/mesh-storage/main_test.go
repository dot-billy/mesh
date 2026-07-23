package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/backupio"
	"mesh/internal/control"
	"mesh/internal/postgresstore"
	"mesh/internal/runtimetelemetry"
)

var (
	testCapturedAt = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	testImportedAt = time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	testVerifiedAt = time.Date(2026, 7, 19, 12, 2, 0, 0, time.UTC)
)

func TestCurrentControlImportVersionMatchesServerSchema(t *testing.T) {
	if postgresstore.ImportControlVersion != control.ControlStateVersionNativeDNS {
		t.Fatalf("PostgreSQL import version=%d, current control schema=%d", postgresstore.ImportControlVersion, control.ControlStateVersionNativeDNS)
	}
}

type fakeArchive struct {
	control       []byte
	identity      []byte
	meta          backupio.ImportArchiveMetadata
	validateErr   error
	validateCalls int
	cleared       bool
	order         *[]string
}

func (archive *fakeArchive) controlBytes() []byte  { return archive.control }
func (archive *fakeArchive) identityBytes() []byte { return archive.identity }
func (archive *fakeArchive) metadata() backupio.ImportArchiveMetadata {
	return archive.meta
}
func (archive *fakeArchive) ValidateExactDocuments(_ context.Context, control, identity []byte) error {
	archive.validateCalls++
	if archive.order != nil {
		*archive.order = append(*archive.order, "validate")
	}
	if archive.validateErr != nil {
		return archive.validateErr
	}
	if !bytes.Equal(control, archive.control) || !bytes.Equal(identity, archive.identity) {
		return errors.New("exact validation mismatch")
	}
	return nil
}
func (archive *fakeArchive) Clear() {
	clear(archive.control)
	clear(archive.identity)
	archive.cleared = true
	if archive.order != nil {
		*archive.order = append(*archive.order, "clear-archive")
	}
}

type fakeStorage struct {
	order              *[]string
	migrateErr         error
	schemaErr          error
	importErr          error
	initializeErr      error
	readErr            map[postgresstore.Domain]error
	importReadinessErr error
	importResult       postgresstore.ImportResult
	documents          map[postgresstore.Domain]postgresstore.Document
	importSource       postgresstore.ImportSource
	readinessCalls     int
	onReadiness        func(int)
}

func (store *fakeStorage) record(value string) {
	if store.order != nil {
		*store.order = append(*store.order, value)
	}
}
func (store *fakeStorage) Migrate(context.Context) error {
	store.record("migrate")
	return store.migrateErr
}
func (store *fakeStorage) CheckSchemaReadiness(context.Context) error {
	store.record("schema-ready")
	return store.schemaErr
}
func (store *fakeStorage) Import(_ context.Context, source postgresstore.ImportSource) (postgresstore.ImportResult, error) {
	store.record("import")
	store.importSource = source
	store.importSource.ControlBytes = bytes.Clone(source.ControlBytes)
	store.importSource.IdentityBytes = bytes.Clone(source.IdentityBytes)
	return cloneImportResult(store.importResult), store.importErr
}
func (store *fakeStorage) Initialize(_ context.Context, domain postgresstore.Domain, body []byte) (postgresstore.WriteResult, error) {
	store.record("initialize:" + string(domain))
	if store.initializeErr != nil {
		return postgresstore.WriteResult{}, store.initializeErr
	}
	if existing, exists := store.documents[domain]; exists {
		if bytes.Equal(existing.Bytes, body) {
			return postgresstore.WriteResult{Document: cloneDocument(existing)}, nil
		}
		return postgresstore.WriteResult{}, postgresstore.ErrAlreadyInitialized
	}
	document := testDocument(domain, string(body))
	store.documents[domain] = document
	return postgresstore.WriteResult{Changed: true, Document: cloneDocument(document)}, nil
}
func (store *fakeStorage) Read(_ context.Context, domain postgresstore.Domain) (postgresstore.Document, error) {
	store.record("read:" + string(domain))
	if err := store.readErr[domain]; err != nil {
		return postgresstore.Document{}, err
	}
	document, exists := store.documents[domain]
	if !exists {
		return postgresstore.Document{}, postgresstore.ErrNotInitialized
	}
	return cloneDocument(document), nil
}
func (store *fakeStorage) ReadPair(context.Context) (postgresstore.Document, postgresstore.Document, error) {
	store.record("read-pair")
	if err := store.readErr[postgresstore.DomainControl]; err != nil {
		return postgresstore.Document{}, postgresstore.Document{}, err
	}
	if err := store.readErr[postgresstore.DomainIdentity]; err != nil {
		return postgresstore.Document{}, postgresstore.Document{}, err
	}
	return cloneDocument(store.documents[postgresstore.DomainControl]), cloneDocument(store.documents[postgresstore.DomainIdentity]), nil
}
func (store *fakeStorage) CheckImportReadiness(context.Context) error {
	store.record("import-ready")
	store.readinessCalls++
	if store.onReadiness != nil {
		store.onReadiness(store.readinessCalls)
	}
	return store.importReadinessErr
}

func cloneDocument(document postgresstore.Document) postgresstore.Document {
	document.Bytes = bytes.Clone(document.Bytes)
	return document
}

func cloneImportResult(result postgresstore.ImportResult) postgresstore.ImportResult {
	result.Control = cloneDocument(result.Control)
	result.Identity = cloneDocument(result.Identity)
	return result
}

func testDocument(domain postgresstore.Domain, body string) postgresstore.Document {
	raw := []byte(body)
	return postgresstore.Document{
		Domain: domain, Revision: 1, Bytes: raw, SHA256: sha256.Sum256(raw),
		LastWriteID: "11111111-1111-4111-8111-111111111111", UpdatedAt: testImportedAt,
	}
}

func testState() (*fakeArchive, *fakeStorage) {
	control := testDocument(postgresstore.DomainControl, `{"version":2}`)
	identity := testDocument(postgresstore.DomainIdentity, `{"schema":"identity-state-v2"}`)
	archive := &fakeArchive{
		control: bytes.Clone(control.Bytes), identity: bytes.Clone(identity.Bytes),
		meta: backupio.ImportArchiveMetadata{
			BackupID: strings.Repeat("a", 32), CapturedAt: testCapturedAt,
			ControlVersion: 2, IdentitySchema: postgresstore.ImportIdentitySchema,
		},
	}
	telemetryRaw, err := runtimetelemetry.EncodeState(runtimetelemetry.EmptyState())
	if err != nil {
		panic(err)
	}
	telemetry := testDocument(postgresstore.DomainRuntimeTelemetry, string(telemetryRaw))
	store := &fakeStorage{
		documents: map[postgresstore.Domain]postgresstore.Document{
			postgresstore.DomainControl: control, postgresstore.DomainIdentity: identity, postgresstore.DomainRuntimeTelemetry: telemetry,
		},
		readErr: make(map[postgresstore.Domain]error),
		importResult: postgresstore.ImportResult{
			ImportID:   "22222222-2222-4222-8222-222222222222",
			ReceiptID:  "11111111-1111-4111-8111-111111111111",
			ImportedAt: testImportedAt, Control: control, Identity: identity,
		},
	}
	return archive, store
}

func testDependencies(archiveValue *fakeArchive, store *fakeStorage, order *[]string) dependencies {
	archiveValue.order = order
	store.order = order
	return dependencies{
		openArchive: func(_ context.Context, options backupio.ImportArchiveOptions) (archive, error) {
			*order = append(*order, "open-archive:"+options.ExpectedBackupID)
			return archiveValue, nil
		},
		openStorage: func(_ context.Context, options storageOpenOptions) (*openedStorage, error) {
			*order = append(*order, "open-storage:"+options.dsnFile)
			return &openedStorage{
				store: store,
				close: func() error {
					*order = append(*order, "close-storage")
					return nil
				},
			}, nil
		},
		build: func() (string, error) {
			*order = append(*order, "build")
			return "mesh-storage/dev@unknown", nil
		},
		now: func() time.Time { return testVerifiedAt },
	}
}

func backupArgs(command string) []string {
	return []string{
		command,
		"--postgres-dsn-file", "/private/postgres.dsn",
		"--backup-key-file", "/private/backup.key",
		"--backup-archive", "/private/backup.meshbackup",
		"--expect-backup-id", strings.Repeat("a", 32),
		"--allow-local-plaintext-postgres",
	}
}

func decodeResult(t *testing.T, output *bytes.Buffer) commandResult {
	t.Helper()
	var result commandResult
	decoder := json.NewDecoder(output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMigrateRunsMigrationThenSchemaReadiness(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), []string{
		"migrate", "--postgres-dsn-file", "/private/postgres.dsn", "--allow-local-plaintext-postgres",
	}, &output, deps)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"build", "open-storage:/private/postgres.dsn", "migrate", "schema-ready", "close-storage"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order=%v, want %v", order, want)
	}
	result := decodeResult(t, &output)
	if result.Schema != resultSchema || result.Status != "migrated" || !result.VerifiedAt.Equal(testVerifiedAt) {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.CapturedAt != nil || result.ImportedAt != nil || result.BackupID != "" {
		t.Fatalf("migrate leaked irrelevant metadata: %+v", result)
	}
}

func TestImportBackupValidatesFirstNeverMigratesAndRereads(t *testing.T) {
	archive, store := testState()
	delete(store.documents, postgresstore.DomainRuntimeTelemetry)
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	if err := run(context.Background(), backupArgs("import-backup"), &output, deps); err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"open-archive:" + strings.Repeat("a", 32), "build", "open-storage:/private/postgres.dsn",
		"schema-ready", "import", "read-pair", "validate", "import-ready",
		"initialize:runtime_telemetry", "read:runtime_telemetry", "read-pair", "validate", "read:runtime_telemetry",
		"close-storage", "clear-archive",
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order=%v, want %v", order, wantOrder)
	}
	if archive.validateCalls != 2 || !archive.cleared {
		t.Fatalf("archive validation=%d cleared=%v", archive.validateCalls, archive.cleared)
	}
	source := store.importSource
	if source.SourceFormat != postgresstore.ImportSourceFormat || source.ControlVersion != 2 || source.IdentitySchema != postgresstore.ImportIdentitySchema || source.AuthenticatedBackupID != strings.Repeat("a", 32) || source.ImporterBuild != "mesh-storage/dev@unknown" {
		t.Fatalf("unexpected import source metadata: %+v", source)
	}
	if string(source.ControlBytes) != `{"version":2}` || string(source.IdentityBytes) != `{"schema":"identity-state-v2"}` {
		t.Fatal("import source did not contain exact archive bytes")
	}
	telemetry, exists := store.documents[postgresstore.DomainRuntimeTelemetry]
	if !exists {
		t.Fatal("import did not initialize the reconstructible runtime telemetry document")
	}
	if state, err := runtimetelemetry.DecodeState(telemetry.Bytes); err != nil || len(state.Records) != 0 {
		t.Fatalf("initialized telemetry state=%#v err=%v", state, err)
	}
	result := decodeResult(t, &output)
	if result.Status != "imported" || result.ImportID != store.importResult.ImportID || result.ReceiptID != store.importResult.ReceiptID || result.ControlRevision != 1 || result.IdentityRevision != 1 || result.CapturedAt == nil || !result.CapturedAt.Equal(testCapturedAt) || result.ImportedAt == nil || !result.ImportedAt.Equal(testImportedAt) {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, forbidden := range []string{"version", "identity-state", "/private/", "mesh-storage/dev@unknown"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("output leaked %q: %s", forbidden, output.String())
		}
	}
}

func TestInitializeRuntimeTelemetryRequiresImportedPairAndIsIdempotent(t *testing.T) {
	archive, store := testState()
	delete(store.documents, postgresstore.DomainRuntimeTelemetry)
	var order []string
	deps := testDependencies(archive, store, &order)
	args := []string{"initialize-runtime-telemetry", "--postgres-dsn-file", "/private/postgres.dsn", "--allow-local-plaintext-postgres"}
	var output bytes.Buffer
	if err := run(context.Background(), args, &output, deps); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"build", "open-storage:/private/postgres.dsn", "import-ready",
		"initialize:runtime_telemetry", "read:runtime_telemetry", "import-ready", "read:runtime_telemetry", "close-storage",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order=%v, want %v", order, want)
	}
	result := decodeResult(t, &output)
	if result.Status != "runtime-telemetry-initialized" || !result.VerifiedAt.Equal(testVerifiedAt) || result.BackupID != "" {
		t.Fatalf("result=%+v", result)
	}

	order = nil
	output.Reset()
	if err := run(context.Background(), args, &output, deps); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if state, err := runtimetelemetry.DecodeState(store.documents[postgresstore.DomainRuntimeTelemetry].Bytes); err != nil || len(state.Records) != 0 {
		t.Fatalf("rerun telemetry state=%#v err=%v", state, err)
	}

	store.importReadinessErr = errors.New("import provenance unavailable")
	output.Reset()
	if err := run(context.Background(), args, &output, deps); err == nil || output.Len() != 0 {
		t.Fatalf("missing import provenance err=%v output=%q", err, output.String())
	}
}

func TestVerifyRequiresImportReadinessAndExactArchiveBytes(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	if err := run(context.Background(), backupArgs("verify"), &output, deps); err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"open-archive:" + strings.Repeat("a", 32), "build", "open-storage:/private/postgres.dsn",
		"import-ready", "read-pair", "validate", "import-ready", "read-pair", "validate", "read:runtime_telemetry",
		"close-storage", "clear-archive",
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order=%v, want %v", order, wantOrder)
	}
	if store.readinessCalls != 2 || archive.validateCalls != 2 || !archive.cleared {
		t.Fatalf("readiness=%d validation=%d cleared=%v", store.readinessCalls, archive.validateCalls, archive.cleared)
	}
	result := decodeResult(t, &output)
	if result.Status != "verified" || result.BackupID != strings.Repeat("a", 32) || result.ImportID != "" || result.ReceiptID != "" || result.ImportedAt != nil {
		t.Fatalf("unexpected verify result: %+v", result)
	}
}

func TestImportFailureClearsArchiveClosesStorageAndWritesNothing(t *testing.T) {
	archive, store := testState()
	store.schemaErr = errors.New("schema unavailable")
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("import-backup"), &output, deps)
	if err == nil || err.Error() != "schema unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"open-archive:" + strings.Repeat("a", 32), "build", "open-storage:/private/postgres.dsn",
		"schema-ready", "close-storage", "clear-archive",
	}
	if !reflect.DeepEqual(order, want) || !archive.cleared || output.Len() != 0 {
		t.Fatalf("order=%v cleared=%v output=%q", order, archive.cleared, output.String())
	}
}

func TestImportRejectsAuthoritativeRereadMismatch(t *testing.T) {
	archive, store := testState()
	store.documents[postgresstore.DomainControl] = testDocument(postgresstore.DomainControl, `{"version":2,"changed":true}`)
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("import-backup"), &output, deps)
	if err == nil || !strings.Contains(err.Error(), "authoritative reread") || !errors.Is(err, errImportVerifyRequired) {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
	if archive.validateCalls != 0 || !archive.cleared || output.Len() != 0 {
		t.Fatalf("mismatch validation=%d cleared=%v output=%q", archive.validateCalls, archive.cleared, output.String())
	}
}

func TestImportUncertainCommitRequiresVerifyBeforeRetry(t *testing.T) {
	archive, store := testState()
	store.importErr = postgresstore.ErrUncertainCommit
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("import-backup"), &output, deps)
	if !errors.Is(err, errImportVerifyRequired) || !errors.Is(err, postgresstore.ErrUncertainCommit) || !strings.Contains(err.Error(), "mesh-storage verify") {
		t.Fatalf("unexpected uncertain-import error: %v", err)
	}
	if !archive.cleared || output.Len() != 0 {
		t.Fatalf("cleared=%v output=%q", archive.cleared, output.String())
	}
}

func TestPostImportFailureRequiresVerifyBeforeRetry(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeStorage)
	}{
		{
			name: "readiness failure",
			setup: func(store *fakeStorage) {
				store.importReadinessErr = errors.New("readiness failed")
			},
		},
		{
			name: "concurrent document change",
			setup: func(store *fakeStorage) {
				store.onReadiness = func(call int) {
					if call == 1 {
						changed := testDocument(postgresstore.DomainControl, `{"version":2,"changed":true}`)
						changed.Revision = 2
						store.documents[postgresstore.DomainControl] = changed
					}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive, store := testState()
			test.setup(store)
			var order []string
			deps := testDependencies(archive, store, &order)
			var output bytes.Buffer
			err := run(context.Background(), backupArgs("import-backup"), &output, deps)
			if !errors.Is(err, errImportVerifyRequired) || !strings.Contains(err.Error(), "mesh-storage verify") {
				t.Fatalf("unexpected post-import error: %v", err)
			}
			if !archive.cleared || output.Len() != 0 {
				t.Fatalf("cleared=%v output=%q", archive.cleared, output.String())
			}
		})
	}
}

func TestVerifyRejectsDocumentChangeAcrossFinalConfirmation(t *testing.T) {
	archive, store := testState()
	store.onReadiness = func(call int) {
		if call == 2 {
			changed := testDocument(postgresstore.DomainIdentity, `{"schema":"identity-state-v2","changed":true}`)
			changed.Revision = 2
			store.documents[postgresstore.DomainIdentity] = changed
		}
	}
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("verify"), &output, deps)
	if err == nil || !strings.Contains(err.Error(), "changed during verification") || output.Len() != 0 {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
	if archive.validateCalls != 1 || !archive.cleared {
		t.Fatalf("validation=%d cleared=%v", archive.validateCalls, archive.cleared)
	}
}

func TestPostImportCloseFailureRequiresVerifyBeforeRetry(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	deps.openStorage = func(context.Context, storageOpenOptions) (*openedStorage, error) {
		return &openedStorage{store: store, close: func() error { return errors.New("close failed") }}, nil
	}
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("import-backup"), &output, deps)
	if !errors.Is(err, errImportVerifyRequired) || !strings.Contains(err.Error(), "close failed") || output.Len() != 0 {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}

func TestCloseFailureSuppressesSuccessOutput(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	deps.openStorage = func(context.Context, storageOpenOptions) (*openedStorage, error) {
		return &openedStorage{store: store, close: func() error { return errors.New("close failed") }}, nil
	}
	var output bytes.Buffer
	err := run(context.Background(), []string{"migrate", "--postgres-dsn-file", "/private/postgres.dsn"}, &output, deps)
	if err == nil || !strings.Contains(err.Error(), "close failed") || output.Len() != 0 {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}

func TestCommandFlagFencesAndNoArgumentSecretLeak(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	tests := [][]string{
		nil,
		{"unknown"},
		{"migrate"},
		{"migrate", "--postgres-dsn-file", "/private/postgres.dsn", "extra"},
		{"initialize-runtime-telemetry"},
		{"import-backup", "--postgres-dsn-file", "/private/postgres.dsn"},
		{"verify", "--password=do-not-print-this"},
		{"migrate", "--allow-local-plaintext-postgres=do-not-print-this"},
	}
	for _, args := range tests {
		var output bytes.Buffer
		err := run(context.Background(), args, &output, deps)
		if err == nil || output.Len() != 0 {
			t.Fatalf("args=%v err=%v output=%q", args, err, output.String())
		}
		if strings.Contains(err.Error(), "do-not-print-this") {
			t.Fatalf("argument secret leaked in error: %v", err)
		}
	}
}

func TestRunHonorsCanceledContext(t *testing.T) {
	archive, store := testState()
	var order []string
	deps := testDependencies(archive, store, &order)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := run(ctx, backupArgs("verify"), &output, deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context canceled", err)
	}
	if len(order) != 0 || output.Len() != 0 {
		t.Fatalf("canceled command performed work: order=%v output=%q", order, output.String())
	}
}

func TestCommandsRejectZeroCompletionClockWithoutSuccessOutput(t *testing.T) {
	t.Run("migrate", func(t *testing.T) {
		archive, store := testState()
		var order []string
		deps := testDependencies(archive, store, &order)
		deps.now = func() time.Time { return time.Time{} }
		var output bytes.Buffer
		err := run(context.Background(), []string{"migrate", "--postgres-dsn-file", "/private/postgres.dsn"}, &output, deps)
		want := []string{"build", "open-storage:/private/postgres.dsn", "migrate", "schema-ready", "close-storage"}
		if err == nil || !strings.Contains(err.Error(), "invalid time") || !reflect.DeepEqual(order, want) || output.Len() != 0 {
			t.Fatalf("err=%v order=%v output=%q", err, order, output.String())
		}
	})
	t.Run("import", func(t *testing.T) {
		archive, store := testState()
		var order []string
		deps := testDependencies(archive, store, &order)
		deps.now = func() time.Time { return time.Time{} }
		var output bytes.Buffer
		err := run(context.Background(), backupArgs("import-backup"), &output, deps)
		want := []string{
			"open-archive:" + strings.Repeat("a", 32), "build", "open-storage:/private/postgres.dsn",
			"schema-ready", "import", "read-pair", "validate", "import-ready",
			"initialize:runtime_telemetry", "read:runtime_telemetry", "read-pair", "validate", "read:runtime_telemetry",
			"close-storage", "clear-archive",
		}
		if err == nil || !strings.Contains(err.Error(), "invalid time") || !errors.Is(err, errImportVerifyRequired) || !reflect.DeepEqual(order, want) || !archive.cleared || output.Len() != 0 {
			t.Fatalf("err=%v order=%v cleared=%v output=%q", err, order, archive.cleared, output.String())
		}
	})
}

func TestImportRejectsZeroAuthenticatedCaptureTimeBeforeDatabaseWork(t *testing.T) {
	archive, store := testState()
	archive.meta.CapturedAt = time.Time{}
	var order []string
	deps := testDependencies(archive, store, &order)
	var output bytes.Buffer
	err := run(context.Background(), backupArgs("import-backup"), &output, deps)
	want := []string{"open-archive:" + strings.Repeat("a", 32), "clear-archive"}
	if err == nil || !strings.Contains(err.Error(), "capture time") || !reflect.DeepEqual(order, want) || !archive.cleared || output.Len() != 0 {
		t.Fatalf("err=%v order=%v cleared=%v output=%q", err, order, archive.cleared, output.String())
	}
}

func TestImporterBuildIsCanonicalAndBounded(t *testing.T) {
	value, err := importerBuild()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "mesh-storage/") || !strings.Contains(value, "@") || len(value) > postgresstore.MaxImporterBuildBytes || strings.ContainsAny(value, " \t\r\n") {
		t.Fatalf("non-canonical importer build %q", value)
	}
}

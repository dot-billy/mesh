package postgresstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const testWriteID = "123e4567-e89b-42d3-a456-426614174000"

var testCommittedAt = time.Date(2026, time.July, 19, 12, 0, 0, 123, time.UTC)

type rowFunc func(...any) error

func (f rowFunc) Scan(dest ...any) error { return f(dest...) }

type fakeRows struct {
	rows  [][]any
	index int
	err   error
}

func (r *fakeRows) Close()     {}
func (r *fakeRows) Err() error { return r.err }
func (r *fakeRows) Next() bool {
	if r.index >= len(r.rows) {
		return false
	}
	r.index++
	return true
}
func (r *fakeRows) Scan(dest ...any) error {
	if r.index == 0 || r.index > len(r.rows) {
		return errors.New("scan called without current row")
	}
	return assignRow(r.rows[r.index-1], dest)
}

type fakeTransaction struct {
	execFn     func(context.Context, string, ...any) (int64, error)
	queryFn    func(context.Context, string, ...any) (rowsScanner, error)
	queryRowFn func(context.Context, string, ...any) rowScanner
	commitFn   func(context.Context) error
	commitErr  error
	readOnly   string
	recovering bool
	commits    atomic.Int64
	rollbacks  atomic.Int64
}

func (t *fakeTransaction) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	if strings.Contains(query, "SET LOCAL search_path") {
		return 0, nil
	}
	if t.execFn == nil {
		return 0, fmt.Errorf("unexpected Exec: %s", query)
	}
	return t.execFn(ctx, query, args...)
}
func (t *fakeTransaction) Query(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	if t.queryFn == nil {
		return nil, fmt.Errorf("unexpected Query: %s", query)
	}
	return t.queryFn(ctx, query, args...)
}
func (t *fakeTransaction) QueryRow(ctx context.Context, query string, args ...any) rowScanner {
	if strings.Contains(query, "SHOW transaction_read_only") {
		mode := t.readOnly
		if mode == "" {
			mode = "off"
		}
		return valuesRow(mode)
	}
	if strings.Contains(query, "pg_is_in_recovery") {
		return valuesRow(t.recovering)
	}
	if t.queryRowFn == nil {
		return rowFunc(func(...any) error { return fmt.Errorf("unexpected QueryRow: %s", query) })
	}
	return t.queryRowFn(ctx, query, args...)
}
func (t *fakeTransaction) Commit(ctx context.Context) error {
	t.commits.Add(1)
	if t.commitFn != nil {
		return t.commitFn(ctx)
	}
	return t.commitErr
}
func (t *fakeTransaction) Rollback(context.Context) error {
	t.rollbacks.Add(1)
	return nil
}

type fakeDatabase struct {
	beginFn    func(context.Context) (transaction, error)
	queryFn    func(context.Context, string, ...any) (rowsScanner, error)
	queryRowFn func(context.Context, string, ...any) rowScanner
	begins     atomic.Int64
	closed     atomic.Bool
}

func (d *fakeDatabase) Begin(ctx context.Context) (transaction, error) {
	d.begins.Add(1)
	if d.beginFn == nil {
		return nil, errors.New("unexpected Begin")
	}
	return d.beginFn(ctx)
}
func (d *fakeDatabase) Ping(context.Context) error { return nil }
func (d *fakeDatabase) Query(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	if d.queryFn == nil {
		return nil, fmt.Errorf("unexpected Query: %s", query)
	}
	return d.queryFn(ctx, query, args...)
}
func (d *fakeDatabase) QueryRow(ctx context.Context, query string, args ...any) rowScanner {
	if d.queryRowFn == nil {
		return rowFunc(func(...any) error { return fmt.Errorf("unexpected QueryRow: %s", query) })
	}
	return d.queryRowFn(ctx, query, args...)
}
func (d *fakeDatabase) Close() { d.closed.Store(true) }

func TestUpdateInvokesCallbackExactlyOnceAndReturnsReceipt(t *testing.T) {
	body := []byte(`{"version":1}`)
	tx := updateTransaction(t, body, nil)
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	store.newWriteID = func() (string, error) { return testWriteID, nil }

	var calls atomic.Int64
	result, err := store.Update(context.Background(), DomainControl, "control.node.create", func(current []byte) ([]byte, error) {
		calls.Add(1)
		current[0] = '['
		return append(current, ']'), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("callback calls = %d, want 1", calls.Load())
	}
	if !result.Changed || result.Document.Revision != 2 || result.Receipt.BaseRevision != 1 || result.Receipt.CommittedRevision != 2 {
		t.Fatalf("unexpected write result: %+v", result)
	}
	if result.Receipt.ID != testWriteID || result.Document.LastWriteID != testWriteID {
		t.Fatalf("unexpected receipt ID: %+v", result)
	}
	if body[0] != '{' {
		t.Fatal("callback mutated the authoritative input buffer")
	}
	if tx.commits.Load() != 1 {
		t.Fatalf("commits = %d, want 1", tx.commits.Load())
	}
}

func TestUpdateNoOpCreatesNoReceiptOrRevision(t *testing.T) {
	body := []byte(`{"version":1}`)
	var queryRows atomic.Int64
	tx := &fakeTransaction{
		queryRowFn: func(_ context.Context, query string, _ ...any) rowScanner {
			queryRows.Add(1)
			if !strings.Contains(query, "FOR UPDATE") {
				t.Fatalf("query did not lock document row: %s", query)
			}
			return documentRow(DomainControl, 9, body, testWriteID, testCommittedAt)
		},
	}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	var calls atomic.Int64
	result, err := store.Update(context.Background(), DomainControl, "control.noop", func(current []byte) ([]byte, error) {
		calls.Add(1)
		return append([]byte(nil), current...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Document.Revision != 9 || result.Receipt.ID != "" {
		t.Fatalf("unexpected no-op result: %+v", result)
	}
	if calls.Load() != 1 || queryRows.Load() != 1 || tx.commits.Load() != 0 {
		t.Fatalf("calls=%d queryRows=%d commits=%d", calls.Load(), queryRows.Load(), tx.commits.Load())
	}
}

func TestUpdateRejectsCorruptCurrentBytesBeforeCallback(t *testing.T) {
	body := []byte(`{"version":1}`)
	tx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
		badHash := bytes.Repeat([]byte{0x7f}, sha256.Size)
		return valuesRow(string(DomainControl), int64(1), body, int64(len(body)), badHash, testWriteID, testCommittedAt)
	}}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	called := false
	_, err := store.Update(context.Background(), DomainControl, "control.change", func(current []byte) ([]byte, error) {
		called = true
		return current, nil
	})
	if !errors.Is(err, ErrCorruptDocument) {
		t.Fatalf("error = %v, want ErrCorruptDocument", err)
	}
	if called {
		t.Fatal("callback ran against corrupt current bytes")
	}
}

func TestAmbiguousCommitResolvedByExactReceipt(t *testing.T) {
	body := []byte(`{"version":1}`)
	commitFailure := errors.New("connection lost after commit")
	tx := updateTransaction(t, body, commitFailure)
	resolutionTx := &fakeTransaction{}
	db := &fakeDatabase{}
	var begins atomic.Int64
	db.beginFn = func(context.Context) (transaction, error) {
		if begins.Add(1) == 1 {
			return tx, nil
		}
		return resolutionTx, nil
	}
	store := testStore(t, db)
	store.newWriteID = func() (string, error) { return testWriteID, nil }
	next := []byte(`{"version":2}`)
	digest := sha256.Sum256(next)
	resolutionTx.queryRowFn = func(_ context.Context, query string, args ...any) rowScanner {
		if !strings.Contains(query, "mesh.mesh_write_receipt_documents") {
			t.Fatalf("unexpected resolution query: %s", query)
		}
		if len(args) != 2 || args[1] != DomainControl {
			t.Fatalf("receipt resolution did not bind domain: %#v", args)
		}
		return receiptRow("control.change", DomainControl, 1, 2, digest, testCommittedAt)
	}

	result, err := store.Update(context.Background(), DomainControl, "control.change", func([]byte) ([]byte, error) {
		return next, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Document.Revision != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, uncertain := store.UncertainWrite(); uncertain {
		t.Fatal("exact receipt should resolve ambiguous commit")
	}
}

func TestUnresolvedCommitPersistsAndFailsClosed(t *testing.T) {
	body := []byte(`{"version":1}`)
	tx := updateTransaction(t, body, errors.New("connection lost during commit"))
	resolutionTx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
		return rowFunc(func(...any) error { return pgx.ErrNoRows })
	}}
	db := &fakeDatabase{}
	var begins atomic.Int64
	db.beginFn = func(context.Context) (transaction, error) {
		if begins.Add(1) == 1 {
			return tx, nil
		}
		return resolutionTx, nil
	}
	store := testStore(t, db)
	store.newWriteID = func() (string, error) { return testWriteID, nil }

	_, err := store.Update(context.Background(), DomainControl, "control.change", func([]byte) ([]byte, error) {
		return []byte(`{"version":2}`), nil
	})
	if !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("error = %v, want ErrUncertainCommit", err)
	}
	uncertain, exists := store.UncertainWrite()
	if !exists || uncertain.ReceiptID != testWriteID || uncertain.TargetRevision != 2 {
		t.Fatalf("unexpected uncertain diagnostic: %+v, exists=%v", uncertain, exists)
	}
	beginCount := db.begins.Load()
	if err := store.CheckReadiness(context.Background()); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("readiness error = %v, want ErrUncertainCommit", err)
	}
	if _, err := store.Read(context.Background(), DomainControl); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("read error = %v, want ErrUncertainCommit", err)
	}
	blockedCallback := false
	if _, err := store.Update(context.Background(), DomainControl, "control.blocked", func(current []byte) ([]byte, error) {
		blockedCallback = true
		return current, nil
	}); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("update error = %v, want ErrUncertainCommit", err)
	}
	if blockedCallback {
		t.Fatal("callback ran after the store entered uncertain state")
	}
	if db.begins.Load() != beginCount {
		t.Fatal("fail-closed readiness opened another transaction")
	}
}

func TestCanceledContextBeforeCommitRollsBackDefinitely(t *testing.T) {
	body := []byte(`{"version":1}`)
	var stateQueries, writeExecs atomic.Int64
	tx := &fakeTransaction{
		queryRowFn: func(_ context.Context, query string, _ ...any) rowScanner {
			stateQueries.Add(1)
			if !strings.Contains(query, "FOR UPDATE") {
				t.Fatalf("update query did not use FOR UPDATE: %s", query)
			}
			return documentRow(DomainControl, 1, body, testWriteID, testCommittedAt)
		},
		execFn: func(context.Context, string, ...any) (int64, error) {
			writeExecs.Add(1)
			return 0, errors.New("write SQL must not run after callback cancellation")
		},
		commitErr: errors.New("Commit must not be called"),
	}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	var receiptIDs atomic.Int64
	store.newWriteID = func() (string, error) {
		receiptIDs.Add(1)
		return testWriteID, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := store.Update(ctx, DomainControl, "control.cancel", func([]byte) ([]byte, error) {
		cancel()
		return []byte(`{"version":2}`), nil
	})
	if !errors.Is(err, ErrNotCommitted) {
		t.Fatalf("error = %v, want ErrNotCommitted", err)
	}
	if tx.commits.Load() != 0 {
		t.Fatalf("Commit called %d times with an already-canceled context", tx.commits.Load())
	}
	if stateQueries.Load() != 1 || receiptIDs.Load() != 0 || writeExecs.Load() != 0 {
		t.Fatalf("canceled callback state_queries=%d receipt_ids=%d write_execs=%d", stateQueries.Load(), receiptIDs.Load(), writeExecs.Load())
	}
	if _, uncertain := store.UncertainWrite(); uncertain {
		t.Fatal("pre-commit cancellation must not set uncertain state")
	}
}

func TestCommitUsesBoundedDetachedContext(t *testing.T) {
	db := &fakeDatabase{}
	store := testStore(t, db)
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	tx := &fakeTransaction{}
	tx.commitFn = func(commitCtx context.Context) error {
		cancelRequest()
		if commitCtx.Err() != nil {
			t.Fatalf("commit context inherited request cancellation: %v", commitCtx.Err())
		}
		deadline, bounded := commitCtx.Deadline()
		if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Second {
			t.Fatalf("commit context deadline = %v, bounded=%v", deadline, bounded)
		}
		return nil
	}
	receipt := WriteReceipt{
		ID:                testWriteID,
		OperationClass:    "control.commit",
		Domain:            DomainControl,
		BaseRevision:      1,
		CommittedRevision: 2,
	}
	if err := store.commitWrite(requestCtx, tx, receipt); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("request context error = %v, want canceled", requestCtx.Err())
	}
}

func TestOpenDoesNotEchoPasswordBearingDSN(t *testing.T) {
	const secret = "do-not-return-this-password"
	_, err := Open(context.Background(), "postgres://mesh:"+secret+"@%zz/mesh", Options{})
	if err == nil {
		t.Fatal("invalid DSN unexpectedly parsed")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Open error disclosed DSN password: %v", err)
	}
}

func TestDefiniteCommitRollbackDoesNotSetUncertain(t *testing.T) {
	tx := updateTransaction(t, []byte(`{"version":1}`), pgx.ErrTxCommitRollback)
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	store.newWriteID = func() (string, error) { return testWriteID, nil }
	_, err := store.Update(context.Background(), DomainControl, "control.change", func([]byte) ([]byte, error) {
		return []byte(`{"version":2}`), nil
	})
	if !errors.Is(err, ErrNotCommitted) {
		t.Fatalf("error = %v, want ErrNotCommitted", err)
	}
	if _, uncertain := store.UncertainWrite(); uncertain {
		t.Fatal("definite rollback must not set uncertain state")
	}
}

func TestValidationPrecedesMutationAndDatabaseAccess(t *testing.T) {
	db := &fakeDatabase{}
	store := testStore(t, db)
	called := false
	_, err := store.Update(context.Background(), Domain("other"), "control.change", func([]byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, ErrInvalidDomain) || called || db.begins.Load() != 0 {
		t.Fatalf("invalid domain: err=%v called=%v begins=%d", err, called, db.begins.Load())
	}
	_, err = store.Update(context.Background(), DomainControl, "INVALID", func([]byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, ErrInvalidOperation) || called || db.begins.Load() != 0 {
		t.Fatalf("invalid operation: err=%v called=%v begins=%d", err, called, db.begins.Load())
	}
	tooLarge := make([]byte, MaxIdentityDocumentBytes+1)
	if _, err := store.Initialize(context.Background(), DomainIdentity, tooLarge); err == nil || db.begins.Load() != 0 {
		t.Fatalf("oversized initialize: err=%v begins=%d", err, db.begins.Load())
	}
}

func TestAuthoritativeReadsAndMutationsRejectReadOnlyEndpoint(t *testing.T) {
	tx := &fakeTransaction{readOnly: "on"}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	if _, err := store.Read(context.Background(), DomainControl); !errors.Is(err, ErrUnwritablePrimary) {
		t.Fatalf("read error = %v, want ErrUnwritablePrimary", err)
	}
	called := false
	if _, err := store.Update(context.Background(), DomainControl, "control.change", func(current []byte) ([]byte, error) {
		called = true
		return current, nil
	}); !errors.Is(err, ErrUnwritablePrimary) {
		t.Fatalf("update error = %v, want ErrUnwritablePrimary", err)
	}
	if called {
		t.Fatal("mutation callback ran on a read-only endpoint")
	}
}

func TestReadPairUsesOneMVCCCommandSnapshotAndDetachedBytes(t *testing.T) {
	controlBody := []byte(`{"version":2}`)
	identityBody := []byte(`{"schema":"identity-state-v2"}`)
	controlHash := sha256.Sum256(controlBody)
	identityHash := sha256.Sum256(identityBody)
	var pairQueries atomic.Int64
	tx := &fakeTransaction{
		queryRowFn: func(_ context.Context, query string, args ...any) rowScanner {
			pairQueries.Add(1)
			if !strings.Contains(query, "CROSS JOIN") || !strings.Contains(query, "control.document_key = $1") || !strings.Contains(query, "identity.document_key = $2") {
				t.Fatalf("paired read was not one bounded join statement: %s", query)
			}
			wantArgs := []any{DomainControl, DomainIdentity, MaxControlDocumentBytes, MaxIdentityDocumentBytes}
			if !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("paired read args=%v, want %v", args, wantArgs)
			}
			return valuesRow(
				string(DomainControl), int64(3), controlBody, int64(len(controlBody)), controlHash[:], testWriteID, testCommittedAt,
				string(DomainIdentity), int64(5), identityBody, int64(len(identityBody)), identityHash[:], testWriteID, testCommittedAt,
			)
		},
	}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	control, identity, err := store.ReadPair(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pairQueries.Load() != 1 || control.Revision != 3 || identity.Revision != 5 || !bytes.Equal(control.Bytes, controlBody) || !bytes.Equal(identity.Bytes, identityBody) {
		t.Fatalf("pair queries=%d control=%+v identity=%+v", pairQueries.Load(), control, identity)
	}
	control.Bytes[0] ^= 1
	identity.Bytes[0] ^= 1
	if controlBody[0] != '{' || identityBody[0] != '{' {
		t.Fatal("paired read returned backend-owned byte aliases")
	}
}

func TestReadPairRejectsMissingOrCorruptDocument(t *testing.T) {
	t.Run("missing pair", func(t *testing.T) {
		tx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
			return rowFunc(func(...any) error { return pgx.ErrNoRows })
		}}
		store := testStore(t, &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }})
		if _, _, err := store.ReadPair(context.Background()); !errors.Is(err, ErrNotInitialized) {
			t.Fatalf("got %v, want ErrNotInitialized", err)
		}
	})
	t.Run("corrupt identity digest", func(t *testing.T) {
		controlBody := []byte(`{"version":2}`)
		identityBody := []byte(`{"schema":"identity-state-v2"}`)
		controlHash := sha256.Sum256(controlBody)
		badHash := bytes.Repeat([]byte{0x41}, sha256.Size)
		tx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
			return valuesRow(
				string(DomainControl), int64(1), controlBody, int64(len(controlBody)), controlHash[:], testWriteID, testCommittedAt,
				string(DomainIdentity), int64(1), identityBody, int64(len(identityBody)), badHash, testWriteID, testCommittedAt,
			)
		}}
		store := testStore(t, &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }})
		if _, _, err := store.ReadPair(context.Background()); !errors.Is(err, ErrCorruptDocument) {
			t.Fatalf("got %v, want ErrCorruptDocument", err)
		}
	})
}

func TestDocumentInitializationLocksCoverEverySupportedDomain(t *testing.T) {
	seen := make(map[int64]Domain)
	for _, domain := range []Domain{DomainControl, DomainIdentity, DomainRuntimeTelemetry} {
		key, err := documentInitializationLockKey(domain)
		if err != nil {
			t.Fatalf("domain %q: %v", domain, err)
		}
		if previous, exists := seen[key]; exists {
			t.Fatalf("domains %q and %q share initialization lock %d", previous, domain, key)
		}
		seen[key] = domain
	}
	if _, err := documentInitializationLockKey(Domain("unsupported")); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("unsupported domain error = %v", err)
	}
}

func TestGenerateUUIDIsCanonicalVersion4(t *testing.T) {
	for range 128 {
		value, err := generateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !validCanonicalUUID(value) || value[14] != '4' || !strings.Contains("89ab", value[19:20]) {
			t.Fatalf("invalid UUIDv4 %q", value)
		}
	}
}

func TestStoreCloseDoesNotCloseCallerPoolBackend(t *testing.T) {
	db := &fakeDatabase{}
	store, err := newStore(db, false, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if db.closed.Load() {
		t.Fatal("caller-owned database was closed")
	}
	if _, err := store.Read(context.Background(), DomainControl); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after Close = %v, want ErrClosed", err)
	}
}

func updateTransaction(t *testing.T, currentBody []byte, commitErr error) *fakeTransaction {
	t.Helper()
	var queryRows atomic.Int64
	return &fakeTransaction{
		queryRowFn: func(_ context.Context, query string, _ ...any) rowScanner {
			switch queryRows.Add(1) {
			case 1:
				if !strings.Contains(query, "FOR UPDATE") {
					t.Fatalf("update query did not use FOR UPDATE: %s", query)
				}
				return documentRow(DomainControl, 1, currentBody, testWriteID, testCommittedAt)
			case 2:
				if !strings.Contains(query, "INSERT INTO mesh.mesh_write_receipts") {
					t.Fatalf("unexpected second query: %s", query)
				}
				return valuesRow(testCommittedAt)
			default:
				return rowFunc(func(...any) error { return errors.New("unexpected transaction QueryRow") })
			}
		},
		execFn: func(_ context.Context, query string, _ ...any) (int64, error) {
			if !strings.Contains(query, "mesh.mesh_state_documents") && !strings.Contains(query, "mesh.mesh_write_receipt_documents") {
				t.Fatalf("unexpected update Exec: %s", query)
			}
			return 1, nil
		},
		commitErr: commitErr,
	}
}

func testStore(t *testing.T, db database) *Store {
	t.Helper()
	store, err := newStore(db, false, Options{CommitTimeout: time.Second, CommitResolutionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func documentRow(domain Domain, revision int64, body []byte, receiptID string, updatedAt time.Time) rowScanner {
	digest := sha256.Sum256(body)
	return valuesRow(string(domain), revision, append([]byte(nil), body...), int64(len(body)), digest[:], receiptID, updatedAt)
}

func receiptRow(operation string, domain Domain, base, committed int64, digest [sha256.Size]byte, committedAt time.Time) rowScanner {
	return valuesRow(operation, string(domain), base, committed, digest[:], committedAt)
}

func valuesRow(values ...any) rowScanner {
	return rowFunc(func(dest ...any) error { return assignRow(values, dest) })
}

func assignRow(values []any, dest []any) error {
	if len(values) != len(dest) {
		return fmt.Errorf("value count %d does not match destination count %d", len(values), len(dest))
	}
	for i, value := range values {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		case *int:
			*target = value.(int)
		case *int64:
			*target = value.(int64)
		case *[]byte:
			*target = append((*target)[:0], value.([]byte)...)
		case *time.Time:
			*target = value.(time.Time)
		case *bool:
			*target = value.(bool)
		default:
			return fmt.Errorf("unsupported scan destination %T at %d", dest[i], i)
		}
	}
	return nil
}

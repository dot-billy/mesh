//go:build !windows

package postgresstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"mesh/internal/postgresconfig"
)

const (
	ambiguousPrimaryDSNEnv   = "MESH_POSTGRES_AMBIGUOUS_PRIMARY_DSN_FILE"
	ambiguousStandbyDSNEnv   = "MESH_POSTGRES_AMBIGUOUS_STANDBY_DSN_FILE"
	ambiguousDivergentDSNEnv = "MESH_POSTGRES_AMBIGUOUS_DIVERGENT_DSN_FILE"
	ambiguousPhaseEnv        = "MESH_POSTGRES_AMBIGUOUS_PHASE_FILE"
	ambiguousResumeEnv       = "MESH_POSTGRES_AMBIGUOUS_RESUME_FILE"
)

var (
	errInjectedPreCommitDisconnect = errors.New("injected connection loss before commit reached PostgreSQL")
	errInjectedLostAcknowledgment  = errors.New("injected connection loss after PostgreSQL committed")
)

// TestPostgresAmbiguousCommitIntegration is intentionally dormant unless the
// five private-path environment variables above are set. The companion smoke
// script owns its disposable PostgreSQL authorities and coordinates one hard
// synchronous-standby promotion through the phase and resume files.
//
// All injected behavior is confined to this _test.go file. Production Store
// construction and commit behavior have no fault hooks.
func TestPostgresAmbiguousCommitIntegration(t *testing.T) {
	primaryPath, standbyPath, divergentPath, phasePath, resumePath := ambiguousIntegrationPaths(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	primaryConfig := loadAmbiguousPoolConfig(t, primaryPath)
	standbyConfig := loadAmbiguousPoolConfig(t, standbyPath)
	divergentConfig := loadAmbiguousPoolConfig(t, divergentPath)

	primaryPool := openAmbiguousPool(t, ctx, primaryConfig, "primary")
	defer primaryPool.Close()
	divergentPool := openAmbiguousPool(t, ctx, divergentConfig, "divergent authority")
	defer divergentPool.Close()

	requireEmptyMeshSchema(t, ctx, primaryPool, "primary")
	requireEmptyMeshSchema(t, ctx, divergentPool, "divergent authority")

	primaryStore := prepareAmbiguousStore(t, ctx, primaryPool, "primary")
	defer primaryStore.Close()
	divergentStore := prepareAmbiguousStore(t, ctx, divergentPool, "divergent authority")
	defer divergentStore.Close()

	primarySystemID, primaryTimeline := readAuthorityIdentity(t, ctx, primaryPool, "primary")
	divergentSystemID, _ := readAuthorityIdentity(t, ctx, divergentPool, "divergent authority")
	if primarySystemID == divergentSystemID {
		t.Fatal("primary and divergent PostgreSQL authorities unexpectedly share one system identifier")
	}

	t.Run("definite cancellation before commit", func(t *testing.T) {
		before := mustReadAmbiguousDocument(t, ctx, primaryStore)
		beforeReceipts := countAmbiguousReceipts(t, ctx, primaryPool)
		requestCtx, cancelRequest := context.WithCancel(ctx)
		var callbacks atomic.Int64
		_, err := primaryStore.Update(requestCtx, DomainControl, "smoke.cancel_before_commit", func(current []byte) ([]byte, error) {
			callbacks.Add(1)
			cancelRequest()
			return incrementAmbiguousCounter(current)
		})
		if !errors.Is(err, ErrNotCommitted) {
			t.Fatalf("canceled pre-commit update error type = %T, want ErrNotCommitted", err)
		}
		if callbacks.Load() != 1 {
			t.Fatalf("canceled pre-commit callback calls = %d, want 1", callbacks.Load())
		}
		assertAmbiguousDocumentUnchanged(t, ctx, primaryStore, before)
		if after := countAmbiguousReceipts(t, ctx, primaryPool); after != beforeReceipts {
			t.Fatalf("canceled pre-commit receipt count = %d, want %d", after, beforeReceipts)
		}
		if _, uncertain := primaryStore.UncertainWrite(); uncertain {
			t.Fatal("definite cancellation marked the store uncertain")
		}
	})

	t.Run("transport loss before commit stays uncertain", func(t *testing.T) {
		before := mustReadAmbiguousDocument(t, ctx, primaryStore)
		beforeReceipts := countAmbiguousReceipts(t, ctx, primaryPool)
		db := newInjectedDatabase(
			&poolDatabase{pool: primaryPool},
			&poolDatabase{pool: primaryPool},
			injectedRollbackThenDisconnect,
			nil,
		)
		faultedStore := newAmbiguousTestStore(t, db)
		defer faultedStore.Close()
		var callbacks atomic.Int64
		_, err := faultedStore.Update(ctx, DomainControl, "smoke.disconnect_before_commit", func(current []byte) ([]byte, error) {
			callbacks.Add(1)
			return incrementAmbiguousCounter(current)
		})
		if !errors.Is(err, ErrUncertainCommit) {
			t.Fatalf("pre-commit transport-loss error type = %T, want ErrUncertainCommit", err)
		}
		if callbacks.Load() != 1 {
			t.Fatalf("pre-commit transport-loss callback calls = %d, want 1", callbacks.Load())
		}
		assertAmbiguousStoreGated(t, ctx, faultedStore)
		assertAmbiguousDocumentUnchanged(t, ctx, primaryStore, before)
		if after := countAmbiguousReceipts(t, ctx, primaryPool); after != beforeReceipts {
			t.Fatalf("rolled-back transport-loss receipt count = %d, want %d", after, beforeReceipts)
		}
	})

	var promotedPool *pgxpool.Pool
	t.Run("lost acknowledgment resolves after synchronous promotion", func(t *testing.T) {
		before := mustReadAmbiguousDocument(t, ctx, primaryStore)
		next, err := incrementAmbiguousCounter(before.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		nextDigest := sha256.Sum256(next)

		var db *injectedDatabase
		afterCommit := func(commitCtx context.Context) error {
			if err := createAmbiguousPhaseFile(phasePath); err != nil {
				return err
			}
			if err := waitForAmbiguousResume(commitCtx, resumePath); err != nil {
				return err
			}

			pool, err := newAmbiguousPool(commitCtx, standbyConfig)
			if err != nil {
				return fmt.Errorf("open fresh promoted-standby pool: %w", err)
			}
			closePool := true
			defer func() {
				if closePool {
					pool.Close()
				}
			}()
			if err := pingAmbiguousPool(commitCtx, pool); err != nil {
				return fmt.Errorf("ping promoted standby: %w", err)
			}
			promotedSystemID, promotedTimeline, err := queryAuthorityIdentity(commitCtx, pool)
			if err != nil {
				return fmt.Errorf("inspect promoted authority identity: %w", err)
			}
			if promotedSystemID != primarySystemID {
				return errors.New("promoted standby changed PostgreSQL system identifier")
			}
			if promotedTimeline <= primaryTimeline {
				return fmt.Errorf("promoted timeline %d did not advance beyond %d", promotedTimeline, primaryTimeline)
			}
			if err := requireWritableAuthority(commitCtx, pool); err != nil {
				return fmt.Errorf("promoted standby is not writable: %w", err)
			}
			if err := requireExactCurrentReceipt(commitCtx, pool, before.Revision+1, nextDigest); err != nil {
				return fmt.Errorf("promoted standby lacks exact committed receipt: %w", err)
			}
			db.setResolution(&poolDatabase{pool: pool})
			promotedPool = pool
			closePool = false
			return nil
		}

		db = newInjectedDatabase(
			&poolDatabase{pool: primaryPool},
			nil,
			injectedCommitThenLoseAcknowledgment,
			afterCommit,
		)
		faultedStore := newAmbiguousTestStore(t, db)
		defer faultedStore.Close()
		var callbacks atomic.Int64
		result, err := faultedStore.Update(ctx, DomainControl, "smoke.ack_loss_across_promotion", func(current []byte) ([]byte, error) {
			callbacks.Add(1)
			return incrementAmbiguousCounter(current)
		})
		if err != nil {
			t.Fatalf("exact promoted receipt did not resolve lost acknowledgment: %T", err)
		}
		if callbacks.Load() != 1 {
			t.Fatalf("lost-ack callback calls = %d, want 1", callbacks.Load())
		}
		if !result.Changed || result.Document.Revision != before.Revision+1 || result.Document.SHA256 != nextDigest {
			t.Fatalf("resolved write returned unexpected revision/digest: changed=%v revision=%d", result.Changed, result.Document.Revision)
		}
		if _, uncertain := faultedStore.UncertainWrite(); uncertain {
			t.Fatal("an exact promoted receipt left the store uncertain")
		}
		if err := faultedStore.CheckReadiness(ctx); err != nil {
			t.Fatalf("resolved store readiness failed: %T", err)
		}

		var freshCallbacks atomic.Int64
		fresh, err := faultedStore.Update(ctx, DomainControl, "smoke.after_exact_resolution", func(current []byte) ([]byte, error) {
			freshCallbacks.Add(1)
			return incrementAmbiguousCounter(current)
		})
		if err != nil {
			t.Fatalf("fresh write after exact resolution failed: %T", err)
		}
		if freshCallbacks.Load() != 1 || !fresh.Changed || fresh.Document.Revision != before.Revision+2 {
			t.Fatalf("fresh post-resolution write callbacks=%d changed=%v revision=%d", freshCallbacks.Load(), fresh.Changed, fresh.Document.Revision)
		}
	})
	if promotedPool == nil {
		t.Fatal("promotion subtest did not retain its freshly verified resolution pool")
	}
	defer promotedPool.Close()

	t.Run("changed authority with missing receipt stays uncertain", func(t *testing.T) {
		promotedStore, err := New(promotedPool, Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer promotedStore.Close()
		before := mustReadAmbiguousDocument(t, ctx, promotedStore)
		divergentBefore := mustReadAmbiguousDocument(t, ctx, divergentStore)

		var db *injectedDatabase
		afterCommit := func(commitCtx context.Context) error {
			committed, err := readAmbiguousDocument(commitCtx, promotedPool)
			if err != nil {
				return fmt.Errorf("read committed write on promoted authority: %w", err)
			}
			if committed.Revision != before.Revision+1 || committed.LastWriteID == before.LastWriteID {
				return errors.New("promoted authority did not retain the injected commit")
			}
			if err := requireWritableAuthority(commitCtx, divergentPool); err != nil {
				return fmt.Errorf("divergent resolution authority is not writable: %w", err)
			}
			resolutionSystemID, _, err := queryAuthorityIdentity(commitCtx, divergentPool)
			if err != nil {
				return fmt.Errorf("inspect divergent resolution authority: %w", err)
			}
			if resolutionSystemID == primarySystemID {
				return errors.New("divergent resolution route did not change PostgreSQL authority")
			}
			var receiptCount int64
			if err := divergentPool.QueryRow(commitCtx, `
SELECT pg_catalog.count(*)
FROM mesh.mesh_write_receipts
WHERE receipt_id = $1::uuid`, committed.LastWriteID).Scan(&receiptCount); err != nil {
				return fmt.Errorf("inspect divergent receipt absence: %w", err)
			}
			if receiptCount != 0 {
				return errors.New("divergent authority unexpectedly contained the attempted receipt")
			}
			db.setResolution(&poolDatabase{pool: divergentPool})
			return nil
		}

		db = newInjectedDatabase(
			&poolDatabase{pool: promotedPool},
			nil,
			injectedCommitThenLoseAcknowledgment,
			afterCommit,
		)
		faultedStore := newAmbiguousTestStore(t, db)
		defer faultedStore.Close()
		var callbacks atomic.Int64
		_, err = faultedStore.Update(ctx, DomainControl, "smoke.ack_loss_changed_authority", func(current []byte) ([]byte, error) {
			callbacks.Add(1)
			return incrementAmbiguousCounter(current)
		})
		if !errors.Is(err, ErrUncertainCommit) {
			t.Fatalf("changed-authority resolution error type = %T, want ErrUncertainCommit", err)
		}
		if callbacks.Load() != 1 {
			t.Fatalf("changed-authority callback calls = %d, want 1", callbacks.Load())
		}
		assertAmbiguousStoreGated(t, ctx, faultedStore)

		committed := mustReadAmbiguousDocument(t, ctx, promotedStore)
		if committed.Revision != before.Revision+1 {
			t.Fatalf("actual committed authority revision = %d, want %d", committed.Revision, before.Revision+1)
		}
		assertAmbiguousDocumentUnchanged(t, ctx, divergentStore, divergentBefore)
	})
}

type injectedCommitMode uint8

const (
	injectedRollbackThenDisconnect injectedCommitMode = iota + 1
	injectedCommitThenLoseAcknowledgment
)

type injectedDatabase struct {
	write       database
	mode        injectedCommitMode
	afterCommit func(context.Context) error

	wrapped atomic.Bool
	faulted atomic.Bool
	mu      sync.RWMutex
	resolve database
}

func newInjectedDatabase(write, resolve database, mode injectedCommitMode, afterCommit func(context.Context) error) *injectedDatabase {
	return &injectedDatabase{write: write, resolve: resolve, mode: mode, afterCommit: afterCommit}
}

func (d *injectedDatabase) setResolution(resolve database) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolve = resolve
}

func (d *injectedDatabase) current() (database, error) {
	if !d.faulted.Load() {
		return d.write, nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.resolve == nil {
		return nil, errors.New("injected resolution authority is unavailable")
	}
	return d.resolve, nil
}

func (d *injectedDatabase) Begin(ctx context.Context) (transaction, error) {
	current, err := d.current()
	if err != nil {
		return nil, err
	}
	tx, err := current.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if !d.faulted.Load() && d.wrapped.CompareAndSwap(false, true) {
		return &injectedTransaction{transaction: tx, owner: d}, nil
	}
	return tx, nil
}

func (d *injectedDatabase) Ping(ctx context.Context) error {
	current, err := d.current()
	if err != nil {
		return err
	}
	return current.Ping(ctx)
}

func (d *injectedDatabase) Query(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	current, err := d.current()
	if err != nil {
		return nil, err
	}
	return current.Query(ctx, query, args...)
}

func (d *injectedDatabase) QueryRow(ctx context.Context, query string, args ...any) rowScanner {
	current, err := d.current()
	if err != nil {
		return rowFunc(func(...any) error { return err })
	}
	return current.QueryRow(ctx, query, args...)
}

func (d *injectedDatabase) Close() {}

type injectedTransaction struct {
	transaction
	owner *injectedDatabase
}

func (tx *injectedTransaction) Commit(ctx context.Context) error {
	switch tx.owner.mode {
	case injectedRollbackThenDisconnect:
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := tx.transaction.Rollback(rollbackCtx); err != nil {
			return err
		}
		tx.owner.faulted.Store(true)
		return errInjectedPreCommitDisconnect
	case injectedCommitThenLoseAcknowledgment:
		if err := tx.transaction.Commit(ctx); err != nil {
			return err
		}
		if tx.owner.afterCommit != nil {
			if err := tx.owner.afterCommit(ctx); err != nil {
				tx.owner.faulted.Store(true)
				return fmt.Errorf("post-commit injection coordination failed: %w", err)
			}
		}
		tx.owner.faulted.Store(true)
		return errInjectedLostAcknowledgment
	default:
		return errors.New("invalid injected commit mode")
	}
}

func ambiguousIntegrationPaths(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	names := []string{
		ambiguousPrimaryDSNEnv,
		ambiguousStandbyDSNEnv,
		ambiguousDivergentDSNEnv,
		ambiguousPhaseEnv,
		ambiguousResumeEnv,
	}
	values := make([]string, len(names))
	set := 0
	for i, name := range names {
		values[i] = os.Getenv(name)
		if values[i] != "" {
			set++
		}
	}
	if set == 0 {
		t.Skip("PostgreSQL ambiguous-commit smoke paths are not set")
	}
	if set != len(names) {
		t.Fatal("PostgreSQL ambiguous-commit smoke paths are only partially configured")
	}
	for i, value := range values {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
			t.Fatalf("%s is not a clean absolute path", names[i])
		}
	}
	for _, path := range values[3:] {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("coordination path must start absent: %s", filepath.Base(path))
		}
		requirePrivateDirectory(t, filepath.Dir(path))
	}
	return values[0], values[1], values[2], values[3], values[4]
}

func requirePrivateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect coordination directory: %T", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("coordination directory is not a private owner-controlled real directory")
	}
}

func loadAmbiguousPoolConfig(t *testing.T, path string) *pgxpool.Config {
	t.Helper()
	config, err := postgresconfig.LoadFile(path, postgresconfig.Options{
		Transport:   postgresconfig.AllowLocalPlaintext,
		PingTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("load private PostgreSQL configuration: %T", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConns = 4
	return config
}

func openAmbiguousPool(t *testing.T, ctx context.Context, config *pgxpool.Config, label string) *pgxpool.Pool {
	t.Helper()
	pool, err := newAmbiguousPool(ctx, config)
	if err != nil {
		t.Fatalf("open %s pool: %T", label, err)
	}
	if err := pingAmbiguousPool(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("ping %s pool: %T", label, err)
	}
	return pool
}

func newAmbiguousPool(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	return pgxpool.NewWithConfig(ctx, config.Copy())
}

func pingAmbiguousPool(ctx context.Context, pool *pgxpool.Pool) error {
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return pool.Ping(pingCtx)
}

func requireEmptyMeshSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace('mesh') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("inspect %s Mesh schema: %T", label, err)
	}
	if exists {
		t.Fatalf("refusing nonempty %s: dedicated schema mesh already exists", label)
	}
}

func prepareAmbiguousStore(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) *Store {
	t.Helper()
	store, err := New(pool, Options{MigrationBuild: "ambiguous-commit-smoke"})
	if err != nil {
		t.Fatalf("construct %s store: %T", label, err)
	}
	if err := store.Migrate(ctx); err != nil {
		store.Close()
		t.Fatalf("migrate %s store: %T", label, err)
	}
	if _, err := store.Initialize(ctx, DomainControl, []byte("0\n")); err != nil {
		store.Close()
		t.Fatalf("initialize %s control document: %T", label, err)
	}
	if _, err := store.Initialize(ctx, DomainIdentity, []byte("identity-state-v2\n")); err != nil {
		store.Close()
		t.Fatalf("initialize %s identity document: %T", label, err)
	}
	if err := store.CheckReadiness(ctx); err != nil {
		store.Close()
		t.Fatalf("verify %s store readiness: %T", label, err)
	}
	return store
}

func newAmbiguousTestStore(t *testing.T, db database) *Store {
	t.Helper()
	store, err := newStore(db, false, Options{
		MigrationBuild:          "ambiguous-commit-smoke",
		CommitTimeout:           2 * time.Minute,
		CommitResolutionTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func incrementAmbiguousCounter(current []byte) ([]byte, error) {
	value, err := strconv.Atoi(strings.TrimSpace(string(current)))
	if err != nil {
		return nil, errors.New("control counter is invalid")
	}
	return []byte(strconv.Itoa(value+1) + "\n"), nil
}

func mustReadAmbiguousDocument(t *testing.T, ctx context.Context, store *Store) Document {
	t.Helper()
	document, err := store.Read(ctx, DomainControl)
	if err != nil {
		t.Fatalf("read control document: %T", err)
	}
	return document
}

func readAmbiguousDocument(ctx context.Context, pool *pgxpool.Pool) (Document, error) {
	store, err := New(pool, Options{})
	if err != nil {
		return Document{}, err
	}
	defer store.Close()
	return store.Read(ctx, DomainControl)
}

func assertAmbiguousDocumentUnchanged(t *testing.T, ctx context.Context, store *Store, before Document) {
	t.Helper()
	after := mustReadAmbiguousDocument(t, ctx, store)
	if after.Revision != before.Revision || after.LastWriteID != before.LastWriteID || after.SHA256 != before.SHA256 || !bytes.Equal(after.Bytes, before.Bytes) {
		t.Fatalf("control document changed: revision %d -> %d", before.Revision, after.Revision)
	}
}

func countAmbiguousReceipts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts`).Scan(&count); err != nil {
		t.Fatalf("count write receipts: %T", err)
	}
	return count
}

func assertAmbiguousStoreGated(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	uncertain, exists := store.UncertainWrite()
	if !exists || uncertain.ReceiptID == "" || uncertain.BaseRevision < 1 || uncertain.TargetRevision != uncertain.BaseRevision+1 {
		t.Fatalf("uncertain write diagnostic is incomplete: exists=%v base=%d target=%d", exists, uncertain.BaseRevision, uncertain.TargetRevision)
	}
	if err := store.CheckReadiness(ctx); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("readiness error type = %T, want ErrUncertainCommit", err)
	}
	if _, err := store.Read(ctx, DomainControl); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("read error type = %T, want ErrUncertainCommit", err)
	}
	var blockedCallbacks atomic.Int64
	if _, err := store.Update(ctx, DomainControl, "smoke.blocked_after_uncertainty", func(current []byte) ([]byte, error) {
		blockedCallbacks.Add(1)
		return incrementAmbiguousCounter(current)
	}); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("blocked update error type = %T, want ErrUncertainCommit", err)
	}
	if blockedCallbacks.Load() != 0 {
		t.Fatal("mutation callback ran after the store entered uncertain state")
	}
}

func readAuthorityIdentity(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) (string, int64) {
	t.Helper()
	systemID, timeline, err := queryAuthorityIdentity(ctx, pool)
	if err != nil {
		t.Fatalf("inspect %s authority identity: %T", label, err)
	}
	return systemID, timeline
}

func queryAuthorityIdentity(ctx context.Context, pool *pgxpool.Pool) (string, int64, error) {
	var systemID string
	var timeline int64
	err := pool.QueryRow(ctx, `
SELECT system_identifier::text, timeline_id::bigint
FROM pg_catalog.pg_control_system(), pg_catalog.pg_control_checkpoint()`).Scan(&systemID, &timeline)
	return systemID, timeline, err
}

func requireWritableAuthority(ctx context.Context, pool *pgxpool.Pool) error {
	var readOnly string
	var recovering bool
	if err := pool.QueryRow(ctx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.pg_is_in_recovery()`).Scan(&recovering); err != nil {
		return err
	}
	if readOnly != "off" || recovering {
		return fmt.Errorf("transaction_read_only=%q recovering=%v", readOnly, recovering)
	}
	return nil
}

func requireExactCurrentReceipt(ctx context.Context, pool *pgxpool.Pool, revision int64, digest [sha256.Size]byte) error {
	var (
		actualRevision int64
		documentHash   []byte
		receiptHash    []byte
		baseRevision   int64
		receiptTarget  int64
	)
	err := pool.QueryRow(ctx, `
SELECT d.revision,
       d.document_sha256,
       i.document_sha256,
       i.base_revision,
       i.committed_revision
FROM mesh.mesh_state_documents AS d
JOIN mesh.mesh_write_receipt_documents AS i
  ON i.receipt_id = d.last_write_receipt
 AND i.document_key = d.document_key
WHERE d.document_key = $1`, DomainControl).Scan(
		&actualRevision,
		&documentHash,
		&receiptHash,
		&baseRevision,
		&receiptTarget,
	)
	if err != nil {
		return err
	}
	if actualRevision != revision || baseRevision != revision-1 || receiptTarget != revision ||
		!bytes.Equal(documentHash, digest[:]) || !bytes.Equal(receiptHash, digest[:]) {
		return errors.New("current document and receipt do not match the expected revision and digest")
	}
	return nil
}

func createAmbiguousPhaseFile(path string) error {
	temporary := path + ".publishing"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create promotion phase temporary file: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.Remove(temporary)
		}
	}()
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if _, err := file.WriteString("remote_apply_commit_durable\n"); err != nil {
		return fmt.Errorf("write promotion phase file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync promotion phase file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close promotion phase file: %w", err)
	}
	closeFile = false
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open promotion phase directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync promotion phase temporary file directory: %w", err)
	}
	// A hard link publishes the already-synced inode atomically and refuses to
	// replace an existing final path. The reader tolerates the brief two-link
	// interval until the private sibling is removed and the directory is synced.
	if err := os.Link(temporary, path); err != nil {
		return fmt.Errorf("publish promotion phase file without replacement: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync published promotion phase directory: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		return fmt.Errorf("remove promotion phase temporary link: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync promotion phase directory: %w", err)
	}
	published = true
	return nil
}

func waitForAmbiguousResume(ctx context.Context, path string) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) {
				return errors.New("promotion resume file is not a private owner-controlled single-link regular file")
			}
			if stat.Nlink == 2 {
				break
			}
			if stat.Nlink != 1 {
				return errors.New("promotion resume file has an invalid link count")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read promotion resume file: %w", err)
			}
			if string(raw) != "promoted_writable\n" {
				return errors.New("promotion resume file has an invalid value")
			}
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("inspect promotion resume file: %w", err)
		}
		select {
		case <-deadlineCtx.Done():
			return deadlineCtx.Err()
		case <-ticker.C:
		}
	}
}

// Compile-time checks keep the harness wrapper aligned with the production
// package-private backend interfaces without exposing any new API surface.
var (
	_ database    = (*injectedDatabase)(nil)
	_ transaction = (*injectedTransaction)(nil)
	_             = pgx.ErrTxCommitRollback
)

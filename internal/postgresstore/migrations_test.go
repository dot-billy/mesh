package postgresstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestEmbeddedMigrationChecksumIsPinned(t *testing.T) {
	migrations, err := supportedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 3 || migrations[0].version != 1 || migrations[0].SQL == "" || migrations[1].version != 2 || migrations[1].SQL == "" || migrations[2].version != 3 || migrations[2].SQL == "" {
		t.Fatalf("unexpected migrations: %+v", migrations)
	}
}

func TestValidateAppliedMigrationsRejectsBehindAheadAndChanged(t *testing.T) {
	supported, err := supportedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppliedMigrations(nil, supported, true); err != nil {
		t.Fatalf("migration runner should permit behind schema: %v", err)
	}
	if err := validateAppliedMigrations(nil, supported, false); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("readiness behind error = %v", err)
	}
	wrong := supported[0].checksum
	wrong[0] ^= 0xff
	if err := validateAppliedMigrations(map[int][sha256.Size]byte{1: wrong}, supported, false); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("changed checksum error = %v", err)
	}
	if err := validateAppliedMigrations(map[int][sha256.Size]byte{2: {}}, supported, false); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("ahead schema error = %v", err)
	}
}

func TestOptionsRejectInvalidBounds(t *testing.T) {
	if _, err := normalizeOptions(Options{CommitTimeout: -1}); err == nil {
		t.Fatal("negative commit timeout accepted")
	}
	if _, err := normalizeOptions(Options{CommitResolutionTimeout: -1}); err == nil {
		t.Fatal("negative resolution timeout accepted")
	}
}

func TestMigrationRetainsExclusiveAdvisoryLock(t *testing.T) {
	sentinel := errors.New("stop after lock assertion")
	tx := &fakeTransaction{execFn: func(_ context.Context, query string, args ...any) (int64, error) {
		if !strings.Contains(query, "pg_advisory_xact_lock($1)") || strings.Contains(query, "_shared") || strings.Contains(query, "pg_try_") {
			t.Fatalf("migration did not use the blocking exclusive advisory lock: %s", query)
		}
		if len(args) != 1 || args[0] != migrationAdvisoryLockKey {
			t.Fatalf("migration lock arguments = %#v", args)
		}
		return 0, sentinel
	}}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	if err := store.Migrate(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("migration lock error = %v, want sentinel", err)
	}
}

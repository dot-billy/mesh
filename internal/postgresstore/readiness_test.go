package postgresstore

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

type singleRowQuery struct {
	row rowScanner
}

func (query singleRowQuery) QueryRow(context.Context, string, ...any) rowScanner {
	return query.row
}

func TestOperationalFunctionSecurityResult(t *testing.T) {
	tests := []struct {
		name    string
		row     rowScanner
		wantErr bool
	}{
		{name: "secure", row: valuesRow(true)},
		{name: "insecure", row: valuesRow(false), wantErr: true},
		{name: "inspection failure", row: rowFunc(func(...any) error { return errors.New("catalog unavailable") }), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkOperationalFunctionSecurity(context.Background(), singleRowQuery{row: test.row})
			if test.wantErr {
				if !errors.Is(err, ErrSchemaNotReady) {
					t.Fatalf("error = %v, want ErrSchemaNotReady", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadinessProbesMigrationLockInSharedMode(t *testing.T) {
	var lockQueries atomic.Int64
	tx := &fakeTransaction{queryRowFn: func(_ context.Context, query string, args ...any) rowScanner {
		lockQueries.Add(1)
		if !strings.Contains(query, "pg_try_advisory_xact_lock_shared") || strings.Contains(query, "pg_try_advisory_xact_lock(") {
			t.Fatalf("readiness did not use the shared migration advisory lock: %s", query)
		}
		if len(args) != 1 || args[0] != migrationAdvisoryLockKey {
			t.Fatalf("readiness migration lock arguments = %#v", args)
		}
		return valuesRow(false)
	}}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return tx, nil }}
	store := testStore(t, db)
	if err := store.CheckSchemaReadiness(context.Background()); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("readiness with unavailable shared migration lock = %v, want ErrSchemaNotReady", err)
	}
	if lockQueries.Load() != 1 {
		t.Fatalf("shared migration lock queries = %d, want 1", lockQueries.Load())
	}
}

func TestSchemaOwnerMigrationRevokesPublicFunctionAccessConditionally(t *testing.T) {
	tests := []struct {
		name          string
		shouldRevoke  bool
		wantChanged   bool
		wantExecCalls int64
	}{
		{name: "owner owned members", shouldRevoke: true, wantChanged: true, wantExecCalls: 1},
		{name: "pre transfer members", shouldRevoke: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var execCalls atomic.Int64
			tx := &fakeTransaction{
				queryRowFn: func(_ context.Context, query string, _ ...any) rowScanner {
					if !strings.Contains(query, "public_can_execute") {
						t.Fatalf("unexpected owner ACL query: %s", query)
					}
					return valuesRow(test.shouldRevoke)
				},
				execFn: func(_ context.Context, query string, _ ...any) (int64, error) {
					execCalls.Add(1)
					if !strings.Contains(query, "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA mesh FROM PUBLIC") {
						t.Fatalf("unexpected function ACL repair: %s", query)
					}
					return 0, nil
				},
			}
			changed, err := revokePublicFunctionAccessForSchemaOwner(context.Background(), tx)
			if err != nil {
				t.Fatal(err)
			}
			if changed != test.wantChanged || execCalls.Load() != test.wantExecCalls {
				t.Fatalf("changed=%v exec calls=%d", changed, execCalls.Load())
			}
		})
	}
}

func TestSchemaOwnerFunctionACLInspectionFailureIsSanitized(t *testing.T) {
	tx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
		return rowFunc(func(...any) error { return errors.New("sensitive catalog failure") })
	}}
	_, err := revokePublicFunctionAccessForSchemaOwner(context.Background(), tx)
	if err == nil || err.Error() != "inspect owner-owned pgcrypto function ACLs failed" {
		t.Fatalf("error = %v", err)
	}
}

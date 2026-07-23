package postgresstore

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const (
	migrationAdvisoryLockKey int64 = 0x4d45534853544f52
	migration001ChecksumHex        = "c31340602b7566bc4de02fbb3dfa076f71dcf57c9642725a1f44b1c4c432bb90"
	migration002ChecksumHex        = "dbc51007c4078267cceb9702f2fd4dcc2eb779722106d7d6136b014ed2ce2acd"
	migration003ChecksumHex        = "cecde7569e13ee7e316fcbde69c9f7cc584b8f40e05c46b90a41733b98ecea6d"
)

const migrationLedgerDDL = `
CREATE TABLE IF NOT EXISTS mesh.mesh_schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    migration_sha256 bytea NOT NULL CHECK (octet_length(migration_sha256) = 32),
    applied_at timestamptz NOT NULL,
    applied_by_build text NOT NULL CHECK (length(applied_by_build) BETWEEN 1 AND 256)
)`

const migrationNamespaceDDL = `CREATE SCHEMA IF NOT EXISTS mesh AUTHORIZATION CURRENT_USER`

//go:embed migrations/001_documents.sql
var migration001SQL string

//go:embed migrations/002_runtime_telemetry.sql
var migration002SQL string

//go:embed migrations/003_control_topology_import.sql
var migration003SQL string

type migration struct {
	version  int
	SQL      string
	checksum [sha256.Size]byte
}

func supportedMigrations() ([]migration, error) {
	definitions := []struct {
		version int
		sql     string
		hex     string
	}{
		{1, migration001SQL, migration001ChecksumHex},
		{2, migration002SQL, migration002ChecksumHex},
		{3, migration003SQL, migration003ChecksumHex},
	}
	migrations := make([]migration, 0, len(definitions))
	for _, definition := range definitions {
		expected, err := hex.DecodeString(definition.hex)
		if err != nil || len(expected) != sha256.Size {
			return nil, fmt.Errorf("invalid compiled migration %d checksum", definition.version)
		}
		actual := sha256.Sum256([]byte(definition.sql))
		if !equalSHA256(actual[:], expected) {
			return nil, fmt.Errorf("embedded migration %d checksum mismatch: got %x", definition.version, actual)
		}
		var checksum [sha256.Size]byte
		copy(checksum[:], expected)
		migrations = append(migrations, migration{version: definition.version, SQL: definition.sql, checksum: checksum})
	}
	return migrations, nil
}

// Migrate applies every supported migration under one transaction-level
// advisory lock. Runtime code should use a separate role that cannot call it.
func (s *Store) Migrate(ctx context.Context) error {
	if err := s.checkAvailable(); err != nil {
		return err
	}
	migrations, err := supportedMigrations()
	if err != nil {
		return err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("begin postgres migration: %w", err)
	}
	defer s.rollback(tx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("take postgres migration advisory lock: %w", err)
	}
	if _, err := tx.Exec(ctx, migrationNamespaceDDL); err != nil {
		return errors.New("create dedicated postgres schema failed")
	}
	var ownedByCurrentUser bool
	if err := tx.QueryRow(ctx, `
SELECT n.nspowner = r.oid
FROM pg_catalog.pg_namespace AS n
JOIN pg_catalog.pg_roles AS r ON r.rolname = CURRENT_USER
WHERE n.nspname = 'mesh'`).Scan(&ownedByCurrentUser); err != nil {
		return errors.New("verify dedicated postgres schema owner failed")
	}
	if !ownedByCurrentUser {
		return errors.New("dedicated postgres schema is not owned by the migration role")
	}
	var publicSchemaPrivileges bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace AS n,
         LATERAL pg_catalog.aclexplode(
             COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
         ) AS acl
    WHERE n.nspname = 'mesh'
      AND acl.grantee = 0
      AND acl.privilege_type IN ('CREATE', 'USAGE')
)`).Scan(&publicSchemaPrivileges); err != nil {
		return errors.New("inspect dedicated postgres schema privileges failed")
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL ON SCHEMA mesh FROM PUBLIC`); err != nil {
		return errors.New("secure dedicated postgres schema failed")
	}
	if _, err := tx.Exec(ctx, migrationLedgerDDL); err != nil {
		return fmt.Errorf("create postgres migration ledger: %w", err)
	}
	publicTablePrivileges, err := hasPublicTablePrivileges(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA mesh FROM PUBLIC`); err != nil {
		return errors.New("secure dedicated postgres tables failed")
	}
	applied, err := loadAppliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateAppliedMigrations(applied, migrations, true); err != nil {
		return err
	}

	changed := publicSchemaPrivileges || publicTablePrivileges
	for _, item := range migrations {
		if _, exists := applied[item.version]; exists {
			continue
		}
		if item.version == 1 {
			var extensionSchema string
			err := tx.QueryRow(ctx, `
SELECT n.nspname
FROM pg_catalog.pg_extension AS e
JOIN pg_catalog.pg_namespace AS n ON n.oid = e.extnamespace
WHERE e.extname = 'pgcrypto'`).Scan(&extensionSchema)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return errors.New("inspect pgcrypto extension failed")
			}
			if err == nil && extensionSchema != "mesh" {
				return fmt.Errorf("pgcrypto is installed in schema %q; Mesh requires a fresh dedicated database with pgcrypto owned by schema mesh", extensionSchema)
			}
		}
		if _, err := tx.Exec(ctx, item.SQL); err != nil {
			return fmt.Errorf("apply postgres migration %d: %w", item.version, err)
		}
		rows, err := tx.Exec(ctx, `
INSERT INTO mesh.mesh_schema_migrations
    (version, migration_sha256, applied_at, applied_by_build)
VALUES ($1, $2, clock_timestamp(), $3)`, item.version, item.checksum[:], s.options.migrationBuild)
		if err != nil {
			return fmt.Errorf("record postgres migration %d: %w", item.version, err)
		}
		if rows != 1 {
			return fmt.Errorf("record postgres migration %d affected %d rows", item.version, rows)
		}
		changed = true
	}
	// New tables can inherit a migration role's altered default ACLs, so repeat
	// this after applying migrations as well as repairing existing installations.
	if _, err := tx.Exec(ctx, `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA mesh FROM PUBLIC`); err != nil {
		return errors.New("secure migrated postgres tables failed")
	}
	functionACLChanged, err := revokePublicFunctionAccessForSchemaOwner(ctx, tx)
	if err != nil {
		return err
	}
	changed = changed || functionACLChanged
	if err := checkNamespaceSecurity(ctx, tx); err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w before migration commit: %v", ErrNotCommitted, err)
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), s.options.commitTimeout)
	defer cancelCommit()
	if err := tx.Commit(commitCtx); err == nil {
		return nil
	} else if errors.Is(err, pgx.ErrTxCommitRollback) {
		return fmt.Errorf("%w: migration commit: %v", ErrNotCommitted, err)
	} else {
		commitErr := err
		resolutionCtx, cancel := context.WithTimeout(context.Background(), s.options.commitResolutionTimeout)
		defer cancel()
		resolvedErr := s.checkMigrationState(resolutionCtx, migrations, functionACLChanged)
		if resolvedErr == nil {
			return nil
		}
		s.markUncertain(UncertainWrite{OperationClass: "schema.migrate"})
		return fmt.Errorf("%w during schema migration: commit error: %v; resolution: %v", ErrUncertainCommit, commitErr, resolvedErr)
	}
}

// revokePublicFunctionAccessForSchemaOwner preserves the two-stage trusted-
// extension ceremony. A schema-owner connection that already owns every
// pgcrypto function member (the common disposable/admin test path) can harden
// itself during migration. A non-superuser migration role whose members are
// still bootstrap-superuser-owned is left untouched for the explicit cluster-
// administrator ownership transfer. Operational import/readiness checks reject
// that intermediate state.
func revokePublicFunctionAccessForSchemaOwner(ctx context.Context, tx transaction) (bool, error) {
	var shouldRevoke bool
	err := tx.QueryRow(ctx, `
WITH boundary AS (
    SELECT
        n.oid AS namespace_oid,
        n.nspowner AS owner_oid,
        e.oid AS extension_oid,
        e.extowner AS extension_owner_oid,
        active_role.oid AS current_user_oid
    FROM pg_catalog.pg_namespace AS n
    JOIN pg_catalog.pg_extension AS e
      ON e.extname = 'pgcrypto'
     AND e.extnamespace = n.oid
    JOIN pg_catalog.pg_roles AS active_role
      ON active_role.rolname = CURRENT_USER
    WHERE n.nspname = 'mesh'
),
members AS (
    SELECT
        p.oid,
        p.proowner,
        p.pronamespace,
        b.namespace_oid,
        b.owner_oid,
        b.extension_oid,
        b.extension_owner_oid,
        b.current_user_oid,
        EXISTS (
            SELECT 1
            FROM LATERAL pg_catalog.aclexplode(
                COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
            ) AS acl
            WHERE acl.grantee = 0
              AND acl.privilege_type = 'EXECUTE'
        ) AS public_can_execute
    FROM boundary AS b
    JOIN pg_catalog.pg_depend AS dependency
      ON dependency.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
     AND dependency.refobjid = b.extension_oid
     AND dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
     AND dependency.deptype = 'e'
    JOIN pg_catalog.pg_proc AS p
      ON p.oid = dependency.objid
     AND p.prokind = 'f'
)
SELECT COALESCE((
    SELECT
        b.current_user_oid = b.owner_oid
        AND b.extension_owner_oid = b.owner_oid
        AND EXISTS (SELECT 1 FROM members)
        AND NOT EXISTS (
            SELECT 1
            FROM members AS m
            WHERE m.proowner <> b.owner_oid
               OR m.pronamespace <> b.namespace_oid
        )
        AND EXISTS (
            SELECT 1 FROM members AS m WHERE m.public_can_execute
        )
    FROM boundary AS b
), false)`).Scan(&shouldRevoke)
	if err != nil {
		return false, errors.New("inspect owner-owned pgcrypto function ACLs failed")
	}
	if !shouldRevoke {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA mesh FROM PUBLIC`); err != nil {
		return false, errors.New("secure owner-owned pgcrypto functions failed")
	}
	return true, nil
}

func hasPublicTablePrivileges(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) rowScanner
}) (bool, error) {
	var found bool
	err := query.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace,
         LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))
         ) AS acl
    WHERE n.nspname = 'mesh'
      AND c.relkind IN ('r', 'p')
      AND acl.grantee = 0
)`).Scan(&found)
	if err != nil {
		return false, errors.New("inspect dedicated postgres table privileges failed")
	}
	return found, nil
}

func loadAppliedMigrations(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (rowsScanner, error)
}) (map[int][sha256.Size]byte, error) {
	rows, err := query.Query(ctx, `
SELECT version, migration_sha256
FROM mesh.mesh_schema_migrations
ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read postgres migration ledger: %w", err)
	}
	defer rows.Close()
	applied := make(map[int][sha256.Size]byte)
	for rows.Next() {
		var (
			version  int
			raw      []byte
			checksum [sha256.Size]byte
		)
		if err := rows.Scan(&version, &raw); err != nil {
			return nil, fmt.Errorf("scan postgres migration ledger: %w", err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("%w: migration %d has an invalid checksum length", ErrSchemaNotReady, version)
		}
		copy(checksum[:], raw)
		if _, duplicate := applied[version]; duplicate {
			return nil, fmt.Errorf("%w: duplicate migration version %d", ErrSchemaNotReady, version)
		}
		applied[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres migration ledger: %w", err)
	}
	return applied, nil
}

func validateAppliedMigrations(applied map[int][sha256.Size]byte, supported []migration, allowBehind bool) error {
	expected := make(map[int][sha256.Size]byte, len(supported))
	for _, item := range supported {
		expected[item.version] = item.checksum
	}
	for version, actual := range applied {
		wanted, known := expected[version]
		if !known {
			return fmt.Errorf("%w: database migration %d is newer than this binary", ErrSchemaNotReady, version)
		}
		if !equalSHA256(actual[:], wanted[:]) {
			return fmt.Errorf("%w: database migration %d checksum mismatch", ErrSchemaNotReady, version)
		}
	}
	if !allowBehind {
		for version := range expected {
			if _, exists := applied[version]; !exists {
				return fmt.Errorf("%w: database is missing migration %d", ErrSchemaNotReady, version)
			}
		}
	}
	return nil
}

func (s *Store) checkMigrationState(ctx context.Context, supported []migration, requireOperationalFunctions bool) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return err
	}
	applied, err := loadAppliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateAppliedMigrations(applied, supported, false); err != nil {
		return err
	}
	if err := checkNamespaceSecurity(ctx, tx); err != nil {
		return err
	}
	if requireOperationalFunctions {
		return checkOperationalFunctionSecurity(ctx, tx)
	}
	return nil
}

func equalSHA256(a, b []byte) bool {
	if len(a) != sha256.Size || len(b) != sha256.Size {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

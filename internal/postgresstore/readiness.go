package postgresstore

import (
	"context"
	"crypto/subtle"
	"fmt"
)

// CheckReadiness proves that this process has no unresolved commit, the exact
// supported schema is present, the endpoint is a writable primary, and both
// authoritative documents and their latest receipts are internally consistent.
//
// This low-level check intentionally does not require mesh_import_metadata's
// singleton row. Complete application wiring must add that import provenance
// requirement and application-level cryptographic validation before serving.
func (s *Store) CheckReadiness(ctx context.Context) error {
	return s.checkReadiness(ctx, true)
}

// CheckSchemaReadiness is the narrower pre-import check for migration and
// provisioning tooling. Unlike CheckReadiness, it permits an empty document
// table while still validating any rows that are present.
func (s *Store) CheckSchemaReadiness(ctx context.Context) error {
	return s.checkReadiness(ctx, false)
}

func (s *Store) checkReadiness(ctx context.Context, requireDocuments bool) error {
	if err := s.checkAvailable(); err != nil {
		return err
	}
	supported, err := supportedMigrations()
	if err != nil {
		return err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("begin postgres readiness transaction: %w", err)
	}
	defer s.rollback(tx)

	if err := checkWritablePrimary(ctx, tx); err != nil {
		return err
	}
	var migrationLockAvailable bool
	// Readiness checks share this transaction-level lock with each other, while
	// migration takes the exclusive form of the same advisory lock. Concurrent
	// replicas can therefore prove readiness without making one another fail
	// closed, but any active migration still excludes every readiness check.
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)`, migrationAdvisoryLockKey).Scan(&migrationLockAvailable); err != nil {
		return fmt.Errorf("probe postgres migration lock: %w", err)
	}
	if !migrationLockAvailable {
		return fmt.Errorf("%w: schema migration lock is active", ErrSchemaNotReady)
	}
	if err := checkNamespaceSecurity(ctx, tx); err != nil {
		return err
	}
	if requireDocuments {
		if err := checkOperationalFunctionSecurity(ctx, tx); err != nil {
			return err
		}
	}

	applied, err := loadAppliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateAppliedMigrations(applied, supported, false); err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `SELECT document_key FROM mesh.mesh_state_documents ORDER BY document_key`)
	if err != nil {
		return fmt.Errorf("list postgres state documents: %w", err)
	}
	var domains []Domain
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres document key: %w", err)
		}
		domain := Domain(raw)
		if err := validateDomain(domain); err != nil {
			rows.Close()
			return fmt.Errorf("%w: %v", ErrCorruptDocument, err)
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate postgres document keys: %w", err)
	}
	rows.Close()

	seen := make(map[Domain]struct{}, len(domains))
	for _, domain := range domains {
		if _, duplicate := seen[domain]; duplicate {
			return fmt.Errorf("%w: duplicate %s document", ErrCorruptDocument, domain)
		}
		seen[domain] = struct{}{}
		limit, _ := maxDocumentBytes(domain)
		document, err := scanDocument(tx.QueryRow(ctx, selectDocumentSQL, domain, limit), domain)
		if err != nil {
			return err
		}
		receipt, err := scanReceipt(tx.QueryRow(ctx, selectReceiptSQL, document.LastWriteID, domain), document.LastWriteID)
		if err != nil {
			return fmt.Errorf("validate %s latest receipt: %w", domain, err)
		}
		if receipt.Domain != domain ||
			receipt.CommittedRevision != document.Revision ||
			receipt.BaseRevision != document.Revision-1 ||
			subtle.ConstantTimeCompare(receipt.SHA256[:], document.SHA256[:]) != 1 {
			return fmt.Errorf("%w: %s latest receipt does not bind its current revision", ErrCorruptDocument, domain)
		}
	}
	if requireDocuments {
		for _, domain := range []Domain{DomainControl, DomainIdentity} {
			if _, exists := seen[domain]; !exists {
				return fmt.Errorf("%w: expected %s document is absent", ErrNotInitialized, domain)
			}
		}
	}
	return nil
}

func checkNamespaceSecurity(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) rowScanner
}) error {
	var secure bool
	err := query.QueryRow(ctx, `
SELECT
    NOT EXISTS (
        SELECT 1
        FROM LATERAL pg_catalog.aclexplode(
            COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
        ) AS acl
        WHERE acl.grantee = 0
          AND acl.privilege_type IN ('CREATE', 'USAGE')
    )
    AND (
        SELECT pg_catalog.count(*) = 5 AND pg_catalog.bool_and(c.relowner = n.nspowner)
        FROM pg_catalog.pg_class AS c
        WHERE c.relnamespace = n.oid
          AND c.relkind IN ('r', 'p')
          AND c.relname IN (
              'mesh_schema_migrations',
              'mesh_write_receipts',
              'mesh_state_documents',
              'mesh_write_receipt_documents',
              'mesh_import_metadata'
        )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS c,
             LATERAL pg_catalog.aclexplode(
                 COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))
             ) AS acl
        WHERE c.relnamespace = n.oid
          AND c.relkind IN ('r', 'p')
          AND acl.grantee = 0
    )
    AND EXISTS (
        SELECT 1
        FROM pg_catalog.pg_extension AS e
        WHERE e.extname = 'pgcrypto'
          AND e.extnamespace = n.oid
          AND e.extowner = n.nspowner
    )
    AND pg_catalog.to_regprocedure('mesh.digest(bytea,text)') IS NOT NULL
FROM pg_catalog.pg_namespace AS n
WHERE n.nspname = 'mesh'`).Scan(&secure)
	if err != nil {
		return fmt.Errorf("%w: inspect dedicated postgres schema security: %v", ErrSchemaNotReady, err)
	}
	if !secure {
		return fmt.Errorf("%w: dedicated schema ACL, ownership, or pgcrypto invariant failed", ErrSchemaNotReady)
	}
	return nil
}

// checkOperationalFunctionSecurity is deliberately separate from
// checkNamespaceSecurity. PostgreSQL installs trusted-extension member
// functions as the bootstrap superuser, so migration/schema provisioning must
// be able to complete before the cluster administrator transfers those members
// to the migration owner. Import and serving readiness use this stricter gate.
//
// The schema owner is the provisioning exception and may execute every member.
// Every other current user must be non-superuser and limited to the exact digest
// function required by document constraints and reads.
func checkOperationalFunctionSecurity(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) rowScanner
}) error {
	var secure bool
	err := query.QueryRow(ctx, `
WITH boundary AS (
    SELECT
        n.oid AS namespace_oid,
        n.nspowner AS owner_oid,
        e.oid AS extension_oid,
        e.extowner AS extension_owner_oid,
        active_role.oid AS current_user_oid,
        active_role.rolsuper AS current_user_superuser,
        pg_catalog.to_regprocedure('mesh.digest(bytea,text)') AS digest_oid
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
        b.current_user_superuser,
        b.digest_oid,
        p.oid = b.digest_oid AS is_digest,
        pg_catalog.has_function_privilege(CURRENT_USER, p.oid, 'EXECUTE') AS current_user_can_execute,
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
        b.extension_owner_oid = b.owner_oid
        AND b.digest_oid IS NOT NULL
        AND EXISTS (SELECT 1 FROM members AS m WHERE m.is_digest)
        AND NOT EXISTS (
            SELECT 1
            FROM members AS m
            WHERE m.proowner <> b.owner_oid
               OR m.pronamespace <> b.namespace_oid
        )
        AND NOT EXISTS (
            SELECT 1 FROM members AS m WHERE m.public_can_execute
        )
        AND EXISTS (
            SELECT 1
            FROM members AS m
            WHERE m.is_digest AND m.current_user_can_execute
        )
        AND (
            b.current_user_oid = b.owner_oid
            OR (
                NOT b.current_user_superuser
                AND NOT EXISTS (
                    SELECT 1
                    FROM members AS m
                    WHERE NOT m.is_digest AND m.current_user_can_execute
                )
            )
        )
    FROM boundary AS b
), false)`).Scan(&secure)
	if err != nil {
		return fmt.Errorf("%w: inspect operational pgcrypto function security: %v", ErrSchemaNotReady, err)
	}
	if !secure {
		return fmt.Errorf("%w: operational pgcrypto function security invariant failed", ErrSchemaNotReady)
	}
	return nil
}

func checkWritablePrimary(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) rowScanner
}) error {
	var readOnly string
	if err := query.QueryRow(ctx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil {
		return fmt.Errorf("read postgres transaction mode: %w", err)
	}
	if readOnly != "off" {
		return fmt.Errorf("%w: transaction_read_only is %q", ErrUnwritablePrimary, readOnly)
	}
	var recovering bool
	if err := query.QueryRow(ctx, `SELECT pg_catalog.pg_is_in_recovery()`).Scan(&recovering); err != nil {
		return fmt.Errorf("read postgres recovery state: %w", err)
	}
	if recovering {
		return fmt.Errorf("%w: endpoint is in recovery", ErrUnwritablePrimary)
	}
	return nil
}

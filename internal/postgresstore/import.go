package postgresstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const importAdvisoryLockKey int64 = 0x4d455348494d5054

type importExpectation struct {
	result         ImportResult
	sourceFormat   string
	controlHash    [sha256.Size]byte
	identityHash   [sha256.Size]byte
	controlBytes   int64
	identityBytes  int64
	controlVersion int
	identitySchema string
	backupID       string
	importerBuild  string
}

type importProvenance struct {
	importID       string
	receiptID      string
	sourceFormat   string
	controlHash    [sha256.Size]byte
	identityHash   [sha256.Size]byte
	controlBytes   int64
	identityBytes  int64
	controlVersion int
	identitySchema string
	backupID       string
	importedAt     time.Time
	importerBuild  string
}

// Import atomically installs the two exact revision-one documents and their
// immutable import provenance. It never overwrites or merges existing state.
func (s *Store) Import(ctx context.Context, source ImportSource) (ImportResult, error) {
	if err := validateImportSource(source); err != nil {
		return ImportResult{}, err
	}
	source.ControlBytes = append([]byte(nil), source.ControlBytes...)
	source.IdentityBytes = append([]byte(nil), source.IdentityBytes...)
	if err := s.checkAvailable(); err != nil {
		return ImportResult{}, err
	}

	tx, err := s.begin(ctx)
	if err != nil {
		return ImportResult{}, fmt.Errorf("begin postgres import: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return ImportResult{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock($1)`, importAdvisoryLockKey); err != nil {
		return ImportResult{}, fmt.Errorf("take postgres import advisory lock: %w", err)
	}
	// Share the existing initialization locks in the fixed cross-domain order.
	// This makes the empty check atomic relative to standalone initialization.
	for _, domain := range []Domain{DomainControl, DomainIdentity} {
		lockKey, _ := documentInitializationLockKey(domain)
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock($1)`, lockKey); err != nil {
			return ImportResult{}, fmt.Errorf("lock %s during postgres import: %w", domain, err)
		}
	}
	var migrationLockAvailable bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_xact_lock($1)`, migrationAdvisoryLockKey).Scan(&migrationLockAvailable); err != nil {
		return ImportResult{}, fmt.Errorf("probe postgres migration lock: %w", err)
	}
	if !migrationLockAvailable {
		return ImportResult{}, fmt.Errorf("%w: schema migration lock is active", ErrSchemaNotReady)
	}
	if err := checkExactMigratedSchema(ctx, tx); err != nil {
		return ImportResult{}, err
	}
	// Migration intentionally permits PostgreSQL's trusted-extension
	// pre-transfer state. Import is the first operation that can install
	// authority, so require the completed function ownership/ACL ceremony before
	// inspecting or writing any application row.
	if err := checkOperationalFunctionSecurity(ctx, tx); err != nil {
		return ImportResult{}, err
	}

	var importExists, documentExists, receiptExists, receiptItemExists bool
	if err := tx.QueryRow(ctx, `
SELECT
    EXISTS (SELECT 1 FROM mesh.mesh_import_metadata),
    EXISTS (SELECT 1 FROM mesh.mesh_state_documents),
    EXISTS (SELECT 1 FROM mesh.mesh_write_receipts),
    EXISTS (SELECT 1 FROM mesh.mesh_write_receipt_documents)`).Scan(
		&importExists,
		&documentExists,
		&receiptExists,
		&receiptItemExists,
	); err != nil {
		return ImportResult{}, fmt.Errorf("inspect postgres import target: %w", err)
	}
	if importExists {
		return ImportResult{}, ErrAlreadyImported
	}
	if documentExists || receiptExists || receiptItemExists {
		return ImportResult{}, ErrNotEmpty
	}

	importID, err := s.newWriteID()
	if err != nil {
		return ImportResult{}, fmt.Errorf("generate import ID: %w", err)
	}
	receiptID, err := s.newWriteID()
	if err != nil {
		return ImportResult{}, fmt.Errorf("generate import receipt ID: %w", err)
	}
	if importID == receiptID {
		return ImportResult{}, errors.New("import and receipt UUIDs must be distinct")
	}
	if !validCanonicalUUID(importID) || !validCanonicalUUID(receiptID) {
		return ImportResult{}, errors.New("generated import identifiers are not canonical UUIDs")
	}
	controlHash := sha256.Sum256(source.ControlBytes)
	identityHash := sha256.Sum256(source.IdentityBytes)
	committedAt, err := insertReceiptHeader(ctx, tx, receiptID, OperationImport)
	if err != nil {
		return ImportResult{}, err
	}
	control := Document{
		Domain:      DomainControl,
		Revision:    1,
		Bytes:       source.ControlBytes,
		SHA256:      controlHash,
		LastWriteID: receiptID,
		UpdatedAt:   committedAt,
	}
	identity := Document{
		Domain:      DomainIdentity,
		Revision:    1,
		Bytes:       source.IdentityBytes,
		SHA256:      identityHash,
		LastWriteID: receiptID,
		UpdatedAt:   committedAt,
	}
	for _, document := range []Document{control, identity} {
		rows, err := tx.Exec(ctx, `
INSERT INTO mesh.mesh_state_documents
    (document_key, revision, document_bytes, document_sha256, last_write_receipt, updated_at)
VALUES ($1, 1, $2, $3, $4::pg_catalog.uuid, $5)`, document.Domain, document.Bytes, document.SHA256[:], receiptID, committedAt)
		if err != nil {
			return ImportResult{}, fmt.Errorf("insert imported %s document: %w", document.Domain, err)
		}
		if rows != 1 {
			return ImportResult{}, fmt.Errorf("insert imported %s document affected %d rows", document.Domain, rows)
		}
		receipt := WriteReceipt{
			ID:                receiptID,
			OperationClass:    OperationImport,
			Domain:            document.Domain,
			BaseRevision:      0,
			CommittedRevision: 1,
			SHA256:            document.SHA256,
			CommittedAt:       committedAt,
		}
		if err := insertReceiptDocument(ctx, tx, receipt); err != nil {
			return ImportResult{}, err
		}
	}
	rows, err := tx.Exec(ctx, `
INSERT INTO mesh.mesh_import_metadata (
    singleton,
    import_id,
    import_receipt,
    source_format,
    source_control_sha256,
    source_identity_sha256,
    source_control_bytes,
    source_identity_bytes,
    source_control_version,
    source_identity_schema,
    source_backup_id,
    imported_at,
    importer_build
) VALUES (1, $1::pg_catalog.uuid, $2::pg_catalog.uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		importID,
		receiptID,
		source.SourceFormat,
		controlHash[:],
		identityHash[:],
		len(source.ControlBytes),
		len(source.IdentityBytes),
		source.ControlVersion,
		source.IdentitySchema,
		source.AuthenticatedBackupID,
		committedAt,
		source.ImporterBuild,
	)
	if err != nil {
		return ImportResult{}, fmt.Errorf("insert postgres import provenance: %w", err)
	}
	if rows != 1 {
		return ImportResult{}, fmt.Errorf("insert postgres import provenance affected %d rows", rows)
	}

	result := ImportResult{
		ImportID:   importID,
		ReceiptID:  receiptID,
		ImportedAt: committedAt,
		Control:    control.clone(),
		Identity:   identity.clone(),
	}
	expected := importExpectation{
		result:         result,
		sourceFormat:   source.SourceFormat,
		controlHash:    controlHash,
		identityHash:   identityHash,
		controlBytes:   int64(len(source.ControlBytes)),
		identityBytes:  int64(len(source.IdentityBytes)),
		controlVersion: source.ControlVersion,
		identitySchema: source.IdentitySchema,
		backupID:       source.AuthenticatedBackupID,
		importerBuild:  source.ImporterBuild,
	}
	if err := s.commitImport(ctx, tx, expected); err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

func validateImportSource(source ImportSource) error {
	if err := validateDocumentBytes(DomainControl, source.ControlBytes); err != nil {
		return fmt.Errorf("%w: control bytes: %v", ErrInvalidImportSource, err)
	}
	if err := validateDocumentBytes(DomainIdentity, source.IdentityBytes); err != nil {
		return fmt.Errorf("%w: identity bytes: %v", ErrInvalidImportSource, err)
	}
	if source.SourceFormat != ImportSourceFormat {
		return fmt.Errorf("%w: source format must be %q", ErrInvalidImportSource, ImportSourceFormat)
	}
	if !validImportControlVersion(source.ControlVersion) {
		return fmt.Errorf("%w: control version must be between %d and %d", ErrInvalidImportSource, ImportControlVersionMin, ImportControlVersionMax)
	}
	if source.IdentitySchema != ImportIdentitySchema {
		return fmt.Errorf("%w: identity schema must be %q", ErrInvalidImportSource, ImportIdentitySchema)
	}
	if !backupIDPattern.MatchString(source.AuthenticatedBackupID) {
		return fmt.Errorf("%w: authenticated backup ID must be exactly 32 lowercase hexadecimal characters", ErrInvalidImportSource)
	}
	if !importerBuildPattern.MatchString(source.ImporterBuild) || len(source.ImporterBuild) > MaxImporterBuildBytes {
		return fmt.Errorf("%w: importer build is not canonical bounded metadata", ErrInvalidImportSource)
	}
	return nil
}

func checkExactMigratedSchema(ctx context.Context, tx transaction) error {
	supported, err := supportedMigrations()
	if err != nil {
		return err
	}
	if err := checkNamespaceSecurity(ctx, tx); err != nil {
		return err
	}
	applied, err := loadAppliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	return validateAppliedMigrations(applied, supported, false)
}

func (s *Store) commitImport(ctx context.Context, tx transaction, expected importExpectation) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w before import commit: %v", ErrNotCommitted, err)
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), s.options.commitTimeout)
	defer cancelCommit()
	err := tx.Commit(commitCtx)
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return fmt.Errorf("%w: import commit: %v", ErrNotCommitted, err)
	}
	resolutionCtx, cancelResolution := context.WithTimeout(context.Background(), s.options.commitResolutionTimeout)
	defer cancelResolution()
	if resolutionErr := s.resolveImport(resolutionCtx, expected); resolutionErr == nil {
		return nil
	} else {
		s.markUncertain(UncertainWrite{
			ReceiptID:      expected.result.ReceiptID,
			OperationClass: OperationImport,
			TargetRevision: 1,
		})
		return fmt.Errorf("%w for import receipt %s: commit error: %v; resolution: %v", ErrUncertainCommit, expected.result.ReceiptID, err, resolutionErr)
	}
}

func (s *Store) resolveImport(ctx context.Context, expected importExpectation) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("open authoritative import resolution transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return err
	}
	actual, err := readImportProvenance(ctx, tx)
	if err != nil {
		return err
	}
	return matchImportExpectation(actual, expected)
}

// CheckImportReadiness adds immutable import-provenance validation to the full
// two-document runtime readiness check. It remains valid after later revisions.
func (s *Store) CheckImportReadiness(ctx context.Context) error {
	if err := s.CheckReadiness(ctx); err != nil {
		return err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("begin postgres import readiness transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return err
	}
	if _, err := readImportProvenance(ctx, tx); err != nil {
		return fmt.Errorf("%w: %w", ErrImportProvenance, err)
	}
	return nil
}

func readImportProvenance(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (rowsScanner, error)
	QueryRow(context.Context, string, ...any) rowScanner
}) (importProvenance, error) {
	var count int64
	if err := query.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.mesh_import_metadata`).Scan(&count); err != nil {
		return importProvenance{}, fmt.Errorf("count import provenance: %w", err)
	}
	if count != 1 {
		return importProvenance{}, fmt.Errorf("expected exactly one import provenance row, found %d", count)
	}
	var (
		provenance      importProvenance
		controlHashRaw  []byte
		identityHashRaw []byte
	)
	err := query.QueryRow(ctx, `
SELECT
    import_id::text,
    import_receipt::text,
    source_format,
    source_control_sha256,
    source_identity_sha256,
    source_control_bytes,
    source_identity_bytes,
    source_control_version,
    source_identity_schema,
    source_backup_id,
    imported_at,
    importer_build
FROM mesh.mesh_import_metadata
WHERE singleton = 1`).Scan(
		&provenance.importID,
		&provenance.receiptID,
		&provenance.sourceFormat,
		&controlHashRaw,
		&identityHashRaw,
		&provenance.controlBytes,
		&provenance.identityBytes,
		&provenance.controlVersion,
		&provenance.identitySchema,
		&provenance.backupID,
		&provenance.importedAt,
		&provenance.importerBuild,
	)
	if err != nil {
		return importProvenance{}, fmt.Errorf("read import provenance: %w", err)
	}
	if !validCanonicalUUID(provenance.importID) || !validCanonicalUUID(provenance.receiptID) || provenance.importID == provenance.receiptID {
		return importProvenance{}, errors.New("import provenance UUIDs are invalid")
	}
	if len(controlHashRaw) != sha256.Size || len(identityHashRaw) != sha256.Size {
		return importProvenance{}, errors.New("import provenance hash length is invalid")
	}
	copy(provenance.controlHash[:], controlHashRaw)
	copy(provenance.identityHash[:], identityHashRaw)
	if provenance.sourceFormat != ImportSourceFormat ||
		!validImportControlVersion(provenance.controlVersion) ||
		provenance.identitySchema != ImportIdentitySchema ||
		!backupIDPattern.MatchString(provenance.backupID) ||
		!importerBuildPattern.MatchString(provenance.importerBuild) ||
		provenance.controlBytes < 1 || provenance.controlBytes > MaxControlDocumentBytes ||
		provenance.identityBytes < 1 || provenance.identityBytes > MaxIdentityDocumentBytes ||
		provenance.importedAt.IsZero() {
		return importProvenance{}, errors.New("import provenance metadata is invalid")
	}
	var operation string
	var receiptCommittedAt time.Time
	if err := query.QueryRow(ctx, `
SELECT operation_class, committed_at
FROM mesh.mesh_write_receipts
WHERE receipt_id = $1::pg_catalog.uuid`, provenance.receiptID).Scan(&operation, &receiptCommittedAt); err != nil {
		return importProvenance{}, fmt.Errorf("read import receipt header: %w", err)
	}
	if operation != OperationImport || !receiptCommittedAt.Equal(provenance.importedAt) {
		return importProvenance{}, errors.New("import receipt header does not bind provenance")
	}
	rows, err := query.Query(ctx, `
SELECT document_key, base_revision, committed_revision, document_sha256
FROM mesh.mesh_write_receipt_documents
WHERE receipt_id = $1::pg_catalog.uuid
ORDER BY document_key`, provenance.receiptID)
	if err != nil {
		return importProvenance{}, fmt.Errorf("read import receipt items: %w", err)
	}
	defer rows.Close()
	seen := make(map[Domain]struct{}, 2)
	for rows.Next() {
		var (
			domainRaw string
			base      int64
			committed int64
			hash      []byte
		)
		if err := rows.Scan(&domainRaw, &base, &committed, &hash); err != nil {
			return importProvenance{}, fmt.Errorf("scan import receipt item: %w", err)
		}
		domain := Domain(domainRaw)
		if _, duplicate := seen[domain]; duplicate || base != 0 || committed != 1 || len(hash) != sha256.Size {
			return importProvenance{}, errors.New("import receipt item metadata is invalid")
		}
		var expectedHash [sha256.Size]byte
		switch domain {
		case DomainControl:
			expectedHash = provenance.controlHash
		case DomainIdentity:
			expectedHash = provenance.identityHash
		default:
			return importProvenance{}, errors.New("import receipt contains an invalid document domain")
		}
		if subtle.ConstantTimeCompare(hash, expectedHash[:]) != 1 {
			return importProvenance{}, errors.New("import receipt hash does not bind provenance")
		}
		seen[domain] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return importProvenance{}, fmt.Errorf("iterate import receipt items: %w", err)
	}
	if len(seen) != 2 {
		return importProvenance{}, fmt.Errorf("import receipt contains %d document items, want 2", len(seen))
	}
	return provenance, nil
}

func matchImportExpectation(actual importProvenance, expected importExpectation) error {
	if actual.importID != expected.result.ImportID ||
		actual.receiptID != expected.result.ReceiptID ||
		actual.sourceFormat != expected.sourceFormat ||
		actual.controlBytes != expected.controlBytes ||
		actual.identityBytes != expected.identityBytes ||
		actual.controlVersion != expected.controlVersion ||
		actual.identitySchema != expected.identitySchema ||
		actual.backupID != expected.backupID ||
		actual.importerBuild != expected.importerBuild ||
		!actual.importedAt.Equal(expected.result.ImportedAt) ||
		subtle.ConstantTimeCompare(actual.controlHash[:], expected.controlHash[:]) != 1 ||
		subtle.ConstantTimeCompare(actual.identityHash[:], expected.identityHash[:]) != 1 {
		return errors.New("committed import provenance does not match attempted import")
	}
	return nil
}

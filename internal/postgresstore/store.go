package postgresstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	db      database
	ownsDB  bool
	options normalizedOptions
	closed  atomic.Bool

	uncertainMu sync.RWMutex
	uncertain   *UncertainWrite

	newWriteID func() (string, error)
}

// Open creates and owns a connection pool. It verifies connectivity but does
// not run migrations or initialize documents.
func Open(ctx context.Context, databaseURL string, options Options) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("parse postgres configuration failed")
	}
	// All application objects are schema-qualified. Forcing pg_catalog prevents
	// a caller-supplied search_path from shadowing built-in functions or types.
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("open postgres pool failed")
	}
	db := &poolDatabase{pool: pool}
	if err := db.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("ping postgres failed")
	}
	store, err := newStore(db, true, options)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

// New uses a caller-owned pool. Closing the Store does not close that pool.
func New(pool *pgxpool.Pool, options Options) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	return newStore(&poolDatabase{pool: pool}, false, options)
}

func newStore(db database, ownsDB bool, options Options) (*Store, error) {
	if db == nil {
		return nil, errors.New("postgres database is required")
	}
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:         db,
		ownsDB:     ownsDB,
		options:    normalized,
		newWriteID: generateUUID,
	}, nil
}

func (s *Store) Close() error {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.ownsDB {
		s.db.Close()
	}
	return nil
}

func (s *Store) checkAvailable() error {
	if s == nil || s.closed.Load() {
		return ErrClosed
	}
	if _, uncertain := s.UncertainWrite(); uncertain {
		return ErrUncertainCommit
	}
	return nil
}

func (s *Store) begin(ctx context.Context) (transaction, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path = pg_catalog`); err != nil {
		s.rollback(tx)
		return nil, errors.New("secure postgres transaction search path failed")
	}
	return tx, nil
}

func (s *Store) UncertainWrite() (UncertainWrite, bool) {
	if s == nil {
		return UncertainWrite{}, false
	}
	s.uncertainMu.RLock()
	defer s.uncertainMu.RUnlock()
	if s.uncertain == nil {
		return UncertainWrite{}, false
	}
	return *s.uncertain, true
}

func (s *Store) markUncertain(write UncertainWrite) {
	s.uncertainMu.Lock()
	defer s.uncertainMu.Unlock()
	if s.uncertain == nil {
		copy := write
		s.uncertain = &copy
	}
}

func (s *Store) Read(ctx context.Context, domain Domain) (Document, error) {
	if err := validateDomain(domain); err != nil {
		return Document{}, err
	}
	if err := s.checkAvailable(); err != nil {
		return Document{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Document{}, fmt.Errorf("begin read transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return Document{}, err
	}
	limit, _ := maxDocumentBytes(domain)
	document, err := scanDocument(tx.QueryRow(ctx, selectDocumentSQL, domain, limit), domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, fmt.Errorf("%w: %s", ErrNotInitialized, domain)
	}
	if err != nil {
		return Document{}, err
	}
	return document.clone(), nil
}

// ReadPair returns control and identity from one SQL statement, so PostgreSQL
// evaluates both exact documents against one MVCC command snapshot. This is
// the recovery-verification primitive; two independent Read calls could
// otherwise observe different committed revisions under READ COMMITTED.
func (s *Store) ReadPair(ctx context.Context) (Document, Document, error) {
	if err := s.checkAvailable(); err != nil {
		return Document{}, Document{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Document{}, Document{}, fmt.Errorf("begin paired read transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return Document{}, Document{}, err
	}
	control, identity, err := scanDocumentPair(tx.QueryRow(
		ctx,
		selectDocumentPairSQL,
		DomainControl,
		DomainIdentity,
		MaxControlDocumentBytes,
		MaxIdentityDocumentBytes,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, Document{}, fmt.Errorf("%w: complete control and identity pair", ErrNotInitialized)
	}
	if err != nil {
		return Document{}, Document{}, err
	}
	return control.clone(), identity.clone(), nil
}

// Initialize creates revision one. Existing byte-identical state is a no-op;
// existing different state is never overwritten.
func (s *Store) Initialize(ctx context.Context, domain Domain, body []byte) (WriteResult, error) {
	if err := validateDocumentBytes(domain, body); err != nil {
		return WriteResult{}, err
	}
	if err := s.checkAvailable(); err != nil {
		return WriteResult{}, err
	}

	tx, err := s.begin(ctx)
	if err != nil {
		return WriteResult{}, fmt.Errorf("begin initialize transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return WriteResult{}, err
	}
	initializationLockKey, _ := documentInitializationLockKey(domain)
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock($1)`, initializationLockKey); err != nil {
		return WriteResult{}, fmt.Errorf("lock %s initialization: %w", domain, err)
	}

	limit, _ := maxDocumentBytes(domain)
	current, err := scanDocument(tx.QueryRow(ctx, selectDocumentForUpdateSQL, domain, limit), domain)
	switch {
	case err == nil:
		if bytes.Equal(current.Bytes, body) {
			return WriteResult{Document: current.clone()}, nil
		}
		return WriteResult{}, fmt.Errorf("%w: %s", ErrAlreadyInitialized, domain)
	case !errors.Is(err, pgx.ErrNoRows):
		return WriteResult{}, err
	}

	nextBytes := append([]byte(nil), body...)
	digest := sha256.Sum256(nextBytes)
	receiptID, err := s.newWriteID()
	if err != nil {
		return WriteResult{}, fmt.Errorf("generate write receipt ID: %w", err)
	}
	committedAt, err := insertReceiptHeader(ctx, tx, receiptID, OperationInitialize)
	if err != nil {
		return WriteResult{}, err
	}
	if rows, err := tx.Exec(ctx, `
INSERT INTO mesh.mesh_state_documents
    (document_key, revision, document_bytes, document_sha256, last_write_receipt, updated_at)
VALUES ($1, 1, $2, $3, $4::uuid, $5)`, domain, nextBytes, digest[:], receiptID, committedAt); err != nil {
		return WriteResult{}, fmt.Errorf("insert %s document: %w", domain, err)
	} else if rows != 1 {
		return WriteResult{}, fmt.Errorf("insert %s document affected %d rows", domain, rows)
	}
	receipt := WriteReceipt{
		ID:                receiptID,
		OperationClass:    OperationInitialize,
		Domain:            domain,
		BaseRevision:      0,
		CommittedRevision: 1,
		SHA256:            digest,
		CommittedAt:       committedAt,
	}
	if err := insertReceiptDocument(ctx, tx, receipt); err != nil {
		return WriteResult{}, err
	}
	document := Document{
		Domain:      domain,
		Revision:    1,
		Bytes:       nextBytes,
		SHA256:      digest,
		LastWriteID: receiptID,
		UpdatedAt:   committedAt,
	}
	if err := s.commitWrite(ctx, tx, receipt); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Changed: true, Document: document.clone(), Receipt: receipt}, nil
}

func documentInitializationLockKey(domain Domain) (int64, error) {
	switch domain {
	case DomainControl:
		return 0x4d455348494e4954, nil
	case DomainIdentity:
		return 0x4d455348494e4955, nil
	case DomainRuntimeTelemetry:
		return 0x4d455348494e4956, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
}

// Update invokes mutate exactly once while holding the authoritative row lock.
// It never retries the callback. Byte-identical output rolls back without a
// revision increment or receipt.
func (s *Store) Update(ctx context.Context, domain Domain, operationClass string, mutate func([]byte) ([]byte, error)) (WriteResult, error) {
	if err := validateDomain(domain); err != nil {
		return WriteResult{}, err
	}
	if err := validateOperationClass(operationClass); err != nil {
		return WriteResult{}, err
	}
	if mutate == nil {
		return WriteResult{}, errors.New("mutation callback is required")
	}
	if err := s.checkAvailable(); err != nil {
		return WriteResult{}, err
	}

	tx, err := s.begin(ctx)
	if err != nil {
		return WriteResult{}, fmt.Errorf("begin update transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return WriteResult{}, err
	}

	limit, _ := maxDocumentBytes(domain)
	current, err := scanDocument(tx.QueryRow(ctx, selectDocumentForUpdateSQL, domain, limit), domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return WriteResult{}, fmt.Errorf("%w: %s", ErrNotInitialized, domain)
	}
	if err != nil {
		return WriteResult{}, err
	}

	callbackInput := append([]byte(nil), current.Bytes...)
	next, err := mutate(callbackInput)
	if err != nil {
		return WriteResult{}, err
	}
	next = append([]byte(nil), next...)
	if err := validateDocumentBytes(domain, next); err != nil {
		return WriteResult{}, err
	}
	// A request canceled after its callback is still a definite non-commit as
	// long as no receipt or document SQL has been issued. Check this boundary
	// before even allocating the receipt ID; a real pgx transaction would
	// otherwise return a raw context error from the first receipt statement.
	if err := ctx.Err(); err != nil {
		return WriteResult{}, fmt.Errorf("%w before receipt creation: %v", ErrNotCommitted, err)
	}
	if bytes.Equal(current.Bytes, next) {
		return WriteResult{Document: current.clone()}, nil
	}
	if current.Revision >= math.MaxInt64-1 {
		return WriteResult{}, errors.New("document revision is exhausted")
	}

	receiptID, err := s.newWriteID()
	if err != nil {
		return WriteResult{}, fmt.Errorf("generate write receipt ID: %w", err)
	}
	digest := sha256.Sum256(next)
	committedAt, err := insertReceiptHeader(ctx, tx, receiptID, operationClass)
	if err != nil {
		return WriteResult{}, err
	}
	nextRevision := current.Revision + 1
	if rows, err := tx.Exec(ctx, `
UPDATE mesh.mesh_state_documents
SET revision = $2,
    document_bytes = $3,
    document_sha256 = $4,
    last_write_receipt = $5::uuid,
    updated_at = $6
WHERE document_key = $1 AND revision = $7`, domain, nextRevision, next, digest[:], receiptID, committedAt, current.Revision); err != nil {
		return WriteResult{}, fmt.Errorf("update %s document: %w", domain, err)
	} else if rows != 1 {
		return WriteResult{}, fmt.Errorf("update %s document affected %d rows after row lock", domain, rows)
	}
	receipt := WriteReceipt{
		ID:                receiptID,
		OperationClass:    operationClass,
		Domain:            domain,
		BaseRevision:      current.Revision,
		CommittedRevision: nextRevision,
		SHA256:            digest,
		CommittedAt:       committedAt,
	}
	if err := insertReceiptDocument(ctx, tx, receipt); err != nil {
		return WriteResult{}, err
	}
	document := Document{
		Domain:      domain,
		Revision:    nextRevision,
		Bytes:       next,
		SHA256:      digest,
		LastWriteID: receiptID,
		UpdatedAt:   committedAt,
	}
	if err := s.commitWrite(ctx, tx, receipt); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Changed: true, Document: document.clone(), Receipt: receipt}, nil
}

func insertReceiptHeader(ctx context.Context, tx transaction, receiptID, operationClass string) (time.Time, error) {
	var committedAt time.Time
	if err := tx.QueryRow(ctx, `
INSERT INTO mesh.mesh_write_receipts (receipt_id, operation_class, committed_at)
VALUES ($1::uuid, $2, clock_timestamp())
RETURNING committed_at`, receiptID, operationClass).Scan(&committedAt); err != nil {
		return time.Time{}, fmt.Errorf("insert write receipt header: %w", err)
	}
	return committedAt, nil
}

func insertReceiptDocument(ctx context.Context, tx transaction, receipt WriteReceipt) error {
	rows, err := tx.Exec(ctx, `
INSERT INTO mesh.mesh_write_receipt_documents
    (receipt_id, document_key, base_revision, committed_revision, document_sha256)
VALUES ($1::uuid, $2, $3, $4, $5)`, receipt.ID, receipt.Domain, receipt.BaseRevision, receipt.CommittedRevision, receipt.SHA256[:])
	if err != nil {
		return fmt.Errorf("insert write receipt document: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("insert write receipt document affected %d rows", rows)
	}
	return nil
}

func (s *Store) commitWrite(ctx context.Context, tx transaction, expected WriteReceipt) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w before commit: %v", ErrNotCommitted, err)
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), s.options.commitTimeout)
	defer cancelCommit()
	err := tx.Commit(commitCtx)
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return fmt.Errorf("%w: %v", ErrNotCommitted, err)
	}

	resolutionCtx, cancel := context.WithTimeout(context.Background(), s.options.commitResolutionTimeout)
	defer cancel()
	resolutionErr := s.resolveWriteReceipt(resolutionCtx, expected)
	if resolutionErr == nil {
		return nil
	}

	s.markUncertain(UncertainWrite{
		ReceiptID:      expected.ID,
		OperationClass: expected.OperationClass,
		Domain:         expected.Domain,
		BaseRevision:   expected.BaseRevision,
		TargetRevision: expected.CommittedRevision,
	})
	return fmt.Errorf("%w for receipt %s: commit error: %v; resolution: %v", ErrUncertainCommit, expected.ID, err, resolutionErr)
}

func (s *Store) rollback(tx transaction) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), s.options.commitTimeout)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

func (s *Store) resolveWriteReceipt(ctx context.Context, expected WriteReceipt) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("open authoritative receipt transaction: %w", err)
	}
	defer s.rollback(tx)
	if err := checkWritablePrimary(ctx, tx); err != nil {
		return err
	}
	actual, err := scanReceipt(tx.QueryRow(ctx, selectReceiptSQL, expected.ID, expected.Domain), expected.ID)
	if err != nil {
		return err
	}
	if !receiptMatches(actual, expected) {
		return errors.New("receipt did not match the attempted write")
	}
	return nil
}

const selectReceiptSQL = `
SELECT r.operation_class,
       d.document_key,
       d.base_revision,
       d.committed_revision,
       d.document_sha256,
       r.committed_at
FROM mesh.mesh_write_receipts AS r
JOIN mesh.mesh_write_receipt_documents AS d ON d.receipt_id = r.receipt_id
WHERE r.receipt_id = $1::uuid AND d.document_key = $2`

func scanReceipt(row rowScanner, receiptID string) (WriteReceipt, error) {
	var (
		receipt WriteReceipt
		hash    []byte
		domain  string
	)
	receipt.ID = receiptID
	err := row.Scan(
		&receipt.OperationClass,
		&domain,
		&receipt.BaseRevision,
		&receipt.CommittedRevision,
		&hash,
		&receipt.CommittedAt,
	)
	if err != nil {
		return WriteReceipt{}, err
	}
	receipt.Domain = Domain(domain)
	if err := validateReceipt(receipt, hash); err != nil {
		return WriteReceipt{}, err
	}
	copy(receipt.SHA256[:], hash)
	return receipt, nil
}

func validateReceipt(receipt WriteReceipt, hash []byte) error {
	if err := validateDomain(receipt.Domain); err != nil {
		return err
	}
	if err := validateOperationClass(receipt.OperationClass); err != nil {
		return err
	}
	if !validCanonicalUUID(receipt.ID) {
		return errors.New("receipt has an invalid UUID")
	}
	if receipt.BaseRevision < 0 || receipt.CommittedRevision != receipt.BaseRevision+1 {
		return errors.New("receipt has invalid revision metadata")
	}
	if len(hash) != sha256.Size {
		return errors.New("receipt has an invalid SHA-256 length")
	}
	if receipt.CommittedAt.IsZero() {
		return errors.New("receipt has an invalid commit time")
	}
	return nil
}

func receiptMatches(actual, expected WriteReceipt) bool {
	return actual.ID == expected.ID &&
		actual.OperationClass == expected.OperationClass &&
		actual.Domain == expected.Domain &&
		actual.BaseRevision == expected.BaseRevision &&
		actual.CommittedRevision == expected.CommittedRevision &&
		subtle.ConstantTimeCompare(actual.SHA256[:], expected.SHA256[:]) == 1
}

const selectDocumentSQL = `
SELECT document_key,
       revision,
       CASE WHEN octet_length(document_bytes) BETWEEN 1 AND $2
            THEN document_bytes ELSE NULL END,
       octet_length(document_bytes),
       document_sha256,
       last_write_receipt::text,
       updated_at
FROM mesh.mesh_state_documents
WHERE document_key = $1`

const selectDocumentForUpdateSQL = selectDocumentSQL + ` FOR UPDATE`

const selectDocumentPairSQL = `
SELECT control.document_key,
       control.revision,
       CASE WHEN octet_length(control.document_bytes) BETWEEN 1 AND $3
            THEN control.document_bytes ELSE NULL END,
       octet_length(control.document_bytes),
       control.document_sha256,
       control.last_write_receipt::text,
       control.updated_at,
       identity.document_key,
       identity.revision,
       CASE WHEN octet_length(identity.document_bytes) BETWEEN 1 AND $4
            THEN identity.document_bytes ELSE NULL END,
       octet_length(identity.document_bytes),
       identity.document_sha256,
       identity.last_write_receipt::text,
       identity.updated_at
FROM mesh.mesh_state_documents AS control
CROSS JOIN mesh.mesh_state_documents AS identity
WHERE control.document_key = $1
  AND identity.document_key = $2`

func scanDocument(row rowScanner, expectedDomain Domain) (Document, error) {
	var (
		document  Document
		domain    string
		bodySize  int64
		storedSHA []byte
	)
	if err := row.Scan(
		&domain,
		&document.Revision,
		&document.Bytes,
		&bodySize,
		&storedSHA,
		&document.LastWriteID,
		&document.UpdatedAt,
	); err != nil {
		return Document{}, err
	}
	return validateScannedDocument(document, domain, bodySize, storedSHA, expectedDomain)
}

func scanDocumentPair(row rowScanner) (Document, Document, error) {
	var (
		control, identity             Document
		controlDomain, identityDomain string
		controlSize, identitySize     int64
		controlSHA, identitySHA       []byte
	)
	if err := row.Scan(
		&controlDomain,
		&control.Revision,
		&control.Bytes,
		&controlSize,
		&controlSHA,
		&control.LastWriteID,
		&control.UpdatedAt,
		&identityDomain,
		&identity.Revision,
		&identity.Bytes,
		&identitySize,
		&identitySHA,
		&identity.LastWriteID,
		&identity.UpdatedAt,
	); err != nil {
		return Document{}, Document{}, err
	}
	control, err := validateScannedDocument(control, controlDomain, controlSize, controlSHA, DomainControl)
	if err != nil {
		clear(identity.Bytes)
		return Document{}, Document{}, err
	}
	identity, err = validateScannedDocument(identity, identityDomain, identitySize, identitySHA, DomainIdentity)
	if err != nil {
		clear(control.Bytes)
		return Document{}, Document{}, err
	}
	return control, identity, nil
}

func validateScannedDocument(document Document, domain string, bodySize int64, storedSHA []byte, expectedDomain Domain) (Document, error) {
	document.Domain = Domain(domain)
	if document.Domain != expectedDomain {
		return Document{}, fmt.Errorf("%w: requested %s but read %q", ErrCorruptDocument, expectedDomain, domain)
	}
	limit, err := maxDocumentBytes(document.Domain)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrCorruptDocument, err)
	}
	if bodySize < 1 || bodySize > int64(limit) || int64(len(document.Bytes)) != bodySize {
		return Document{}, fmt.Errorf("%w: %s body length %d is outside its safety bound", ErrCorruptDocument, document.Domain, bodySize)
	}
	if document.Revision <= 0 || document.Revision >= math.MaxInt64 {
		return Document{}, fmt.Errorf("%w: invalid %s revision %d", ErrCorruptDocument, document.Domain, document.Revision)
	}
	if len(storedSHA) != sha256.Size {
		return Document{}, fmt.Errorf("%w: invalid %s SHA-256 length", ErrCorruptDocument, document.Domain)
	}
	computed := sha256.Sum256(document.Bytes)
	if subtle.ConstantTimeCompare(storedSHA, computed[:]) != 1 {
		return Document{}, fmt.Errorf("%w: %s SHA-256 mismatch", ErrCorruptDocument, document.Domain)
	}
	copy(document.SHA256[:], storedSHA)
	if !validCanonicalUUID(document.LastWriteID) {
		return Document{}, fmt.Errorf("%w: invalid %s last-write receipt UUID", ErrCorruptDocument, document.Domain)
	}
	if document.UpdatedAt.IsZero() {
		return Document{}, fmt.Errorf("%w: invalid %s update time", ErrCorruptDocument, document.Domain)
	}
	return document, nil
}

func generateUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || strings.ToLower(value) != value {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16
}

// Package postgresstore provides an exact-byte, revisioned PostgreSQL document
// primitive for Mesh's control and identity state. It deliberately does not
// decode application state or replace the existing file stores.
package postgresstore

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"time"
)

type Domain string

const (
	DomainControl  Domain = "control"
	DomainIdentity Domain = "identity"
	// DomainRuntimeTelemetry is an independently versioned, reconstructible
	// observation plane. It is deliberately absent from authenticated two-
	// document backup import and from ReadPair.
	DomainRuntimeTelemetry Domain = "runtime_telemetry"

	MaxControlDocumentBytes          = 64 << 20
	MaxIdentityDocumentBytes         = 8 << 20
	MaxRuntimeTelemetryDocumentBytes = 32 << 20

	defaultCommitResolutionTimeout = 5 * time.Second
	defaultCommitTimeout           = 10 * time.Second
	defaultMigrationBuild          = "mesh-postgresstore"
	maxMigrationBuildBytes         = 256

	OperationInitialize = "document.initialize"
	OperationImport     = "storage.import"

	ImportSourceFormat      = "mesh-json-two-document-v1"
	ImportControlVersionMin = 2
	ImportControlVersionMax = 12
	// ImportControlVersion is the current version emitted by a freshly started
	// server. Older authenticated archives remain eligible for the ordered
	// topology, managed-DNS, managed-relay, CA-lifecycle, firewall-rollout,
	// firewall-pause, route-transfer, and route-profile transitions.
	ImportControlVersion  = ImportControlVersionMax
	ImportIdentitySchema  = "identity-state-v2"
	MaxImporterBuildBytes = 256
)

func validImportControlVersion(version int) bool {
	return version >= ImportControlVersionMin && version <= ImportControlVersionMax
}

var (
	ErrAlreadyInitialized  = errors.New("document is already initialized with different bytes")
	ErrAlreadyImported     = errors.New("postgres state has already been imported")
	ErrClosed              = errors.New("postgres document store is closed")
	ErrCorruptDocument     = errors.New("postgres document is corrupt")
	ErrInvalidDomain       = errors.New("invalid postgres document domain")
	ErrInvalidOperation    = errors.New("invalid postgres write operation class")
	ErrInvalidImportSource = errors.New("invalid postgres import source")
	ErrImportProvenance    = errors.New("postgres import provenance is invalid")
	ErrNotCommitted        = errors.New("postgres transaction was not committed")
	ErrNotInitialized      = errors.New("postgres document is not initialized")
	ErrNotEmpty            = errors.New("postgres state storage is not empty")
	ErrSchemaNotReady      = errors.New("postgres schema is not ready")
	ErrUncertainCommit     = errors.New("postgres commit outcome is uncertain")
	ErrUnwritablePrimary   = errors.New("postgres endpoint is not a writable primary")
)

var operationClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var backupIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var importerBuildPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,255}$`)

// Options configures bounded transaction behavior and migration provenance.
type Options struct {
	MigrationBuild          string
	CommitTimeout           time.Duration
	CommitResolutionTimeout time.Duration
}

type normalizedOptions struct {
	migrationBuild          string
	commitTimeout           time.Duration
	commitResolutionTimeout time.Duration
}

func normalizeOptions(in Options) (normalizedOptions, error) {
	out := normalizedOptions{
		migrationBuild:          in.MigrationBuild,
		commitTimeout:           in.CommitTimeout,
		commitResolutionTimeout: in.CommitResolutionTimeout,
	}
	if out.migrationBuild == "" {
		out.migrationBuild = defaultMigrationBuild
	}
	if len(out.migrationBuild) > maxMigrationBuildBytes {
		return normalizedOptions{}, fmt.Errorf("migration build identifier exceeds %d bytes", maxMigrationBuildBytes)
	}
	if out.commitTimeout == 0 {
		out.commitTimeout = defaultCommitTimeout
	}
	if out.commitTimeout < 0 {
		return normalizedOptions{}, errors.New("commit timeout must not be negative")
	}
	if out.commitResolutionTimeout == 0 {
		out.commitResolutionTimeout = defaultCommitResolutionTimeout
	}
	if out.commitResolutionTimeout < 0 {
		return normalizedOptions{}, errors.New("commit resolution timeout must not be negative")
	}
	return out, nil
}

func validateDomain(domain Domain) error {
	switch domain {
	case DomainControl, DomainIdentity, DomainRuntimeTelemetry:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
}

func maxDocumentBytes(domain Domain) (int, error) {
	switch domain {
	case DomainControl:
		return MaxControlDocumentBytes, nil
	case DomainIdentity:
		return MaxIdentityDocumentBytes, nil
	case DomainRuntimeTelemetry:
		return MaxRuntimeTelemetryDocumentBytes, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
}

func validateDocumentBytes(domain Domain, body []byte) error {
	limit, err := maxDocumentBytes(domain)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("document must not be empty")
	}
	if len(body) > limit {
		return fmt.Errorf("%s document exceeds the %d-byte safety limit", domain, limit)
	}
	return nil
}

func validateOperationClass(operationClass string) error {
	if !operationClassPattern.MatchString(operationClass) {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operationClass)
	}
	return nil
}

type Document struct {
	Domain      Domain
	Revision    int64
	Bytes       []byte
	SHA256      [sha256.Size]byte
	LastWriteID string
	UpdatedAt   time.Time
}

func (d Document) clone() Document {
	d.Bytes = append([]byte(nil), d.Bytes...)
	return d
}

type WriteReceipt struct {
	ID                string
	OperationClass    string
	Domain            Domain
	BaseRevision      int64
	CommittedRevision int64
	SHA256            [sha256.Size]byte
	CommittedAt       time.Time
}

type WriteResult struct {
	Changed  bool
	Document Document
	Receipt  WriteReceipt
}

// ImportSource contains already-authenticated, exact persisted bytes. The
// caller remains responsible for strict application decoding and cryptographic
// recovery validation before invoking Import.
type ImportSource struct {
	ControlBytes          []byte
	IdentityBytes         []byte
	SourceFormat          string
	ControlVersion        int
	IdentitySchema        string
	AuthenticatedBackupID string
	ImporterBuild         string
}

type ImportResult struct {
	ImportID   string
	ReceiptID  string
	ImportedAt time.Time
	Control    Document
	Identity   Document
}

// UncertainWrite contains safe operator diagnostics for a commit whose exact
// outcome could not be proved. It intentionally omits document bytes and hash.
type UncertainWrite struct {
	ReceiptID      string
	OperationClass string
	Domain         Domain
	BaseRevision   int64
	TargetRevision int64
}

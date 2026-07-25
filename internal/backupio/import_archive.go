package backupio

import (
	"time"
)

// ImportArchiveOptions identifies one authenticated backup archive. The
// expected ID is mandatory so an operator cannot accidentally import a valid
// but unintended archive.
type ImportArchiveOptions struct {
	KeyFile          string
	ArchivePath      string
	ExpectedBackupID string
}

// ImportArchiveMetadata is the non-secret provenance authenticated by the
// encrypted archive.
type ImportArchiveMetadata struct {
	BackupID       string
	CapturedAt     time.Time
	ControlVersion int
	IdentitySchema string
}

// ValidatedImportArchive holds exact, detached persisted documents plus the
// recovered credentials needed to revalidate a database copy. Credentials are
// deliberately private and are never exposed to callers.
//
// Call Clear as soon as the import or verification operation finishes. Clear
// zeroes all document and credential buffers before releasing their slices.
type ValidatedImportArchive struct {
	ControlBytes  []byte
	IdentityBytes []byte
	Metadata      ImportArchiveMetadata

	masterKey  []byte
	adminToken []byte
	cleared    bool
}

// Clear performs best-effort in-process zeroization and is idempotent. Any
// aliases previously taken from the exported document fields observe zeroes.
func (archive *ValidatedImportArchive) Clear() {
	if archive == nil || archive.cleared {
		return
	}
	clear(archive.ControlBytes)
	clear(archive.IdentityBytes)
	clear(archive.masterKey)
	clear(archive.adminToken)
	archive.ControlBytes = nil
	archive.IdentityBytes = nil
	archive.masterKey = nil
	archive.adminToken = nil
	archive.cleared = true
}

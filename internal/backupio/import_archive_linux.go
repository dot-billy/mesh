//go:build linux

package backupio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"time"

	"mesh/internal/backup"
	"mesh/internal/control"
)

const (
	importControlVersionMin = 2
	importControlVersionMax = control.ControlStateVersionFirewallScopes
	importIdentitySchema    = "identity-state-v2"
)

// ValidateExactDocuments proves that controlRaw and identityRaw are exact
// copies of the authenticated archive documents, then repeats the full
// credential-bound control and sealed-identity recovery validation over those
// caller-supplied bytes. It never modifies its inputs.
func (archive *ValidatedImportArchive) ValidateExactDocuments(ctx context.Context, controlRaw, identityRaw []byte) error {
	if ctx == nil {
		return errors.New("backup import validation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if archive == nil || archive.cleared || len(archive.masterKey) == 0 || len(archive.adminToken) == 0 {
		return errors.New("validated backup import archive has been cleared")
	}
	if !constantTimeExact(controlRaw, archive.ControlBytes) || !constantTimeExact(identityRaw, archive.IdentityBytes) {
		return errors.New("database documents do not exactly match the authenticated backup archive")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controlVersion, identitySchema, err := validateSnapshotBodies(controlRaw, identityRaw, archive.masterKey, archive.adminToken)
	if err != nil {
		return err
	}
	if int(controlVersion) != archive.Metadata.ControlVersion || identitySchema != archive.Metadata.IdentitySchema {
		return errors.New("database document metadata does not match the authenticated backup archive")
	}
	return ctx.Err()
}

func constantTimeExact(left, right []byte) bool {
	leftHash := sha256.Sum256(left)
	rightHash := sha256.Sum256(right)
	hashesMatch := subtle.ConstantTimeCompare(leftHash[:], rightHash[:])
	bytesMatch := subtle.ConstantTimeCompare(left, right)
	return hashesMatch&bytesMatch == 1
}

// OpenValidatedImportArchive performs a stable, owner-private read of the key
// and archive, authenticates and decrypts the complete archive, enforces the
// operator-selected backup ID, and cryptographically validates both recovered
// state documents. It is intentionally Linux-only because the backup reader's
// inode, ownership, and directory guarantees are Linux-specific.
func OpenValidatedImportArchive(ctx context.Context, options ImportArchiveOptions) (*ValidatedImportArchive, error) {
	if ctx == nil {
		return nil, errors.New("backup import context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validLowerHex(options.ExpectedBackupID, 16) {
		return nil, errors.New("--expect-backup-id must be an exact canonical backup ID")
	}

	key, envelope, _, inspected, err := readArchive(ArchiveOptions{
		KeyFile: options.KeyFile, ArchivePath: options.ArchivePath,
	})
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(envelope)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(options.ExpectedBackupID), []byte(inspected.BackupID)) != 1 {
		return nil, errors.New("expected backup ID does not match the authenticated archive")
	}

	contents, err := backup.Open(key, envelope)
	if err != nil {
		return nil, fmt.Errorf("open backup archive: %w", err)
	}
	defer clearContents(&contents)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sameImportManifest(inspected, contents.Manifest) {
		return nil, errors.New("backup manifest changed between authenticated archive reads")
	}
	controlVersion, identitySchema, err := validateSnapshotBodies(
		contents.StateJSON,
		contents.IdentityStateJSON,
		contents.MasterKey,
		contents.AdminToken,
	)
	if err != nil {
		return nil, err
	}
	if controlVersion < importControlVersionMin || controlVersion > importControlVersionMax ||
		contents.Manifest.ControlVersion < importControlVersionMin || contents.Manifest.ControlVersion > importControlVersionMax {
		return nil, errors.New("backup import requires exact control state version 2, 3, 4, or 5")
	}
	if identitySchema != importIdentitySchema || contents.Manifest.IdentitySchema != importIdentitySchema {
		return nil, errors.New("backup import requires exact identity-state-v2 state")
	}
	capturedAt, err := time.Parse(time.RFC3339, contents.Manifest.CapturedAt)
	if err != nil || capturedAt.IsZero() {
		return nil, errors.New("backup manifest has an invalid capture time")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	archive := &ValidatedImportArchive{
		ControlBytes:  bytes.Clone(contents.StateJSON),
		IdentityBytes: bytes.Clone(contents.IdentityStateJSON),
		Metadata: ImportArchiveMetadata{
			BackupID:       contents.Manifest.BackupID,
			CapturedAt:     capturedAt,
			ControlVersion: int(controlVersion),
			IdentitySchema: identitySchema,
		},
		masterKey:  bytes.Clone(contents.MasterKey),
		adminToken: bytes.Clone(contents.AdminToken),
	}
	return archive, nil
}

func sameImportManifest(left, right backup.Manifest) bool {
	// Both manifests have already passed strict canonical decoding. Compare the
	// complete values so future authenticated fields cannot be silently skipped.
	return reflect.DeepEqual(left, right)
}

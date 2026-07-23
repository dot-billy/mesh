//go:build linux

package backupio

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mesh/internal/backup"
)

type restoreReceipt struct {
	Schema              string `json:"schema"`
	BackupID            string `json:"backup_id"`
	OperationID         string `json:"operation_id"`
	TargetDir           string `json:"target_dir"`
	RestoredAt          string `json:"restored_at"`
	ControlStateSHA256  string `json:"control_state_sha256"`
	IdentityStateSHA256 string `json:"identity_state_sha256"`
	ReceiptHMACSHA256   string `json:"receipt_hmac_sha256"`
}

func validLowerHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	valid := err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func canonicalUTCSecond(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Nanosecond() == 0 && parsed.Format(time.RFC3339) == value
}

func newOperationID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	clear(raw)
	return id, nil
}

func validateMarker(marker restoreMarker, expectedTarget string) error {
	if marker.Schema != RestoreMarkerSchema || !validLowerHex(marker.BackupID, 16) || !validLowerHex(marker.OperationID, 16) {
		return errors.New("restore marker has invalid schema or identifiers")
	}
	if marker.Target != expectedTarget {
		return errors.New("restore marker target does not match the requested target")
	}
	if marker.CreatedAt.Location() != time.UTC || marker.CreatedAt.Nanosecond() != 0 || marker.CreatedAt.IsZero() {
		return errors.New("restore marker has a non-canonical creation time")
	}
	return nil
}

func validateReceipt(receipt restoreReceipt, marker restoreMarker) error {
	if receipt.Schema != RestoreReceiptSchema || receipt.BackupID != marker.BackupID || receipt.OperationID != marker.OperationID || receipt.TargetDir != marker.Target {
		return errors.New("restore receipt does not match the restore marker")
	}
	if !canonicalUTCSecond(receipt.RestoredAt) || !validLowerHex(receipt.ControlStateSHA256, sha256.Size) || !validLowerHex(receipt.IdentityStateSHA256, sha256.Size) || !validLowerHex(receipt.ReceiptHMACSHA256, sha256.Size) {
		return errors.New("restore receipt contains non-canonical metadata")
	}
	return nil
}

func appendLengthPrefixed(buffer *strings.Builder, name, value string) {
	buffer.WriteString(name)
	buffer.WriteByte('=')
	buffer.WriteString(strconv.Itoa(len(value)))
	buffer.WriteByte('\n')
	buffer.WriteString(value)
	buffer.WriteByte('\n')
}

func receiptMAC(receipt restoreReceipt, masterKey, masterBody, adminBody []byte) string {
	derive := hmac.New(sha256.New, masterKey)
	_, _ = derive.Write([]byte("mesh-restore-receipt-subkey-v1"))
	subkey := derive.Sum(nil)
	defer clear(subkey)

	var public strings.Builder
	public.WriteString("mesh-restore-receipt-v1\n")
	appendLengthPrefixed(&public, "schema", receipt.Schema)
	appendLengthPrefixed(&public, "backup_id", receipt.BackupID)
	appendLengthPrefixed(&public, "operation_id", receipt.OperationID)
	appendLengthPrefixed(&public, "target_dir", receipt.TargetDir)
	appendLengthPrefixed(&public, "restored_at", receipt.RestoredAt)
	appendLengthPrefixed(&public, "control_state_sha256", receipt.ControlStateSHA256)
	appendLengthPrefixed(&public, "identity_state_sha256", receipt.IdentityStateSHA256)

	mac := hmac.New(sha256.New, subkey)
	_, _ = mac.Write([]byte(public.String()))
	_, _ = mac.Write([]byte("master.key=" + strconv.Itoa(len(masterBody)) + "\n"))
	_, _ = mac.Write(masterBody)
	_, _ = mac.Write([]byte("admin.token=" + strconv.Itoa(len(adminBody)) + "\n"))
	_, _ = mac.Write(adminBody)
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalSecretBodies(masterKey, adminToken []byte) ([]byte, []byte) {
	masterBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(masterKey))+1)
	base64.RawURLEncoding.Encode(masterBody[:len(masterBody)-1], masterKey)
	masterBody[len(masterBody)-1] = '\n'
	adminBody := make([]byte, len(adminToken)+1)
	copy(adminBody, adminToken)
	adminBody[len(adminBody)-1] = '\n'
	return masterBody, adminBody
}

func decodeRecoveredMaster(raw []byte) ([]byte, error) {
	if len(raw) != backupKeyFileLen || raw[len(raw)-1] != '\n' || strings.ContainsRune(string(raw), '\r') {
		return nil, errors.New("recovered master.key is not canonical")
	}
	encoded := string(raw[:len(raw)-1])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errors.New("recovered master.key is not canonical")
	}
	return decoded, nil
}

func decodeRecoveredAdmin(raw []byte) ([]byte, error) {
	if len(raw) < 33 || len(raw) > 4097 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("recovered admin.token is not canonical")
	}
	token := append([]byte(nil), raw[:len(raw)-1]...)
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			clear(token)
			return nil, errors.New("recovered admin.token is not canonical")
		}
	}
	return token, nil
}

func digestHex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (operations unixOperations) Restore(ctx context.Context, options RestoreOptions) (result ArchiveResult, resultErr error) {
	if ctx == nil {
		return ArchiveResult{}, errors.New("backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	if !validLowerHex(options.ExpectedBackupID, 16) {
		return ArchiveResult{}, errors.New("--expect-backup-id must be an exact canonical backup ID")
	}
	target, err := cleanAbsolute(options.TargetDir, "restore target", false)
	if err != nil {
		return ArchiveResult{}, err
	}
	key, envelope, _, manifest, err := readArchive(ArchiveOptions{KeyFile: options.KeyFile, ArchivePath: options.ArchivePath})
	if err != nil {
		return ArchiveResult{}, err
	}
	defer clear(key)
	defer clear(envelope)
	if subtle.ConstantTimeCompare([]byte(options.ExpectedBackupID), []byte(manifest.BackupID)) != 1 {
		return ArchiveResult{}, errors.New("expected backup ID does not match the authenticated archive")
	}
	contents, err := backup.Open(key, envelope)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("open backup archive: %w", err)
	}
	defer clearContents(&contents)
	controlVersion, identitySchema, err := validateSnapshotBodies(contents.StateJSON, contents.IdentityStateJSON, contents.MasterKey, contents.AdminToken)
	if err != nil {
		return ArchiveResult{}, err
	}
	if controlVersion != manifest.ControlVersion || identitySchema != manifest.IdentitySchema {
		return ArchiveResult{}, errors.New("backup manifest store metadata does not match recovered state")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	fence, err := AcquireStartupFence(target)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("acquire restore parent fence: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, fence.Close())
	}()

	parent, targetName, err := openParent(target, "restore target", true)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer parent.Close()
	if err := fence.verifyParent(); err != nil {
		return ArchiveResult{}, err
	}
	if _, err := parent.root.Lstat(targetName); err == nil {
		return ArchiveResult{}, errors.New("restore target already exists; in-place and overwrite restores are forbidden")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArchiveResult{}, fmt.Errorf("inspect restore target: %w", err)
	}
	markerPath, err := RestoreMarkerPath(target)
	if err != nil {
		return ArchiveResult{}, err
	}
	markerName := filepath.Base(markerPath)
	if _, err := parent.root.Lstat(markerName); err == nil {
		return ArchiveResult{}, fmt.Errorf("%w: marker already exists at %s", ErrIncompleteRestore, markerPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArchiveResult{}, fmt.Errorf("inspect restore marker: %w", err)
	}
	operationID, err := newOperationID()
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("generate restore operation ID: %w", err)
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	restoredAt := now().UTC().Truncate(time.Second)
	marker := restoreMarker{Schema: RestoreMarkerSchema, BackupID: manifest.BackupID, OperationID: operationID, Target: target, CreatedAt: restoredAt}
	markerRaw, err := encodeJSONLine(marker)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("encode restore marker: %w", err)
	}
	if err := writeNewSynced(parent.root, markerName, "restore marker", markerRaw, 0o600); err != nil {
		return ArchiveResult{}, err
	}
	if err := syncRoot(parent.root); err != nil {
		return ArchiveResult{}, fmt.Errorf("sync restore marker directory: %w", err)
	}
	// From this point onward every failure deliberately leaves the exact marker.
	if err := parent.root.Mkdir(targetName, 0o700); err != nil {
		return ArchiveResult{}, fmt.Errorf("create restore target: %w", err)
	}
	if err := parent.root.Chmod(targetName, 0o700); err != nil {
		return ArchiveResult{}, fmt.Errorf("set restore target mode: %w", err)
	}
	if err := syncRoot(parent.root); err != nil {
		return ArchiveResult{}, fmt.Errorf("sync new restore target directory entry: %w", err)
	}
	targetRoot, err := openVerifiedRoot(target, "restore target", true)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer targetRoot.Close()
	masterBody, adminBody := canonicalSecretBodies(contents.MasterKey, contents.AdminToken)
	defer clear(masterBody)
	defer clear(adminBody)
	files := []struct {
		name string
		raw  []byte
	}{
		{ControlStateName, contents.StateJSON},
		{IdentityStateName, contents.IdentityStateJSON},
		{MasterKeyName, masterBody},
		{AdminTokenName, adminBody},
	}
	for _, file := range files {
		if err := writeNewSynced(targetRoot.root, file.name, "restored "+file.name, file.raw, 0o600); err != nil {
			return ArchiveResult{}, err
		}
	}
	receipt := restoreReceipt{
		Schema: RestoreReceiptSchema, BackupID: manifest.BackupID, OperationID: operationID,
		TargetDir: target, RestoredAt: restoredAt.Format(time.RFC3339),
		ControlStateSHA256: digestHex(contents.StateJSON), IdentityStateSHA256: digestHex(contents.IdentityStateJSON),
	}
	receipt.ReceiptHMACSHA256 = receiptMAC(receipt, contents.MasterKey, masterBody, adminBody)
	receiptRaw, err := encodeJSONLine(receipt)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("encode restore receipt: %w", err)
	}
	if err := writeNewSynced(targetRoot.root, ReceiptName, "restore receipt", receiptRaw, 0o600); err != nil {
		return ArchiveResult{}, err
	}
	if err := requireExactRestoredEntries(targetRoot.root); err != nil {
		return ArchiveResult{}, err
	}
	if err := validateRestoredTarget(targetRoot, marker, receipt); err != nil {
		return ArchiveResult{}, err
	}
	if err := syncRoot(targetRoot.root); err != nil {
		return ArchiveResult{}, fmt.Errorf("sync restored target: %w", err)
	}
	if err := fence.verifyParent(); err != nil {
		return ArchiveResult{}, err
	}
	if err := removeMarker(parent.root, markerName, markerRaw, operations.beforeMarkerDrop); err != nil {
		return ArchiveResult{}, err
	}
	capturedAt, _ := time.Parse(time.RFC3339, manifest.CapturedAt)
	return ArchiveResult{
		Schema: commandResultSchema, Status: "restored", BackupID: manifest.BackupID,
		CreatedAt: capturedAt, ArchivePath: options.ArchivePath, TargetDir: target, OperationID: operationID,
	}, nil
}

func removeMarker(parent *os.Root, markerName string, expectedRaw []byte, beforeDrop func() error) error {
	current, _, err := readStableFile(parent, markerName, "restore marker", maxMarkerSize, true)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(current, expectedRaw) != 1 {
		return errors.New("restore marker changed before finalization")
	}
	if beforeDrop != nil {
		if err := beforeDrop(); err != nil {
			return fmt.Errorf("restore marker removal interrupted: %w", err)
		}
	}
	if err := parent.Remove(markerName); err != nil {
		return fmt.Errorf("remove restore marker: %w", err)
	}
	if err := syncRoot(parent); err != nil {
		// Re-establish the fence after an uncertain unlink durability barrier.
		// The caller must never observe a failed restore/finalization that
		// knowingly leaves an unfenced target.
		recreateErr := writeNewSynced(parent, markerName, "restore marker recovery", expectedRaw, 0o600)
		var recoverySyncErr error
		if recreateErr == nil {
			recoverySyncErr = syncRoot(parent)
		}
		return fmt.Errorf("sync restore marker removal: %w (marker recovery: %v)", err, errors.Join(recreateErr, recoverySyncErr))
	}
	return nil
}

func validateExactMode(info os.FileInfo, label string, mode os.FileMode) error {
	if err := requirePrivateRegular(info, label, true); err != nil {
		return err
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s mode is %04o, expected %04o", label, info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func requireExactRestoredEntries(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open restored target for entry verification: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("list restored target: %w", err)
	}
	expected := map[string]bool{
		ControlStateName: false, IdentityStateName: false, MasterKeyName: false,
		AdminTokenName: false, ReceiptName: false,
	}
	if len(entries) != len(expected) {
		return errors.New("restored target must contain exactly the four recovered files and the restore receipt")
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("restored target contains unexpected entry %q", entry.Name())
		}
		expected[entry.Name()] = true
	}
	for name, found := range expected {
		if !found {
			return fmt.Errorf("restored target is missing %q", name)
		}
	}
	return nil
}

func syncRecoveredFiles(root *os.Root, hook func(*os.File, string) error) error {
	files := []struct {
		name  string
		label string
		limit int64
	}{
		{ControlStateName, "restored control state", backup.MaxControlStateSize},
		{IdentityStateName, "restored identity state", backup.MaxIdentityStateSize},
		{MasterKeyName, "restored master key", maxSecretFile},
		{AdminTokenName, "restored admin token", maxSecretFile + 1},
		{ReceiptName, "restore receipt", maxMarkerSize},
	}
	for _, item := range files {
		file, info, err := openStableFile(root, item.name, item.label, item.limit, true)
		if err != nil {
			return err
		}
		if err := validateExactMode(info, item.label, 0o600); err != nil {
			_ = file.Close()
			return err
		}
		syncFile := func(file *os.File, _ string) error { return file.Sync() }
		if hook != nil {
			syncFile = hook
		}
		syncErr := syncFile(file, item.name)
		closeErr := file.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return fmt.Errorf("sync %s before restore finalization: %w", item.label, err)
		}
	}
	return nil
}

func validateRestoredTarget(root *verifiedRoot, marker restoreMarker, receipt restoreReceipt) error {
	controlRaw, controlInfo, err := readStableFile(root.root, ControlStateName, "restored control state", backup.MaxControlStateSize, true)
	if err != nil {
		return err
	}
	defer clear(controlRaw)
	identityRaw, identityInfo, err := readStableFile(root.root, IdentityStateName, "restored identity state", backup.MaxIdentityStateSize, true)
	if err != nil {
		return err
	}
	defer clear(identityRaw)
	masterBody, masterInfo, err := readStableFile(root.root, MasterKeyName, "restored master key", maxSecretFile, true)
	if err != nil {
		return err
	}
	defer clear(masterBody)
	adminBody, adminInfo, err := readStableFile(root.root, AdminTokenName, "restored admin token", maxSecretFile+1, true)
	if err != nil {
		return err
	}
	defer clear(adminBody)
	receiptRaw, receiptInfo, err := readStableFile(root.root, ReceiptName, "restore receipt", maxMarkerSize, true)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		info  os.FileInfo
		label string
	}{{controlInfo, "restored control state"}, {identityInfo, "restored identity state"}, {masterInfo, "restored master key"}, {adminInfo, "restored admin token"}, {receiptInfo, "restore receipt"}} {
		if err := validateExactMode(item.info, item.label, 0o600); err != nil {
			return err
		}
	}
	var diskReceipt restoreReceipt
	if err := decodeStrictJSON(receiptRaw, &diskReceipt); err != nil {
		return fmt.Errorf("decode restore receipt: %w", err)
	}
	if diskReceipt != receipt {
		return errors.New("restore receipt changed during verification")
	}
	if err := validateReceipt(diskReceipt, marker); err != nil {
		return err
	}
	masterKey, err := decodeRecoveredMaster(masterBody)
	if err != nil {
		return err
	}
	defer clear(masterKey)
	adminToken, err := decodeRecoveredAdmin(adminBody)
	if err != nil {
		return err
	}
	defer clear(adminToken)
	if digestHex(controlRaw) != receipt.ControlStateSHA256 || digestHex(identityRaw) != receipt.IdentityStateSHA256 {
		return errors.New("restored state digest does not match the receipt")
	}
	expectedMAC := receiptMAC(receipt, masterKey, masterBody, adminBody)
	if subtle.ConstantTimeCompare([]byte(expectedMAC), []byte(receipt.ReceiptHMACSHA256)) != 1 {
		return errors.New("restore receipt integrity check failed")
	}
	if _, _, err := validateSnapshotBodies(controlRaw, identityRaw, masterKey, adminToken); err != nil {
		return err
	}
	return nil
}

func (operations unixOperations) FinalizeRestore(ctx context.Context, options FinalizeRestoreOptions) (result ArchiveResult, resultErr error) {
	if ctx == nil {
		return ArchiveResult{}, errors.New("backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	target, err := cleanAbsolute(options.TargetDir, "restore target", false)
	if err != nil {
		return ArchiveResult{}, err
	}
	fence, err := AcquireStartupFence(target)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("acquire restore finalization parent fence: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, fence.Close())
	}()
	parent, _, err := openParent(target, "restore target", true)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer parent.Close()
	if err := fence.verifyParent(); err != nil {
		return ArchiveResult{}, err
	}
	markerPath, err := RestoreMarkerPath(target)
	if err != nil {
		return ArchiveResult{}, err
	}
	markerName := filepath.Base(markerPath)
	markerRaw, markerInfo, err := readStableFile(parent.root, markerName, "restore marker", maxMarkerSize, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ArchiveResult{}, errors.New("no incomplete restore marker exists for the target")
		}
		return ArchiveResult{}, err
	}
	if err := validateExactMode(markerInfo, "restore marker", 0o600); err != nil {
		return ArchiveResult{}, err
	}
	var marker restoreMarker
	if err := decodeStrictJSON(markerRaw, &marker); err != nil {
		return ArchiveResult{}, fmt.Errorf("decode restore marker: %w", err)
	}
	if err := validateMarker(marker, target); err != nil {
		return ArchiveResult{}, err
	}
	targetRoot, err := openVerifiedRoot(target, "restore target", true)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer targetRoot.Close()
	if err := requireExactRestoredEntries(targetRoot.root); err != nil {
		return ArchiveResult{}, err
	}
	// A failed earlier Restore may have returned after writing bytes but before
	// a file Sync completed. Finalization retries every file barrier; a
	// directory Sync alone cannot substitute for these data-durability proofs.
	if err := syncRecoveredFiles(targetRoot.root, operations.syncRecovered); err != nil {
		return ArchiveResult{}, err
	}
	receiptRaw, _, err := readStableFile(targetRoot.root, ReceiptName, "restore receipt", maxMarkerSize, true)
	if err != nil {
		return ArchiveResult{}, err
	}
	var receipt restoreReceipt
	if err := decodeStrictJSON(receiptRaw, &receipt); err != nil {
		return ArchiveResult{}, fmt.Errorf("decode restore receipt: %w", err)
	}
	if err := validateReceipt(receipt, marker); err != nil {
		return ArchiveResult{}, err
	}
	if err := validateRestoredTarget(targetRoot, marker, receipt); err != nil {
		return ArchiveResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	if err := syncRoot(targetRoot.root); err != nil {
		return ArchiveResult{}, fmt.Errorf("sync restored target before finalization: %w", err)
	}
	if err := fence.verifyParent(); err != nil {
		return ArchiveResult{}, err
	}
	if err := removeMarker(parent.root, markerName, markerRaw, operations.beforeMarkerDrop); err != nil {
		return ArchiveResult{}, err
	}
	restoredAt, _ := time.Parse(time.RFC3339, receipt.RestoredAt)
	return ArchiveResult{
		Schema: commandResultSchema, Status: "finalized", BackupID: receipt.BackupID,
		CreatedAt: restoredAt, TargetDir: target, OperationID: receipt.OperationID,
	}, nil
}

//go:build linux

package backupio

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mesh/internal/backup"
	"mesh/internal/control"
	"mesh/internal/identity"
)

const commandResultSchema = "mesh-backup-command-result-v1"

type heldLock struct {
	file *os.File
	name string
}

func acquireExistingLock(root *os.Root, name string) (*heldLock, error) {
	file, _, err := openStableFile(root, name, name, maxSecretFile, true)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%s is locked; stop mesh-server before taking an offline backup", name)
		}
		return nil, fmt.Errorf("lock %s: %w", name, err)
	}
	return &heldLock{file: file, name: name}, nil
}

func (l *heldLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if err := errors.Join(unlockErr, closeErr); err != nil {
		return fmt.Errorf("release %s: %w", l.name, err)
	}
	return nil
}

type sourceCapture struct {
	root         *verifiedRoot
	controlLock  *heldLock
	identityLock *heldLock
	controlFile  *os.File
	identityFile *os.File
	controlInfo  os.FileInfo
	identityInfo os.FileInfo
	controlRaw   []byte
	identityRaw  []byte
}

func (c *sourceCapture) Close() error {
	if c == nil {
		return nil
	}
	clear(c.controlRaw)
	clear(c.identityRaw)
	var result error
	if c.identityFile != nil {
		result = errors.Join(result, c.identityFile.Close())
		c.identityFile = nil
	}
	if c.controlFile != nil {
		result = errors.Join(result, c.controlFile.Close())
		c.controlFile = nil
	}
	// Release in reverse acquisition order.
	result = errors.Join(result, c.identityLock.Close(), c.controlLock.Close(), c.root.Close())
	return result
}

func captureSources(dataDir string) (*sourceCapture, error) {
	root, err := openVerifiedRoot(dataDir, "Mesh data directory", true)
	if err != nil {
		return nil, err
	}
	capture := &sourceCapture{root: root}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = capture.Close()
		}
	}()

	// This acquisition order matches mesh-server and is security-sensitive.
	capture.controlLock, err = acquireExistingLock(root.root, ".mesh.lock")
	if err != nil {
		return nil, err
	}
	capture.identityLock, err = acquireExistingLock(root.root, ".identity-state.json.lock")
	if err != nil {
		return nil, err
	}
	if err := RefuseIncompleteRestore(dataDir); err != nil {
		return nil, fmt.Errorf("refuse backup of an incomplete restore after store locks: %w", err)
	}
	capture.controlFile, capture.controlInfo, err = openStableFile(root.root, ControlStateName, "control state", backup.MaxControlStateSize, true)
	if err != nil {
		return nil, err
	}
	capture.identityFile, capture.identityInfo, err = openStableFile(root.root, IdentityStateName, "identity state", backup.MaxIdentityStateSize, true)
	if err != nil {
		return nil, err
	}
	if err := capture.controlFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync control state before capture: %w", err)
	}
	if err := capture.identityFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync identity state before capture: %w", err)
	}
	if err := syncRoot(root.root); err != nil {
		return nil, fmt.Errorf("sync Mesh data directory before capture: %w", err)
	}
	capture.controlRaw, err = readOpenedStable(root.root, ControlStateName, "control state", capture.controlFile, capture.controlInfo, backup.MaxControlStateSize)
	if err != nil {
		return nil, err
	}
	capture.identityRaw, err = readOpenedStable(root.root, IdentityStateName, "identity state", capture.identityFile, capture.identityInfo, backup.MaxIdentityStateSize)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return capture, nil
}

func (c *sourceCapture) proveUnchanged() error {
	controlAgain, err := readOpenedStable(c.root.root, ControlStateName, "control state", c.controlFile, c.controlInfo, backup.MaxControlStateSize)
	if err != nil {
		return err
	}
	defer clear(controlAgain)
	identityAgain, err := readOpenedStable(c.root.root, IdentityStateName, "identity state", c.identityFile, c.identityInfo, backup.MaxIdentityStateSize)
	if err != nil {
		return err
	}
	defer clear(identityAgain)
	controlBefore := sha256.Sum256(c.controlRaw)
	controlAfter := sha256.Sum256(controlAgain)
	identityBefore := sha256.Sum256(c.identityRaw)
	identityAfter := sha256.Sum256(identityAgain)
	if controlBefore != controlAfter || identityBefore != identityAfter {
		return errors.New("source state changed during backup")
	}
	return nil
}

func parseMasterKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("MESH_MASTER_KEY must be canonical unpadded base64url containing exactly 32 bytes")
	}
	return decoded, nil
}

func parseAdminToken(value string) ([]byte, error) {
	token := []byte(strings.TrimSpace(value))
	if len(token) < 32 || len(token) > 4096 {
		clear(token)
		return nil, errors.New("MESH_ADMIN_TOKEN must contain 32-4096 printable ASCII characters")
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			clear(token)
			return nil, errors.New("MESH_ADMIN_TOKEN must contain 32-4096 printable ASCII characters")
		}
	}
	return token, nil
}

func snapshotMetadata(controlRaw, identityRaw []byte) (uint64, string, error) {
	var controlHeader struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(controlRaw, &controlHeader); err != nil || controlHeader.Version < 1 {
		return 0, "", errors.New("control state has no valid version")
	}
	var identityHeader struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(identityRaw, &identityHeader); err != nil || identityHeader.Schema == "" {
		return 0, "", errors.New("identity state has no valid schema")
	}
	return uint64(controlHeader.Version), identityHeader.Schema, nil
}

func validateSnapshotBodies(controlRaw, identityRaw, masterKey, adminToken []byte) (uint64, string, error) {
	if err := control.ValidateRecoverySnapshotCredentials(controlRaw, masterKey, adminToken); err != nil {
		return 0, "", fmt.Errorf("validate control recovery state and credentials: %w", err)
	}
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		return 0, "", err
	}
	if err := identity.ValidateRecoverySnapshot(identityRaw, box); err != nil {
		return 0, "", fmt.Errorf("validate identity recovery state: %w", err)
	}
	return snapshotMetadata(controlRaw, identityRaw)
}

func pathsOverlapSource(dataDir, other, label string) error {
	dataDir, err := cleanAbsolute(dataDir, "Mesh data directory", false)
	if err != nil {
		return err
	}
	other, err = cleanAbsolute(other, label, false)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(dataDir, other)
	if err != nil {
		return fmt.Errorf("compare %s with source directory: %w", label, err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return fmt.Errorf("%s must not be equal to or inside the Mesh data directory", label)
	}
	return nil
}

func (operations unixOperations) Create(ctx context.Context, options CreateOptions) (ArchiveResult, error) {
	if ctx == nil {
		return ArchiveResult{}, errors.New("backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	dataDir, err := cleanAbsolute(options.DataDir, "Mesh data directory", false)
	if err != nil {
		return ArchiveResult{}, err
	}
	keyPath, err := cleanAbsolute(options.KeyFile, "backup key file", false)
	if err != nil {
		return ArchiveResult{}, err
	}
	outputPath, err := cleanAbsolute(options.OutputPath, "backup output", false)
	if err != nil {
		return ArchiveResult{}, err
	}
	if keyPath == outputPath {
		return ArchiveResult{}, errors.New("backup key file and output path must be different")
	}
	if err := pathsOverlapSource(dataDir, keyPath, "backup key file"); err != nil {
		return ArchiveResult{}, err
	}
	if err := pathsOverlapSource(dataDir, outputPath, "backup output"); err != nil {
		return ArchiveResult{}, err
	}
	if err := RefuseIncompleteRestore(dataDir); err != nil {
		return ArchiveResult{}, fmt.Errorf("refuse backup of an incomplete restore: %w", err)
	}
	masterKey, err := parseMasterKey(options.MasterKey)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer clear(masterKey)
	adminToken, err := parseAdminToken(options.AdminToken)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer clear(adminToken)
	backupKey, keyInfo, err := loadBackupKeyWithInfo(keyPath)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer clear(backupKey)
	if subtle.ConstantTimeCompare(backupKey, masterKey) == 1 {
		return ArchiveResult{}, errors.New("backup key must be cryptographically independent from MESH_MASTER_KEY")
	}
	if operations.beforeCapture != nil {
		if err := operations.beforeCapture(); err != nil {
			return ArchiveResult{}, fmt.Errorf("prepare source capture: %w", err)
		}
	}

	capture, err := captureSources(dataDir)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer capture.Close()
	if os.SameFile(keyInfo, capture.controlInfo) || os.SameFile(keyInfo, capture.identityInfo) {
		return ArchiveResult{}, errors.New("backup key file must not alias a source state inode")
	}
	controlVersion, identitySchema, err := validateSnapshotBodies(capture.controlRaw, capture.identityRaw, masterKey, adminToken)
	if err != nil {
		return ArchiveResult{}, err
	}
	if err := capture.proveUnchanged(); err != nil {
		return ArchiveResult{}, fmt.Errorf("%w: source changed after semantic validation: %v", ErrUnsafeSnapshot, err)
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	codec := backup.NewCodec()
	if options.Now != nil {
		codec, err = backup.NewCodecForTesting(rand.Reader, options.Now)
		if err != nil {
			return ArchiveResult{}, fmt.Errorf("initialize backup codec: %w", err)
		}
	}
	envelope, manifest, err := codec.Seal(backupKey, backup.Source{
		StateJSON: capture.controlRaw, IdentityStateJSON: capture.identityRaw,
		MasterKey: masterKey, AdminToken: adminToken,
		ControlVersion: controlVersion, IdentitySchema: identitySchema,
	})
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("seal backup archive: %w", err)
	}
	defer clear(envelope)
	if operations.beforePublication != nil {
		if err := operations.beforePublication(); err != nil {
			return ArchiveResult{}, fmt.Errorf("prepare backup publication: %w", err)
		}
	}
	if err := capture.proveUnchanged(); err != nil {
		return ArchiveResult{}, fmt.Errorf("%w: source changed before archive publication: %v", ErrUnsafeSnapshot, err)
	}
	if err := publishArchiveWithHooks(outputPath, envelope, backupKey, manifest, operations.publication); err != nil {
		return ArchiveResult{}, err
	}
	if err := capture.proveUnchanged(); err != nil {
		return ArchiveResult{}, fmt.Errorf("%w: archive was published but the final source stability proof failed: %v", ErrUnsafeSnapshot, err)
	}
	capturedAt, _ := time.Parse(time.RFC3339, manifest.CapturedAt)
	return ArchiveResult{Schema: commandResultSchema, Status: "created", BackupID: manifest.BackupID, CreatedAt: capturedAt, ArchivePath: outputPath}, nil
}

func randomTemporaryName(base string) (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	name := "." + base + ".mesh-backup-tmp-" + hex.EncodeToString(raw)
	clear(raw)
	if len(name) > 255 {
		return "", errors.New("backup output file name is too long for a private sibling temporary file")
	}
	return name, nil
}

type publicationHooks struct {
	syncDirectory func(*os.Root) error
	remove        func(*os.Root, string) error
	afterLink     func() error
}

func publishArchiveWithHooks(path string, envelope, backupKey []byte, expected backup.Manifest, hooks *publicationHooks) error {
	root, finalName, err := openParent(path, "backup output", true)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.root.Lstat(finalName); err == nil {
		return errors.New("backup output already exists; archives are never overwritten")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup output: %w", err)
	}
	tempName, err := randomTemporaryName(finalName)
	if err != nil {
		return fmt.Errorf("name backup temporary file: %w", err)
	}
	linked := false
	defer func() {
		if !linked {
			_ = root.root.Remove(tempName)
		}
	}()
	if err := writeNewSynced(root.root, tempName, "backup temporary archive", envelope, 0o600); err != nil {
		return err
	}
	reopened, _, err := readStableFile(root.root, tempName, "backup temporary archive", backup.MaxArchiveSize, true)
	if err != nil {
		return err
	}
	defer clear(reopened)
	if !bytes.Equal(reopened, envelope) {
		return errors.New("backup temporary archive changed after close and reopen")
	}
	contents, err := backup.Open(backupKey, reopened)
	if err != nil {
		return fmt.Errorf("verify backup temporary archive: %w", err)
	}
	defer clearContents(&contents)
	if contents.Manifest.BackupID != expected.BackupID || contents.Manifest.CapturedAt != expected.CapturedAt {
		return errors.New("backup temporary archive metadata changed during publication")
	}
	if err := root.root.Link(tempName, finalName); err != nil {
		return fmt.Errorf("publish backup archive without overwrite: %w", err)
	}
	linked = true
	if hooks != nil && hooks.afterLink != nil {
		if err := hooks.afterLink(); err != nil {
			// This hook models process death after link(2): both names are left
			// deliberately so verify can exercise the supported repair path.
			return fmt.Errorf("backup archive linked before publication interruption: %v: %w", err, ErrVerifyRequired)
		}
	}
	syncDirectory := syncRoot
	remove := func(root *os.Root, name string) error { return root.Remove(name) }
	if hooks != nil {
		if hooks.syncDirectory != nil {
			syncDirectory = hooks.syncDirectory
		}
		if hooks.remove != nil {
			remove = hooks.remove
		}
	}
	firstSyncErr := syncDirectory(root.root)
	removeErr := remove(root.root, tempName)
	if removeErr != nil {
		// A transient unlink failure must not knowingly strand a final archive
		// with two links, because strict verification rejects such archives.
		removeErr = errors.Join(removeErr, root.root.Remove(tempName))
	}
	var secondSyncErr error
	if _, statErr := root.root.Lstat(tempName); errors.Is(statErr, os.ErrNotExist) {
		secondSyncErr = syncDirectory(root.root)
	} else if statErr == nil {
		removeErr = errors.Join(removeErr, errors.New("backup temporary link still exists after unlink attempts"))
	} else {
		removeErr = errors.Join(removeErr, fmt.Errorf("inspect backup temporary link after unlink: %w", statErr))
	}
	info, err := root.root.Lstat(finalName)
	if err != nil {
		return fmt.Errorf("inspect published backup archive: %w: %w", err, ErrVerifyRequired)
	}
	if err := requirePrivateRegular(info, "published backup archive", true); err != nil {
		return fmt.Errorf("%v: %w", err, ErrVerifyRequired)
	}
	if err := errors.Join(firstSyncErr, removeErr, secondSyncErr); err != nil {
		return fmt.Errorf("backup archive was linked and is verify-required after a publication barrier error: %v: %w", err, ErrVerifyRequired)
	}
	return nil
}

func clearContents(contents *backup.Contents) {
	if contents == nil {
		return
	}
	clear(contents.StateJSON)
	clear(contents.IdentityStateJSON)
	clear(contents.MasterKey)
	clear(contents.AdminToken)
}

func readArchive(options ArchiveOptions) ([]byte, []byte, os.FileInfo, backup.Manifest, error) {
	keyPath, err := cleanAbsolute(options.KeyFile, "backup key file", false)
	if err != nil {
		return nil, nil, nil, backup.Manifest{}, err
	}
	archivePath, err := cleanAbsolute(options.ArchivePath, "backup archive", false)
	if err != nil {
		return nil, nil, nil, backup.Manifest{}, err
	}
	if keyPath == archivePath {
		return nil, nil, nil, backup.Manifest{}, errors.New("backup key file and archive path must be different")
	}
	key, keyInfo, err := loadBackupKeyWithInfo(keyPath)
	if err != nil {
		return nil, nil, nil, backup.Manifest{}, err
	}
	archiveRoot, archiveName, err := openParent(archivePath, "backup archive", true)
	if err != nil {
		clear(key)
		return nil, nil, nil, backup.Manifest{}, err
	}
	defer archiveRoot.Close()
	envelope, archiveInfo, err := readStableFile(archiveRoot.root, archiveName, "backup archive", backup.MaxArchiveSize, true)
	if err != nil {
		clear(key)
		return nil, nil, nil, backup.Manifest{}, err
	}
	if os.SameFile(keyInfo, archiveInfo) {
		clear(key)
		clear(envelope)
		return nil, nil, nil, backup.Manifest{}, errors.New("backup key file and archive must not alias the same inode")
	}
	manifest, err := backup.Inspect(key, envelope)
	if err != nil {
		clear(key)
		clear(envelope)
		return nil, nil, nil, backup.Manifest{}, fmt.Errorf("authenticate backup archive: %w", err)
	}
	return key, envelope, archiveInfo, manifest, nil
}

func resultFromManifest(status, archivePath string, manifest backup.Manifest) (ArchiveResult, error) {
	capturedAt, err := time.Parse(time.RFC3339, manifest.CapturedAt)
	if err != nil {
		return ArchiveResult{}, errors.New("backup manifest has an invalid capture time")
	}
	return ArchiveResult{Schema: commandResultSchema, Status: status, BackupID: manifest.BackupID, CreatedAt: capturedAt, ArchivePath: archivePath}, nil
}

func (unixOperations) Inspect(ctx context.Context, options ArchiveOptions) (ArchiveResult, error) {
	if ctx == nil {
		return ArchiveResult{}, errors.New("backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	key, envelope, _, manifest, err := readArchive(options)
	clear(key)
	clear(envelope)
	if err != nil {
		return ArchiveResult{}, err
	}
	return resultFromManifest("inspected", options.ArchivePath, manifest)
}

func (operations unixOperations) Verify(ctx context.Context, options ArchiveOptions) (ArchiveResult, error) {
	if ctx == nil {
		return ArchiveResult{}, errors.New("backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	if err := repairInterruptedPublication(options, operations.syncArchiveDir); err != nil {
		return ArchiveResult{}, err
	}
	key, envelope, _, manifest, err := readArchive(options)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer clear(key)
	defer clear(envelope)
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
	if err := syncVerifiedArchive(options.ArchivePath, envelope, operations.syncArchiveFile, operations.syncArchiveDir); err != nil {
		return ArchiveResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ArchiveResult{}, err
	}
	return resultFromManifest("verified", options.ArchivePath, manifest)
}

func repairInterruptedPublication(options ArchiveOptions, syncDirectory func(*os.Root) error) error {
	keyPath, err := cleanAbsolute(options.KeyFile, "backup key file", false)
	if err != nil {
		return err
	}
	archivePath, err := cleanAbsolute(options.ArchivePath, "backup archive", false)
	if err != nil {
		return err
	}
	if keyPath == archivePath {
		return errors.New("backup key file and archive path must be different")
	}
	key, keyInfo, err := loadBackupKeyWithInfo(keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	root, finalName, err := openParent(archivePath, "backup archive", true)
	if err != nil {
		return err
	}
	defer root.Close()
	finalInfo, err := root.root.Lstat(finalName)
	if err != nil {
		return fmt.Errorf("inspect backup archive for interrupted publication: %w", err)
	}
	if err := requirePrivateRegular(finalInfo, "backup archive", false); err != nil {
		return err
	}
	finalStat, err := unixStat(finalInfo)
	if err != nil {
		return err
	}
	if finalStat.Nlink == 1 {
		return nil
	}
	if finalStat.Nlink != 2 {
		return fmt.Errorf("interrupted backup publication has %d links; exactly final plus one private temporary link is required", finalStat.Nlink)
	}
	envelope, openedInfo, err := readStableFile(root.root, finalName, "interrupted backup archive", backup.MaxArchiveSize, false)
	if err != nil {
		return err
	}
	defer clear(envelope)
	if os.SameFile(keyInfo, openedInfo) {
		return errors.New("backup key file and archive must not alias the same inode")
	}
	if _, err := backup.Inspect(key, envelope); err != nil {
		return fmt.Errorf("authenticate interrupted backup publication before repair: %w", err)
	}
	tempName, err := findInterruptedPublicationTemp(root.root, finalName)
	if err != nil {
		return err
	}
	tempInfo, err := root.root.Lstat(tempName)
	if err != nil {
		return fmt.Errorf("inspect interrupted backup temporary link: %w", err)
	}
	if err := requirePrivateRegular(tempInfo, "interrupted backup temporary link", false); err != nil {
		return err
	}
	if tempInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("interrupted backup temporary link mode is %04o, expected 0600", tempInfo.Mode().Perm())
	}
	if !os.SameFile(openedInfo, tempInfo) {
		return errors.New("interrupted backup temporary candidate does not alias the authenticated final archive")
	}
	if err := root.root.Remove(tempName); err != nil {
		return fmt.Errorf("remove authenticated interrupted backup temporary link: %w", err)
	}
	if syncDirectory == nil {
		syncDirectory = syncRoot
	}
	if err := syncDirectory(root.root); err != nil {
		return fmt.Errorf("sync interrupted backup publication repair: %v: %w", err, ErrVerifyRequired)
	}
	after, err := root.root.Lstat(finalName)
	if err != nil {
		return fmt.Errorf("recheck repaired backup archive: %v: %w", err, ErrVerifyRequired)
	}
	if !os.SameFile(openedInfo, after) {
		return fmt.Errorf("repaired backup archive inode changed: %w", ErrVerifyRequired)
	}
	if err := requirePrivateRegular(after, "repaired backup archive", true); err != nil {
		return fmt.Errorf("%v: %w", err, ErrVerifyRequired)
	}
	reopened, _, err := readStableFile(root.root, finalName, "repaired backup archive", backup.MaxArchiveSize, true)
	if err != nil {
		return fmt.Errorf("reopen repaired backup archive: %v: %w", err, ErrVerifyRequired)
	}
	defer clear(reopened)
	if !bytes.Equal(reopened, envelope) {
		return fmt.Errorf("repaired backup archive bytes changed: %w", ErrVerifyRequired)
	}
	return nil
}

func findInterruptedPublicationTemp(root *os.Root, finalName string) (result string, resultErr error) {
	directory, err := root.Open(".")
	if err != nil {
		return "", fmt.Errorf("open backup archive parent for interrupted-publication scan: %w", err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close interrupted-publication scan: %w", closeErr))
		}
	}()
	prefix := "." + finalName + ".mesh-backup-tmp-"
	scanned := 0
	for {
		entries, readErr := directory.ReadDir(markerScanBatchSize)
		if len(entries) == 0 && readErr == nil {
			return "", errors.New("interrupted-publication parent scan made no progress")
		}
		for _, entry := range entries {
			scanned++
			if scanned > maxMarkerScanEntries {
				return "", fmt.Errorf("backup archive parent exceeds the bounded %d-entry publication-repair scan", maxMarkerScanEntries)
			}
			name := entry.Name()
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			suffix := strings.TrimPrefix(name, prefix)
			decoded, decodeErr := hex.DecodeString(suffix)
			canonical := decodeErr == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == suffix
			clear(decoded)
			if !canonical {
				continue
			}
			if result != "" {
				return "", errors.New("interrupted backup publication has multiple exact temporary candidates")
			}
			result = name
		}
		if errors.Is(readErr, io.EOF) {
			if result == "" {
				return "", errors.New("interrupted backup publication has no exact temporary candidate")
			}
			return result, nil
		}
		if readErr != nil {
			return "", fmt.Errorf("scan interrupted backup publication: %w", readErr)
		}
	}
}

func syncVerifiedArchive(path string, expected []byte, syncFile func(*os.File) error, syncDirectory func(*os.Root) error) error {
	root, name, err := openParent(path, "backup archive", true)
	if err != nil {
		return err
	}
	defer root.Close()
	file, opened, err := openStableFile(root.root, name, "backup archive", backup.MaxArchiveSize, true)
	if err != nil {
		return err
	}
	if syncFile == nil {
		syncFile = func(file *os.File) error { return file.Sync() }
	}
	if err := syncFile(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync verified backup archive: %w", err)
	}
	reopened, readErr := readOpenedStable(root.root, name, "backup archive", file, opened, backup.MaxArchiveSize)
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		clear(reopened)
		return err
	}
	defer clear(reopened)
	if !bytes.Equal(reopened, expected) {
		return errors.New("backup archive changed between validation and durability repair")
	}
	if syncDirectory == nil {
		syncDirectory = syncRoot
	}
	if err := syncDirectory(root.root); err != nil {
		return fmt.Errorf("sync verified backup archive directory: %w", err)
	}
	return nil
}

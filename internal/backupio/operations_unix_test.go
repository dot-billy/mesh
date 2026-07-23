//go:build linux

package backupio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"mesh/internal/backup"
	"mesh/internal/control"
	"mesh/internal/identity"
)

type backupFixture struct {
	root       string
	dataDir    string
	keyPath    string
	outputDir  string
	masterText string
	adminText  string
}

func newBackupFixture(t *testing.T) backupFixture {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x31}, 32)
	masterText := base64.RawURLEncoding.EncodeToString(master)
	adminText := strings.Repeat("A", 43)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	controlStore, err := control.OpenStore(filepath.Join(dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := control.DeriveAdminCredentialVerifier(master, []byte(adminText))
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	clear(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.NewService(controlStore, box, control.NebulaIssuer{}).EnsureRecoveryCredentialBinding(masterVerifier, verifier, false); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.Close(); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(dataDir, IdentityStateName), box)
	if err != nil {
		t.Fatal(err)
	}
	if err := identityStore.Close(); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(root, "keys")
	outputDir := filepath.Join(root, "archives")
	for _, directory := range []string{keyDir, outputDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "backup.key")
	if _, err := (unixOperations{}).Keygen(KeygenOptions{OutputPath: keyPath}); err != nil {
		t.Fatal(err)
	}
	return backupFixture{
		root: root, dataDir: dataDir, keyPath: keyPath, outputDir: outputDir,
		masterText: masterText, adminText: adminText,
	}
}

func (f backupFixture) create(t *testing.T, operations unixOperations, name string) (ArchiveResult, string) {
	t.Helper()
	output := filepath.Join(f.outputDir, name)
	result, err := operations.Create(context.Background(), CreateOptions{
		DataDir: f.dataDir, KeyFile: f.keyPath, OutputPath: output,
		MasterKey: f.masterText, AdminToken: f.adminText,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result, output
}

func (f backupFixture) writeAuthenticatedArchiveWithAdmin(t *testing.T, name, admin string) (backup.Manifest, string) {
	t.Helper()
	controlRaw, err := os.ReadFile(filepath.Join(f.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	identityRaw, err := os.ReadFile(filepath.Join(f.dataDir, IdentityStateName))
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := parseMasterKey(f.masterText)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(masterKey)
	backupKey, _, err := loadBackupKeyWithInfo(f.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(backupKey)
	controlVersion, identitySchema, err := snapshotMetadata(controlRaw, identityRaw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, manifest, err := backup.NewCodec().Seal(backupKey, backup.Source{
		StateJSON: controlRaw, IdentityStateJSON: identityRaw,
		MasterKey: masterKey, AdminToken: []byte(admin),
		ControlVersion: controlVersion, IdentitySchema: identitySchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(envelope)
	path := filepath.Join(f.outputDir, name)
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifest, path
}

func fileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(raw)
}

func TestKeygenCreatesExactPrivateSingleLinkKey(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "backup.key")
	result, err := (unixOperations{}).Keygen(KeygenOptions{OutputPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != path || result.Status != "created" {
		t.Fatalf("unexpected result: %+v", result)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 44 || raw[43] != '\n' {
		t.Fatalf("key file is not exact canonical length: %d", len(raw))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw[:43]))
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != string(raw[:43]) {
		t.Fatal("key file is not canonical base64url")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		t.Fatalf("unexpected key metadata: mode=%04o links=%d", info.Mode().Perm(), stat.Nlink)
	}
	if _, err := (unixOperations{}).Keygen(KeygenOptions{OutputPath: path}); err == nil {
		t.Fatal("keygen clobbered an existing key")
	}
}

func TestCreateInspectVerifyRestoreEndToEndWithoutSourceMutation(t *testing.T) {
	fixture := newBackupFixture(t)
	controlPath := filepath.Join(fixture.dataDir, ControlStateName)
	identityPath := filepath.Join(fixture.dataDir, IdentityStateName)
	controlBefore := fileDigest(t, controlPath)
	identityBefore := fileDigest(t, identityPath)
	controlInfo, _ := os.Lstat(controlPath)
	identityInfo, _ := os.Lstat(identityPath)

	created, archivePath := fixture.create(t, unixOperations{}, "snapshot.meshbackup")
	if !validLowerHex(created.BackupID, 16) || created.ArchivePath != archivePath {
		t.Fatalf("unexpected create result: %+v", created)
	}
	inspected, err := (unixOperations{}).Inspect(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath})
	if err != nil || inspected.BackupID != created.BackupID || inspected.Status != "inspected" {
		t.Fatalf("inspect failed: %+v, %v", inspected, err)
	}
	verified, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath})
	if err != nil || verified.BackupID != created.BackupID || verified.Status != "verified" {
		t.Fatalf("verify failed: %+v, %v", verified, err)
	}
	if controlBefore != fileDigest(t, controlPath) || identityBefore != fileDigest(t, identityPath) {
		t.Fatal("source state content changed")
	}
	controlAfter, _ := os.Lstat(controlPath)
	identityAfter, _ := os.Lstat(identityPath)
	if !os.SameFile(controlInfo, controlAfter) || !os.SameFile(identityInfo, identityAfter) {
		t.Fatal("source state inode changed")
	}

	target := filepath.Join(fixture.root, "restored")
	restored, err := (unixOperations{}).Restore(context.Background(), RestoreOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID,
	})
	if err != nil || restored.Status != "restored" || restored.TargetDir != target {
		t.Fatalf("restore failed: %+v, %v", restored, err)
	}
	if err := RefuseIncompleteRestore(target); err != nil {
		t.Fatalf("completed restore remained fenced: %v", err)
	}
	for _, name := range []string{ControlStateName, IdentityStateName, MasterKeyName, AdminTokenName, ReceiptName} {
		info, err := os.Lstat(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
			t.Fatalf("%s metadata: mode=%04o links=%d", name, info.Mode().Perm(), stat.Nlink)
		}
	}
	if fileDigest(t, filepath.Join(target, ControlStateName)) != controlBefore || fileDigest(t, filepath.Join(target, IdentityStateName)) != identityBefore {
		t.Fatal("restored state digests differ from source")
	}
	masterBody, _ := os.ReadFile(filepath.Join(target, MasterKeyName))
	adminBody, _ := os.ReadFile(filepath.Join(target, AdminTokenName))
	if string(masterBody) != fixture.masterText+"\n" || string(adminBody) != fixture.adminText+"\n" {
		t.Fatal("restored credentials are not exact canonical file bodies")
	}
}

func TestCreateHonorsBothLocksInOrderAndReleasesOnFailure(t *testing.T) {
	fixture := newBackupFixture(t)
	boxKey, _ := base64.RawURLEncoding.DecodeString(fixture.masterText)
	box, _ := control.NewSecretBox(boxKey)
	clear(boxKey)
	controlStore, err := control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(fixture.dataDir, IdentityStateName), box)
	if err != nil {
		t.Fatal(err)
	}
	options := CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: filepath.Join(fixture.outputDir, "locked.meshbackup"),
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	}
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil || !strings.Contains(err.Error(), ".mesh.lock") {
		t.Fatalf("control lock was not checked first: %v", err)
	}
	if err := controlStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil || !strings.Contains(err.Error(), ".identity-state.json.lock") {
		t.Fatalf("identity lock contention not detected: %v", err)
	}
	lock, err := os.OpenFile(filepath.Join(fixture.dataDir, ".mesh.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("control lock leaked after identity contention: %v", err)
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := identityStore.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateNeverClobbersAndRejectsSourceCollisions(t *testing.T) {
	fixture := newBackupFixture(t)
	_, output := fixture.create(t, unixOperations{}, "immutable.meshbackup")
	before := fileDigest(t, output)
	options := CreateOptions{DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output, MasterKey: fixture.masterText, AdminToken: fixture.adminText}
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil {
		t.Fatal("existing output was clobbered")
	}
	if before != fileDigest(t, output) {
		t.Fatal("existing output content changed")
	}
	insideKey := filepath.Join(fixture.dataDir, "backup.key")
	keyRaw, _ := os.ReadFile(fixture.keyPath)
	if err := os.WriteFile(insideKey, keyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	options.KeyFile = insideKey
	options.OutputPath = filepath.Join(fixture.outputDir, "inside-key.meshbackup")
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("source-contained key was accepted: %v", err)
	}
	options.KeyFile = fixture.keyPath
	options.OutputPath = filepath.Join(fixture.dataDir, "inside-output.meshbackup")
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("source-contained output was accepted: %v", err)
	}
	options.OutputPath = fixture.keyPath
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil {
		t.Fatal("key/output collision was accepted")
	}
}

func TestCreateRejectsBackupKeyEqualToMasterKey(t *testing.T) {
	fixture := newBackupFixture(t)
	equalKey := filepath.Join(filepath.Dir(fixture.keyPath), "copied-master.key")
	if err := os.WriteFile(equalKey, []byte(fixture.masterText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(fixture.outputDir, "collapsed-domains.meshbackup")
	_, err := (unixOperations{}).Create(context.Background(), CreateOptions{
		DataDir: fixture.dataDir, KeyFile: equalKey, OutputPath: output,
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	})
	if err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("backup key equal to live master was accepted: %v", err)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("rejected equal-key create published output")
	}
}

func TestCreateRequiresTheBoundAdministratorCredentialAndVersionTwoState(t *testing.T) {
	fixture := newBackupFixture(t)
	wrongOutput := filepath.Join(fixture.outputDir, "wrong-admin.meshbackup")
	_, err := (unixOperations{}).Create(context.Background(), CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: wrongOutput,
		MasterKey: fixture.masterText, AdminToken: strings.Repeat("B", 43),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unrelated administrator credential was accepted: %v", err)
	}
	if _, statErr := os.Lstat(wrongOutput); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("credential mismatch published an archive")
	}

	statePath := filepath.Join(fixture.dataDir, ControlStateName)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["version"] = float64(1)
	delete(legacy, "master_key_verifier")
	delete(legacy, "admin_credential_verifier")
	legacyRaw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyOutput := filepath.Join(fixture.outputDir, "unbound-v1.meshbackup")
	_, err = (unixOperations{}).Create(context.Background(), CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: legacyOutput,
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	})
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound version 1 state was accepted: %v", err)
	}
	if _, statErr := os.Lstat(legacyOutput); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("unbound legacy state published an archive")
	}
}

func TestVerifyRestoreAndFinalizeRevalidateCredentialBindings(t *testing.T) {
	fixture := newBackupFixture(t)
	manifest, wrongArchive := fixture.writeAuthenticatedArchiveWithAdmin(t, "wrong-inside.meshbackup", strings.Repeat("B", 43))
	if _, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: wrongArchive}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("verify accepted authenticated archive with unrelated admin credential: %v", err)
	}
	target := filepath.Join(fixture.root, "wrong-restore-target")
	if _, err := (unixOperations{}).Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: wrongArchive, TargetDir: target, ExpectedBackupID: manifest.BackupID}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("restore accepted authenticated archive with unrelated admin credential: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected credential archive created a restore target")
	}
	markerPath, err := RestoreMarkerPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected credential archive created a restore marker")
	}

	created, goodArchive := fixture.create(t, unixOperations{}, "good-finalize.meshbackup")
	finalizeTarget := filepath.Join(fixture.root, "finalize-revalidation")
	if _, err := (unixOperations{}).Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: goodArchive, TargetDir: finalizeTarget, ExpectedBackupID: created.BackupID}); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(finalizeTarget, ReceiptName)
	receiptRaw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt restoreReceipt
	if err := decodeStrictJSON(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	masterBody, err := os.ReadFile(filepath.Join(finalizeTarget, MasterKeyName))
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := decodeRecoveredMaster(masterBody)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(masterKey)
	wrongAdminBody := []byte(strings.Repeat("C", 43) + "\n")
	if err := os.WriteFile(filepath.Join(finalizeTarget, AdminTokenName), wrongAdminBody, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptHMACSHA256 = receiptMAC(receipt, masterKey, masterBody, wrongAdminBody)
	newReceiptRaw, err := encodeJSONLine(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, newReceiptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	createdAt, err := time.Parse(time.RFC3339, receipt.RestoredAt)
	if err != nil {
		t.Fatal(err)
	}
	marker := restoreMarker{Schema: RestoreMarkerSchema, BackupID: receipt.BackupID, OperationID: receipt.OperationID, Target: finalizeTarget, CreatedAt: createdAt}
	markerRaw, err := encodeJSONLine(marker)
	if err != nil {
		t.Fatal(err)
	}
	finalizeMarkerPath, err := RestoreMarkerPath(finalizeTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(finalizeMarkerPath, markerRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: finalizeTarget}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("finalize accepted a receipt-authenticated unrelated admin credential: %v", err)
	}
	if _, err := os.Lstat(finalizeMarkerPath); err != nil {
		t.Fatalf("failed finalization removed its safety marker: %v", err)
	}
}

func TestPrivatePathSymlinkHardlinkAndModeChecks(t *testing.T) {
	fixture := newBackupFixture(t)
	options := ArchiveOptions{KeyFile: fixture.keyPath}
	_, archivePath := fixture.create(t, unixOperations{}, "checks.meshbackup")
	options.ArchivePath = archivePath

	keyLink := filepath.Join(filepath.Dir(fixture.keyPath), "key-link")
	if err := os.Symlink(fixture.keyPath, keyLink); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), ArchiveOptions{KeyFile: keyLink, ArchivePath: archivePath}); err == nil {
		t.Fatal("symlink key was accepted")
	}
	hardKey := filepath.Join(filepath.Dir(fixture.keyPath), "key-hard")
	if err := os.Link(fixture.keyPath, hardKey); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), options); err == nil {
		t.Fatal("multiply-linked key was accepted")
	}
	if err := os.Remove(hardKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), options); err == nil {
		t.Fatal("group-readable key was accepted")
	}
	if err := os.Chmod(fixture.keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveHard := archivePath + ".hard"
	if err := os.Link(archivePath, archiveHard); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), options); err == nil {
		t.Fatal("multiply-linked archive was accepted")
	}
	if err := os.Remove(archiveHard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archivePath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), options); err == nil {
		t.Fatal("weak archive mode was accepted")
	}
}

func TestBackupKeyAndArchiveParentsMustRemainPrivate(t *testing.T) {
	fixture := newBackupFixture(t)
	_, archivePath := fixture.create(t, unixOperations{}, "parent-checks.meshbackup")
	keyParent := filepath.Dir(fixture.keyPath)
	if err := os.Chmod(keyParent, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath}); err == nil {
		t.Fatal("key under a non-private parent was accepted")
	}
	if err := os.Chmod(keyParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath}); err == nil {
		t.Fatal("archive under a non-private parent was accepted")
	}
}

func TestCreateRejectsUnsafeSourcePathsAndStateLinks(t *testing.T) {
	fixture := newBackupFixture(t)
	options := CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: filepath.Join(fixture.outputDir, "unsafe.meshbackup"),
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	}
	dataLink := filepath.Join(fixture.root, "data-link")
	if err := os.Symlink(fixture.dataDir, dataLink); err != nil {
		t.Fatal(err)
	}
	options.DataDir = dataLink
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil {
		t.Fatal("symlink data directory was accepted")
	}
	options.DataDir = fixture.dataDir
	if err := os.Chmod(fixture.dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil {
		t.Fatal("weak data directory mode was accepted")
	}
	if err := os.Chmod(fixture.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateHard := filepath.Join(fixture.dataDir, "state-hard.json")
	if err := os.Link(filepath.Join(fixture.dataDir, ControlStateName), stateHard); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Create(context.Background(), options); err == nil {
		t.Fatal("multiply-linked source state was accepted")
	}
}

func TestWrongBackupKeyTamperWrongIDAndExistingTargetFailClosed(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "auth.meshbackup")
	wrongKey := filepath.Join(filepath.Dir(fixture.keyPath), "wrong.key")
	if _, err := (unixOperations{}).Keygen(KeygenOptions{OutputPath: wrongKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: wrongKey, ArchivePath: archivePath}); !errors.Is(err, backup.ErrAuthentication) {
		t.Fatalf("wrong key did not return authentication failure: %v", err)
	}
	tampered := filepath.Join(fixture.outputDir, "tampered.meshbackup")
	raw, _ := os.ReadFile(archivePath)
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: tampered}); !errors.Is(err, backup.ErrAuthentication) {
		t.Fatalf("tampering did not return authentication failure: %v", err)
	}
	target := filepath.Join(fixture.root, "wrong-id-target")
	wrongID := strings.Repeat("0", 32)
	if wrongID == created.BackupID {
		wrongID = strings.Repeat("1", 32)
	}
	if _, err := (unixOperations{}).Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: wrongID}); err == nil {
		t.Fatal("wrong expected ID was accepted")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong-ID restore created a target")
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID}); err == nil {
		t.Fatal("existing restore target was accepted")
	}
	marker, _ := RestoreMarkerPath(target)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("existing-target refusal created a marker")
	}
}

func TestInterruptedRestoreLeavesMarkerAndFinalizeRevalidates(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "finalize.meshbackup")
	target := filepath.Join(fixture.root, "partial")
	interrupted := unixOperations{beforeMarkerDrop: func() error { return errors.New("injected stop") }}
	if _, err := interrupted.Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID}); err == nil {
		t.Fatal("injected interruption unexpectedly succeeded")
	}
	marker, _ := RestoreMarkerPath(target)
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("interrupted restore did not leave marker: %v", err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("server helper did not refuse marker: %v", err)
	}
	result, err := (unixOperations{}).FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: target})
	if err != nil || result.Status != "finalized" || result.BackupID != created.BackupID {
		t.Fatalf("finalize failed: %+v, %v", result, err)
	}
	if err := RefuseIncompleteRestore(target); err != nil {
		t.Fatalf("finalized target remained fenced: %v", err)
	}
}

func TestFinalizeRetriesEveryRecoveredFileSyncAndKeepsMarkerOnSyncFailure(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "resync.meshbackup")
	target := filepath.Join(fixture.root, "resync-partial")
	interrupted := unixOperations{beforeMarkerDrop: func() error { return errors.New("injected stop") }}
	_, _ = interrupted.Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID})

	seen := make(map[string]int)
	failing := unixOperations{syncRecovered: func(file *os.File, name string) error {
		seen[name]++
		if name == IdentityStateName {
			return errors.New("injected file sync failure")
		}
		return file.Sync()
	}}
	if _, err := failing.FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: target}); err == nil || !strings.Contains(err.Error(), "sync") {
		t.Fatalf("injected recovered-file sync failure was ignored: %v", err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("sync failure did not preserve marker: %v", err)
	}
	if seen[ControlStateName] != 1 || seen[IdentityStateName] != 1 {
		t.Fatalf("unexpected sync sequence before failure: %+v", seen)
	}

	seen = make(map[string]int)
	counting := unixOperations{syncRecovered: func(file *os.File, name string) error {
		seen[name]++
		return file.Sync()
	}}
	if _, err := counting.FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: target}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ControlStateName, IdentityStateName, MasterKeyName, AdminTokenName, ReceiptName} {
		if seen[name] != 1 {
			t.Fatalf("%s sync count = %d, want 1; all=%+v", name, seen[name], seen)
		}
	}
}

func TestFinalizeRejectsPollutedTargetAndPreservesMarker(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "polluted.meshbackup")
	target := filepath.Join(fixture.root, "polluted-partial")
	interrupted := unixOperations{beforeMarkerDrop: func() error { return errors.New("injected stop") }}
	_, _ = interrupted.Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID})
	if err := os.Symlink("missing", filepath.Join(target, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: target}); err == nil || !strings.Contains(err.Error(), "exactly") {
		t.Fatalf("polluted target was finalized: %v", err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("polluted-target failure did not preserve marker: %v", err)
	}
}

func TestFinalizeDetectsTamperAndPreservesMarker(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "tamper-restore.meshbackup")
	target := filepath.Join(fixture.root, "tampered-partial")
	interrupted := unixOperations{beforeMarkerDrop: func() error { return errors.New("injected stop") }}
	_, _ = interrupted.Restore(context.Background(), RestoreOptions{KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID})
	adminPath := filepath.Join(target, AdminTokenName)
	if err := os.WriteFile(adminPath, []byte(strings.Repeat("B", 43)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).FinalizeRestore(context.Background(), FinalizeRestoreOptions{TargetDir: target}); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered target was finalized: %v", err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("tamper failure did not preserve marker: %v", err)
	}
}

func TestPublicationBarrierFailuresLeaveStrictlyVerifiableFinal(t *testing.T) {
	fixture := newBackupFixture(t)
	tests := []struct {
		name  string
		hooks *publicationHooks
	}{
		{name: "first-sync", hooks: &publicationHooks{syncDirectory: failSyncCall(1)}},
		{name: "second-sync", hooks: &publicationHooks{syncDirectory: failSyncCall(2)}},
		{name: "unlink", hooks: &publicationHooks{remove: func(*os.Root, string) error { return errors.New("injected unlink failure") }}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(fixture.outputDir, test.name+".meshbackup")
			_, err := (unixOperations{publication: test.hooks}).Create(context.Background(), CreateOptions{
				DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
				MasterKey: fixture.masterText, AdminToken: fixture.adminText,
			})
			if !errors.Is(err, ErrVerifyRequired) {
				t.Fatalf("publication failure did not require verify: %v", err)
			}
			fileSyncs, directorySyncs := 0, 0
			verifier := unixOperations{
				syncArchiveFile: func(file *os.File) error {
					fileSyncs++
					return file.Sync()
				},
				syncArchiveDir: func(root *os.Root) error {
					directorySyncs++
					return syncRoot(root)
				},
			}
			if _, err := verifier.Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: output}); err != nil {
				t.Fatalf("verify-required final was not strictly verifiable: %v", err)
			}
			if fileSyncs != 1 || directorySyncs != 1 {
				t.Fatalf("verify did not repair both durability barriers: file=%d dir=%d", fileSyncs, directorySyncs)
			}
			info, _ := os.Lstat(output)
			if info.Sys().(*syscall.Stat_t).Nlink != 1 {
				t.Fatalf("verify-required final retained %d links", info.Sys().(*syscall.Stat_t).Nlink)
			}
		})
	}
}

func failSyncCall(target int) func(*os.Root) error {
	count := 0
	return func(root *os.Root) error {
		count++
		if count == target {
			return errors.New("injected directory sync failure")
		}
		return syncRoot(root)
	}
}

func TestRestoreMarkerHelperFailsClosedForEveryMarkerObject(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	marker, err := RestoreMarkerPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", marker); err != nil {
		t.Fatal(err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("symlink marker was not refused: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RefuseIncompleteRestore(target); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("directory marker was not refused: %v", err)
	}
}

func TestRestoreMarkerHelperFindsSymlinkAliasOfFencedDirectory(t *testing.T) {
	parent := t.TempDir()
	realTarget := filepath.Join(parent, "actual")
	if err := os.Mkdir(realTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	marker, err := RestoreMarkerPath(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("interrupted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alternate")
	if err := os.Symlink(filepath.Base(realTarget), alias); err != nil {
		t.Fatal(err)
	}
	if err := RefuseIncompleteRestore(alias); !errors.Is(err, ErrIncompleteRestore) {
		t.Fatalf("alternate spelling of fenced directory was accepted: %v", err)
	}
}

type injectedMarkerDirectory struct {
	entries  []os.DirEntry
	readErr  error
	closeErr error
	served   bool
}

func (directory *injectedMarkerDirectory) ReadDir(int) ([]os.DirEntry, error) {
	if directory.served {
		return nil, io.EOF
	}
	directory.served = true
	return directory.entries, directory.readErr
}

func (directory *injectedMarkerDirectory) Close() error { return directory.closeErr }

func TestRestoreMarkerHelperBoundsAndFailsClosedOnScanErrors(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(parent, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	filesystem := operatingSystemMarkerScan()
	filesystem.openDir = func(string) (markerScanDirectory, error) {
		return &injectedMarkerDirectory{entries: entries}, nil
	}
	if err := refuseIncompleteRestoreWith(target, filesystem, 2); err == nil || !strings.Contains(err.Error(), "bounded") {
		t.Fatalf("bounded marker scan did not fail closed: %v", err)
	}

	filesystem.openDir = func(string) (markerScanDirectory, error) {
		return &injectedMarkerDirectory{readErr: errors.New("injected read failure")}, nil
	}
	if err := refuseIncompleteRestoreWith(target, filesystem, 10); err == nil || !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("marker scan read error did not fail closed: %v", err)
	}

	filesystem.openDir = func(string) (markerScanDirectory, error) {
		return &injectedMarkerDirectory{closeErr: errors.New("injected close failure")}, nil
	}
	if err := refuseIncompleteRestoreWith(target, filesystem, 10); err == nil || !strings.Contains(err.Error(), "injected close failure") {
		t.Fatalf("marker scan close error did not fail closed: %v", err)
	}
}

func TestCreateRefusesIncompleteRestoreBeforeAndAfterLocks(t *testing.T) {
	for _, test := range []struct {
		name       string
		operations func(string) unixOperations
	}{
		{name: "before-capture", operations: func(string) unixOperations { return unixOperations{} }},
		{name: "after-precheck", operations: func(marker string) unixOperations {
			return unixOperations{beforeCapture: func() error { return os.WriteFile(marker, []byte("interrupted\n"), 0o600) }}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBackupFixture(t)
			marker, err := RestoreMarkerPath(fixture.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			operations := test.operations(marker)
			if test.name == "before-capture" {
				if err := os.WriteFile(marker, []byte("interrupted\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(fixture.outputDir, test.name+".meshbackup")
			_, err = operations.Create(context.Background(), CreateOptions{
				DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
				MasterKey: fixture.masterText, AdminToken: fixture.adminText,
			})
			if !errors.Is(err, ErrIncompleteRestore) {
				t.Fatalf("fenced source was accepted for backup: %v", err)
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fenced-source refusal published output: %v", err)
			}
		})
	}
}

func TestCreateReportsUnsafeSnapshotSeparatelyFromPublicationDurability(t *testing.T) {
	t.Run("before-publication", func(t *testing.T) {
		fixture := newBackupFixture(t)
		output := filepath.Join(fixture.outputDir, "unsafe-before.meshbackup")
		operations := unixOperations{beforePublication: func() error {
			file, err := os.OpenFile(filepath.Join(fixture.dataDir, ControlStateName), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.WriteString("x")
			return errors.Join(writeErr, file.Close())
		}}
		_, err := operations.Create(context.Background(), CreateOptions{
			DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
			MasterKey: fixture.masterText, AdminToken: fixture.adminText,
		})
		if !errors.Is(err, ErrUnsafeSnapshot) || errors.Is(err, ErrVerifyRequired) {
			t.Fatalf("source instability was conflated with publication durability: %v", err)
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pre-publication instability left an archive: %v", err)
		}
	})

	t.Run("after-publication", func(t *testing.T) {
		fixture := newBackupFixture(t)
		output := filepath.Join(fixture.outputDir, "unsafe-after.meshbackup")
		mutated := false
		operations := unixOperations{publication: &publicationHooks{syncDirectory: func(root *os.Root) error {
			if !mutated {
				mutated = true
				file, err := os.OpenFile(filepath.Join(fixture.dataDir, ControlStateName), os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteString("x"); err != nil {
					_ = file.Close()
					return err
				}
				if err := file.Close(); err != nil {
					return err
				}
			}
			return syncRoot(root)
		}}}
		_, err := operations.Create(context.Background(), CreateOptions{
			DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
			MasterKey: fixture.masterText, AdminToken: fixture.adminText,
		})
		if !errors.Is(err, ErrUnsafeSnapshot) || errors.Is(err, ErrVerifyRequired) {
			t.Fatalf("post-publication source instability was conflated with durability: %v", err)
		}
		if info, statErr := os.Lstat(output); statErr != nil || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatalf("post-publication instability did not leave the durable single-link result for quarantine: info=%v err=%v", info, statErr)
		}
	})
}

func TestVerifyRepairsCrashImmediatelyAfterPublicationLink(t *testing.T) {
	fixture := newBackupFixture(t)
	output := filepath.Join(fixture.outputDir, "linked-crash.meshbackup")
	operations := unixOperations{publication: &publicationHooks{afterLink: func() error { return errors.New("simulated crash") }}}
	_, err := operations.Create(context.Background(), CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	})
	if !errors.Is(err, ErrVerifyRequired) {
		t.Fatalf("post-link interruption did not require verification: %v", err)
	}
	before, err := os.Lstat(output)
	if err != nil || before.Sys().(*syscall.Stat_t).Nlink != 2 {
		t.Fatalf("simulated post-link crash did not leave two names: info=%v err=%v", before, err)
	}
	if _, err := (unixOperations{}).Inspect(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: output}); err == nil {
		t.Fatal("inspect accepted an unrepaired multiply-linked publication")
	}
	if _, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: output}); err != nil {
		t.Fatalf("verify did not safely repair interrupted publication: %v", err)
	}
	after, err := os.Lstat(output)
	if err != nil || after.Sys().(*syscall.Stat_t).Nlink != 1 || !os.SameFile(before, after) {
		t.Fatalf("publication repair did not preserve the final inode as one link: info=%v err=%v", after, err)
	}
	entries, err := os.ReadDir(fixture.outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(output) {
		t.Fatalf("publication repair left unexpected entries: %v", entries)
	}
}

func TestVerifyDoesNotRepairNonmatchingPublicationCandidate(t *testing.T) {
	fixture := newBackupFixture(t)
	output := filepath.Join(fixture.outputDir, "mismatch.meshbackup")
	operations := unixOperations{publication: &publicationHooks{afterLink: func() error { return errors.New("simulated crash") }}}
	_, _ = operations.Create(context.Background(), CreateOptions{
		DataDir: fixture.dataDir, KeyFile: fixture.keyPath, OutputPath: output,
		MasterKey: fixture.masterText, AdminToken: fixture.adminText,
	})
	entries, err := os.ReadDir(fixture.outputDir)
	if err != nil {
		t.Fatal(err)
	}
	var tempName string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+filepath.Base(output)+".mesh-backup-tmp-") {
			tempName = entry.Name()
		}
	}
	if tempName == "" {
		t.Fatal("simulated crash did not leave its temporary name")
	}
	originalTemp := filepath.Join(fixture.outputDir, tempName)
	unexpectedLink := filepath.Join(fixture.outputDir, "unexpected-hardlink")
	if err := os.Rename(originalTemp, unexpectedLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originalTemp, []byte("not the archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (unixOperations{}).Verify(context.Background(), ArchiveOptions{KeyFile: fixture.keyPath, ArchivePath: output}); err == nil || !strings.Contains(err.Error(), "does not alias") {
		t.Fatalf("verify repaired a nonmatching temporary candidate: %v", err)
	}
	if info, err := os.Lstat(output); err != nil || info.Sys().(*syscall.Stat_t).Nlink != 2 {
		t.Fatalf("failed repair mutated final link state: info=%v err=%v", info, err)
	}
	for _, path := range []string{originalTemp, unexpectedLink} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("failed repair removed %s: %v", path, err)
		}
	}
}

func TestRestoreHoldsParentFenceThroughMarkerRemoval(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "restore-fence.meshbackup")
	target := filepath.Join(fixture.root, "restore-fence-target")
	entered := make(chan struct{})
	release := make(chan struct{})
	operations := unixOperations{beforeMarkerDrop: func() error {
		close(entered)
		<-release
		return nil
	}}
	done := make(chan error, 1)
	go func() {
		_, err := operations.Restore(context.Background(), RestoreOptions{
			KeyFile: fixture.keyPath, ArchivePath: archivePath, TargetDir: target, ExpectedBackupID: created.BackupID,
		})
		done <- err
	}()
	<-entered
	if fence, err := AcquireStartupFence(target); !errors.Is(err, ErrStartupFenceBusy) {
		if fence != nil {
			_ = fence.Close()
		}
		close(release)
		t.Fatalf("server-side fence acquired before restore removed its marker: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("restore failed after fence ordering proof: %v", err)
	}
}

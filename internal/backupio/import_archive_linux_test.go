//go:build linux

package backupio

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestOpenValidatedImportArchiveAndExactRevalidation(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "import.meshbackup")

	archive, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.BackupID != created.BackupID || archive.Metadata.ControlVersion != 2 || archive.Metadata.IdentitySchema != "identity-state-v2" || archive.Metadata.CapturedAt.IsZero() {
		t.Fatalf("unexpected authenticated metadata: %+v", archive.Metadata)
	}
	wantControl, err := os.ReadFile(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	wantIdentity, err := os.ReadFile(filepath.Join(fixture.dataDir, IdentityStateName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(archive.ControlBytes, wantControl) || !bytes.Equal(archive.IdentityBytes, wantIdentity) {
		t.Fatal("import reader did not return exact persisted documents")
	}
	if err := archive.ValidateExactDocuments(context.Background(), wantControl, wantIdentity); err != nil {
		t.Fatalf("exact revalidation failed: %v", err)
	}

	tampered := bytes.Clone(wantControl)
	tampered[len(tampered)-1] ^= 1
	if err := archive.ValidateExactDocuments(context.Background(), tampered, wantIdentity); err == nil || !strings.Contains(err.Error(), "exactly match") {
		t.Fatalf("tampered database document was accepted: %v", err)
	}
}

func TestOpenValidatedImportArchiveAcceptsBoundControlVersionsThreeThroughNine(t *testing.T) {
	fixture := newBackupFixture(t)
	master, err := parseMasterKey(fixture.masterText)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	store, err := control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureTopologySchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	created, archivePath := fixture.create(t, unixOperations{}, "topology-v3.meshbackup")
	archive, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if archive.Metadata.ControlVersion != control.ControlStateVersionTopology {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionTopology)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	created, archivePath = fixture.create(t, unixOperations{}, "network-dns-v4.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if archive.Metadata.ControlVersion != control.ControlStateVersionNetworkDNS {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionNetworkDNS)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	created, archivePath = fixture.create(t, unixOperations{}, "network-relays-v5.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if archive.Metadata.ControlVersion != control.ControlStateVersionNetworkRelays {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionNetworkRelays)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureCARotationSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	created, archivePath = fixture.create(t, unixOperations{}, "ca-rotation-v6.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.ControlVersion != control.ControlStateVersionCARotation {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionCARotation)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	created, archivePath = fixture.create(t, unixOperations{}, "firewall-rollout-v7.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.ControlVersion != control.ControlStateVersionFirewallRollout {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionFirewallRollout)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	created, archivePath = fixture.create(t, unixOperations{}, "firewall-pause-v8.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.ControlVersion != control.ControlStateVersionFirewallPause {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionFirewallPause)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureRouteTransferSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	created, archivePath = fixture.create(t, unixOperations{}, "route-transfer-v9.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.ControlVersion != control.ControlStateVersionRouteTransfer {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionRouteTransfer)
	}
	archive.Clear()

	store, err = control.OpenStore(filepath.Join(fixture.dataDir, ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	service = control.NewService(store, box, control.NebulaIssuer{})
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	created, archivePath = fixture.create(t, unixOperations{}, "route-profile-v10.meshbackup")
	archive, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Clear()
	if archive.Metadata.ControlVersion != control.ControlStateVersionRouteProfileEdit {
		t.Fatalf("import metadata control version=%d, want %d", archive.Metadata.ControlVersion, control.ControlStateVersionRouteProfileEdit)
	}
}

func TestOpenValidatedImportArchiveRequiresExactExpectedID(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "wrong-id.meshbackup")
	wrong := strings.Repeat("f", 32)
	if wrong == created.BackupID {
		wrong = strings.Repeat("e", 32)
	}
	_, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: wrong,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong expected ID was accepted: %v", err)
	}
	_, err = OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: strings.ToUpper(created.BackupID),
	})
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("non-canonical expected ID was accepted: %v", err)
	}
}

func TestOpenValidatedImportArchiveInheritsStablePrivateFileChecks(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, backupFixture, string) string
	}{
		{
			name: "archive hard link",
			mutate: func(t *testing.T, fixture backupFixture, archivePath string) string {
				if err := os.Link(archivePath, filepath.Join(fixture.outputDir, "archive-alias")); err != nil {
					t.Fatal(err)
				}
				return archivePath
			},
		},
		{
			name: "archive symbolic link",
			mutate: func(t *testing.T, fixture backupFixture, archivePath string) string {
				link := filepath.Join(fixture.outputDir, "archive-link")
				if err := os.Symlink(filepath.Base(archivePath), link); err != nil {
					t.Fatal(err)
				}
				return link
			},
		},
		{
			name: "symbolic parent component",
			mutate: func(t *testing.T, fixture backupFixture, archivePath string) string {
				link := filepath.Join(fixture.root, "archives-link")
				if err := os.Symlink(fixture.outputDir, link); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(link, filepath.Base(archivePath))
			},
		},
		{
			name: "public archive permissions",
			mutate: func(t *testing.T, _ backupFixture, archivePath string) string {
				if err := os.Chmod(archivePath, 0o644); err != nil {
					t.Fatal(err)
				}
				return archivePath
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBackupFixture(t)
			created, original := fixture.create(t, unixOperations{}, "unsafe.meshbackup")
			archivePath := test.mutate(t, fixture, original)
			opened, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
				KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
			})
			if opened != nil {
				opened.Clear()
			}
			if err == nil {
				t.Fatal("unsafe archive path or metadata was accepted")
			}
		})
	}
}

func TestOpenValidatedImportArchiveRejectsCredentialInvalidAuthenticatedArchive(t *testing.T) {
	fixture := newBackupFixture(t)
	manifest, archivePath := fixture.writeAuthenticatedArchiveWithAdmin(t, "wrong-admin.meshbackup", strings.Repeat("B", 43))
	opened, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: manifest.BackupID,
	})
	if opened != nil {
		opened.Clear()
	}
	if err == nil || !strings.Contains(err.Error(), "administrator credential") {
		t.Fatalf("credential-invalid authenticated archive was accepted: %v", err)
	}
}

func TestValidatedImportArchiveIsDetachedAndClearZeroesBuffers(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "clear.meshbackup")
	first, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	controlAlias := first.ControlBytes
	identityAlias := first.IdentityBytes
	masterAlias := first.masterKey
	adminAlias := first.adminToken

	first.ControlBytes[0] ^= 1
	second, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if err != nil {
		first.Clear()
		t.Fatal(err)
	}
	if bytes.Equal(first.ControlBytes, second.ControlBytes) {
		first.Clear()
		second.Clear()
		t.Fatal("separate import reads unexpectedly shared document storage")
	}
	second.Clear()

	first.Clear()
	first.Clear()
	for label, raw := range map[string][]byte{
		"control": controlAlias, "identity": identityAlias, "master": masterAlias, "admin": adminAlias,
	} {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatalf("%s buffer was not zeroed", label)
		}
	}
	if first.ControlBytes != nil || first.IdentityBytes != nil || first.masterKey != nil || first.adminToken != nil {
		t.Fatal("cleared archive retained byte slices")
	}
	if err := first.ValidateExactDocuments(context.Background(), controlAlias, identityAlias); err == nil || !strings.Contains(err.Error(), "cleared") {
		t.Fatalf("cleared archive remained usable: %v", err)
	}
}

func TestOpenValidatedImportArchiveHonorsContext(t *testing.T) {
	fixture := newBackupFixture(t)
	created, archivePath := fixture.create(t, unixOperations{}, "canceled.meshbackup")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opened, err := OpenValidatedImportArchive(ctx, ImportArchiveOptions{
		KeyFile: fixture.keyPath, ArchivePath: archivePath, ExpectedBackupID: created.BackupID,
	})
	if opened != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled import read returned archive=%v err=%v", opened != nil, err)
	}
	if opened, err := OpenValidatedImportArchive(nil, ImportArchiveOptions{}); opened != nil || err == nil {
		t.Fatalf("nil context returned archive=%v err=%v", opened != nil, err)
	}
}

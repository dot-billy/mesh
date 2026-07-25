//go:build linux

package linuxinstall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

func TestOnlineIntakeOwnsOnePrivateSnapshotAndCleansIt(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	workspace, err := lock.newWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(workspace.path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("workspace metadata = %v, %v", info, err)
	}
	stat, ok := rootInfoSys(info)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 2 {
		t.Fatalf("workspace stat = %+v", stat)
	}
	if err := workspace.writeFile("channel.json", []byte("channel"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := workspace.writeFile("channel.json", []byte("replacement"), 0o400); err == nil || !strings.Contains(err.Error(), "exist") {
		t.Fatalf("create-only write returned %v", err)
	}
	if err := workspace.writeFile("unknown", []byte("body"), 0o400); err == nil || !strings.Contains(err.Error(), "allowed") {
		t.Fatalf("unknown workspace file returned %v", err)
	}
	if err := workspace.remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workspace.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived: %v", err)
	}
	if _, err := lock.newWorkspace(); err != nil {
		t.Fatalf("lock did not release removed workspace ownership: %v", err)
	}
}

func TestOnlineIntakeLockContentionIsStable(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	first, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if second != nil || err == nil || !strings.Contains(err.Error(), "another online install holds the intake lock") {
		t.Fatalf("second lock = %v, %v", second, err)
	}
}

func TestOnlineIntakeReconcilesOnlyRecognizedCrashLeftovers(t *testing.T) {
	t.Run("recognized workspace", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		workspace, err := lock.newWorkspace()
		if err != nil {
			t.Fatal(err)
		}
		if err := workspace.writeFile("channel.json", []byte("partial metadata"), 0o400); err != nil {
			t.Fatal(err)
		}
		workspaceName := workspace.name
		if err := workspace.root.Close(); err != nil {
			t.Fatal(err)
		}
		workspace.root = nil
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}

		lock, err = acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := lock.reconcile(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(rootPath, workspaceName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recognized crash leftover survived: %v", err)
		}
	})

	t.Run("unknown sentinel refuses all cleanup", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspace := createStaleOnlineWorkspace(t, lock, "channel.json", []byte("recognized"))
		sentinel := filepath.Join(rootPath, "operator-sentinel")
		if err := os.WriteFile(sentinel, []byte("never remove"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := lock.reconcile(); err == nil || !strings.Contains(err.Error(), "unknown online intake entry") {
			t.Fatalf("unknown entry reconciliation returned %v", err)
		}
		if got := mustReadLinuxInstallFile(t, sentinel); !bytes.Equal(got, []byte("never remove")) {
			t.Fatalf("sentinel changed to %q", got)
		}
		if _, err := os.Lstat(workspace); err != nil {
			t.Fatalf("recognized entry was removed despite unknown sibling: %v", err)
		}
	})
}

func TestOnlineIntakeRejectsUnsafeCrashLeftovers(t *testing.T) {
	tests := []struct {
		name   string
		create func(*testing.T, string)
		match  string
	}{
		{name: "symlink", create: func(t *testing.T, path string) {
			if err := os.Symlink("/dev/null", path); err != nil {
				t.Fatal(err)
			}
		}, match: "regular file"},
		{name: "FIFO", create: func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o400); err != nil {
				t.Fatal(err)
			}
		}, match: "regular file"},
		{name: "nested directory", create: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, match: "regular file"},
		{name: "hard link", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("body"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "release.json")); err != nil {
				t.Fatal(err)
			}
		}, match: "one link"},
		{name: "wrong mode", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("body"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, match: "mode"},
		{name: "oversize", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, releasetrust.MaxManifestSize+1); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
		}, match: "size"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath := filepath.Join(t.TempDir(), "online-intake")
			lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			workspacePath := makeRawOnlineWorkspace(t, rootPath, "1")
			test.create(t, filepath.Join(workspacePath, "channel.json"))
			if err := lock.reconcile(); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("unsafe cleanup returned %v, want %q", err, test.match)
			}
			if _, err := os.Lstat(workspacePath); err != nil {
				t.Fatalf("unsafe workspace was removed: %v", err)
			}
		})
	}

	t.Run("device", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("device node creation requires root")
		}
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspacePath := makeRawOnlineWorkspace(t, rootPath, "2")
		devicePath := filepath.Join(workspacePath, "channel.json")
		if err := unix.Mknod(devicePath, unix.S_IFCHR|0o400, int(unix.Mkdev(1, 3))); err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("container does not grant mknod")
			}
			t.Fatal(err)
		}
		if err := lock.reconcile(); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("device cleanup returned %v", err)
		}
	})

	t.Run("wrong owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing ownership requires root")
		}
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspacePath := makeRawOnlineWorkspace(t, rootPath, "3")
		path := filepath.Join(workspacePath, "channel.json")
		if err := os.WriteFile(path, []byte("body"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1, -1); err != nil {
			t.Fatal(err)
		}
		if err := lock.reconcile(); err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("wrong-owner cleanup returned %v", err)
		}
	})
}

func TestOnlineIntakeDetectsReplacementMutationAndParentSwap(t *testing.T) {
	t.Run("workspace replacement after inspection", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspacePath := createStaleOnlineWorkspace(t, lock, "channel.json", []byte("original"))
		moved := workspacePath + ".moved"
		err = lock.reconcileUsing(onlineIntakeHooks{afterInspect: func() {
			if renameErr := os.Rename(workspacePath, moved); renameErr != nil {
				t.Fatal(renameErr)
			}
			if mkdirErr := os.Mkdir(workspacePath, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			if writeErr := os.WriteFile(filepath.Join(workspacePath, "channel.json"), []byte("replacement"), 0o400); writeErr != nil {
				t.Fatal(writeErr)
			}
		}})
		if err == nil || !strings.Contains(err.Error(), "changed after inspection") {
			t.Fatalf("replacement returned %v", err)
		}
		if got := mustReadLinuxInstallFile(t, filepath.Join(moved, "channel.json")); !bytes.Equal(got, []byte("original")) {
			t.Fatalf("original changed to %q", got)
		}
		if got := mustReadLinuxInstallFile(t, filepath.Join(workspacePath, "channel.json")); !bytes.Equal(got, []byte("replacement")) {
			t.Fatalf("replacement changed to %q", got)
		}
	})

	t.Run("file mutation after inspection", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspacePath := createStaleOnlineWorkspace(t, lock, "channel.json", []byte("original"))
		filePath := filepath.Join(workspacePath, "channel.json")
		err = lock.reconcileUsing(onlineIntakeHooks{afterInspect: func() {
			if chmodErr := os.Chmod(filePath, 0o600); chmodErr != nil {
				t.Fatal(chmodErr)
			}
			if writeErr := os.WriteFile(filePath, []byte("mutated!"), 0o400); writeErr != nil {
				t.Fatal(writeErr)
			}
			if chmodErr := os.Chmod(filePath, 0o400); chmodErr != nil {
				t.Fatal(chmodErr)
			}
		}})
		if err == nil || !strings.Contains(err.Error(), "changed after inspection") {
			t.Fatalf("mutation returned %v", err)
		}
		if got := mustReadLinuxInstallFile(t, filePath); !bytes.Equal(got, []byte("mutated!")) {
			t.Fatalf("mutated file changed to %q", got)
		}
	})

	t.Run("intake parent replacement", func(t *testing.T) {
		base := t.TempDir()
		rootPath := filepath.Join(base, "online-intake")
		lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		workspacePath := createStaleOnlineWorkspace(t, lock, "channel.json", []byte("original"))
		movedRoot := filepath.Join(base, "moved-intake")
		err = lock.reconcileUsing(onlineIntakeHooks{afterInspect: func() {
			if renameErr := os.Rename(rootPath, movedRoot); renameErr != nil {
				t.Fatal(renameErr)
			}
			if mkdirErr := os.Mkdir(rootPath, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
		}})
		if err == nil || !strings.Contains(err.Error(), "intake root changed") {
			t.Fatalf("parent replacement returned %v", err)
		}
		movedWorkspace := filepath.Join(movedRoot, filepath.Base(workspacePath))
		if got := mustReadLinuxInstallFile(t, filepath.Join(movedWorkspace, "channel.json")); !bytes.Equal(got, []byte("original")) {
			t.Fatalf("moved original changed to %q", got)
		}
	})
}

func TestOnlineIntakeReportsCleanupFsyncFailure(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	workspacePath := createStaleOnlineWorkspace(t, lock, "channel.json", []byte("stale"))
	want := errors.New("injected cleanup fsync failure")
	err = lock.reconcileUsing(onlineIntakeHooks{syncParent: func(*os.Root) error { return want }})
	if !errors.Is(err, want) {
		t.Fatalf("cleanup fsync returned %v", err)
	}
	if _, err := os.Lstat(workspacePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recognized workspace survived failed fsync: %v", err)
	}
}

func createStaleOnlineWorkspace(t *testing.T, lock *onlineIntakeLock, name string, raw []byte) string {
	t.Helper()
	workspace, err := lock.newWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.writeFile(name, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	path := workspace.path
	if err := workspace.root.Close(); err != nil {
		t.Fatal(err)
	}
	workspace.root = nil
	lock.activeWorkspace = ""
	return path
}

func makeRawOnlineWorkspace(t *testing.T, rootPath, suffix string) string {
	t.Helper()
	name := onlineWorkspacePrefix + strings.Repeat("0", 31) + suffix
	path := filepath.Join(rootPath, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustReadLinuxInstallFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOnlineIntakeFixtureNamesAreCanonical(t *testing.T) {
	for index := 1; index <= releasetrust.MaxSignatureEnvelopes; index++ {
		for _, role := range []string{"channel", "release"} {
			name := fmt.Sprintf("%s-signature-%03d.json", role, index)
			if _, _, err := onlineWorkspaceFilePolicy(name); err != nil {
				t.Fatalf("canonical fixture name %q rejected: %v", name, err)
			}
		}
	}
}

func TestOnlineWorkspaceMaterializeSnapshotPreservesExactBytesAndArtifactInode(t *testing.T) {
	lock, workspace := newOnlineWorkspaceFixture(t)
	defer lock.Close()
	defer workspace.remove()
	artifact, err := workspace.openArtifact()
	if err != nil {
		t.Fatal(err)
	}
	artifactRaw := []byte("authenticated Linux bundle bytes")
	if _, err := artifact.Write(artifactRaw); err != nil {
		t.Fatal(err)
	}
	artifactBefore, err := artifact.Stat()
	if err != nil {
		t.Fatal(err)
	}
	bundle := onlineSnapshotTestBundle()
	bundle.ChannelSignatures = reverseByteSlices(bundle.ChannelSignatures)
	bundle.ReleaseSignatures = reverseByteSlices(bundle.ReleaseSignatures)

	snapshotPath, err := workspace.materializeSnapshot(bundle, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotPath != workspace.path {
		t.Fatalf("snapshot path = %q, want %q", snapshotPath, workspace.path)
	}
	snapshot, err := OpenMetadataSnapshot(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.Metadata.ChannelManifest, bundle.ChannelManifest) || !bytes.Equal(snapshot.Metadata.ReleaseManifest, bundle.ReleaseManifest) {
		t.Fatal("materialized snapshot changed exact manifest bytes")
	}
	assertByteSlicesDigestSortedAndExact(t, snapshot.Metadata.ChannelSignatures, bundle.ChannelSignatures)
	assertByteSlicesDigestSortedAndExact(t, snapshot.Metadata.ReleaseSignatures, bundle.ReleaseSignatures)
	wantIdentity, ok := sourceIdentity(artifactBefore)
	if !ok || snapshot.Artifact.Identity.Device != wantIdentity.Device || snapshot.Artifact.Identity.Inode != wantIdentity.Inode || snapshot.Artifact.Identity.Size != int64(len(artifactRaw)) {
		t.Fatalf("snapshot artifact identity = %+v, original = %+v", snapshot.Artifact.Identity, wantIdentity)
	}
	if got := mustReadLinuxInstallFile(t, snapshot.Artifact.Path); !bytes.Equal(got, artifactRaw) {
		t.Fatalf("artifact bytes = %q, want %q", got, artifactRaw)
	}

	descriptorRaw := mustReadLinuxInstallFile(t, filepath.Join(snapshotPath, InstallSnapshotFile))
	descriptor, err := parseInstallSnapshotDescriptor(descriptorRaw)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Schema != InstallSnapshotSchema || descriptor.ChannelManifest != onlineChannelManifestName || descriptor.ReleaseManifest != onlineReleaseManifestName || descriptor.Artifact != onlineArtifactName {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	assertOnlineSnapshotModes(t, snapshotPath)
	if _, err := artifact.Write([]byte("must fail")); err == nil {
		t.Fatal("materialization left the downloader artifact descriptor writable")
	}
}

func TestOnlineWorkspaceMaterializeSnapshotCarriesExactRootUpdates(t *testing.T) {
	lock, workspace, artifact := onlineMaterializeFixture(t)
	defer lock.Close()
	defer workspace.remove()
	_, updates := rootStoreFixture(t, 3)
	bundle := onlineSnapshotTestBundle()
	bundle.RootUpdates = updates

	snapshotPath, err := workspace.materializeSnapshot(bundle, artifact)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := OpenMetadataSnapshot(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if !equalOnlineByteSlices(snapshot.RootUpdates, updates) {
		t.Fatal("materialized snapshot changed exact root-update bytes")
	}
	descriptor, err := parseInstallSnapshotDescriptor(mustReadLinuxInstallFile(t, filepath.Join(snapshotPath, InstallSnapshotFile)))
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range descriptor.RootUpdates {
		want := fmt.Sprintf("root-update-%03d.json", index)
		if name != want {
			t.Fatalf("root update name = %q, want %q", name, want)
		}
	}
	assertOnlineSnapshotModes(t, snapshotPath)
}

func TestOnlineWorkspaceMaterializeSnapshotRejectsUnsafeInputsAndFailures(t *testing.T) {
	t.Run("duplicate signature bytes", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		bundle := onlineSnapshotTestBundle()
		bundle.ReleaseSignatures[0] = append([]byte(nil), bundle.ChannelSignatures[0]...)
		if _, err := workspace.materializeSnapshot(bundle, artifact); err == nil || !strings.Contains(err.Error(), "byte-identical") {
			t.Fatalf("duplicate signature returned %v", err)
		}
	})

	t.Run("too many signatures", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		bundle := onlineSnapshotTestBundle()
		bundle.ChannelSignatures = make([][]byte, releasetrust.MaxSignatureEnvelopes+1)
		for index := range bundle.ChannelSignatures {
			bundle.ChannelSignatures[index] = []byte(fmt.Sprintf("unique signature %03d", index))
		}
		if _, err := workspace.materializeSnapshot(bundle, artifact); err == nil || !strings.Contains(err.Error(), "count") {
			t.Fatalf("signature overflow returned %v", err)
		}
	})

	t.Run("artifact size changes before final readback", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		path := filepath.Join(workspace.path, onlineArtifactName)
		_, err := workspace.materializeSnapshotUsing(onlineSnapshotTestBundle(), artifact, onlineMaterializeHooks{beforeReadback: func() {
			if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
				t.Fatal(chmodErr)
			}
			file, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			if _, writeErr := file.WriteString("changed"); writeErr != nil {
				_ = file.Close()
				t.Fatal(writeErr)
			}
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if chmodErr := os.Chmod(path, 0o400); chmodErr != nil {
				t.Fatal(chmodErr)
			}
		}})
		if err == nil || !strings.Contains(err.Error(), "readback") {
			t.Fatalf("artifact mutation returned %v", err)
		}
	})

	t.Run("replaced artifact descriptor", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		path := filepath.Join(workspace.path, onlineArtifactName)
		moved := path + ".original"
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := workspace.materializeSnapshot(onlineSnapshotTestBundle(), artifact); err == nil || !strings.Contains(err.Error(), "artifact identity") {
			t.Fatalf("artifact replacement returned %v", err)
		}
	})

	t.Run("preexisting metadata name", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		if err := workspace.writeFile(onlineChannelManifestName, []byte("operator-owned"), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := workspace.materializeSnapshot(onlineSnapshotTestBundle(), artifact); err == nil || !strings.Contains(err.Error(), "exist") {
			t.Fatalf("preexisting name returned %v", err)
		}
		if got := mustReadLinuxInstallFile(t, filepath.Join(workspace.path, onlineChannelManifestName)); !bytes.Equal(got, []byte("operator-owned")) {
			t.Fatalf("preexisting metadata changed to %q", got)
		}
	})

	t.Run("artifact chmod failure", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		want := errors.New("injected chmod failure")
		_, err := workspace.materializeSnapshotUsing(onlineSnapshotTestBundle(), artifact, onlineMaterializeHooks{chmodArtifact: func(*os.File, os.FileMode) error { return want }})
		if !errors.Is(err, want) {
			t.Fatalf("chmod failure returned %v", err)
		}
	})

	t.Run("final directory fsync failure", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		want := errors.New("injected snapshot fsync failure")
		_, err := workspace.materializeSnapshotUsing(onlineSnapshotTestBundle(), artifact, onlineMaterializeHooks{syncWorkspace: func(*onlineWorkspace) error { return want }})
		if !errors.Is(err, want) {
			t.Fatalf("fsync failure returned %v", err)
		}
	})

	t.Run("metadata source changes before final readback", func(t *testing.T) {
		lock, workspace, artifact := onlineMaterializeFixture(t)
		defer lock.Close()
		defer workspace.remove()
		path := filepath.Join(workspace.path, onlineChannelManifestName)
		_, err := workspace.materializeSnapshotUsing(onlineSnapshotTestBundle(), artifact, onlineMaterializeHooks{beforeReadback: func() {
			if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
				t.Fatal(chmodErr)
			}
			if writeErr := os.WriteFile(path, []byte("attacker changed exact bytes"), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if chmodErr := os.Chmod(path, 0o400); chmodErr != nil {
				t.Fatal(chmodErr)
			}
		}})
		if err == nil || !strings.Contains(err.Error(), "readback") {
			t.Fatalf("metadata mutation returned %v", err)
		}
	})
}

func newOnlineWorkspaceFixture(t *testing.T) (*onlineIntakeLock, *onlineWorkspace) {
	t.Helper()
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.reconcile(); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	workspace, err := lock.newWorkspace()
	if err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	return lock, workspace
}

func onlineMaterializeFixture(t *testing.T) (*onlineIntakeLock, *onlineWorkspace, *os.File) {
	t.Helper()
	lock, workspace := newOnlineWorkspaceFixture(t)
	artifact, err := workspace.openArtifact()
	if err != nil {
		_ = workspace.remove()
		_ = lock.Close()
		t.Fatal(err)
	}
	if _, err := artifact.WriteString("authenticated artifact bytes"); err != nil {
		_ = artifact.Close()
		_ = workspace.remove()
		_ = lock.Close()
		t.Fatal(err)
	}
	return lock, workspace, artifact
}

func onlineSnapshotTestBundle() onlinerelease.Bundle {
	return onlinerelease.Bundle{
		ChannelManifest: []byte("{\n  \"exact channel bytes\": true\n}\n"),
		ChannelSignatures: [][]byte{
			[]byte("channel signature z\n"),
			[]byte("channel signature a\n"),
		},
		ReleaseManifest: []byte("{\"exact release bytes\":true}"),
		ReleaseSignatures: [][]byte{
			[]byte("release signature z\n"),
			[]byte("release signature a\n"),
		},
	}
}

func reverseByteSlices(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[len(values)-1-index] = append([]byte(nil), values[index]...)
	}
	return result
}

func assertByteSlicesDigestSortedAndExact(t *testing.T, got, source [][]byte) {
	t.Helper()
	want := make([][]byte, len(source))
	for index := range source {
		want[index] = append([]byte(nil), source[index]...)
	}
	sort.Slice(want, func(left, right int) bool {
		leftDigest := sha256.Sum256(want[left])
		rightDigest := sha256.Sum256(want[right])
		if compared := bytes.Compare(leftDigest[:], rightDigest[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare(want[left], want[right]) < 0
	})
	if len(got) != len(want) {
		t.Fatalf("signature count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			t.Fatalf("signature %d differs: got %q want %q", index, got[index], want[index])
		}
	}
}

func assertOnlineSnapshotModes(t *testing.T, path string) {
	t.Helper()
	rootInfo, err := os.Lstat(path)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot root metadata = %v, %v", rootInfo, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := rootInfoSys(info)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			t.Fatalf("snapshot entry %q metadata = %v, %+v", entry.Name(), info.Mode(), stat)
		}
	}
}

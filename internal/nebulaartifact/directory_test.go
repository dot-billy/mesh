package nebulaartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

var (
	stagedNebulaBody = []byte("locked nebula fixture\n")
	stagedNoticeBody = []byte("notice\n")
)

func TestVerifyStagedDirectoryExactTree(t *testing.T) {
	root, artifact := makeStagedDirectoryFixture(t)
	if err := verifyStagedDirectory(root, artifact); err != nil {
		t.Fatal(err)
	}
	assertStagedFile(t, filepath.Join(root, "bin", "nebula"), stagedNebulaBody, 0o755)
	assertStagedFile(t, filepath.Join(root, "NOTICE"), stagedNoticeBody, 0o644)
}

func TestVerifyStagedDirectoryRejectsTreeAndIntegrityChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *ArtifactLock)
	}{
		{
			name: "extra-file",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				writeTestFile(t, filepath.Join(root, "extra"), []byte("extra"), 0o600)
			},
		},
		{
			name: "extra-directory",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				if err := os.Mkdir(filepath.Join(root, "extra"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				if err := os.Remove(filepath.Join(root, "NOTICE")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-mode",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				if err := os.Chmod(filepath.Join(root, "NOTICE"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-hash",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				writeTestFile(t, filepath.Join(root, "NOTICE"), []byte("Notice\n"), 0o644)
			},
		},
		{
			name: "symlink-member",
			mutate: func(t *testing.T, root string, _ *ArtifactLock) {
				if err := os.Remove(filepath.Join(root, "NOTICE")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("bin", "nebula"), filepath.Join(root, "NOTICE")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
		},
		{
			name: "wrong-binary-identity",
			mutate: func(_ *testing.T, _ string, artifact *ArtifactLock) {
				artifact.Entries[1].Binary = &BinaryExpectation{
					Format:   "elf",
					MainPath: "github.com/slackhq/nebula/cmd/nebula",
					Targets:  []Target{{OS: "linux", Arch: "amd64"}},
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, artifact := makeStagedDirectoryFixture(t)
			test.mutate(t, root, &artifact)
			if err := verifyStagedDirectory(root, artifact); err == nil {
				t.Fatal("changed staged directory was accepted")
			}
		})
	}
}

func TestVerifyStagedDirectoryRejectsSymlinkRoot(t *testing.T) {
	root, _ := makeStagedDirectoryFixture(t)
	link := filepath.Join(t.TempDir(), "stage-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := VerifyStagedDirectory(link, "linux", "amd64"); err == nil {
		t.Fatal("symlink root was accepted")
	}
}

func TestVerifyStagedDirectoryRejectsUnsupportedTarget(t *testing.T) {
	if err := VerifyStagedDirectory(t.TempDir(), "linux", "mips64"); err == nil {
		t.Fatal("unsupported target was accepted")
	}
}

func makeStagedDirectoryFixture(t *testing.T) (string, ArtifactLock) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "NOTICE"), stagedNoticeBody, 0o644)
	writeTestFile(t, filepath.Join(root, "bin", "nebula"), stagedNebulaBody, 0o755)
	return root, ArtifactLock{Entries: []EntryLock{
		{Name: "bin/", Type: "dir", OutputMode: 0o755},
		lockedStagedFile("bin/nebula", 0o755, stagedNebulaBody),
		lockedStagedFile("NOTICE", 0o644, stagedNoticeBody),
	}}
}

func lockedStagedFile(name string, mode uint32, body []byte) EntryLock {
	digest := sha256.Sum256(body)
	return EntryLock{
		Name:       name,
		Type:       "file",
		OutputMode: mode,
		Size:       int64(len(body)),
		SHA256:     hex.EncodeToString(digest[:]),
	}
}

func writeTestFile(t *testing.T, name string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func assertStagedFile(t *testing.T, name string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s bytes = %q, want %q", name, got, want)
	}
	info, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("%s mode = %04o, want %04o", name, info.Mode().Perm(), mode)
	}
}

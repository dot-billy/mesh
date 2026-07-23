//go:build linux

package releaseorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishAndInspectExactImmutableGeneration(t *testing.T) {
	sourceRoot, channelPath, artifactPath := writeOriginFixture(t)
	if err := os.WriteFile(filepath.Join(sourceRoot, "unpublished-private.key"), []byte("must not copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := BuildIndex(sourceRoot, []string{artifactPath, channelPath})
	if err != nil {
		t.Fatal(err)
	}
	indexRaw := mustEncodeIndex(t, index)
	indexPath := filepath.Join(t.TempDir(), "origin-index.json")
	if err := WriteNewIndex(indexPath, indexRaw); err != nil {
		t.Fatal(err)
	}
	generationsRoot := filepath.Join(t.TempDir(), "generations")
	if err := os.Mkdir(generationsRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	receipt, generationPath, err := PublishGeneration(sourceRoot, indexPath, generationsRoot)
	if err != nil {
		t.Fatal(err)
	}
	allowGenerationTestCleanup(t, generationPath)
	digest := sha256.Sum256(indexRaw)
	expectedGeneration := hex.EncodeToString(digest[:])
	if receipt.Generation != expectedGeneration || receipt.IndexSHA256 != expectedGeneration || filepath.Base(generationPath) != expectedGeneration || receipt.ObjectCount != 2 {
		t.Fatalf("unexpected generation publication: %#v at %q", receipt, generationPath)
	}
	expectedTotal := index.Objects[0].Size + index.Objects[1].Size
	if receipt.TotalSize != expectedTotal {
		t.Fatalf("generation total = %d, want %d", receipt.TotalSize, expectedTotal)
	}
	inspected, err := InspectGeneration(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	if inspected != receipt {
		t.Fatalf("inspection receipt = %#v, want %#v", inspected, receipt)
	}
	canonical, err := EncodeGenerationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(generationPath, GenerationReceiptName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, canonical) {
		t.Fatalf("generation receipt changed bytes: %q", stored)
	}
	if _, err := os.Lstat(filepath.Join(generationPath, GenerationRepoName, "unpublished-private.key")); !os.IsNotExist(err) {
		t.Fatalf("unindexed source file entered generation: %v", err)
	}
	for _, path := range []string{
		generationPath,
		filepath.Join(generationPath, GenerationRepoName),
		filepath.Join(generationPath, GenerationRepoName, "channels", "stable"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != generationDirMode {
			t.Fatalf("directory %q mode = %04o, want %04o", path, info.Mode().Perm(), generationDirMode)
		}
	}
	for _, path := range []string{
		filepath.Join(generationPath, GenerationReceiptName),
		filepath.Join(generationPath, GenerationIndexName),
		objectFilesystemPath(filepath.Join(generationPath, GenerationRepoName), channelPath),
		objectFilesystemPath(filepath.Join(generationPath, GenerationRepoName), artifactPath),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != generationFileMode {
			t.Fatalf("file %q mode = %04o, want %04o", path, info.Mode().Perm(), generationFileMode)
		}
	}

	if err := os.WriteFile(objectFilesystemPath(sourceRoot, artifactPath), []byte("source changed after publication\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectGeneration(generationPath); err != nil {
		t.Fatalf("source mutation affected published generation: %v", err)
	}
	if _, _, err := PublishGeneration(sourceRoot, indexPath, generationsRoot); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("generation replacement returned %v", err)
	}
}

func TestPublishGenerationRejectsChangedSourceAndCleansStaging(t *testing.T) {
	sourceRoot, channelPath, artifactPath := writeOriginFixture(t)
	index, err := BuildIndex(sourceRoot, []string{channelPath, artifactPath})
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(t.TempDir(), "origin-index.json")
	if err := WriteNewIndex(indexPath, mustEncodeIndex(t, index)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectFilesystemPath(sourceRoot, artifactPath), []byte("changed before publication\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	generationsRoot := filepath.Join(t.TempDir(), "generations")
	if err := os.Mkdir(generationsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PublishGeneration(sourceRoot, indexPath, generationsRoot); err == nil || !strings.Contains(err.Error(), "index requires") && !strings.Contains(err.Error(), "differs from its index") {
		t.Fatalf("changed source publication returned %v", err)
	}
	entries, err := os.ReadDir(generationsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed publication left entries: %v", entries)
	}
}

func TestInspectGenerationRejectsTreeAndReceiptAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, generationPath string, index Index)
	}{
		{
			name: "extra file",
			mutate: func(t *testing.T, generationPath string, _ Index) {
				repository := filepath.Join(generationPath, GenerationRepoName)
				if err := os.Chmod(repository, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(repository, "extra"), []byte("extra\n"), generationFileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(repository, generationDirMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, generationPath string, index Index) {
				repository := filepath.Join(generationPath, GenerationRepoName)
				if err := os.Chmod(repository, 0o755); err != nil {
					t.Fatal(err)
				}
				target := objectFilesystemPath(repository, index.Objects[1].Path)
				if err := os.Link(target, filepath.Join(repository, "linked")); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(repository, generationDirMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "writable object",
			mutate: func(t *testing.T, generationPath string, index Index) {
				if err := os.Chmod(objectFilesystemPath(filepath.Join(generationPath, GenerationRepoName), index.Objects[1].Path), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "receipt bytes",
			mutate: func(t *testing.T, generationPath string, _ Index) {
				path := filepath.Join(generationPath, GenerationReceiptName)
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`{"schema":"mesh-release-origin-generation-v1"}`+"\n"), generationFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot, channelPath, artifactPath := writeOriginFixture(t)
			index, err := BuildIndex(sourceRoot, []string{channelPath, artifactPath})
			if err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(t.TempDir(), "origin-index.json")
			if err := WriteNewIndex(indexPath, mustEncodeIndex(t, index)); err != nil {
				t.Fatal(err)
			}
			generationsRoot := filepath.Join(t.TempDir(), "generations")
			if err := os.Mkdir(generationsRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			_, generationPath, err := PublishGeneration(sourceRoot, indexPath, generationsRoot)
			if err != nil {
				t.Fatal(err)
			}
			allowGenerationTestCleanup(t, generationPath)
			test.mutate(t, generationPath, index)
			if _, err := InspectGeneration(generationPath); err == nil {
				t.Fatal("ambiguous generation inspected successfully")
			}
		})
	}
}

func TestGenerationReceiptIsStrictAndCanonical(t *testing.T) {
	receipt := GenerationReceipt{
		Schema: GenerationSchema, Generation: strings.Repeat("a", 64), IndexSHA256: strings.Repeat("a", 64),
		ObjectCount: 2, TotalSize: 123,
	}
	raw, err := EncodeGenerationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGenerationReceipt(raw)
	if err != nil || parsed != receipt {
		t.Fatalf("receipt round trip = %#v, %v", parsed, err)
	}
	for name, candidate := range map[string][]byte{
		"missing newline": bytes.TrimSuffix(raw, []byte("\n")),
		"unknown field":   []byte(`{"schema":"mesh-release-origin-generation-v1","generation":"` + strings.Repeat("a", 64) + `","index_sha256":"` + strings.Repeat("a", 64) + `","object_count":2,"total_size":123,"unknown":true}` + "\n"),
		"mismatch":        bytes.Replace(raw, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGenerationReceipt(candidate); err == nil {
				t.Fatal("inexact generation receipt accepted")
			}
		})
	}
}

func allowGenerationTestCleanup(t *testing.T, generationPath string) {
	t.Helper()
	t.Cleanup(func() {
		var directories []string
		_ = filepath.WalkDir(generationPath, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				directories = append(directories, path)
			}
			return nil
		})
		for _, directory := range directories {
			_ = os.Chmod(directory, 0o700)
		}
	})
}

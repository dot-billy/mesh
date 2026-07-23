package nebulaartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

func TestGoldenPinnedArchives(t *testing.T) {
	goldenDir := os.Getenv("MESH_NEBULA_GOLDEN_DIR")
	if goldenDir == "" {
		t.Skip("set MESH_NEBULA_GOLDEN_DIR to a directory containing the five pinned v1.10.3 archives")
	}
	lock, err := EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range lock.Artifacts {
		artifact := artifact
		t.Run(artifact.Name, func(t *testing.T) {
			archivePath := filepath.Join(goldenDir, artifact.Name)
			archive, err := os.Open(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			info, err := archive.Stat()
			if err != nil || info.Size() != artifact.Size {
				t.Fatalf("archive size = %d, err=%v; want %d", info.Size(), err, artifact.Size)
			}
			hash := sha256.New()
			if _, err := io.Copy(hash, archive); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(hash.Sum(nil)); got != artifact.SHA256 {
				t.Fatalf("archive SHA-256 = %s, want %s", got, artifact.SHA256)
			}
			if _, err := archive.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			stagePath := filepath.Join(t.TempDir(), "stage")
			if err := os.Mkdir(stagePath, 0o700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(stagePath)
			if err != nil {
				t.Fatal(err)
			}
			count, total, stageErr := stageArchive(archive, artifact, root)
			closeErr := root.Close()
			if stageErr != nil {
				t.Fatal(stageErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			var wantCount int
			var wantTotal int64
			wantPaths := make(map[string]struct{})
			for _, entry := range artifact.Entries {
				name := outputPath(entry)
				wantPaths[name] = struct{}{}
				for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
					wantPaths[parent] = struct{}{}
				}
				stagedInfo, err := os.Lstat(filepath.Join(stagePath, filepath.FromSlash(name)))
				if err != nil {
					t.Fatalf("stat %s: %v", name, err)
				}
				if uint32(stagedInfo.Mode().Perm()) != entry.OutputMode {
					t.Fatalf("%s output mode = %04o, want %04o", name, stagedInfo.Mode().Perm(), entry.OutputMode)
				}
				if entry.Type == "dir" {
					if !stagedInfo.IsDir() {
						t.Fatalf("%s is not a directory", name)
					}
					continue
				}
				wantCount++
				wantTotal += entry.Size
				file, err := os.Open(filepath.Join(stagePath, filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.New()
				_, copyErr := io.Copy(hash, file)
				closeErr := file.Close()
				if copyErr != nil || closeErr != nil {
					t.Fatalf("read %s: copy=%v close=%v", name, copyErr, closeErr)
				}
				if got := hex.EncodeToString(hash.Sum(nil)); got != entry.SHA256 {
					t.Fatalf("%s SHA-256 = %s, want %s", name, got, entry.SHA256)
				}
			}
			if count != wantCount || total != wantTotal {
				t.Fatalf("staged count/bytes = %d/%d, want %d/%d", count, total, wantCount, wantTotal)
			}
			err = filepath.WalkDir(stagePath, func(current string, entry os.DirEntry, err error) error {
				if err != nil || current == stagePath {
					return err
				}
				relative, err := filepath.Rel(stagePath, current)
				if err != nil {
					return err
				}
				if _, ok := wantPaths[filepath.ToSlash(relative)]; !ok {
					t.Fatalf("unexpected staged path %s", relative)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			target := artifact.Targets[0]
			if err := VerifyStagedDirectory(stagePath, target.OS, target.Arch); err != nil {
				t.Fatalf("verify published staging directory: %v", err)
			}
		})
	}
}

func TestGoldenNetworkFetchLinuxAMD64(t *testing.T) {
	testGoldenNetworkFetchLinux(t, "amd64")
}

func TestGoldenNetworkFetchLinuxARM64(t *testing.T) {
	testGoldenNetworkFetchLinux(t, "arm64")
}

func testGoldenNetworkFetchLinux(t *testing.T, arch string) {
	t.Helper()
	if os.Getenv("MESH_TEST_NEBULA_FETCH") != "1" {
		t.Skip("set MESH_TEST_NEBULA_FETCH=1 to exercise the real locked GitHub fetch")
	}
	parent := t.TempDir()
	output := filepath.Join(parent, "nebula-linux-"+arch)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := FetchNebula(ctx, "linux", arch, output)
	if err != nil {
		t.Fatal(err)
	}
	if result.AssetName != "nebula-linux-"+arch+".tar.gz" || result.FileCount != 2 {
		t.Fatalf("unexpected fetch result: %+v", result)
	}
	if err := VerifyStagedDirectory(output, "linux", arch); err != nil {
		t.Fatalf("verify fetched staging directory: %v", err)
	}
	lock, _ := EmbeddedLock()
	artifact, _ := lock.Select("linux", arch)
	for _, entry := range artifact.Entries {
		file, err := os.Open(filepath.Join(output, entry.Name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("read %s: %v / %v", entry.Name, copyErr, closeErr)
		}
		if got := hex.EncodeToString(hash.Sum(nil)); got != entry.SHA256 {
			t.Fatalf("%s SHA-256 = %s, want %s", entry.Name, got, entry.SHA256)
		}
	}
}

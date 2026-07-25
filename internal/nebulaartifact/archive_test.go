package nebulaartifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type fixtureEntry struct {
	name     string
	mode     os.FileMode
	body     []byte
	tarType  byte
	linkName string
}

func TestStageTarGZExactEntry(t *testing.T) {
	body := []byte("locked content")
	archivePath := makeTarGZ(t, []fixtureEntry{{name: "bin/nebula-note", mode: 0o644, body: body}})
	artifact := artifactForFixture(t, archivePath, "tar.gz", []EntryLock{lockedFixtureEntry("bin/nebula-note", 0o644, body)})
	stagePath := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	count, total, err := stageFixture(archivePath, stagePath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || total != int64(len(body)) {
		t.Fatalf("count/total = %d/%d", count, total)
	}
	got, err := os.ReadFile(filepath.Join(stagePath, "bin", "nebula-note"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("staged bytes = %q, err=%v", got, err)
	}
}

func TestStageZIPExactEntryAndDirectory(t *testing.T) {
	body := []byte("locked zip content")
	archivePath := makeZIP(t, []fixtureEntry{{name: "bin/", mode: os.ModeDir | 0o755}, {name: "bin/file", mode: 0o644, body: body}})
	directory := EntryLock{Name: "bin/", Type: "dir", ArchiveMode: 0o755, OutputMode: 0o755}
	file := lockedFixtureEntry("bin/file", 0o644, body)
	fillZIPMetadata(t, archivePath, &directory, &file)
	artifact := artifactForFixture(t, archivePath, "zip", []EntryLock{directory, file})
	stagePath := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageFixture(archivePath, stagePath, artifact); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(stagePath, "bin", "file"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("staged bytes = %q, err=%v", got, err)
	}
}

func TestStageTarRejectsUnsafeTypesPathsDuplicatesAndIntegrity(t *testing.T) {
	body := []byte("content")
	tests := []struct {
		name    string
		entries []fixtureEntry
		locked  []EntryLock
		mutate  func(*tar.Header)
	}{
		{name: "traversal", entries: []fixtureEntry{{name: "../escape", mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry("../escape", 0o644, body)}},
		{name: "backslash", entries: []fixtureEntry{{name: `dir\file`, mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry(`dir\file`, 0o644, body)}},
		{name: "drive", entries: []fixtureEntry{{name: "C:evil", mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry("C:evil", 0o644, body)}},
		{name: "duplicate", entries: []fixtureEntry{{name: "file", mode: 0o644, body: body}, {name: "file", mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry("file", 0o644, body)}},
		{name: "unlisted", entries: []fixtureEntry{{name: "file", mode: 0o644, body: body}, {name: "extra", mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry("file", 0o644, body)}},
		{name: "wrong-hash", entries: []fixtureEntry{{name: "file", mode: 0o644, body: body}}, locked: []EntryLock{lockedFixtureEntry("file", 0o644, []byte("different"))}},
		{name: "symlink", entries: []fixtureEntry{{name: "link", mode: os.ModeSymlink | 0o777, body: []byte("target")}}, locked: []EntryLock{lockedFixtureEntry("link", 0o777, []byte("target"))}},
		{name: "hardlink", entries: []fixtureEntry{{name: "hard", mode: 0o644, tarType: tar.TypeLink, linkName: "target"}}, locked: []EntryLock{lockedFixtureEntry("hard", 0o644, nil)}},
		{name: "fifo", entries: []fixtureEntry{{name: "fifo", mode: 0o644, tarType: tar.TypeFifo}}, locked: []EntryLock{lockedFixtureEntry("fifo", 0o644, nil)}},
		{name: "char-device", entries: []fixtureEntry{{name: "char", mode: 0o644, tarType: tar.TypeChar}}, locked: []EntryLock{lockedFixtureEntry("char", 0o644, nil)}},
		{name: "block-device", entries: []fixtureEntry{{name: "block", mode: 0o644, tarType: tar.TypeBlock}}, locked: []EntryLock{lockedFixtureEntry("block", 0o644, nil)}},
		{name: "special-mode", entries: []fixtureEntry{{name: "file", mode: os.ModeSetuid | 0o755, body: body}}, locked: []EntryLock{lockedFixtureEntry("file", 0o755, body)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := makeTarGZ(t, test.entries)
			artifact := artifactForFixture(t, archivePath, "tar.gz", test.locked)
			stagePath := filepath.Join(t.TempDir(), "stage")
			if err := os.Mkdir(stagePath, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, _, err := stageFixture(archivePath, stagePath, artifact); err == nil {
				t.Fatal("adversarial tar accepted")
			}
		})
	}
}

func TestStageZIPRejectsUnsafeAndBombEntries(t *testing.T) {
	t.Run("self-extracting-prefix", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		prependOrAppendZIP(t, archivePath, []byte("prefix"), nil)
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("archive-comment", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		patchZIPComment(t, archivePath, []byte("comment"))
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("raw-trailing", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		prependOrAppendZIP(t, archivePath, nil, []byte("trailing"))
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("symlink", func(t *testing.T) {
		archivePath := makeZIP(t, []fixtureEntry{{name: "link", mode: os.ModeSymlink | 0o777, body: []byte("target")}})
		locked := lockedFixtureEntry("link", 0o777, []byte("target"))
		fillZIPMetadata(t, archivePath, &locked)
		artifact := artifactForFixture(t, archivePath, "zip", []EntryLock{locked})
		assertStageFails(t, archivePath, artifact)
	})
	t.Run("traversal", func(t *testing.T) {
		archivePath := makeZIP(t, []fixtureEntry{{name: "../escape", mode: 0o644, body: []byte("bad")}})
		locked := lockedFixtureEntry("../escape", 0o644, []byte("bad"))
		fillZIPMetadata(t, archivePath, &locked)
		artifact := artifactForFixture(t, archivePath, "zip", []EntryLock{locked})
		assertStageFails(t, archivePath, artifact)
	})
	t.Run("duplicate", func(t *testing.T) {
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: []byte("one")}, {name: "file", mode: 0o644, body: []byte("two")}})
		locked := lockedFixtureEntry("file", 0o644, []byte("one"))
		fillZIPMetadata(t, archivePath, &locked)
		artifact := artifactForFixture(t, archivePath, "zip", []EntryLock{locked})
		assertStageFails(t, archivePath, artifact)
	})
	t.Run("ratio", func(t *testing.T) {
		body := bytes.Repeat([]byte{0}, 4<<20)
		archivePath := makeZIP(t, []fixtureEntry{{name: "bomb", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("bomb", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		artifact := artifactForFixture(t, archivePath, "zip", []EntryLock{locked})
		assertStageFails(t, archivePath, artifact)
	})
	t.Run("encrypted-flag", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		patchZIPFlags(t, archivePath, 1)
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("unsupported-flag", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		patchZIPFlags(t, archivePath, 1<<5)
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("bad-crc", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, body)
		fillZIPMetadata(t, archivePath, &locked)
		patchZIPCentralCRC(t, archivePath, locked.CRC32^0xffffffff)
		locked.CRC32 ^= 0xffffffff
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
	t.Run("same-length-hash", func(t *testing.T) {
		body := []byte("content")
		archivePath := makeZIP(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		locked := lockedFixtureEntry("file", 0o644, []byte("Content"))
		fillZIPMetadata(t, archivePath, &locked)
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "zip", []EntryLock{locked}))
	})
}

func TestStageTarRejectsAdditionalGzipData(t *testing.T) {
	body := []byte("content")
	locked := lockedFixtureEntry("file", 0o644, body)
	for _, test := range []struct {
		name   string
		append func(*testing.T, string) []byte
	}{
		{name: "raw-trailing", append: func(_ *testing.T, _ string) []byte { return []byte("trailing") }},
		{name: "second-member", append: func(t *testing.T, _ string) []byte {
			second := makeTarGZ(t, []fixtureEntry{{name: "other", mode: 0o644, body: []byte("other")}})
			data, err := os.ReadFile(second)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			archivePath := makeTarGZ(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
			file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(test.append(t, archivePath)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "tar.gz", []EntryLock{locked}))
		})
	}
	t.Run("bad-footer", func(t *testing.T) {
		archivePath := makeTarGZ(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		raw, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "tar.gz", []EntryLock{locked}))
	})
	t.Run("nonzero-tail-in-member", func(t *testing.T) {
		archivePath := makeTarGZ(t, []fixtureEntry{{name: "file", mode: 0o644, body: body}})
		compressed, err := os.Open(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(compressed)
		if err != nil {
			t.Fatal(err)
		}
		uncompressed, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		_ = compressed.Close()
		output, err := os.Create(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		writer := gzip.NewWriter(output)
		if _, err := writer.Write(append(uncompressed, []byte("hidden")...)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
		assertStageFails(t, archivePath, artifactForFixture(t, archivePath, "tar.gz", []EntryLock{locked}))
	})
}

func TestStageUsesAuthenticatedOpenFileAfterPathReplacement(t *testing.T) {
	goodBody := []byte("authenticated")
	locked := lockedFixtureEntry("file", 0o644, goodBody)
	originalPath := makeTarGZ(t, []fixtureEntry{{name: "file", mode: 0o644, body: goodBody}})
	authenticatedFile, err := os.Open(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer authenticatedFile.Close()
	if err := os.Rename(originalPath, originalPath+".authenticated"); err != nil {
		t.Fatal(err)
	}
	maliciousPath := makeTarGZ(t, []fixtureEntry{{name: "file", mode: 0o644, body: []byte("malicious")}})
	malicious, err := os.ReadFile(maliciousPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originalPath, malicious, 0o600); err != nil {
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
	defer root.Close()
	info, err := authenticatedFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	artifact := ArtifactLock{Size: info.Size(), ArchiveFormat: "tar.gz", Entries: []EntryLock{locked}}
	if _, _, err := stageArchive(authenticatedFile, artifact, root); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(stagePath, "file"))
	if err != nil || !bytes.Equal(got, goodBody) {
		t.Fatalf("staged replacement path instead of authenticated FD: %q, %v", got, err)
	}
}

func TestFetchFailureLeavesNoDestinationOrTemporaryFiles(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "output")
	body := []byte("not an archive")
	digest := sha256.Sum256(body)
	artifact := ArtifactLock{URL: "https://github.test/release", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), ArchiveFormat: "tar.gz", Entries: []EntryLock{lockedFixtureEntry("file", 0o644, []byte("content"))}}
	policy := networkPolicy{initialURL: artifact.URL, initialHost: "github.test", finalHost: "assets.test"}
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(request, http.StatusFound, nil, map[string]string{"Location": "https://assets.test/object"}), nil
		}
		return response(request, http.StatusOK, body, nil), nil
	}), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if _, err := fetchNebula(context.Background(), artifact, Target{OS: "linux", Arch: "amd64"}, output, client, policy); err == nil {
		t.Fatal("invalid archive accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after failure: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary residue after failure: %v", entries)
	}
}

func TestFetchRefusesExistingDestinationWithoutNetwork(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(output, "owned")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("network used for existing destination")
		return nil, nil
	})}
	artifact := ArtifactLock{URL: "https://github.test/release"}
	policy := networkPolicy{initialURL: artifact.URL, initialHost: "github.test", finalHost: "assets.test"}
	if _, err := fetchNebula(context.Background(), artifact, Target{}, output, client, policy); err == nil {
		t.Fatal("existing destination accepted")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "preserve" {
		t.Fatalf("existing destination mutated: %q, %v", got, err)
	}
}

func TestFetchRejectsInsecureOrSymlinkAncestorWithoutNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("network used before ancestry validation")
		return nil, nil
	})}
	artifact := ArtifactLock{URL: "https://github.test/release"}
	policy := networkPolicy{initialURL: artifact.URL, initialHost: "github.test", finalHost: "assets.test"}
	t.Run("writable-ancestor", func(t *testing.T) {
		base := t.TempDir()
		insecure := filepath.Join(base, "insecure")
		if err := os.Mkdir(insecure, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(insecure, 0o777); err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(insecure, "private")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := fetchNebula(context.Background(), artifact, Target{}, filepath.Join(parent, "output"), client, policy); err == nil {
			t.Fatal("non-sticky writable ancestor accepted")
		}
	})
	t.Run("symlink-ancestor", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(target, "private")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := fetchNebula(context.Background(), artifact, Target{}, filepath.Join(link, "private", "output"), client, policy); err == nil {
			t.Fatal("symlink ancestor accepted")
		}
	})
}

func makeTarGZ(t *testing.T, entries []fixtureEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeFlag := entry.tarType
		if typeFlag == 0 {
			typeFlag = tar.TypeReg
		}
		linkName := entry.linkName
		if entry.mode&os.ModeSymlink != 0 && entry.tarType == 0 {
			typeFlag = tar.TypeSymlink
			linkName = string(entry.body)
		}
		mode := int64(entry.mode.Perm())
		if entry.mode&os.ModeSetuid != 0 {
			mode |= 0o4000
		}
		header := &tar.Header{Name: entry.name, Mode: mode, Size: int64(len(entry.body)), Typeflag: typeFlag, Linkname: linkName}
		if typeFlag != tar.TypeReg {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if typeFlag == tar.TypeReg {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func patchZIPFlags(t *testing.T, archivePath string, flags uint16) {
	t.Helper()
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	local := bytes.Index(raw, []byte{'P', 'K', 3, 4})
	central := bytes.Index(raw, []byte{'P', 'K', 1, 2})
	if local < 0 || central < 0 {
		t.Fatal("ZIP headers not found")
	}
	raw[local+6], raw[local+7] = byte(flags), byte(flags>>8)
	raw[central+8], raw[central+9] = byte(flags), byte(flags>>8)
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func patchZIPCentralCRC(t *testing.T, archivePath string, crc uint32) {
	t.Helper()
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.Index(raw, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("ZIP central header not found")
	}
	for index := 0; index < 4; index++ {
		raw[central+16+index] = byte(crc >> (8 * index))
	}
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func prependOrAppendZIP(t *testing.T, archivePath string, prefix, suffix []byte) {
	t.Helper()
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 0, len(prefix)+len(raw)+len(suffix))
	result = append(result, prefix...)
	result = append(result, raw...)
	result = append(result, suffix...)
	if err := os.WriteFile(archivePath, result, 0o600); err != nil {
		t.Fatal(err)
	}
}

func patchZIPComment(t *testing.T, archivePath string, comment []byte) {
	t.Helper()
	if len(comment) > 0xffff {
		t.Fatal("test comment too large")
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	end := bytes.LastIndex(raw, []byte{'P', 'K', 5, 6})
	if end < 0 || end+22 != len(raw) {
		t.Fatal("standard ZIP end record not found")
	}
	raw[end+20], raw[end+21] = byte(len(comment)), byte(len(comment)>>8)
	raw = append(raw, comment...)
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func makeZIP(t *testing.T, entries []fixtureEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode.IsDir() {
			header.Method = zip.Store
		}
		header.SetMode(entry.mode)
		part, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func lockedFixtureEntry(name string, mode uint32, body []byte) EntryLock {
	digest := sha256.Sum256(body)
	return EntryLock{Name: name, Type: "file", ArchiveMode: mode, OutputMode: mode, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
}

func fillZIPMetadata(t *testing.T, archivePath string, locks ...*EntryLock) {
	t.Helper()
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, locked := range locks {
		for _, file := range reader.File {
			if file.Name == locked.Name {
				locked.CompressedSize = int64(file.CompressedSize64)
				locked.CRC32 = file.CRC32
				locked.Compression = file.Method
				break
			}
		}
	}
}

func artifactForFixture(t *testing.T, archivePath, format string, entries []EntryLock) ArtifactLock {
	t.Helper()
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	return ArtifactLock{Size: info.Size(), ArchiveFormat: format, Entries: entries}
}

func stageFixture(archivePath, stagePath string, artifact ArtifactLock) (int, int64, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return 0, 0, err
	}
	defer archive.Close()
	root, err := os.OpenRoot(stagePath)
	if err != nil {
		return 0, 0, err
	}
	defer root.Close()
	return stageArchive(archive, artifact, root)
}

func assertStageFails(t *testing.T, archivePath string, artifact ArtifactLock) {
	t.Helper()
	stagePath := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageFixture(archivePath, stagePath, artifact); err == nil {
		t.Fatal("adversarial ZIP accepted")
	}
}

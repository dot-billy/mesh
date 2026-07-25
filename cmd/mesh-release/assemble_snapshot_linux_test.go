//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"mesh/internal/linuxbundle"
	"mesh/internal/linuxinstall"
	releasetrust "mesh/internal/release"
)

func TestAssembleSnapshotIsDeterministicExactAndPrivate(t *testing.T) {
	root := t.TempDir()
	options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	first := filepath.Join(root, "snapshot-first")
	options.outputPath = first

	args := []string{
		"--output", first,
		"--channel-manifest", options.channelManifestPath,
		"--channel-signature", options.channelSignaturePaths[1],
		"--channel-signature", options.channelSignaturePaths[0],
		"--release-manifest", options.releaseManifestPath,
		"--release-signature", options.releaseSignaturePaths[1],
		"--release-signature", options.releaseSignaturePaths[0],
		"--artifact", options.artifactPath,
	}
	var output bytes.Buffer
	if err := assembleSnapshot(args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), first) || strings.Contains(output.String(), "trusted") && !strings.Contains(output.String(), "No metadata was trusted") {
		t.Fatalf("unexpected operator output %q", output.String())
	}

	secondOptions := options
	secondOptions.outputPath = filepath.Join(root, "snapshot-second")
	secondOptions.channelSignaturePaths = reverseStrings(options.channelSignaturePaths)
	secondOptions.releaseSignaturePaths = reverseStrings(options.releaseSignaturePaths)
	second, err := assembleSnapshotUsing(secondOptions, snapshotAssemblyHooks{})
	if err != nil {
		t.Fatal(err)
	}

	firstTree := readSnapshotTree(t, first)
	secondTree := readSnapshotTree(t, second)
	if len(firstTree) != len(secondTree) {
		t.Fatalf("tree sizes differ: %d and %d", len(firstTree), len(secondTree))
	}
	for name, firstRaw := range firstTree {
		if !bytes.Equal(firstRaw, secondTree[name]) {
			t.Fatalf("deterministic output %q differs", name)
		}
	}
	wantNames := []string{
		"channel-signature-001.json", "channel-signature-002.json", snapshotChannelManifestName,
		linuxinstall.InstallSnapshotFile, snapshotArtifactName,
		"release-signature-001.json", "release-signature-002.json", snapshotReleaseManifestName,
	}
	sort.Strings(wantNames)
	gotNames := make([]string, 0, len(firstTree))
	for name := range firstTree {
		gotNames = append(gotNames, name)
	}
	sort.Strings(gotNames)
	if fmt.Sprint(gotNames) != fmt.Sprint(wantNames) {
		t.Fatalf("snapshot names = %v, want %v", gotNames, wantNames)
	}

	channelRaw := mustReadFile(t, options.channelManifestPath)
	releaseRaw := mustReadFile(t, options.releaseManifestPath)
	artifactRaw := mustReadFile(t, options.artifactPath)
	if !bytes.Equal(firstTree[snapshotChannelManifestName], channelRaw) || !bytes.Equal(firstTree[snapshotReleaseManifestName], releaseRaw) || !bytes.Equal(firstTree[snapshotArtifactName], artifactRaw) {
		t.Fatal("manifest or artifact bytes were not preserved exactly")
	}
	assertSignaturesSortedByDigest(t, firstTree, "channel", options.channelSignaturePaths)
	assertSignaturesSortedByDigest(t, firstTree, "release", options.releaseSignaturePaths)

	descriptor := linuxinstall.InstallSnapshotDescriptor{
		Schema:            linuxinstall.InstallSnapshotSchema,
		RootUpdates:       []string{},
		ChannelManifest:   snapshotChannelManifestName,
		ChannelSignatures: []string{"channel-signature-001.json", "channel-signature-002.json"},
		ReleaseManifest:   snapshotReleaseManifestName,
		ReleaseSignatures: []string{"release-signature-001.json", "release-signature-002.json"},
		Artifact:          snapshotArtifactName,
	}
	wantDescriptor, err := linuxinstall.EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstTree[linuxinstall.InstallSnapshotFile], wantDescriptor) {
		t.Fatalf("install.json = %q, want %q", firstTree[linuxinstall.InstallSnapshotFile], wantDescriptor)
	}
	assertSnapshotModes(t, first)
	if _, err := linuxinstall.OpenMetadataSnapshot(first); err != nil {
		t.Fatalf("assembler output rejected by installer readback: %v", err)
	}
}

func TestAssembleSnapshotSortsAndCarriesContiguousRootUpdates(t *testing.T) {
	root := t.TempDir()
	options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	updates := writeSnapshotRootUpdates(t, filepath.Join(root, "root-updates"), 3)
	options.outputPath = filepath.Join(root, "snapshot")
	options.rootUpdatePaths = []string{updates[2], updates[0], updates[1]}
	path, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := linuxinstall.OpenMetadataSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RootUpdates) != 3 {
		t.Fatalf("snapshot root update count = %d", len(snapshot.RootUpdates))
	}
	for index := range snapshot.RootUpdates {
		want := mustReadFile(t, updates[index])
		if !bytes.Equal(snapshot.RootUpdates[index], want) {
			t.Fatalf("root update %d was not sorted by decoded version", index)
		}
		if _, err := os.Stat(filepath.Join(path, fmt.Sprintf("root-update-%03d.json", index))); err != nil {
			t.Fatal(err)
		}
	}

	duplicate := options
	duplicate.outputPath = filepath.Join(root, "duplicate")
	copyPath := filepath.Join(root, "duplicate-version.json")
	if err := os.WriteFile(copyPath, mustReadFile(t, updates[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	duplicate.rootUpdatePaths = []string{updates[0], copyPath}
	if _, err := assembleSnapshotUsing(duplicate, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "duplicate root update version") {
		t.Fatalf("duplicate root version returned %v", err)
	}

	gap := options
	gap.outputPath = filepath.Join(root, "gap")
	gap.rootUpdatePaths = []string{updates[0], updates[2]}
	if _, err := assembleSnapshotUsing(gap, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "does not continue") {
		t.Fatalf("root update gap returned %v", err)
	}
}

func writeSnapshotRootUpdates(t *testing.T, directory string, count int) []string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]releasetrust.PublicKeyFile, 4)
	privateKeys := make([]ed25519.PrivateKey, 4)
	for index := range files {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := releasetrust.KeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		files[index] = releasetrust.PublicKeyFile{Schema: releasetrust.PublicKeySchema, KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
		privateKeys[index] = privateKey
	}
	t.Cleanup(func() {
		for _, key := range privateKeys {
			clear(key)
		}
	})
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z", Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	current, err := releasetrust.ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, count)
	for index := range count {
		next := current.Document
		next.Keys = append([]releasetrust.PublicKeyFile(nil), current.Document.Keys...)
		next.Roles.Root.KeyIDs = append([]string(nil), current.Document.Roles.Root.KeyIDs...)
		next.Roles.Release.KeyIDs = append([]string(nil), current.Document.Roles.Release.KeyIDs...)
		next.Version++
		next.IssuedAt = time.Date(2026, 7, 21+index, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
		next.ExpiresAt = time.Date(2027, 7, 21+index, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
		nextRaw, err := releasetrust.EncodeRoot(next)
		if err != nil {
			t.Fatal(err)
		}
		signatures := make([][]byte, 2)
		for signer := range signatures {
			signatures[signer], err = releasetrust.SignManifest(releasetrust.RootManifestKind, nextRaw, privateKeys[signer])
			if err != nil {
				t.Fatal(err)
			}
		}
		updateRaw, err := releasetrust.EncodeRootUpdate(releasetrust.RootUpdate{RootManifest: nextRaw, Signatures: signatures})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, fmt.Sprintf("update-%03d.json", index))
		if err := os.WriteFile(path, updateRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[index] = path
		current, err = releasetrust.ParseRoot(nextRaw)
		if err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func TestAssembleSnapshotNeverOverwritesTarget(t *testing.T) {
	root := t.TempDir()
	options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))

	t.Run("preexisting directory", func(t *testing.T) {
		options.outputPath = filepath.Join(root, "existing")
		if err := os.Mkdir(options.outputPath, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(options.outputPath, "keep")
		if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("existing output returned %v", err)
		}
		if got := string(mustReadFile(t, marker)); got != "unchanged" {
			t.Fatalf("existing output changed to %q", got)
		}
	})

	t.Run("collision at publication", func(t *testing.T) {
		options.outputPath = filepath.Join(root, "raced")
		victim := filepath.Join(root, "victim")
		if err := os.Mkdir(victim, 0o700); err != nil {
			t.Fatal(err)
		}
		err := func() error {
			_, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{beforePublish: func() {
				if linkErr := os.Symlink(victim, options.outputPath); linkErr != nil {
					t.Fatalf("create publication collision: %v", linkErr)
				}
			}})
			return err
		}()
		if err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("publication collision returned %v", err)
		}
		target, err := os.Readlink(options.outputPath)
		if err != nil || target != victim {
			t.Fatalf("collision symlink changed: %q, %v", target, err)
		}
		assertNoSnapshotTemporaryDirectories(t, root)
	})
}

func TestAssembleSnapshotRejectsSymlinksMutationAndCollisions(t *testing.T) {
	t.Run("symlink input", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		link := filepath.Join(root, "channel-link.json")
		if err := os.Symlink(options.channelManifestPath, link); err != nil {
			t.Fatal(err)
		}
		options.channelManifestPath = link
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink input returned %v", err)
		}
		assertPathAbsent(t, options.outputPath)
	})

	t.Run("same inode in two roles", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		options.releaseManifestPath = options.channelManifestPath
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "collision") {
			t.Fatalf("source collision returned %v", err)
		}
		assertPathAbsent(t, options.outputPath)
	})

	t.Run("byte-identical signature envelopes", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		duplicate := mustReadFile(t, options.channelSignaturePaths[0])
		if err := os.WriteFile(options.releaseSignaturePaths[0], duplicate, 0o600); err != nil {
			t.Fatal(err)
		}
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "byte-identical") {
			t.Fatalf("signature collision returned %v", err)
		}
		assertPathAbsent(t, options.outputPath)
	})

	for _, test := range []struct {
		name       string
		mutateRole string
		path       func(snapshotAssemblyOptions) string
	}{
		{name: "metadata mutation", mutateRole: "metadata", path: func(options snapshotAssemblyOptions) string { return options.channelManifestPath }},
		{name: "artifact mutation", mutateRole: "artifact", path: func(options snapshotAssemblyOptions) string { return options.artifactPath }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
			options.outputPath = filepath.Join(root, "snapshot")
			target := test.path(options)
			mutated := false
			_, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{afterInputRead: func(path string) {
				if path != target || mutated {
					return
				}
				mutated = true
				raw := mustReadFile(t, path)
				raw[0] ^= 0x01
				if writeErr := os.WriteFile(path, raw, 0o600); writeErr != nil {
					t.Fatalf("mutate %s: %v", test.mutateRole, writeErr)
				}
			}})
			if err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("%s returned %v", test.name, err)
			}
			assertPathAbsent(t, options.outputPath)
			assertNoSnapshotTemporaryDirectories(t, root)
		})
	}
}

func TestAssembleSnapshotEnforcesInputBounds(t *testing.T) {
	t.Run("empty manifest", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		if err := os.WriteFile(options.channelManifestPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("empty input returned %v", err)
		}
	})

	t.Run("oversize signature", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		if err := os.WriteFile(options.channelSignaturePaths[0], bytes.Repeat([]byte("x"), releasetrust.MaxEnvelopeSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("oversize input returned %v", err)
		}
	})

	t.Run("oversize Linux bundle", func(t *testing.T) {
		root := t.TempDir()
		options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		if err := os.Truncate(options.artifactPath, linuxbundle.MaxArchiveSize+1); err != nil {
			t.Fatal(err)
		}
		options.outputPath = filepath.Join(root, "snapshot")
		if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("oversize artifact returned %v", err)
		}
	})
}

func TestAssembleSnapshotDoesNotDeleteUnknownStagingDirectories(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, ".mesh-install-snapshot-stale")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stale, "operator-owned")
	if err := os.WriteFile(marker, []byte("leave intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	options.outputPath = filepath.Join(root, "snapshot")
	if _, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := string(mustReadFile(t, marker)); got != "leave intact" {
		t.Fatalf("unknown staging directory changed to %q", got)
	}
}

func writeSnapshotAssemblyInputs(t *testing.T, directory string) snapshotAssemblyOptions {
	t.Helper()
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return snapshotAssemblyOptions{
		channelManifestPath: write("source-channel.json", "{\n  \"exact channel bytes\": true\n}\n"),
		channelSignaturePaths: []string{
			write("source-channel-z.json", "channel signature z\n"),
			write("source-channel-a.json", "channel signature a\n"),
		},
		releaseManifestPath: write("source-release.json", "{\"exact release bytes\":true}"),
		releaseSignaturePaths: []string{
			write("source-release-z.json", "release signature z\n"),
			write("source-release-a.json", "release signature a\n"),
		},
		artifactPath: write("source-bundle.tar", "exact linux bundle bytes\x00\x01\n"),
	}
}

func reverseStrings(values []string) []string {
	result := append([]string(nil), values...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func readSnapshotTree(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected nested directory %q", entry.Name())
		}
		result[entry.Name()] = mustReadFile(t, filepath.Join(directory, entry.Name()))
	}
	return result
}

func assertSignaturesSortedByDigest(t *testing.T, tree map[string][]byte, kind string, sourcePaths []string) {
	t.Helper()
	want := make([][]byte, len(sourcePaths))
	for index, path := range sourcePaths {
		want[index] = mustReadFile(t, path)
	}
	sort.Slice(want, func(left, right int) bool {
		leftDigest := sha256.Sum256(want[left])
		rightDigest := sha256.Sum256(want[right])
		if compared := bytes.Compare(leftDigest[:], rightDigest[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare(want[left], want[right]) < 0
	})
	for index, raw := range want {
		name := fmt.Sprintf("%s-signature-%03d.json", kind, index+1)
		if !bytes.Equal(tree[name], raw) {
			t.Fatalf("%s contains unexpected signature bytes", name)
		}
	}
}

func assertSnapshotModes(t *testing.T, directory string) {
	t.Helper()
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != snapshotDirectoryMode || hasSnapshotSpecialMode(info.Mode()) {
		t.Fatalf("snapshot directory mode = %v", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != snapshotFileMode || hasSnapshotSpecialMode(info.Mode()) {
			t.Fatalf("snapshot file %q metadata = mode %v, stat %+v", entry.Name(), info.Mode(), stat)
		}
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %q unexpectedly exists: %v", path, err)
	}
}

func assertNoSnapshotTemporaryDirectories(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mesh-install-snapshot-") {
			t.Fatalf("temporary snapshot %q was not removed", entry.Name())
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

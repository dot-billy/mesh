//go:build linux

package linuxinstall

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	releasetrust "mesh/internal/release"
)

func TestRootStorePublishesAndReplaysCreateOnlyHistory(t *testing.T) {
	initial, updates := rootStoreFixture(t, 2)
	path := filepath.Join(t.TempDir(), "trust")
	store, err := NewRootStore(path, uint32(os.Geteuid()), initial)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if lock.Current().Document.Version != 1 {
		t.Fatalf("initial version = %d", lock.Current().Document.Version)
	}
	if empty, err := lock.HistoryEmpty(); err != nil || !empty {
		t.Fatalf("initial history empty = %v, %v", empty, err)
	}
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	result, err := lock.ApplyChain(updates, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Root.Document.Version != 3 || len(result.Applied) != 2 {
		t.Fatalf("apply result: %+v", result)
	}
	if empty, err := lock.HistoryEmpty(); err != nil || empty {
		t.Fatalf("advanced history empty = %v, %v", empty, err)
	}
	historical, err := lock.RootVersion(2)
	if err != nil || historical.Document.Version != 2 {
		t.Fatalf("historical root = %+v, %v", historical, err)
	}
	if _, err := lock.RootVersion(4); err == nil {
		t.Fatal("unpersisted historical root version returned")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{path, filepath.Join(path, "roots")} {
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s = %v, %v", directory, info, err)
		}
	}
	for version := uint64(2); version <= 3; version++ {
		filePath := filepath.Join(path, "roots", rootHistoryName(version))
		info, err := os.Stat(filePath)
		if err != nil || info.Mode().Perm() != 0o400 || info.Mode().Type() != 0 {
			t.Fatalf("history %s = %v, %v", filePath, info, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			t.Fatalf("history identity = %+v", stat)
		}
	}

	reopened, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Current().Document.Version != 3 {
		t.Fatalf("replayed version = %d", reopened.Current().Document.Version)
	}
	idempotent, err := reopened.ApplyChain(updates, now, 5*time.Minute)
	if err != nil || len(idempotent.Applied) != 0 || idempotent.Root.Document.Version != 3 {
		t.Fatalf("idempotent apply = %+v, %v", idempotent, err)
	}
}

func TestRootStoreRejectsGapEquivocationUnknownAndCorruption(t *testing.T) {
	initial, updates := rootStoreFixture(t, 2)
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	t.Run("gap", func(t *testing.T) {
		store := mustRootStore(t, filepath.Join(t.TempDir(), "trust"), initial)
		lock, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if _, err := lock.ApplyChain(updates[1:], now, 0); err == nil || !strings.Contains(err.Error(), "successor") {
			t.Fatalf("gap returned %v", err)
		}
	})
	t.Run("equivocation", func(t *testing.T) {
		store := mustRootStore(t, filepath.Join(t.TempDir(), "trust"), initial)
		lock, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lock.ApplyChain(updates[:1], now, 0); err != nil {
			t.Fatal(err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		parsed, err := releasetrust.ParseRootUpdate(updates[0])
		if err != nil {
			t.Fatal(err)
		}
		root, err := releasetrust.ParseRoot(parsed.RootManifest)
		if err != nil {
			t.Fatal(err)
		}
		root.Document.MinimumReleaseSequence++
		different, err := releasetrust.EncodeRoot(root.Document)
		if err != nil {
			t.Fatal(err)
		}
		differentUpdate, err := releasetrust.EncodeRootUpdate(releasetrust.RootUpdate{RootManifest: different, Signatures: parsed.Signatures})
		if err != nil {
			t.Fatal(err)
		}
		lock, err = store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if _, err := lock.ApplyChain([][]byte{differentUpdate}, now, 0); err == nil || !strings.Contains(err.Error(), "equivocation") {
			t.Fatalf("equivocation returned %v", err)
		}
	})
	for name, content := range map[string][]byte{
		"unknown":         []byte("unknown"),
		"corrupt history": []byte("not a root update"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trust")
			store := mustRootStore(t, path, initial)
			lock, err := store.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			filename := "unknown"
			if name == "corrupt history" {
				filename = rootHistoryName(2)
			}
			if err := os.WriteFile(filepath.Join(path, "roots", filename), content, 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Acquire(); err == nil {
				t.Fatal("unsafe root history accepted")
			}
		})
	}
}

func TestRootStoreLockContentionAndRecognizedTemporaryCleanup(t *testing.T) {
	initial, _ := rootStoreFixture(t, 0)
	path := filepath.Join(t.TempDir(), "trust")
	store := mustRootStore(t, path, initial)
	first, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("contention returned %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(path, "roots", ".pending-"+strings.Repeat("a", 32))
	if err := os.WriteFile(pending, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		t.Fatalf("recognized temporary survived: %v", err)
	}
}

func mustRootStore(t *testing.T, path string, initial releasetrust.ParsedRoot) *RootStore {
	t.Helper()
	store, err := NewRootStore(path, uint32(os.Geteuid()), initial)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func rootStoreFixture(t *testing.T, count int) (releasetrust.ParsedRoot, [][]byte) {
	t.Helper()
	publicKeys := make([]releasetrust.TrustedKey, 4)
	privateKeys := make([]ed25519.PrivateKey, 4)
	files := make([]releasetrust.PublicKeyFile, 4)
	for index := range publicKeys {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := releasetrust.KeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[index] = releasetrust.TrustedKey{KeyID: keyID, PublicKey: publicKey}
		privateKeys[index] = privateKey
		files[index] = releasetrust.PublicKeyFile{Schema: releasetrust.PublicKeySchema, KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
	}
	t.Cleanup(func() {
		for _, key := range privateKeys {
			clear(key)
		}
	})
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	initialRaw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	current, err := releasetrust.ParseRoot(initialRaw)
	if err != nil {
		t.Fatal(err)
	}
	initial := current
	updates := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		next := current.Document
		next.Keys = append([]releasetrust.PublicKeyFile(nil), current.Document.Keys...)
		next.Roles.Root.KeyIDs = append([]string(nil), current.Document.Roles.Root.KeyIDs...)
		next.Roles.Release.KeyIDs = append([]string(nil), current.Document.Roles.Release.KeyIDs...)
		next.Version++
		next.IssuedAt = fmt.Sprintf("2026-07-%02dT12:00:00Z", 21+index)
		next.ExpiresAt = fmt.Sprintf("2027-07-%02dT12:00:00Z", 21+index)
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
		transition, err := releasetrust.VerifyRootTransition(current, nextRaw, signatures)
		if err != nil {
			t.Fatal(err)
		}
		current = transition.Root
		updates = append(updates, updateRaw)
	}
	return initial, updates
}

package identity

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidateIdentityRecoverySnapshotSchemasAndSealedPayloads(t *testing.T) {
	store, sealer, path := newIdentityRecoverySnapshotHarness(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	stateBefore := cloneIdentityState(store.state)
	if err := ValidateRecoverySnapshot(raw, sealer); err != nil {
		t.Fatalf("validate v2 recovery snapshot: %v", err)
	}
	if !bytes.Equal(raw, original) || !reflect.DeepEqual(store.state, stateBefore) {
		t.Fatal("offline validation mutated its input or live store")
	}

	wrongSealer := newRecoveryTestSealer(t, 0x73)
	if err := ValidateRecoverySnapshot(raw, wrongSealer); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("wrong identity sealer was accepted: %v", err)
	}
	if err := ValidateRecoverySnapshot(raw, nil); err == nil {
		t.Fatal("nil identity sealer was accepted")
	}
	var typedNil *testSealer
	if err := ValidateRecoverySnapshot(raw, typedNil); err == nil {
		t.Fatal("typed-nil identity sealer was accepted")
	}

	corrupt := dumpIdentityState(t, path)
	corrupt.LoginAttempts[0].SealedOIDCPayload = tamperIdentityRecoveryCiphertext(corrupt.LoginAttempts[0].SealedOIDCPayload)
	corruptRaw, err := json.MarshalIndent(corrupt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(corruptRaw, sealer); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("corrupt sealed OIDC payload was accepted: %v", err)
	}

	legacy := legacyIdentityStateV1{
		Schema: legacyIdentityStateSchema, LoginAttempts: []persistedLoginAttempt{},
		Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{},
	}
	legacyRaw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := bytes.Clone(legacyRaw)
	if err := ValidateRecoverySnapshot(legacyRaw, sealer); err != nil {
		t.Fatalf("validate legacy recovery snapshot without migration: %v", err)
	}
	if !bytes.Equal(legacyRaw, legacyBefore) {
		t.Fatal("legacy recovery validation rewrote its input")
	}
}

func TestFileStoreExportRecoverySnapshotExactDetachedAndDurable(t *testing.T) {
	t.Run("exact bytes detached and read-only", func(t *testing.T) {
		store, _, path := newIdentityRecoverySnapshotHarness(t)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		exact := append([]byte("\n "), raw...)
		exact = append(exact, '\n', '\t')
		if err := os.WriteFile(path, exact, 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.ExportRecoverySnapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(snapshot, exact) {
			t.Fatal("identity export canonicalized persisted bytes")
		}
		snapshot[0] ^= 0xff
		second, err := store.ExportRecoverySnapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(second, exact) {
			t.Fatal("returned identity snapshot was not detached")
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
			t.Fatal("identity snapshot export rewrote the source file")
		}

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := store.ExportRecoverySnapshot(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled identity export = %v, want context cancellation", err)
		}
	})

	t.Run("pending durability barrier", func(t *testing.T) {
		store, _, _ := newIdentityRecoverySnapshotHarness(t)
		var syncCalls int
		store.syncRoot = func(root *os.Root) error {
			syncCalls++
			if syncCalls == 1 {
				return errors.New("injected directory sync failure")
			}
			return syncIdentityRoot(root)
		}
		now := identityTestTime().Add(time.Minute)
		input := LoginAttemptInput{
			ID: "login_snapshot_pending", TransactionToken: mustToken(t), StateToken: mustToken(t),
			Nonce: mustToken(t), PKCEVerifier: mustToken(t), ReturnPath: "/pending",
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		}
		if err := store.CreateLoginAttempt(context.Background(), input); !errors.Is(err, ErrUncertainCommit) {
			t.Fatalf("identity update = %v, want uncertain commit", err)
		}
		if _, err := store.ExportRecoverySnapshot(context.Background()); err != nil {
			t.Fatalf("identity export did not resolve durability barrier: %v", err)
		}
		if syncCalls != 2 || store.durabilityPending {
			t.Fatalf("identity sync calls=%d pending=%v, want resolved barrier", syncCalls, store.durabilityPending)
		}
	})

	t.Run("disk and memory mismatch", func(t *testing.T) {
		store, _, path := newIdentityRecoverySnapshotHarness(t)
		changed := dumpIdentityState(t, path)
		changed.LoginAttempts[0].ReturnPath = "/externally-changed"
		changedRaw, err := json.MarshalIndent(changed, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, changedRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportRecoverySnapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("identity disk/memory mismatch was accepted: %v", err)
		}
	})

	t.Run("closed store", func(t *testing.T) {
		store, _, _ := newIdentityRecoverySnapshotHarness(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportRecoverySnapshot(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed identity export = %v, want ErrClosed", err)
		}
	})
}

func newIdentityRecoverySnapshotHarness(t *testing.T) (*FileStore, Sealer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	sealer := newRecoveryTestSealer(t, 0x52)
	store, err := OpenFileStore(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := identityTestTime()
	input := LoginAttemptInput{
		ID: "login_snapshot", TransactionToken: mustToken(t), StateToken: mustToken(t),
		Nonce: mustToken(t), PKCEVerifier: mustToken(t), ReturnPath: "/networks?recovery=1",
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := store.CreateLoginAttempt(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	return store, sealer, path
}

func newRecoveryTestSealer(t *testing.T, fill byte) *testSealer {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testSealer{aead: aead}
}

func tamperIdentityRecoveryCiphertext(value string) string {
	if value == "" {
		return "A"
	}
	replacement := byte('A')
	if value[0] == replacement {
		replacement = 'B'
	}
	return string(replacement) + value[1:]
}

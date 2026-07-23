package control

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRecoverySnapshotCredentialsRequiresExactBoundPair(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x61}, 32)
	token := bytes.Repeat([]byte{'E'}, 43)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, NebulaIssuer{})
	verifier, err := DeriveAdminCredentialVerifier(master, token)
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, verifier, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	if err := ValidateRecoverySnapshotCredentials(raw, master, token); err != nil {
		t.Fatalf("bound credential pair was rejected: %v", err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("credential validation modified its input")
	}
	if err := ValidateRecoverySnapshotCredentials(raw, master, bytes.Repeat([]byte{'F'}, 43)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong administrator credential was accepted: %v", err)
	}
	if err := ValidateRecoverySnapshotCredentials(raw, bytes.Repeat([]byte{0x62}, 32), token); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong master key was accepted for an otherwise empty state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRecoverySnapshotCredentialsRejectsUnboundLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRecoverySnapshotCredentials(raw, bytes.Repeat([]byte{0x71}, 32), bytes.Repeat([]byte{'G'}, 43))
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound legacy state was accepted: %v", err)
	}
}

package nodeagent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestStateSchemaVersion(t *testing.T) {
	if StateSchemaVersion != 2 {
		t.Fatalf("agent state schema version = %d, want 2", StateSchemaVersion)
	}
}

func TestStateAndEnrollmentJournalRejectLegacySchema(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := testState(t, filepath.Join(dir, "nebula"), "https://mesh.example.com")
	legacy.Version = 1
	if err := store.Save(legacy); err == nil || !strings.Contains(err.Error(), "unsupported agent state version 1") {
		t.Fatalf("legacy state save error = %v", err)
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicPrivateFile(store.Path(), append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "unsupported agent state version 1") {
		t.Fatalf("legacy state error = %v", err)
	}

	journal, err := NewProvisionalEnrollment("https://mesh.example.com", testBearer(t), filepath.Join(dir, "nebula"), "private-key", "public-key")
	if err != nil {
		t.Fatal(err)
	}
	journal.Version = 1
	if err := journal.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported provisional enrollment version 1") {
		t.Fatalf("legacy journal error = %v", err)
	}
}

func TestStateStorePersistsPrivateAtomicState(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := testState(t, filepath.Join(dir, "nebula"), "https://mesh.example.com")
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}
	info, err := os.Lstat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded.Bearer != state.Bearer || loaded.NodeID != state.NodeID || loaded.OutputDir != state.OutputDir {
		t.Fatalf("state did not round-trip: %#v", loaded)
	}
	if err := os.Chmod(store.Path(), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("insecure state permissions were accepted: %v", err)
	}
}

func TestStateStoreRejectsSharedOrSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(filepath.Join(shared, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := testState(t, filepath.Join(root, "nebula"), "https://mesh.example.com")
	if err := store.Save(state); err == nil || !strings.Contains(err.Error(), "private permissions") {
		t.Fatalf("shared state parent error = %v", err)
	}
	if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state was written through shared parent: %v", err)
	}

	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(private, linked); err != nil {
		t.Fatal(err)
	}
	store, err = NewStateStore(filepath.Join(linked, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(state); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlinked state parent error = %v", err)
	}
}

func TestServerURLRequiresHTTPSExceptLoopback(t *testing.T) {
	accepted := []string{"https://mesh.example.com", "https://10.0.0.2:8443", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"}
	for _, raw := range accepted {
		if _, err := normalizeServerURL(raw); err != nil {
			t.Errorf("normalizeServerURL(%q): %v", raw, err)
		}
	}
	rejected := []string{"http://mesh.example.com", "http://127.0.0.1.example.com", "ftp://localhost", "https://user:pass@mesh.example.com", "https://mesh.example.com/api", "https://mesh.example.com?secret=x"}
	for _, raw := range rejected {
		if _, err := normalizeServerURL(raw); err == nil {
			t.Errorf("normalizeServerURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestRecoveryKeysAreImmutableAndPrivate(t *testing.T) {
	store, err := NewStateStore(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRecoveryKeyPair("private-key", "public-key"); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey, err := store.LoadRecoveryKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if privateKey != "private-key" || publicKey != "public-key" {
		t.Fatal("recovery keypair did not round-trip")
	}
	for _, suffix := range []string{".host.key", ".host.pub"} {
		info, err := os.Lstat(store.Path() + suffix)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("recovery key %s is not mode 0600: info=%v err=%v", suffix, info, err)
		}
	}
	if err := store.SaveRecoveryKeyPair("different", "public-key"); err == nil {
		t.Fatal("existing recovery private key was overwritten")
	}
}

func TestProvisionalEnrollmentJournalPreservesIdempotentRequest(t *testing.T) {
	store, err := NewStateStore(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewProvisionalEnrollment("https://mesh.example.com", testBearer(t), filepath.Join(t.TempDir(), "nebula"), "private-key", "public-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveProvisionalEnrollment(journal); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadProvisionalEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Bearer != journal.Bearer || loaded.EnrollmentToken != journal.EnrollmentToken || control.HashToken(loaded.Bearer) != control.HashToken(journal.Bearer) {
		t.Fatal("provisional journal did not preserve the exact enrollment request")
	}
	info, err := os.Lstat(store.Path() + ".enrollment.json")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal is not mode 0600: info=%v err=%v", info, err)
	}
	different := journal
	different.Bearer = testBearer(t)
	if err := store.SaveProvisionalEnrollment(different); err == nil {
		t.Fatal("pending enrollment journal was overwritten")
	}
	if err := store.ClearProvisionalEnrollment(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadProvisionalEnrollment(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared journal load error = %v", err)
	}
}

func TestProcessLockExcludesAnotherAgent(t *testing.T) {
	store, err := NewStateStore(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.AcquireProcessLock()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := store.AcquireProcessLock(); !errors.Is(err, ErrAgentAlreadyRunning) {
		t.Fatalf("second process lock error = %v, want ErrAgentAlreadyRunning", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := store.AcquireProcessLock()
	if err != nil {
		t.Fatalf("reacquire process lock: %v", err)
	}
	_ = second.Close()
}

func TestGenerateBearerUsesValidTokenHash(t *testing.T) {
	first, err := GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) < 32 || !control.ValidTokenHash(control.HashToken(first)) {
		t.Fatal("generated bearer is not a unique valid agent credential")
	}
}

func TestStateRejectsDetachedRecoveryGenerationAdvanceFlag(t *testing.T) {
	state := testState(t, filepath.Join(t.TempDir(), "nebula"), "https://mesh.example.com")
	state.PendingRecoveryAllowsGenerationAdvance = true
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "only valid for a pending") {
		t.Fatalf("detached recovery generation flag error = %v", err)
	}
}

func testState(t *testing.T, outputDir, serverURL string) State {
	t.Helper()
	publicKey, _, err := control.GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	return State{
		Version: StateSchemaVersion, ServerURL: serverURL, Bearer: bearer,
		NodeID: "node-1", NetworkID: "network-1", ConfigSigningPublicKey: publicKey,
		CACertificateSHA256:       control.ConfigDigest("ca-certificate"),
		PublicKeyHash:             canonicalPublicKeyHash("public-key"),
		CertificateFingerprint:    strings.Repeat("a", 64),
		CertificateGeneration:     1,
		CertificateExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
		CertificateRenewAfter:     time.Now().UTC().Add(16 * time.Hour),
		AgentCredentialExpiresAt:  time.Now().UTC().Add(90 * 24 * time.Hour),
		AgentCredentialGeneration: 1, BootID: bootID, OutputDir: filepath.Clean(outputDir),
	}
}

func testBearer(t *testing.T) string {
	t.Helper()
	token, err := control.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

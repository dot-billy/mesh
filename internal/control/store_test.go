package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRejectsConcurrentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil {
		first.Close()
		t.Fatal("second writer acquired the same state lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStore(path)
	if err != nil {
		t.Fatalf("state lock was not released: %v", err)
	}
	_ = second.Close()
}

func TestStoreNoOpUpdateDoesNotRewriteState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("no-op transaction replaced the state file")
	}
}

func TestStoreRetriesUncertainDirectorySyncBeforeLaterRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC)
	var syncCalls int
	store.syncDirectory = func(directory string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected directory sync failure")
		}
		return syncStateDirectory(directory)
	}
	if err := store.Update(func(state *State) error {
		state.Audit = append(state.Audit, newAudit(now, "store.durability_test", "store", "durability", nil))
		return nil
	}); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("update returned %v, want uncertain commit", err)
	}
	var auditCount int
	if err := store.View(func(state State) error {
		auditCount = len(state.Audit)
		return nil
	}); err != nil {
		t.Fatalf("read did not retry the durability barrier: %v", err)
	}
	if auditCount != 1 || syncCalls != 2 || store.durabilityPending {
		t.Fatalf("audit=%d syncCalls=%d pending=%v", auditCount, syncCalls, store.durabilityPending)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(func(state State) error {
		if len(state.Audit) != 1 || state.Audit[0].Action != "store.durability_test" {
			t.Fatalf("reopened state lost uncertain commit: %#v", state.Audit)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreReadinessReportsRepairsAndRejectsClosedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC)
	var syncCalls int
	store.syncDirectory = func(string) error {
		syncCalls++
		return errors.New("injected persistent directory sync failure")
	}
	if err := store.Update(func(state *State) error {
		state.Audit = append(state.Audit, newAudit(now, "store.readiness_test", "store", "readiness", nil))
		return nil
	}); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("update returned %v, want uncertain commit", err)
	}
	if err := store.CheckReadiness(); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("readiness returned %v, want uncertain commit", err)
	}
	if !store.durabilityPending || syncCalls != 2 {
		t.Fatalf("pending=%v sync calls=%d, want pending after two failed barriers", store.durabilityPending, syncCalls)
	}
	store.syncDirectory = syncStateDirectory
	if err := store.CheckReadiness(); err != nil {
		t.Fatalf("readiness did not repair the pending durability barrier: %v", err)
	}
	if store.durabilityPending {
		t.Fatal("readiness left a repaired durability barrier pending")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed-store readiness returned %v, want closed", err)
	}
	if err := store.View(func(State) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed-store view returned %v, want closed", err)
	}
	if err := store.Update(func(*State) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed-store update returned %v, want closed", err)
	}
}

func TestStoreRejectsUnknownPersistedFields(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	data := []byte(`{"version":1,"networks":[],"nodes":[],"enrollments":[],"audit":[],"unexpected":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown persisted field was accepted: %v", err)
	}
}

func TestStoreRejectsOrphanedGraphMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	err = store.Update(func(state *State) error {
		state.Enrollments = append(state.Enrollments, EnrollmentToken{
			ID: "orphan", NodeID: "missing", TokenHash: HashToken("orphan-token"),
			CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		})
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "missing node") {
		t.Fatalf("orphaned enrollment mutation was accepted: %v", err)
	}
	var enrollmentCount int
	if err := store.View(func(state State) error {
		enrollmentCount = len(state.Enrollments)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if enrollmentCount != 0 {
		t.Fatal("rejected graph mutation changed in-memory state")
	}
}

func TestStoreRejectsOrphanedPersistedGraph(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	now := time.Now().UTC()
	data, err := encodePersistedState(State{
		Version: 1,
		Enrollments: []EnrollmentToken{{
			ID: "orphan", NodeID: "missing", TokenHash: HashToken("orphan-token"),
			CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "missing node") {
		t.Fatalf("orphaned persisted graph was accepted: %v", err)
	}
}

func TestStoreRoundTripsCommittedRecoveryAlongsideUnusedReplacement(t *testing.T) {
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-roundtrip", CIDR: "10.79.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('2')
	originalBearer := strings.Repeat("K", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(originalBearer)); err != nil {
		t.Fatal(err)
	}
	committedToken, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	recoveredBearer := strings.Repeat("L", 42) + "A"
	committed, err := service.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(recoveredBearer))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}

	storePath, box := service.store.path, service.box
	if err := service.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(storePath)
	if err != nil {
		t.Fatalf("reopen state with retained recovery result: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted := NewService(reopened, box, issuer)
	restarted.now = func() time.Time { return now }
	var records []AgentRecoveryToken
	if err := reopened.View(func(state State) error {
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID == created.Node.ID {
				records = append(records, candidate)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("reopened store has %d recovery records, want committed plus replacement", len(records))
	}
	replayed, err := restarted.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(recoveredBearer))
	if err != nil {
		t.Fatalf("replay retained result after store reopen: %v", err)
	}
	if replayed.RecoveryReceipt.Signature != committed.RecoveryReceipt.Signature || replayed.ConfigSignature != committed.ConfigSignature {
		t.Fatal("store round trip changed the committed signed recovery result")
	}
	if _, err := restarted.RecoverAgent(replacement.RecoveryToken, publicKey, HashToken(strings.Repeat("M", 42)+"A")); err != nil {
		t.Fatalf("unused replacement did not survive store round trip: %v", err)
	}
}

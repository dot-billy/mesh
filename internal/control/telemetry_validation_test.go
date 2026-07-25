package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/postgresstore"
)

func TestValidateStateGraphRejectsCorruptLifecycleTelemetryAndKeepsCompatibility(t *testing.T) {
	fixture := newActiveControlRecoveryFixture(t, 1)
	preHeartbeat := cloneRecoveryState(t, fixture.state)
	if err := validateStateGraph(preHeartbeat); err != nil {
		t.Fatalf("active pre-heartbeat state was rejected: %v", err)
	}

	validHeartbeat := validPersistedHeartbeatState(t, fixture.state)
	// Zero remains the supported legacy omitted certificate-generation value.
	validHeartbeat.Nodes[0].AppliedCertificateGeneration = 0
	if err := validateStateGraph(validHeartbeat); err != nil {
		t.Fatalf("legacy generation-compatible heartbeat was rejected: %v", err)
	}

	revoked := cloneRecoveryState(t, validHeartbeat)
	revokedAt := recoverySnapshotNow.Add(time.Minute)
	revoked.Nodes[0].Status = "revoked"
	revoked.Nodes[0].RevokedAt = &revokedAt
	revoked.Nodes[0].AgentTokenHash = ""
	revoked.Nodes[0].PreviousAgentTokenHash = ""
	revoked.Nodes[0].PreviousAgentTokenExpiresAt = nil
	revoked.Nodes[0].AgentCredentialExpiresAt = nil
	revoked.Nodes[0].AgentStatus = "revoked"
	if err := validateStateGraph(revoked); err != nil {
		t.Fatalf("current revoked telemetry state was rejected: %v", err)
	}
	revoked.Nodes[0].AgentStatus = ""
	if err := validateStateGraph(revoked); err != nil {
		t.Fatalf("legacy revoked state without terminal telemetry was rejected: %v", err)
	}

	tests := map[string]func(*Node, Network){
		"oversized agent version": func(node *Node, _ Network) { node.AgentVersion = strings.Repeat("a", maxPersistedAgentVersionBytes+1) },
		"oversized Nebula version": func(node *Node, _ Network) {
			node.NebulaVersion = strings.Repeat("n", maxPersistedNebulaVersionBytes+1)
		},
		"oversized last error": func(node *Node, _ Network) { node.LastError = strings.Repeat("e", maxPersistedLastErrorBytes+1) },
		"unsafe last error":    func(node *Node, _ Network) { node.LastError = "failure\nRAW-SECRET" },
		"negative applied revision": func(node *Node, _ Network) {
			node.AppliedConfigRevision = -1
		},
		"future applied revision": func(node *Node, network Network) {
			node.AppliedConfigRevision = network.ConfigRevision + 1
		},
		"raw secret config digest": func(node *Node, _ Network) { node.AppliedConfigSHA256 = "RAW-CONFIG-SECRET" },
		"digest without revision": func(node *Node, _ Network) {
			node.AppliedConfigRevision = 0
			node.AppliedConfigSHA256 = strings.Repeat("a", 64)
		},
		"revision without digest": func(node *Node, _ Network) { node.AppliedConfigSHA256 = "" },
		"raw secret certificate fingerprint": func(node *Node, _ Network) {
			node.ReportedCertificateFingerprint = "RAW-CERTIFICATE-SECRET"
		},
		"invalid boot ID":       func(node *Node, _ Network) { node.AgentBootID = "boot id with spaces" },
		"missing boot ID":       func(node *Node, _ Network) { node.AgentBootID = "" },
		"negative sequence":     func(node *Node, _ Network) { node.HeartbeatSequence = -1 },
		"poisoned sequence":     func(node *Node, _ Network) { node.HeartbeatSequence = maxPersistedHeartbeatSequence + 1 },
		"invalid active status": func(node *Node, _ Network) { node.AgentStatus = "RAW-STATUS-SECRET" },
		"missing last seen":     func(node *Node, _ Network) { node.LastSeenAt = nil },
		"zero heartbeat sequence": func(node *Node, _ Network) {
			node.HeartbeatSequence = 0
		},
		"last seen before enrollment": func(node *Node, _ Network) {
			seen := node.EnrolledAt.Add(-time.Second)
			node.LastSeenAt = &seen
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state := cloneRecoveryState(t, validHeartbeat)
			mutate(&state.Nodes[0], state.Networks[0])
			if err := validateStateGraph(state); err == nil || !strings.Contains(err.Error(), "lifecycle telemetry") {
				t.Fatalf("corrupt telemetry was accepted: %v", err)
			}
		})
	}
}

func TestDecodedFileStoreRejectsRawTelemetryBeforeServing(t *testing.T) {
	fixture := newActiveControlRecoveryFixture(t, 1)
	state := validPersistedHeartbeatState(t, fixture.state)
	state.Nodes[0].AppliedConfigSHA256 = "RAW-PERSISTED-CONFIG-SECRET"
	raw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	var decoded State
	if err := decodePersistedState(raw, &decoded); err != nil {
		t.Fatalf("strict JSON decode unexpectedly hid the graph test: %v", err)
	}
	if err := validateStateGraph(decoded); err == nil {
		t.Fatal("decoded raw telemetry passed graph validation")
	}

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if store != nil {
		_ = store.Close()
		t.Fatal("corrupt decoded telemetry produced a readable store")
	}
	if err == nil || !strings.Contains(err.Error(), "lifecycle telemetry") {
		t.Fatalf("decoded file telemetry error = %v", err)
	}
}

func TestRecoveryAndPostgresReadinessRejectCorruptTelemetry(t *testing.T) {
	fixture := newActiveControlRecoveryFixture(t, 1)

	t.Run("recovery oversized field", func(t *testing.T) {
		state := validPersistedHeartbeatState(t, fixture.state)
		state.Nodes[0].LastError = strings.Repeat("s", maxPersistedLastErrorBytes+1)
		raw, err := encodePersistedState(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRecoverySnapshot(raw, fixture.box); err == nil || !strings.Contains(err.Error(), "lifecycle telemetry") {
			t.Fatalf("recovery accepted oversized telemetry: %v", err)
		}
	})

	t.Run("postgres invalid status", func(t *testing.T) {
		state := validPersistedHeartbeatState(t, fixture.state)
		state.Nodes[0].AgentStatus = "RAW-STATUS-SECRET"
		raw, err := encodePersistedState(state)
		if err != nil {
			t.Fatal(err)
		}
		repository := &fakePostgresControlRepository{body: raw}
		store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
		if err := store.CheckReadiness(context.Background()); !errors.Is(err, postgresstore.ErrCorruptDocument) {
			t.Fatalf("Postgres readiness error = %v, want corrupt document", err)
		}
		if repository.readinessCalls != 1 || repository.readCalls != 1 {
			t.Fatalf("Postgres readiness/read calls = %d/%d, want 1/1", repository.readinessCalls, repository.readCalls)
		}
		called := false
		if err := store.View(func(State) error { called = true; return nil }); !errors.Is(err, postgresstore.ErrCorruptDocument) {
			t.Fatalf("Postgres View error = %v, want corrupt document", err)
		}
		if called {
			t.Fatal("corrupt Postgres telemetry reached a serving callback")
		}
	})
}

func validPersistedHeartbeatState(t *testing.T, source State) State {
	t.Helper()
	state := cloneRecoveryState(t, source)
	node := &state.Nodes[0]
	seen := recoverySnapshotNow.Add(30 * time.Second)
	node.AgentVersion = "meshctl/test"
	node.NebulaVersion = "1.10.3"
	node.AppliedConfigRevision = state.Networks[0].ConfigRevision
	node.AppliedConfigSHA256 = strings.Repeat("a", 64)
	node.ReportedCertificateFingerprint = node.CertificateFingerprint
	node.NebulaRunning = true
	node.AgentStatus = "healthy"
	node.AgentBootID = "boot-test"
	node.HeartbeatSequence = 1
	node.LastSeenAt = &seen
	return state
}

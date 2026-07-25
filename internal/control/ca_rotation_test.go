package control

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCARotationTestService(t *testing.T, migrateCurrent bool) (*Service, *Store) {
	t.Helper()
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x6a}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, NebulaIssuer{})
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'C'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	if migrateCurrent {
		if err := service.EnsureCARotationSchema(); err != nil {
			t.Fatal(err)
		}
	}
	return service, store
}

func caRotationPublicKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyPath, publicPath := filepath.Join(dir, "host.key"), filepath.Join(dir, "host.pub")
	if output, err := exec.Command("nebula-cert", "keygen", "-out-key", keyPath, "-out-pub", publicPath).CombinedOutput(); err != nil {
		t.Fatalf("nebula keygen: %v: %s", err, output)
	}
	publicKey, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(publicKey)
}

func TestEnsureCARotationSchemaBindsExistingCertificatesWithoutChangingConfig(t *testing.T) {
	service, store := newCARotationTestService(t, false)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "ca-migration", CIDR: "10.86.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-1", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, caRotationPublicKey(t), HashToken(strings.Repeat("m", 43))); err != nil {
		t.Fatal(err)
	}
	var before State
	if err := store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if before.Version != ControlStateVersionNetworkRelays || before.Nodes[0].CertificateAuthoritySHA256 != "" {
		t.Fatalf("unexpected v5 fixture: version=%d node=%+v", before.Version, before.Nodes[0])
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	var after State
	if err := store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if after.Version != ControlStateVersionCARotation || after.Networks[0].ConfigRevision != before.Networks[0].ConfigRevision || !after.Networks[0].ConfigUpdatedAt.Equal(before.Networks[0].ConfigUpdatedAt) {
		t.Fatalf("CA schema migration changed signed lifecycle: before=%+v after=%+v", before.Networks[0], after.Networks[0])
	}
	if after.Nodes[0].CertificateAuthoritySHA256 != ConfigDigest(after.Networks[0].CACertificate) {
		t.Fatalf("migrated node CA digest=%q", after.Nodes[0].CertificateAuthoritySHA256)
	}
	last := after.Audit[len(after.Audit)-1]
	if last.Action != "control.ca_rotation_schema_migrated" || last.Details["from_version"] != ControlStateVersionNetworkRelays || last.Details["to_version"] != ControlStateVersionCARotation {
		t.Fatalf("unexpected migration audit: %+v", last)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	repeated, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != repeated.Size() || !info.ModTime().Equal(repeated.ModTime()) {
		t.Fatal("repeated current-schema startup rewrote CA rotation v6 state")
	}
}

func TestNetworkCARotationStagesDualTrustEarlyRenewalAndSafeFinalization(t *testing.T) {
	service, store := newCARotationTestService(t, true)
	ctx := context.Background()
	network, err := service.CreateNetwork(ctx, CreateNetworkInput{Name: "ca-lifecycle", CIDR: "10.87.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-1", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := caRotationPublicKey(t)
	agentToken, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := service.Enroll(ctx, created.EnrollmentToken, publicKey, HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	oldCA, oldCADigest := enrolled.CA, ConfigDigest(enrolled.CA)
	prepared, err := service.UpdateNetworkCARotation(ctx, network.ID, UpdateNetworkCARotationInput{Action: "prepare", ExpectedConfigRevision: enrolled.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Phase != CARotationPhasePrepared || prepared.ConfigRevision != enrolled.ConfigRevision+1 || prepared.PreviousTrustBundleSHA256 != oldCADigest || prepared.TargetCACertificateSHA256 == "" || prepared.TargetCACertificateSHA256 == oldCADigest {
		t.Fatalf("unexpected prepared rotation: %+v", prepared)
	}
	preparedConfig, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	preparedBootstrap, err := service.AgentBootstrap(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if preparedConfig.CARotationRequired || preparedConfig.PreviousCACertificateSHA256 != oldCADigest || preparedConfig.CACertificateSHA256 != ConfigDigest(preparedBootstrap.CA) || preparedBootstrap.CA == oldCA || !strings.HasPrefix(preparedBootstrap.CA, oldCA) {
		t.Fatalf("prepared artifact did not carry authenticated dual trust: config=%+v CA-bytes=%d", preparedConfig, len(preparedBootstrap.CA))
	}

	setCARotationApplied(t, store, created.Node.ID, prepared.ConfigRevision, 1)
	activated, err := service.UpdateNetworkCARotation(ctx, network.ID, UpdateNetworkCARotationInput{Action: "activate", ExpectedConfigRevision: prepared.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	if activated.Phase != CARotationPhaseRotating || activated.ConfigRevision != prepared.ConfigRevision+1 {
		t.Fatalf("unexpected activated rotation: %+v", activated)
	}
	desired, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if !desired.CARotationRequired || desired.Revision != activated.ConfigRevision {
		t.Fatalf("old certificate was not marked for forced CA renewal: %+v", desired)
	}
	renewed, err := service.Renew(ctx, agentToken, publicKey)
	if err != nil {
		t.Fatalf("rotation-required early renewal failed: %v", err)
	}
	if renewed.CARotationRequired || renewed.CertificateGeneration != 2 || renewed.CACertificateSHA256 != prepared.CurrentTrustBundleSHA256 || renewed.PreviousCACertificateSHA256 != oldCADigest {
		t.Fatalf("unexpected replacement certificate bundle: %+v", renewed)
	}
	var authoritative Node
	if err := store.View(func(state State) error { authoritative, _ = findNode(state, created.Node.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if authoritative.CertificateAuthoritySHA256 != prepared.TargetCACertificateSHA256 {
		t.Fatalf("replacement certificate issuer=%q target=%q", authoritative.CertificateAuthoritySHA256, prepared.TargetCACertificateSHA256)
	}
	setCARotationApplied(t, store, created.Node.ID, activated.ConfigRevision, renewed.CertificateGeneration)
	finalizing, err := service.UpdateNetworkCARotation(ctx, network.ID, UpdateNetworkCARotationInput{Action: "finalize", ExpectedConfigRevision: activated.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	if finalizing.Phase != CARotationPhaseFinalizing || finalizing.ActiveCACertificateSHA256 != prepared.TargetCACertificateSHA256 || finalizing.CurrentTrustBundleSHA256 != prepared.TargetCACertificateSHA256 || finalizing.PreviousTrustBundleSHA256 != prepared.CurrentTrustBundleSHA256 {
		t.Fatalf("unexpected finalizing rotation: %+v", finalizing)
	}
	setCARotationApplied(t, store, created.Node.ID, finalizing.ConfigRevision, renewed.CertificateGeneration)
	completed, err := service.UpdateNetworkCARotation(ctx, network.ID, UpdateNetworkCARotationInput{Action: "complete", ExpectedConfigRevision: finalizing.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != "stable" || completed.CurrentTrustBundleSHA256 != prepared.TargetCACertificateSHA256 || completed.PreviousTrustBundleSHA256 != "" || completed.ConfigRevision != finalizing.ConfigRevision+1 {
		t.Fatalf("unexpected completed rotation: %+v", completed)
	}
}

func setCARotationApplied(t *testing.T, store *Store, nodeID string, revision, generation int64) {
	t.Helper()
	if err := store.Update(func(state *State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID != nodeID {
				continue
			}
			state.Nodes[index].AppliedConfigRevision = revision
			state.Nodes[index].AppliedConfigSHA256 = ConfigDigest("ca-rotation-test-applied")
			state.Nodes[index].AppliedCertificateGeneration = generation
			state.Nodes[index].ReportedCertificateFingerprint = state.Nodes[index].CertificateFingerprint
			state.Nodes[index].HeartbeatSequence++
			state.Nodes[index].AgentBootID = "ca-rotation-test-boot"
			state.Nodes[index].AgentStatus = "healthy"
			seenAt := state.Nodes[index].EnrolledAt.Add(time.Duration(state.Nodes[index].HeartbeatSequence) * time.Minute)
			state.Nodes[index].LastSeenAt = &seenAt
			return nil
		}
		return ErrNotFound
	}); err != nil {
		t.Fatal(err)
	}
}

package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

type countingCertificateRotationIssuer struct {
	delegate CertificateIssuer
	calls    int
}

func (i *countingCertificateRotationIssuer) CreateCA(ctx context.Context, name, duration string) (string, string, error) {
	return i.delegate.CreateCA(ctx, name, duration)
}

func (i *countingCertificateRotationIssuer) SignPublicKey(ctx context.Context, caCertificate, caPrivateKey, publicKey, name, network, groups, unsafeNetworks string, ttl time.Duration) (string, string, time.Time, error) {
	i.calls++
	return i.delegate.SignPublicKey(ctx, caCertificate, caPrivateKey, publicKey, name, network, groups, unsafeNetworks, ttl)
}

func TestRotateNodeCertificateBlocklistsOldIdentityAndReplaysExactly(t *testing.T) {
	originalIssuerNow := recoverySnapshotNow
	t.Cleanup(func() { recoverySnapshotNow = originalIssuerNow })
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	recoverySnapshotNow = base
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &countingCertificateRotationIssuer{delegate: recoverySnapshotIssuer{}}
	service := NewService(store, box, issuer)
	service.now = func() time.Time { return recoverySnapshotNow }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "certificate-rotation", CIDR: "10.111.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, CreateNodeInput{Name: "rotate-me", Groups: []string{"operators"}, RoutedSubnets: []string{"192.168.82.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNode(network.ID, CreateNodeInput{Name: "rotation-peer"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "rotation-pending"})
	if err != nil {
		t.Fatal(err)
	}
	targetToken := strings.Repeat("t", 42) + "A"
	targetPublicKey := testNebulaPublicKey('T')
	first, err := service.Enroll(context.Background(), target.EnrollmentToken, targetPublicKey, HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	peerToken := strings.Repeat("p", 42) + "A"
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('P'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	recovery, err := service.IssueAgentRecovery(target.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeNetworks, err := service.Networks()
	if err != nil || len(beforeNetworks) != 1 {
		t.Fatalf("load pre-rotation network: networks=%#v err=%v", beforeNetworks, err)
	}
	input := RotateNodeCertificateInput{
		ExpectedConfigRevision: beforeNetworks[0].ConfigRevision,
		ConfirmationName:       target.Node.Name,
		RequestID:              "certificate-rotation-request-0001",
	}

	beforeRejected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, rejected := range map[string]RotateNodeCertificateInput{
		"stale revision": {ExpectedConfigRevision: 1, ConfirmationName: target.Node.Name, RequestID: "certificate-rotation-stale"},
		"wrong name":     {ExpectedConfigRevision: input.ExpectedConfigRevision, ConfirmationName: "Rotate-me", RequestID: "certificate-rotation-wrong-name"},
		"short request":  {ExpectedConfigRevision: input.ExpectedConfigRevision, ConfirmationName: target.Node.Name, RequestID: "short"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.RotateNodeCertificate(context.Background(), target.Node.ID, rejected); err == nil {
				t.Fatal("rejected certificate rotation succeeded")
			}
		})
	}
	if afterRejected, err := os.ReadFile(path); err != nil || !bytes.Equal(beforeRejected, afterRejected) {
		t.Fatalf("rejected certificate rotation changed state: equal=%t err=%v", bytes.Equal(beforeRejected, afterRejected), err)
	}
	if _, err := service.RotateNodeCertificate(context.Background(), pending.Node.ID, RotateNodeCertificateInput{ExpectedConfigRevision: input.ExpectedConfigRevision, ConfirmationName: pending.Node.Name, RequestID: "certificate-rotation-pending"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending-node certificate rotation returned %v", err)
	}

	recoverySnapshotNow = base.Add(time.Hour)
	actor := Actor{ID: "service_rotation_operator", Kind: ActorKindServiceAccount, SessionID: "rotation-session"}
	receipt, err := service.RotateNodeCertificateAs(context.Background(), actor, target.Node.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != input.RequestID || receipt.NodeID != target.Node.ID || receipt.NetworkID != network.ID || receipt.Name != target.Node.Name || receipt.IP != target.Node.IP || receipt.Role != target.Node.Role || !receipt.RotatedAt.Equal(recoverySnapshotNow) || !receipt.PreviousCertificateExpiresAt.Equal(first.CertificateExpiresAt) || !receipt.CertificateExpiresAt.Equal(recoverySnapshotNow.Add(24*time.Hour)) || !receipt.CertificateRenewAfter.Equal(recoverySnapshotNow.Add(16*time.Hour)) || receipt.PreviousCertificateGeneration != first.CertificateGeneration || receipt.CertificateGeneration != first.CertificateGeneration+1 || receipt.AgentRecoveryRecordsInvalidated != 1 || receipt.CertificateIssuancesAdded != 1 || receipt.BlocklistEntriesAdded != 1 || !receipt.PreviousCertificateBlocklisted || receipt.ConfigRevision != input.ExpectedConfigRevision+1 {
		t.Fatalf("unexpected certificate rotation receipt: %#v", receipt)
	}
	if issuer.calls != 3 {
		t.Fatalf("issuer calls=%d, want two enrollments plus one rotation", issuer.calls)
	}

	targetConfig, err := service.AgentConfig(targetToken)
	if err != nil {
		t.Fatal(err)
	}
	peerConfig, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	for label, config := range map[string]AgentConfig{"target": targetConfig, "peer": peerConfig} {
		if config.Revision != receipt.ConfigRevision || !strings.Contains(config.Config, first.CertificateFingerprint) {
			t.Fatalf("%s config did not receive old-certificate blocklist at revision %d", label, receipt.ConfigRevision)
		}
		if err := VerifyConfig(first.ConfigSigningPublicKey, config.SignatureMetadata(), config.Config, config.SHA256, config.Signature); err != nil {
			t.Fatalf("verify %s post-rotation config: %v", label, err)
		}
	}
	if targetConfig.CertificateGeneration != receipt.CertificateGeneration || targetConfig.CertificateFingerprint == first.CertificateFingerprint || !targetConfig.CertificateExpiresAt.Equal(receipt.CertificateExpiresAt) || !targetConfig.CertificateRenewAfter.Equal(receipt.CertificateRenewAfter) {
		t.Fatalf("rotated target config has wrong certificate metadata: %#v", targetConfig)
	}
	bootstrap, err := service.AgentBootstrap(targetToken)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificate, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(first.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	newCertificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(bootstrap.Certificate))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatalf("parse rotated certificate: remainder=%q err=%v", remainder, err)
	}
	if !bytes.Equal(oldCertificate.MarshalPublicKeyPEM(), newCertificate.MarshalPublicKeyPEM()) {
		t.Fatal("same-key certificate rotation changed the node public key")
	}
	if _, err := service.RecoverAgent(recovery.RecoveryToken, targetPublicKey, HashToken(strings.Repeat("n", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pre-rotation recovery token returned %v", err)
	}

	var state State
	if err := store.View(func(snapshot State) error { state = snapshot; return nil }); err != nil {
		t.Fatal(err)
	}
	targetIssuances := 0
	for _, issuance := range state.Issuances {
		if issuance.NodeID == target.Node.ID {
			targetIssuances++
		}
	}
	if targetIssuances != 2 || len(state.Revocations) != 1 || state.Revocations[0].Fingerprint != first.CertificateFingerprint || state.Revocations[0].ExpiresAt == nil || !state.Revocations[0].ExpiresAt.Equal(first.CertificateExpiresAt) {
		t.Fatalf("certificate history was not rotated safely: issuances=%d revocations=%#v", targetIssuances, state.Revocations)
	}
	var rotationEvent AuditEvent
	for _, event := range state.Audit {
		if event.Action == nodeCertificateRotatedAuditAction && event.ResourceID == target.Node.ID {
			rotationEvent = event
			break
		}
	}
	if rotationEvent.Action == "" || rotationEvent.Details[auditActorIDKey] != actor.ID || rotationEvent.Details[auditActorKindKey] != actor.Kind || rotationEvent.Details[auditActorSessionIDKey] != actor.SessionID {
		t.Fatalf("certificate rotation audit attribution is missing: %#v", rotationEvent)
	}

	committedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	committedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.RotateNodeCertificateAs(context.Background(), actor, target.Node.ID, input)
	if err != nil || replayed != receipt {
		t.Fatalf("exact certificate rotation replay=%#v err=%v", replayed, err)
	}
	replayedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replayedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 3 || !bytes.Equal(committedBytes, replayedBytes) || !os.SameFile(committedInfo, replayedInfo) || !committedInfo.ModTime().Equal(replayedInfo.ModTime()) {
		t.Fatal("exact certificate rotation replay performed signing or a state write")
	}
	conflicting := input
	conflicting.ConfirmationName = "different-node"
	if _, err := service.RotateNodeCertificate(context.Background(), target.Node.ID, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting request_id binding returned %v", err)
	}

	for name, mutate := range map[string]func(*State){
		"missing request id": func(candidate *State) { delete(candidate.Audit[len(candidate.Audit)-1].Details, "request_id") },
		"forged generation": func(candidate *State) {
			candidate.Audit[len(candidate.Audit)-1].Details["certificate_generation"] = float64(99)
		},
		"duplicate request": func(candidate *State) {
			duplicate := candidate.Audit[len(candidate.Audit)-1]
			duplicate.ID = "duplicate-rotation-audit"
			candidate.Audit = append(candidate.Audit, duplicate)
		},
	} {
		t.Run("reject corrupt audit "+name, func(t *testing.T) {
			candidate, err := cloneState(state)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := validateStateGraph(candidate); err == nil {
				t.Fatal("corrupt certificate rotation audit was accepted")
			}
		})
	}

	if !slices.Equal(bootstrap.Node.RoutedSubnets, target.Node.RoutedSubnets) || !slices.Equal(bootstrap.Node.Groups, target.Node.Groups) {
		t.Fatal("certificate rotation changed node authorization metadata")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen rotated state: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateNodeCertificateRejectsCARotationWithoutMutation(t *testing.T) {
	service, store := newCARotationTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rotation-ca-fence", CIDR: "10.112.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "ca-fenced-node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, caRotationPublicKey(t), HashToken(strings.Repeat("f", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	prepared, err := service.UpdateNetworkCARotation(context.Background(), network.ID, UpdateNetworkCARotationInput{Action: "prepare", ExpectedConfigRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.RotateNodeCertificate(context.Background(), created.Node.ID, RotateNodeCertificateInput{
		ExpectedConfigRevision: prepared.ConfigRevision,
		ConfirmationName:       created.Node.Name,
		RequestID:              "certificate-rotation-ca-fenced",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CA-fenced certificate rotation returned %v", err)
	}
	after, readErr := os.ReadFile(store.path)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("CA-fenced certificate rotation changed state: equal=%t err=%v", bytes.Equal(before, after), readErr)
	}
}

func TestRotateNodeCertificateRejectsFirewallRolloutAndCurrentRenewalWithoutMutation(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rotation-lifecycle-fences", CIDR: "10.113.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "rollout-fenced-node", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('F'), HashToken(strings.Repeat("g", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	started, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: 1, CanaryNodeIDs: []string{created.Node.ID},
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "operators"}},
		Outbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "any"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRejectedWriteFree := func(label string, revision int64) {
		t.Helper()
		before, err := os.ReadFile(store.path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = service.RotateNodeCertificate(context.Background(), created.Node.ID, RotateNodeCertificateInput{
			ExpectedConfigRevision: revision,
			ConfirmationName:       created.Node.Name,
			RequestID:              "certificate-rotation-" + label,
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("%s certificate rotation returned %v", label, err)
		}
		after, readErr := os.ReadFile(store.path)
		if readErr != nil || !bytes.Equal(before, after) {
			t.Fatalf("%s certificate rotation changed state: equal=%t err=%v", label, bytes.Equal(before, after), readErr)
		}
	}
	assertRejectedWriteFree("firewall-fenced", started.ConfigRevision)
	rolledBack, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "rollback", ExpectedConfigRevision: started.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	claimedAt := service.now().UTC()
	if err := store.Update(func(state *State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == created.Node.ID {
				state.Nodes[index].RenewalClaimID = "renewal-in-progress"
				state.Nodes[index].RenewalClaimedAt = &claimedAt
				return nil
			}
		}
		return ErrNotFound
	}); err != nil {
		t.Fatal(err)
	}
	assertRejectedWriteFree("renewal-fenced", rolledBack.ConfigRevision)
}

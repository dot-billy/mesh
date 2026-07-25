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
)

func TestRevokeNodeWithReceiptCutsTrustAndReplaysExactly(t *testing.T) {
	originalIssuerNow := recoverySnapshotNow
	t.Cleanup(func() { recoverySnapshotNow = originalIssuerNow })
	base := time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC)
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
	service := NewService(store, box, recoverySnapshotIssuer{})
	service.now = func() time.Time { return recoverySnapshotNow }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "safe-revocation", CIDR: "10.111.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, CreateNodeInput{Name: "revoke-me", Groups: []string{"operators"}, RoutedSubnets: []string{"192.168.114.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNode(network.ID, CreateNodeInput{Name: "revocation-peer"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "never-enrolled", RoutedSubnets: []string{"192.168.115.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	targetToken := strings.Repeat("v", 42) + "A"
	targetBundle, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('V'), HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	peerToken := strings.Repeat("w", 42) + "A"
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('W'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueAgentRecovery(target.Node.ID); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("load pre-revocation network: networks=%#v err=%v", networks, err)
	}
	input := RevokeNodeInput{ExpectedConfigRevision: networks[0].ConfigRevision, ConfirmationName: target.Node.Name, RequestID: "node-revocation-request-0001"}

	beforeRejected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, rejected := range map[string]RevokeNodeInput{
		"stale revision": {ExpectedConfigRevision: 999, ConfirmationName: target.Node.Name, RequestID: "node-revocation-stale"},
		"wrong name":     {ExpectedConfigRevision: input.ExpectedConfigRevision, ConfirmationName: "Revoke-me", RequestID: "node-revocation-wrong-name"},
		"short request":  {ExpectedConfigRevision: input.ExpectedConfigRevision, ConfirmationName: target.Node.Name, RequestID: "short"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.RevokeNodeWithReceipt(target.Node.ID, rejected); err == nil {
				t.Fatal("rejected revocation succeeded")
			}
		})
	}
	if afterRejected, err := os.ReadFile(path); err != nil || !bytes.Equal(beforeRejected, afterRejected) {
		t.Fatalf("rejected revocation changed state: equal=%t err=%v", bytes.Equal(beforeRejected, afterRejected), err)
	}

	recoverySnapshotNow = base.Add(time.Hour)
	actor := Actor{ID: "service_revocation_operator", Kind: ActorKindServiceAccount, SessionID: "revocation-session"}
	receipt, err := service.RevokeNodeWithReceiptAs(actor, target.Node.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != input.RequestID || receipt.NodeID != target.Node.ID || receipt.NetworkID != network.ID || receipt.Name != target.Node.Name || receipt.IP != target.Node.IP || receipt.Role != target.Node.Role || !receipt.RevokedAt.Equal(recoverySnapshotNow) || !receipt.WasEnrolled || receipt.EnrollmentRecordsInvalidated != 1 || receipt.AgentRecoveryRecordsInvalidated != 1 || receipt.BlocklistEntriesAdded != 1 || receipt.RelayAssignmentRemoved || receipt.FirewallCanaryRemoved || receipt.FirewallRolloutAutoRolledBack || !receipt.CredentialsInvalidated || receipt.RoutedSubnetReservationsReleased != 1 || receipt.ConfigRevision != input.ExpectedConfigRevision+1 {
		t.Fatalf("unexpected active-node revocation receipt: %#v", receipt)
	}
	if _, err := service.AgentConfig(targetToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked agent credential returned %v", err)
	}
	peerConfig, err := service.AgentConfig(peerToken)
	if err != nil || peerConfig.Revision != receipt.ConfigRevision || !strings.Contains(peerConfig.Config, targetBundle.CertificateFingerprint) {
		t.Fatalf("peer did not receive revoked fingerprint at revision %d: config=%#v err=%v", receipt.ConfigRevision, peerConfig, err)
	}

	var committed State
	if err := store.View(func(state State) error { committed = state; return nil }); err != nil {
		t.Fatal(err)
	}
	revoked, ok := findNode(committed, target.Node.ID)
	if !ok || revoked.Status != "revoked" || revoked.RevokedAt == nil || revoked.AgentTokenHash != "" || revoked.PreviousAgentTokenHash != "" || revoked.AgentCredentialExpiresAt != nil || revoked.RenewalClaimID != "" {
		t.Fatalf("revoked node retained trust state: %#v", revoked)
	}
	if slices.ContainsFunc(committed.Enrollments, func(record EnrollmentToken) bool { return record.NodeID == target.Node.ID }) || slices.ContainsFunc(committed.AgentRecoveries, func(record AgentRecoveryToken) bool { return record.NodeID == target.Node.ID }) {
		t.Fatal("safe revocation retained a node enrollment or recovery record")
	}
	var event AuditEvent
	for _, candidate := range committed.Audit {
		if candidate.Action == nodeRevocationCommittedAuditAction && candidate.ResourceID == target.Node.ID {
			event = candidate
			break
		}
	}
	if event.Action == "" || event.Details[auditActorIDKey] != actor.ID || event.Details[auditActorKindKey] != actor.Kind || event.Details[auditActorSessionIDKey] != actor.SessionID {
		t.Fatalf("safe revocation audit attribution is missing: %#v", event)
	}

	committedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	committedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.RevokeNodeWithReceiptAs(actor, target.Node.ID, input)
	if err != nil || replayed != receipt {
		t.Fatalf("exact revocation replay=%#v err=%v", replayed, err)
	}
	replayedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replayedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committedBytes, replayedBytes) || !os.SameFile(committedInfo, replayedInfo) || !committedInfo.ModTime().Equal(replayedInfo.ModTime()) {
		t.Fatalf("exact revocation replay performed a state write: bytes=%t inode=%t mtime=%s/%s", bytes.Equal(committedBytes, replayedBytes), os.SameFile(committedInfo, replayedInfo), committedInfo.ModTime(), replayedInfo.ModTime())
	}
	conflicting := input
	conflicting.ConfirmationName = pending.Node.Name
	if _, err := service.RevokeNodeWithReceipt(pending.Node.ID, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting request_id binding returned %v", err)
	}

	pendingInput := RevokeNodeInput{ExpectedConfigRevision: receipt.ConfigRevision, ConfirmationName: pending.Node.Name, RequestID: "node-revocation-pending-0001"}
	pendingReceipt, err := service.RevokeNodeWithReceipt(pending.Node.ID, pendingInput)
	if err != nil {
		t.Fatal(err)
	}
	if pendingReceipt.WasEnrolled || pendingReceipt.EnrollmentRecordsInvalidated != 1 || pendingReceipt.AgentRecoveryRecordsInvalidated != 0 || pendingReceipt.BlocklistEntriesAdded != 0 || !pendingReceipt.CredentialsInvalidated || pendingReceipt.RoutedSubnetReservationsReleased != 1 || pendingReceipt.ConfigRevision != receipt.ConfigRevision+1 {
		t.Fatalf("unexpected pending-node revocation receipt: %#v", pendingReceipt)
	}
	if _, err := service.Enroll(context.Background(), pending.EnrollmentToken, testNebulaPublicKey('X'), HashToken(strings.Repeat("x", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalidated pending enrollment returned %v", err)
	}

	var final State
	if err := store.View(func(state State) error { final = state; return nil }); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*State){
		"missing request id": func(candidate *State) { delete(candidate.Audit[len(candidate.Audit)-1].Details, "request_id") },
		"forged revision": func(candidate *State) {
			candidate.Audit[len(candidate.Audit)-1].Details["config_revision"] = float64(99)
		},
		"duplicate request": func(candidate *State) {
			duplicate := candidate.Audit[len(candidate.Audit)-1]
			duplicate.ID = "duplicate-revocation-audit"
			candidate.Audit = append(candidate.Audit, duplicate)
		},
	} {
		t.Run("reject corrupt audit "+name, func(t *testing.T) {
			candidate, err := cloneState(final)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := validateStateGraph(candidate); err == nil {
				t.Fatal("corrupt node revocation audit was accepted")
			}
		})
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen safely revoked state: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeNodeWithReceiptRemovesRelayAndRollsBackFinalFirewallCanary(t *testing.T) {
	service, _ := newFirewallRolloutTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "revocation-assignments", CIDR: "10.115.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, CreateNodeInput{Name: "assigned-target", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNode(network.ID, CreateNodeInput{Name: "assigned-peer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('Y'), HashToken(strings.Repeat("y", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('Z'), HashToken(strings.Repeat("z", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	relays, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{ExpectedConfigRevision: 1, Enabled: true, RelayNodeIDs: []string{target.Node.ID}})
	if err != nil {
		t.Fatal(err)
	}
	rollout, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: relays.ConfigRevision, CanaryNodeIDs: []string{target.Node.ID},
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "operators"}},
		Outbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "any"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.RevokeNodeWithReceipt(target.Node.ID, RevokeNodeInput{
		ExpectedConfigRevision: rollout.ConfigRevision, ConfirmationName: target.Node.Name, RequestID: "node-revocation-assignment-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.RelayAssignmentRemoved || !receipt.FirewallCanaryRemoved || !receipt.FirewallRolloutAutoRolledBack || receipt.ConfigRevision != rollout.ConfigRevision+1 {
		t.Fatalf("assignment-aware revocation receipt=%#v", receipt)
	}
	afterRelays, err := service.NetworkRelays(network.ID)
	if err != nil || afterRelays.Enabled || len(afterRelays.RelayNodeIDs) != 0 || afterRelays.ConfigRevision != receipt.ConfigRevision {
		t.Fatalf("revocation did not remove relay assignment: document=%#v err=%v", afterRelays, err)
	}
	afterRollout, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || afterRollout.Phase != "stable" || afterRollout.ConfigRevision != receipt.ConfigRevision || afterRollout.LastTransition == nil || afterRollout.LastTransition.Action != "auto_rolled_back" || afterRollout.LastTransition.ReasonCode != "last_canary_revoked" {
		t.Fatalf("revocation did not roll back the final canary: document=%#v err=%v", afterRollout, err)
	}
}

package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestArchiveNodeWaitsForAllCertificateAuthorityThenRemovesExpiredHistory(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return base }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return base }
	actor := Actor{ID: "oidc_" + strings.Repeat("D", 42) + "A", Kind: ActorKindOIDCAdmin, SessionID: "archive_session"}
	network, err := service.CreateNetworkAs(context.Background(), actor, CreateNetworkInput{Name: "archive-node", CIDR: "10.61.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{Name: "retired-gateway", RoutedSubnets: []string{"192.168.61.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{Name: "archive-peer"})
	if err != nil {
		t.Fatal(err)
	}
	targetToken := strings.Repeat("t", 42) + "A"
	peerToken := strings.Repeat("p", 42) + "A"
	targetBundle, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('T'), HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('P'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return base.Add(time.Hour) }
	if _, err := service.RevokeNodeAs(actor, target.Node.ID); err != nil {
		t.Fatal(err)
	}
	beforeArchive, err := service.AgentConfig(peerToken)
	if err != nil || !strings.Contains(beforeArchive.Config, targetBundle.CertificateFingerprint) {
		t.Fatalf("revoked certificate was not blocklisted before archival: config=%q err=%v", beforeArchive.Config, err)
	}

	var revokedRevision int64
	networks, err := service.Networks()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range networks {
		if candidate.ID == network.ID {
			revokedRevision = candidate.ConfigRevision
		}
	}
	if revokedRevision < 2 {
		t.Fatalf("revocation revision is invalid: %d", revokedRevision)
	}
	var rejectedBaseline State
	_ = service.store.View(func(state State) error { rejectedBaseline = state; return nil })
	for _, input := range []ArchiveNodeInput{
		{ExpectedConfigRevision: revokedRevision - 1, ConfirmationName: target.Node.Name},
		{ExpectedConfigRevision: revokedRevision, ConfirmationName: "Retired-Gateway"},
	} {
		if _, err := service.ArchiveNode(target.Node.ID, input); !errors.Is(err, ErrConflict) {
			t.Fatalf("unsafe archive input %#v returned %v", input, err)
		}
	}
	service.now = func() time.Time {
		return targetBundle.CertificateExpiresAt.Add(nodeArchiveCertificateSafetyMargin - time.Nanosecond)
	}
	if _, err := service.ArchiveNode(target.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: revokedRevision, ConfirmationName: target.Node.Name}); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "blocklist authority remains required") {
		t.Fatalf("pre-expiry archive returned %v", err)
	}
	var afterRejected State
	_ = service.store.View(func(state State) error { afterRejected = state; return nil })
	if len(afterRejected.Nodes) != len(rejectedBaseline.Nodes) || len(afterRejected.Issuances) != len(rejectedBaseline.Issuances) || len(afterRejected.Revocations) != len(rejectedBaseline.Revocations) || len(afterRejected.Audit) != len(rejectedBaseline.Audit) {
		t.Fatal("rejected node archival changed state")
	}

	archiveAt := targetBundle.CertificateExpiresAt.Add(nodeArchiveCertificateSafetyMargin)
	service.now = func() time.Time { return archiveAt }
	receipt, err := service.ArchiveNodeAs(actor, target.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: revokedRevision, ConfirmationName: target.Node.Name})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.NodeID != target.Node.ID || receipt.NetworkID != network.ID || receipt.Name != target.Node.Name || receipt.IP != target.Node.IP || receipt.Role != target.Node.Role || !receipt.ArchivedAt.Equal(archiveAt) || receipt.LastCertificateExpiredAt == nil || !receipt.LastCertificateExpiredAt.Equal(targetBundle.CertificateExpiresAt) {
		t.Fatalf("unexpected archival receipt: %#v", receipt)
	}
	if receipt.EnrollmentRecordsRemoved != 1 || receipt.AgentRecoveryRecordsRemoved != 0 || receipt.CertificateIssuancesRemoved != 1 || receipt.RevocationsRemoved != 1 || receipt.BlocklistEntriesRemoved != 1 || receipt.RoutedSubnetReservationsReleased != 1 || receipt.ConfigRevision != revokedRevision+1 {
		t.Fatalf("incomplete archival receipt: %#v", receipt)
	}
	if _, err := service.AgentConfig(targetToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("archived agent credential returned %v", err)
	}
	afterArchive, err := service.AgentConfig(peerToken)
	if err != nil || afterArchive.Revision != receipt.ConfigRevision || strings.Contains(afterArchive.Config, targetBundle.CertificateFingerprint) {
		t.Fatalf("expired blocklist entry was not removed in the archival revision: config=%q err=%v", afterArchive.Config, err)
	}

	var archived State
	_ = service.store.View(func(state State) error { archived = state; return nil })
	for _, node := range archived.Nodes {
		if node.ID == target.Node.ID {
			t.Fatal("archived node remains persisted")
		}
	}
	for _, enrollment := range archived.Enrollments {
		if enrollment.NodeID == target.Node.ID {
			t.Fatal("archived enrollment remains persisted")
		}
	}
	for _, issuance := range archived.Issuances {
		if issuance.NodeID == target.Node.ID {
			t.Fatal("archived issuance remains persisted")
		}
	}
	for _, revocation := range archived.Revocations {
		if revocation.NodeID == target.Node.ID {
			t.Fatal("archived revocation remains persisted")
		}
	}
	event := archived.Audit[len(archived.Audit)-1]
	if event.Action != nodeArchivedAuditAction || event.ResourceID != target.Node.ID || event.Details["all_certificate_records_expired"] != true || event.Details["config_revision"] != receipt.ConfigRevision {
		t.Fatalf("invalid archival tombstone: %#v", event)
	}
	assertAuditActor(t, event, actor)
	if err := validateStateGraph(archived); err != nil {
		t.Fatalf("archived graph does not validate: %v", err)
	}
	if _, err := service.ArchiveNode(target.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: receipt.ConfigRevision, ConfirmationName: target.Node.Name}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated archive returned %v", err)
	}
	replacement, err := service.CreateNode(network.ID, CreateNodeInput{Name: target.Node.Name, IP: target.Node.IP, RoutedSubnets: target.Node.RoutedSubnets})
	if err != nil {
		t.Fatalf("archival did not leave already-released reservations reusable: %v", err)
	}
	if replacement.Node.ID == target.Node.ID || replacement.EnrollmentToken == target.EnrollmentToken {
		t.Fatal("post-archive identity reused node ID or credential")
	}

	archiveIndex := len(archived.Audit) - 1
	for name, mutate := range map[string]func(*State){
		"missing proof":  func(state *State) { delete(state.Audit[archiveIndex].Details, "all_certificate_records_expired") },
		"unknown detail": func(state *State) { state.Audit[archiveIndex].Details["invented"] = true },
		"early archive":  func(state *State) { state.Audit[archiveIndex].At = targetBundle.CertificateExpiresAt },
		"duplicate tombstone": func(state *State) {
			duplicate := state.Audit[archiveIndex]
			duplicate.ID = "duplicate_archive_event"
			state.Audit = append(state.Audit, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := cloneState(archived)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := validateStateGraph(candidate); err == nil || !strings.Contains(err.Error(), "archived node tombstone") {
				t.Fatalf("corrupt archival tombstone returned %v", err)
			}
		})
	}
}

func TestArchiveNeverEnrolledRevokedNodeIsImmediateAndRevisionNeutral(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	base := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return base }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "archive-pending", CIDR: "10.62.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "legacy-pending"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(pending.Node.ID); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	revision := networks[0].ConfigRevision
	receipt, err := service.ArchiveNode(pending.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: revision, ConfirmationName: pending.Node.Name})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.LastCertificateExpiredAt != nil || receipt.EnrollmentRecordsRemoved != 1 || receipt.CertificateIssuancesRemoved != 0 || receipt.RevocationsRemoved != 0 || receipt.ConfigRevision != revision {
		t.Fatalf("never-enrolled archival changed signed history: %#v", receipt)
	}
	if _, err := service.PreflightEnrollment(pending.EnrollmentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("archived legacy pending token returned %v", err)
	}
}

func TestArchiveNodeRejectsPermanentLegacyRevocationAndActiveNode(t *testing.T) {
	base := time.Date(2026, 7, 21, 14, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return base }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return base }
	network, _ := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "archive-legacy", CIDR: "10.63.0.0/24", CertificateTTL: 24})
	created, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "legacy-revocation"})
	if _, err := service.ArchiveNode(created.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: network.ConfigRevision, ConfirmationName: created.Node.Name}); !errors.Is(err, ErrConflict) {
		t.Fatalf("active/pending node archival returned %v", err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('L'), HashToken(strings.Repeat("l", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.updateState(func(state *State) error {
		for index := range state.Revocations {
			if state.Revocations[index].NodeID == created.Node.ID {
				state.Revocations[index].ExpiresAt = nil
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return base.Add(365 * 24 * time.Hour) }
	networks, _ := service.Networks()
	if _, err := service.ArchiveNode(created.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: networks[0].ConfigRevision, ConfirmationName: created.Node.Name}); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "without an expiry") {
		t.Fatalf("legacy permanent revocation archive returned %v", err)
	}
}

package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCancelPendingNodeInvalidatesCredentialsReleasesReservationsAndRemovesRelay(t *testing.T) {
	service, _ := newNetworkRelayTestService(t, true)
	now := time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	actor := Actor{ID: "oidc_" + strings.Repeat("C", 42) + "A", Kind: ActorKindOIDCAdmin, SessionID: "cancel_session"}
	network, err := service.CreateNetworkAs(context.Background(), actor, CreateNetworkInput{Name: "cancel-pending", CIDR: "10.58.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{
		Name: "pending-relay", Role: "member", RoutedSubnets: []string{"192.168.58.0/24"}, Site: "site-a", FailureDomain: "rack-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	relays, err := service.UpdateNetworkRelaysAs(actor, network.ID, UpdateNetworkRelaysInput{
		ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{created.Node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	var before State
	if err := service.store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CancelPendingNodeAs(actor, created.Node.ID, CancelPendingNodeInput{ConfirmationName: "Pending-Relay"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-case confirmation returned %v", err)
	}
	var afterRejected State
	_ = service.store.View(func(state State) error { afterRejected = state; return nil })
	if len(afterRejected.Nodes) != len(before.Nodes) || len(afterRejected.Enrollments) != len(before.Enrollments) || len(afterRejected.Audit) != len(before.Audit) {
		t.Fatal("rejected pending cancellation changed state")
	}

	receipt, err := service.CancelPendingNodeAs(actor, created.Node.ID, CancelPendingNodeInput{ConfirmationName: created.Node.Name})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.NodeID != created.Node.ID || receipt.NetworkID != network.ID || receipt.Name != created.Node.Name || receipt.IP != created.Node.IP || receipt.Role != created.Node.Role || !receipt.CancelledAt.Equal(now) {
		t.Fatalf("unexpected cancellation receipt: %#v", receipt)
	}
	if receipt.EnrollmentRecordsInvalidated != 1 || !receipt.RelayAssignmentRemoved || receipt.RoutedSubnetReservationsReleased != 1 || receipt.ConfigRevision != relays.ConfigRevision+1 {
		t.Fatalf("incomplete cancellation receipt: %#v", receipt)
	}
	if _, err := service.PreflightEnrollment(created.EnrollmentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled enrollment preflight returned %v", err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('C'), HashToken(strings.Repeat("c", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled enrollment returned %v", err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 0 {
		t.Fatalf("cancelled node remains in inventory: nodes=%#v err=%v", nodes, err)
	}
	relaysAfter, err := service.NetworkRelays(network.ID)
	if err != nil || relaysAfter.Enabled || len(relaysAfter.RelayNodeIDs) != 0 || relaysAfter.ConfigRevision != receipt.ConfigRevision {
		t.Fatalf("cancelled relay remains configured: relays=%#v err=%v", relaysAfter, err)
	}
	replacement, err := service.CreateNode(network.ID, CreateNodeInput{
		Name: created.Node.Name, IP: created.Node.IP, RoutedSubnets: created.Node.RoutedSubnets,
	})
	if err != nil {
		t.Fatalf("cancelled node reservations were not released: %v", err)
	}
	if replacement.Node.ID == created.Node.ID || replacement.EnrollmentToken == created.EnrollmentToken {
		t.Fatal("recreated pending node reused identity or credential")
	}

	var state State
	_ = service.store.View(func(snapshot State) error { state = snapshot; return nil })
	for _, enrollment := range state.Enrollments {
		if enrollment.NodeID == created.Node.ID {
			t.Fatal("cancelled node retained an enrollment record")
		}
	}
	event := state.Audit[len(state.Audit)-2]
	if event.Action != "node.pending_cancelled" || event.ResourceID != created.Node.ID || event.Details["enrollment_records_invalidated"] != 1 || event.Details["relay_assignment_removed"] != true || event.Details["config_revision"] != receipt.ConfigRevision {
		t.Fatalf("unexpected cancellation audit: %#v", event)
	}
	assertAuditActor(t, event, actor)
	if _, err := service.CancelPendingNode(created.Node.ID, CancelPendingNodeInput{ConfirmationName: created.Node.Name}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated cancellation returned %v", err)
	}
}

func TestCancelPendingNodeLosesCleanlyToEnrollmentAndInvalidatesInFlightClaim(t *testing.T) {
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	issuer := &enrollmentBarrierIssuer{now: func() time.Time { return now }, entered: make(chan struct{}), release: make(chan struct{})}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "cancel-race", CIDR: "10.59.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-race"})
	if err != nil {
		t.Fatal(err)
	}
	enrollResult := make(chan error, 1)
	go func() {
		_, enrollErr := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('R'), HashToken(strings.Repeat("r", 42)+"A"))
		enrollResult <- enrollErr
	}()
	<-issuer.entered
	receipt, err := service.CancelPendingNode(created.Node.ID, CancelPendingNodeInput{ConfirmationName: created.Node.Name})
	if err != nil || receipt.EnrollmentRecordsInvalidated != 1 {
		t.Fatalf("cancel in-flight enrollment: receipt=%#v err=%v", receipt, err)
	}
	close(issuer.release)
	if err := <-enrollResult; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled in-flight enrollment committed with %v", err)
	}
	var state State
	_ = service.store.View(func(snapshot State) error { state = snapshot; return nil })
	if len(state.Nodes) != 0 || len(state.Enrollments) != 0 || len(state.Issuances) != 0 {
		t.Fatalf("cancelled in-flight enrollment persisted identity material: %#v", state)
	}

	// Use a fresh nonblocking service to prove that an enrollment that commits
	// first changes the lifecycle and makes cancellation fail without mutation.
	activeService := testServiceWithIssuer(t, &countingIssuer{})
	activeNetwork, _ := activeService.CreateNetwork(context.Background(), CreateNetworkInput{Name: "active-wins", CIDR: "10.60.0.0/24", CertificateTTL: 24})
	activeCreated, _ := activeService.CreateNode(activeNetwork.ID, CreateNodeInput{Name: "active-wins"})
	if _, err := activeService.Enroll(context.Background(), activeCreated.EnrollmentToken, testNebulaPublicKey('A'), HashToken(strings.Repeat("a", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := activeService.CancelPendingNode(activeCreated.Node.ID, CancelPendingNodeInput{ConfirmationName: activeCreated.Node.Name}); !errors.Is(err, ErrConflict) {
		t.Fatalf("active node cancellation returned %v", err)
	}
}

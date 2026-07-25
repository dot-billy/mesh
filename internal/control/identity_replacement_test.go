package control

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReplaceNodeAtomicallyRevokesIdentityAndCarriesLifecycleMetadata(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	actor := Actor{ID: "oidc_" + strings.Repeat("I", 42) + "A", Kind: ActorKindOIDCAdmin, SessionID: "session_identity_replacement"}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "identity-replacement", CIDR: "10.98.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{
		Name: "edge-gateway", Role: "lighthouse", PublicEndpoint: "198.51.100.98:4242",
		Groups: []string{"routers", "operators"}, RoutedSubnets: []string{"172.28.0.0/16"},
		Site: "site-east", FailureDomain: "rack-7",
	})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNode(network.ID, CreateNodeInput{Name: "peer"})
	if err != nil {
		t.Fatal(err)
	}
	oldAgentToken := strings.Repeat("i", 42) + "A"
	oldBundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('I'), HashToken(oldAgentToken))
	if err != nil {
		t.Fatal(err)
	}
	peerAgentToken := strings.Repeat("p", 42) + "A"
	peerBundle, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('P'), HashToken(peerAgentToken))
	if err != nil {
		t.Fatal(err)
	}
	if peerBundle.ConfigRevision != 2 || !strings.Contains(peerBundle.Config, "route: \"172.28.0.0/16\"") {
		t.Fatalf("peer did not initially receive the active gateway route: revision=%d\n%s", peerBundle.ConfigRevision, peerBundle.Config)
	}
	if _, err := service.IssueAgentRecovery(created.Node.ID); err != nil {
		t.Fatal(err)
	}

	beforeRejected, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceNode(created.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale identity replacement returned %v, want conflict", err)
	}
	afterRejected, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterRejected) != string(beforeRejected) {
		t.Fatal("stale identity replacement changed persisted state")
	}

	replacement, err := service.ReplaceNodeAs(actor, created.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.RevokedNodeID != created.Node.ID || replacement.Node.Status != "pending" || replacement.Node.ID == created.Node.ID || replacement.Node.IP == created.Node.IP || replacement.ConfigRevision != 3 {
		t.Fatalf("unexpected replacement response: %#v", replacement)
	}
	if replacement.EnrollmentToken == "" || !replacement.ExpiresAt.Equal(service.now().Add(30*time.Minute)) {
		t.Fatalf("replacement omitted its one-time enrollment lifecycle: %#v", replacement)
	}
	if replacement.Node.Name != created.Node.Name || replacement.Node.NetworkID != created.Node.NetworkID || replacement.Node.Role != created.Node.Role || replacement.Node.PublicEndpoint != created.Node.PublicEndpoint || replacement.Node.Site != created.Node.Site || replacement.Node.FailureDomain != created.Node.FailureDomain || !slices.Equal(replacement.Node.Groups, created.Node.Groups) || !slices.Equal(replacement.Node.RoutedSubnets, created.Node.RoutedSubnets) {
		t.Fatalf("replacement did not carry immutable node metadata: old=%#v new=%#v", created.Node, replacement.Node)
	}
	if _, err := service.AgentConfig(oldAgentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked identity agent credential returned %v, want unauthorized", err)
	}
	peerAfterRevocation, err := service.AgentConfig(peerAgentToken)
	if err != nil {
		t.Fatal(err)
	}
	if peerAfterRevocation.Revision != 3 || strings.Contains(peerAfterRevocation.Config, "route: \"172.28.0.0/16\"") || !strings.Contains(peerAfterRevocation.Config, oldBundle.CertificateFingerprint) {
		t.Fatalf("replacement did not remove the old route and blocklist the old certificate: revision=%d\n%s", peerAfterRevocation.Revision, peerAfterRevocation.Config)
	}

	var snapshot State
	if err := store.View(func(state State) error { snapshot = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes) != 3 || snapshot.Networks[0].ConfigRevision != 3 || len(snapshot.AgentRecoveries) != 0 {
		t.Fatalf("unexpected replacement state graph: nodes=%d revision=%d recoveries=%d", len(snapshot.Nodes), snapshot.Networks[0].ConfigRevision, len(snapshot.AgentRecoveries))
	}
	oldNode, ok := findNode(snapshot, created.Node.ID)
	if !ok || oldNode.Status != "revoked" || oldNode.RevokedAt == nil || oldNode.AgentTokenHash != "" || oldNode.AgentStatus != "revoked" {
		t.Fatalf("old identity was not fully revoked: %#v", oldNode)
	}
	newNode, ok := findNode(snapshot, replacement.Node.ID)
	if !ok || !reflect.DeepEqual(newNode, replacement.Node) {
		t.Fatalf("pending replacement was not persisted exactly: %#v", newNode)
	}
	matchingEnrollment := 0
	for _, enrollment := range snapshot.Enrollments {
		if enrollment.NodeID == replacement.Node.ID {
			matchingEnrollment++
			if !TokenEqual(enrollment.TokenHash, replacement.EnrollmentToken) || enrollment.UsedAt != nil {
				t.Fatalf("replacement enrollment was not hash-only and unused: %#v", enrollment)
			}
		}
	}
	if matchingEnrollment != 1 {
		t.Fatalf("replacement has %d enrollment records, want one", matchingEnrollment)
	}
	if !slices.ContainsFunc(snapshot.Revocations, func(revocation CertificateRevocation) bool {
		return revocation.NodeID == created.Node.ID && revocation.Fingerprint == oldBundle.CertificateFingerprint
	}) {
		t.Fatalf("old certificate was not blocklisted: %#v", snapshot.Revocations)
	}
	if len(snapshot.Audit) < 2 || snapshot.Audit[len(snapshot.Audit)-2].Action != "node.revoked" || snapshot.Audit[len(snapshot.Audit)-1].Action != "node.identity_replacement_created" {
		t.Fatalf("replacement audit boundary is incomplete: %#v", snapshot.Audit)
	}
	assertAuditActor(t, snapshot.Audit[len(snapshot.Audit)-2], actor)
	assertAuditActor(t, snapshot.Audit[len(snapshot.Audit)-1], actor)
	persisted, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), replacement.EnrollmentToken) {
		t.Fatal("raw replacement enrollment token was persisted")
	}

	beforeRepeat := string(persisted)
	if _, err := service.ReplaceNode(created.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: 3}); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated identity replacement returned %v, want conflict", err)
	}
	afterRepeat, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterRepeat) != beforeRepeat {
		t.Fatal("repeated identity replacement changed persisted state")
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "route-conflict", RoutedSubnets: created.Node.RoutedSubnets}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("pending replacement did not retain its routed-subnet reservation: %v", err)
	}

	newAgentToken := strings.Repeat("n", 42) + "A"
	newBundle, err := service.Enroll(context.Background(), replacement.EnrollmentToken, testNebulaPublicKey('N'), HashToken(newAgentToken))
	if err != nil {
		t.Fatal(err)
	}
	if newBundle.Node.ID != replacement.Node.ID || newBundle.ConfigRevision != 4 || !strings.Contains(newBundle.Config, "local_cidr: 172.28.0.0/16") {
		t.Fatalf("replacement did not enroll with its carried route: %#v\n%s", newBundle, newBundle.Config)
	}
	peerAfterEnrollment, err := service.AgentConfig(peerAgentToken)
	if err != nil {
		t.Fatal(err)
	}
	if peerAfterEnrollment.Revision != 4 || !strings.Contains(peerAfterEnrollment.Config, "route: \"172.28.0.0/16\"") || !strings.Contains(peerAfterEnrollment.Config, "via: \""+replacement.Node.IP+"\"") {
		t.Fatalf("replacement route was not republished through the new identity: revision=%d\n%s", peerAfterEnrollment.Revision, peerAfterEnrollment.Config)
	}
}

func TestReplaceNodeLateCredentialFailureRollsBackEveryMutation(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "identity-replacement-rollback", CIDR: "10.99.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "active-node"})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('R'), HashToken(strings.Repeat("r", 42)+"A"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	service.generateBearer = func() (string, error) { return "", errors.New("injected bearer failure") }
	if _, err := service.ReplaceNode(created.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: enrolled.ConfigRevision}); err == nil || !strings.Contains(err.Error(), "injected bearer failure") {
		t.Fatalf("late replacement failure returned %v", err)
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("late replacement failure partially committed revocation or replacement")
	}
}

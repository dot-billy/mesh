package control

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestRetireNetworkAtomicallyRemovesTrustDomainAndPermanentlyReservesIdentity(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	actor := Actor{ID: "oidc_" + strings.Repeat("D", 42) + "A", Kind: ActorKindOIDCAdmin, SessionID: "session_network_retirement"}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "retire-production", CIDR: "10.100.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNode(network.ID, CreateNodeInput{Name: "active", Site: "site-a", FailureDomain: "rack-a"})
	if err != nil {
		t.Fatal(err)
	}
	activeAgentToken := strings.Repeat("a", 42) + "A"
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, testNebulaPublicKey('A'), HashToken(activeAgentToken)); err != nil {
		t.Fatal(err)
	}
	recovery, err := service.IssueAgentRecovery(active.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending", Site: "site-a", FailureDomain: "rack-b"})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := service.CreateNode(network.ID, CreateNodeInput{Name: "revoked", Site: "site-b", FailureDomain: "rack-c"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), revoked.EnrollmentToken, testNebulaPublicKey('R'), HashToken(strings.Repeat("r", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(revoked.Node.ID); err != nil {
		t.Fatal(err)
	}
	unaffected, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "keep-production", CIDR: "10.101.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	unaffectedNode, err := service.CreateNode(unaffected.ID, CreateNodeInput{Name: "keep-node", Site: "site-c", FailureDomain: "rack-d"})
	if err != nil {
		t.Fatal(err)
	}

	var before State
	if err := store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	retiredNetwork, ok := findNetwork(before, network.ID)
	if !ok {
		t.Fatal("network disappeared before retirement")
	}
	beforeRejected, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RetireNetwork(network.ID, RetireNetworkInput{ExpectedConfigRevision: retiredNetwork.ConfigRevision - 1, ConfirmationName: network.Name}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale retirement returned %v, want conflict", err)
	}
	if _, err := service.RetireNetwork(network.ID, RetireNetworkInput{ExpectedConfigRevision: retiredNetwork.ConfigRevision, ConfirmationName: "keep-production"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-name retirement returned %v, want conflict", err)
	}
	afterRejected, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterRejected) != string(beforeRejected) {
		t.Fatal("rejected retirement changed persisted state")
	}

	retired, err := service.RetireNetworkAs(actor, network.ID, RetireNetworkInput{
		ExpectedConfigRevision: retiredNetwork.ConfigRevision,
		ConfirmationName:       network.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	if retired.NetworkID != network.ID || retired.Name != network.Name || retired.CIDR != network.CIDR || retired.ConfigRevision != retiredNetwork.ConfigRevision || retired.NodeCount != 3 || retired.ActiveNodes != 1 || retired.PendingNodes != 1 || retired.RevokedNodes != 1 || !retired.CredentialsInvalidated || !retired.EncryptedKeyMaterialRemoved || !retired.NameCIDRPermanentlyReserved {
		t.Fatalf("unexpected retirement receipt: %#v", retired)
	}
	wantNodeIDs := []string{active.Node.ID, pending.Node.ID, revoked.Node.ID}
	slices.Sort(wantNodeIDs)
	if !reflect.DeepEqual(retired.NodeIDs, wantNodeIDs) {
		t.Fatalf("retired node IDs are not deterministic: %v", retired.NodeIDs)
	}
	if _, err := service.AgentConfig(activeAgentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired active agent credential returned %v, want unauthorized", err)
	}
	if _, err := service.PreflightEnrollment(pending.EnrollmentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired pending enrollment returned %v, want unauthorized", err)
	}
	if _, err := service.RecoverAgent(recovery.RecoveryToken, testNebulaPublicKey('A'), HashToken(strings.Repeat("n", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired agent recovery returned %v, want unauthorized", err)
	}

	var after State
	if err := store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(after.Networks) != 1 || after.Networks[0].ID != unaffected.ID || len(after.Nodes) != 1 || after.Nodes[0].ID != unaffectedNode.Node.ID {
		t.Fatalf("retirement damaged another network: networks=%#v nodes=%#v", after.Networks, after.Nodes)
	}
	for _, enrollment := range after.Enrollments {
		if slices.Contains(retired.NodeIDs, enrollment.NodeID) {
			t.Fatalf("retirement retained enrollment %#v", enrollment)
		}
	}
	for _, recoveryRecord := range after.AgentRecoveries {
		if slices.Contains(retired.NodeIDs, recoveryRecord.NodeID) {
			t.Fatalf("retirement retained recovery %#v", recoveryRecord)
		}
	}
	for _, issuance := range after.Issuances {
		if issuance.NetworkID == network.ID {
			t.Fatalf("retirement retained issuance %#v", issuance)
		}
	}
	for _, revocation := range after.Revocations {
		if revocation.NetworkID == network.ID {
			t.Fatalf("retirement retained revocation %#v", revocation)
		}
	}
	last := after.Audit[len(after.Audit)-1]
	if last.Action != networkRetiredAuditAction || last.ResourceID != network.ID || last.Details["name"] != network.Name || last.Details["cidr"] != network.CIDR || last.Details["node_count"] != 3 || last.Details["active_nodes"] != 1 || last.Details["pending_nodes"] != 1 || last.Details["revoked_nodes"] != 1 {
		t.Fatalf("retirement audit is incomplete: %#v", last)
	}
	assertAuditActor(t, last, actor)
	persisted, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	for label, secret := range map[string]string{
		"encrypted CA key": retiredNetwork.EncryptedCAKey, "encrypted signing key": retiredNetwork.EncryptedConfigSigningKey,
		"active bearer": activeAgentToken, "pending enrollment": pending.EnrollmentToken, "agent recovery": recovery.RecoveryToken,
	} {
		if strings.Contains(string(persisted), secret) {
			t.Fatalf("retirement persisted %s", label)
		}
	}

	beforeRepeat := string(persisted)
	if _, err := service.RetireNetwork(network.ID, RetireNetworkInput{ExpectedConfigRevision: retired.ConfigRevision, ConfirmationName: retired.Name}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated retirement returned %v, want not found", err)
	}
	afterRepeat, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterRepeat) != beforeRepeat {
		t.Fatal("repeated retirement changed persisted state")
	}
	for label, input := range map[string]CreateNetworkInput{
		"same name":        {Name: strings.ToUpper(network.Name), CIDR: "10.102.0.0/24"},
		"same CIDR":        {Name: "replacement-cidr", CIDR: network.CIDR},
		"overlapping CIDR": {Name: "replacement-overlap", CIDR: "10.100.0.0/25"},
	} {
		if _, err := service.CreateNetwork(context.Background(), input); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s after retirement returned %v, want conflict", label, err)
		}
	}
	if _, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "fresh-network", CIDR: "10.102.0.0/24"}); err != nil {
		t.Fatalf("retirement blocked an unrelated fresh network: %v", err)
	}
}

func TestRetiredNetworkAuditTombstoneIsStrictAndCannotConflictWithActiveGraph(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "retirement-validation", CIDR: "10.103.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	var activeNetwork Network
	if err := store.View(func(state State) error {
		activeNetwork, _ = findNetwork(state, network.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RetireNetwork(network.ID, RetireNetworkInput{ExpectedConfigRevision: network.ConfigRevision, ConfirmationName: network.Name}); err != nil {
		t.Fatal(err)
	}
	var retired State
	if err := store.View(func(state State) error { retired = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := validateStateGraph(retired); err != nil {
		t.Fatalf("valid retirement tombstone rejected: %v", err)
	}

	for name, mutate := range map[string]func(*State){
		"missing CIDR":      func(state *State) { delete(state.Audit[len(state.Audit)-1].Details, "cidr") },
		"fractional count":  func(state *State) { state.Audit[len(state.Audit)-1].Details["node_count"] = 0.5 },
		"false key removal": func(state *State) { state.Audit[len(state.Audit)-1].Details["encrypted_key_material_removed"] = false },
		"active conflict":   func(state *State) { state.Networks = append(state.Networks, activeNetwork) },
		"duplicate tombstone": func(state *State) {
			duplicate := state.Audit[len(state.Audit)-1]
			duplicate.ID = "duplicate_retirement"
			state.Audit = append(state.Audit, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := cloneState(retired)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := validateStateGraph(candidate); err == nil || !strings.Contains(err.Error(), "retired network") {
				t.Fatalf("invalid retirement tombstone returned %v", err)
			}
		})
	}
}

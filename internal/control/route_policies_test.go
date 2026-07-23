package control

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func migrateRoutePolicyTestService(t *testing.T, service *Service) {
	t.Helper()
	migrateRouteProfileEditPrerequisites(t, service)
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureRoutePolicySchemaPreservesSignedStateAndIsWriteFree(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRouteProfileEditPrerequisites(t, service)
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-policy-schema", CIDR: "10.140.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateNode(network.ID, CreateNodeInput{Name: "route-policy-owner", RoutedSubnets: []string{"10.20.0.0/16", "10.100.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.CreateNode(network.ID, CreateNodeInput{Name: "route-policy-peer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), first.EnrollmentToken, testNebulaPublicKey('P'), HashToken(strings.Repeat("p", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	peerToken := strings.Repeat("q", 42) + "A"
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('Q'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	before, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	after, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("v11 migration changed signed desired artifact:\nbefore=%#v\nafter=%#v", before, after)
	}
	var state State
	if err := service.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	if state.Version != ControlStateVersionRoutePolicies || len(state.Networks) != 1 || state.Networks[0].RoutePolicies != nil || state.Audit[len(state.Audit)-1].Action != "control.route_policy_schema_migrated" {
		t.Fatalf("unexpected v11 migration state: %#v", state)
	}
	infoBefore, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("repeated v11 migration rewrote durable state")
	}
}

func TestWeightedECMPJoinsUpdatesAndLeavesThroughSafeLifecycle(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	migrateRoutePolicyTestService(t, service)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "weighted-ecmp", CIDR: "10.141.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "192.168.141.0/24"
	firstCreated, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "ecmp-gateway-a", RoutedSubnets: []string{prefix}})
	secondCreated, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "ecmp-gateway-b"})
	peerCreated, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "ecmp-peer"})
	firstToken, secondToken, peerToken := strings.Repeat("a", 42)+"A", strings.Repeat("b", 42)+"A", strings.Repeat("c", 42)+"A"
	if _, err := service.Enroll(context.Background(), firstCreated.EnrollmentToken, testNebulaPublicKey('A'), HashToken(firstToken)); err != nil {
		t.Fatal(err)
	}
	secondInitial, err := service.Enroll(context.Background(), secondCreated.EnrollmentToken, testNebulaPublicKey('B'), HashToken(secondToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peerCreated.EnrollmentToken, testNebulaPublicKey('C'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), secondCreated.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: []string{prefix}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "weighted-ecmp-join-request-0001",
	})
	if err != nil || started.Phase != RouteProfileEditPhasePreparingOwner {
		t.Fatalf("ECMP join start=%#v err=%v", started, err)
	}
	stagedGateway, err := service.AgentConfig(secondToken)
	if err != nil {
		t.Fatal(err)
	}
	if !stagedGateway.CertificateProfileRenewalRequired || strings.Contains(stagedGateway.Config, "route: \""+prefix+"\"") {
		t.Fatalf("joining gateway received a loopable peer route during certificate prepare:\n%s", stagedGateway.Config)
	}
	peerBefore, _ := service.AgentConfig(peerToken)
	assertUnsafeRouteVia(t, peerBefore.Config, prefix, firstCreated.Node.IP)
	prepared, err := service.Renew(context.Background(), secondToken, testNebulaPublicKey('B'))
	if err != nil || prepared.CertificateGeneration != secondInitial.CertificateGeneration+1 {
		t.Fatalf("prepare renewal=%#v err=%v", prepared, err)
	}
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, secondToken, prepared.ConfigRevision, prepared.ConfigSHA256, prepared.CertificateGeneration, prepared.CertificateFingerprint, 1)
	ready, _ := service.NodeRouteProfileEdit(secondCreated.Node.ID)
	joined, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), secondCreated.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
	if err != nil || joined.Phase != RouteProfileEditPhaseCompleted {
		t.Fatalf("ECMP join promotion=%#v err=%v", joined, err)
	}
	document, err := service.NetworkRoutePolicies(network.ID)
	if err != nil || len(document.Policies) != 1 || len(document.Policies[0].Gateways) != 2 || document.Policies[0].Install != true {
		t.Fatalf("derived ECMP policy=%#v err=%v", document, err)
	}
	gateways := make([]NetworkRoutePolicyGateway, len(document.Policies[0].Gateways))
	for index, gateway := range document.Policies[0].Gateways {
		weight := 3
		if gateway.NodeID == firstCreated.Node.ID {
			weight = 7
		}
		gateways[index] = NetworkRoutePolicyGateway{NodeID: gateway.NodeID, Weight: weight}
	}
	update := UpdateNetworkRoutePolicyInput{
		Prefix: prefix, Gateways: gateways, MTU: 1300, Metric: 42,
		ExpectedConfigRevision: document.ConfigRevision, RequestID: "weighted-ecmp-policy-request-0001",
	}
	updated, err := service.UpdateNetworkRoutePolicyAs(LegacyAdminActor(), network.ID, update)
	if err != nil || updated.ConfigRevision != document.ConfigRevision+1 || len(updated.Policies) != 1 || updated.Policies[0].MTU != 1300 || updated.Policies[0].Metric != 42 {
		t.Fatalf("updated ECMP policy=%#v err=%v", updated, err)
	}
	peerECMP, _ := service.AgentConfig(peerToken)
	if strings.Count(peerECMP.Config, "route: \""+prefix+"\"") != 1 || !strings.Contains(peerECMP.Config, "via:\n") || !strings.Contains(peerECMP.Config, "weight: 7") || !strings.Contains(peerECMP.Config, "weight: 3") || !strings.Contains(peerECMP.Config, "mtu: 1300") || !strings.Contains(peerECMP.Config, "metric: 42") {
		t.Fatalf("peer did not receive one weighted route entry:\n%s", peerECMP.Config)
	}
	for name, token := range map[string]string{"first": firstToken, "second": secondToken} {
		gatewayConfig, _ := service.AgentConfig(token)
		if strings.Contains(gatewayConfig.Config, "route: \""+prefix+"\"") {
			t.Fatalf("%s gateway received its locally served prefix as an unsafe route:\n%s", name, gatewayConfig.Config)
		}
	}
	infoBefore, _ := os.Stat(service.store.path)
	var auditBefore int
	_ = service.store.View(func(state State) error { auditBefore = len(state.Audit); return nil })
	replayed, err := service.UpdateNetworkRoutePolicyAs(LegacyAdminActor(), network.ID, update)
	if err != nil || replayed.ConfigRevision != updated.ConfigRevision {
		t.Fatalf("policy replay=%#v err=%v", replayed, err)
	}
	infoAfter, _ := os.Stat(service.store.path)
	var auditAfter int
	_ = service.store.View(func(state State) error { auditAfter = len(state.Audit); return nil })
	if !os.SameFile(infoBefore, infoAfter) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) || auditAfter != auditBefore {
		t.Fatal("exact route-policy replay rewrote durable state")
	}
	if _, err := service.UpdateNetworkRoutePolicy(network.ID, UpdateNetworkRoutePolicyInput{
		Prefix: prefix, Gateways: []NetworkRoutePolicyGateway{{NodeID: firstCreated.Node.ID, Weight: 1}},
		ExpectedConfigRevision: updated.ConfigRevision, RequestID: "weighted-ecmp-omit-owner-0001",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("policy omitted an authoritative gateway: %v", err)
	}
	left, err := service.StartRouteProfileEditAs(LegacyAdminActor(), secondCreated.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: nil, ExpectedConfigRevision: updated.ConfigRevision, RequestID: "weighted-ecmp-leave-request-0001",
	})
	if err != nil || left.Phase != RouteProfileEditPhaseCleaningOwner {
		t.Fatalf("ECMP leave start=%#v err=%v", left, err)
	}
	peerAfterLeave, _ := service.AgentConfig(peerToken)
	assertUnsafeRouteVia(t, peerAfterLeave.Config, prefix, firstCreated.Node.IP)
	if strings.Contains(peerAfterLeave.Config, "gateway:") || !strings.Contains(peerAfterLeave.Config, "mtu: 1300") || !strings.Contains(peerAfterLeave.Config, "metric: 42") {
		t.Fatalf("route-first leave did not preserve the surviving route controls:\n%s", peerAfterLeave.Config)
	}
	policyAfterLeave, _ := service.NetworkRoutePolicies(network.ID)
	if len(policyAfterLeave.Policies) != 1 || len(policyAfterLeave.Policies[0].Gateways) != 1 || policyAfterLeave.Policies[0].Gateways[0].NodeID != firstCreated.Node.ID {
		t.Fatalf("policy did not reconcile surviving owner: %#v", policyAfterLeave)
	}
	if !slices.Contains(left.AvailableActions, "advance") && left.Owner != nil && left.Owner.Ready {
		t.Fatalf("unexpected leave convergence actions: %#v", left)
	}
}

func TestRoutePolicyControlBounds(t *testing.T) {
	validGateways := []NetworkRoutePolicyGateway{{NodeID: "abcdefghijklmnop", Weight: 1}}
	if _, err := normalizeRoutePolicyGatewayInput(validGateways); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		mtu, metric int
	}{{499, 0}, {maxRoutePolicyMTU + 1, 0}, {0, -1}} {
		if err := validateRoutePolicyControls(input.mtu, input.metric); err == nil {
			t.Fatalf("accepted invalid controls mtu=%d metric=%d", input.mtu, input.metric)
		}
	}
	badWeight := slices.Clone(validGateways)
	badWeight[0].Weight = maxRoutePolicyWeight + 1
	if _, err := normalizeRoutePolicyGatewayInput(badWeight); err == nil {
		t.Fatal("accepted oversized route weight")
	}
}

func TestECMPOwnerIdentityReplacementReconcilesAndRejoins(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	migrateRoutePolicyTestService(t, service)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "ecmp-identity-replacement", CIDR: "10.143.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "192.168.143.0/24"
	first, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "replacement-gateway-a", RoutedSubnets: []string{prefix}})
	second, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "replacement-gateway-b"})
	peer, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "replacement-peer"})
	firstToken, secondToken, peerToken := strings.Repeat("d", 42)+"A", strings.Repeat("e", 42)+"A", strings.Repeat("f", 42)+"A"
	if _, err := service.Enroll(context.Background(), first.EnrollmentToken, testNebulaPublicKey('D'), HashToken(firstToken)); err != nil {
		t.Fatal(err)
	}
	secondInitial, err := service.Enroll(context.Background(), second.EnrollmentToken, testNebulaPublicKey('E'), HashToken(secondToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('F'), HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), second.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: []string{prefix}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "ecmp-replacement-join-request-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Renew(context.Background(), secondToken, testNebulaPublicKey('E'))
	if err != nil || prepared.CertificateGeneration != secondInitial.CertificateGeneration+1 {
		t.Fatalf("prepare replacement owner=%#v err=%v", prepared, err)
	}
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, secondToken, prepared.ConfigRevision, prepared.ConfigSHA256, prepared.CertificateGeneration, prepared.CertificateFingerprint, 1)
	joined, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), second.Node.ID, UpdateRouteProfileEditInput{
		ExpectedConfigRevision: started.ConfigRevision, RequestID: started.RequestID,
	})
	if err != nil || joined.Phase != RouteProfileEditPhaseCompleted {
		t.Fatalf("join second owner=%#v err=%v", joined, err)
	}
	policy, _ := service.NetworkRoutePolicies(network.ID)
	gateways := make([]NetworkRoutePolicyGateway, len(policy.Policies[0].Gateways))
	for index, gateway := range policy.Policies[0].Gateways {
		weight := 3
		if gateway.NodeID == first.Node.ID {
			weight = 7
		}
		gateways[index] = NetworkRoutePolicyGateway{NodeID: gateway.NodeID, Weight: weight}
	}
	weighted, err := service.UpdateNetworkRoutePolicy(network.ID, UpdateNetworkRoutePolicyInput{
		Prefix: prefix, Gateways: gateways, MTU: 1300, Metric: 42,
		ExpectedConfigRevision: policy.ConfigRevision, RequestID: "ecmp-replacement-policy-request-0001",
	})
	if err != nil {
		t.Fatal(err)
	}

	replacement, err := service.ReplaceNode(second.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: weighted.ConfigRevision})
	if err != nil {
		t.Fatalf("replace ECMP owner: %v", err)
	}
	if replacement.Node.Status != "pending" || !slices.Equal(replacement.Node.RoutedSubnets, []string{prefix}) {
		t.Fatalf("replacement did not retain exact routed authorization: %#v", replacement)
	}
	afterRevoke, _ := service.NetworkRoutePolicies(network.ID)
	if len(afterRevoke.Policies) != 1 || len(afterRevoke.Policies[0].Gateways) != 1 || afterRevoke.Policies[0].Gateways[0].NodeID != first.Node.ID || afterRevoke.Policies[0].Gateways[0].Weight != 7 || afterRevoke.Policies[0].MTU != 1300 || afterRevoke.Policies[0].Metric != 42 {
		t.Fatalf("replacement did not preserve surviving route policy: %#v", afterRevoke)
	}
	peerDuringReplacement, _ := service.AgentConfig(peerToken)
	assertUnsafeRouteVia(t, peerDuringReplacement.Config, prefix, first.Node.IP)
	if strings.Contains(peerDuringReplacement.Config, "gateway:") || strings.Contains(peerDuringReplacement.Config, second.Node.IP) {
		t.Fatalf("pending replacement remained published in peer route:\n%s", peerDuringReplacement.Config)
	}

	replacementToken := strings.Repeat("g", 42) + "A"
	if _, err := service.Enroll(context.Background(), replacement.EnrollmentToken, testNebulaPublicKey('G'), HashToken(replacementToken)); err != nil {
		t.Fatalf("enroll replacement ECMP owner: %v", err)
	}
	afterEnrollment, _ := service.NetworkRoutePolicies(network.ID)
	if len(afterEnrollment.Policies) != 1 || len(afterEnrollment.Policies[0].Gateways) != 2 {
		t.Fatalf("replacement did not rejoin ECMP policy: %#v", afterEnrollment)
	}
	wantWeights := map[string]int{first.Node.ID: 7, replacement.Node.ID: 1}
	for _, gateway := range afterEnrollment.Policies[0].Gateways {
		if gateway.Weight != wantWeights[gateway.NodeID] {
			t.Fatalf("replacement ECMP weight reconciliation changed: %#v", afterEnrollment)
		}
		delete(wantWeights, gateway.NodeID)
	}
	if len(wantWeights) != 0 {
		t.Fatalf("replacement ECMP owners missing: %#v", wantWeights)
	}
	peerAfterEnrollment, _ := service.AgentConfig(peerToken)
	if strings.Count(peerAfterEnrollment.Config, "route: \""+prefix+"\"") != 1 || strings.Count(peerAfterEnrollment.Config, "gateway:") != 2 || strings.Contains(peerAfterEnrollment.Config, second.Node.IP) || !strings.Contains(peerAfterEnrollment.Config, replacement.Node.IP) {
		t.Fatalf("replacement ECMP route did not publish only current owners:\n%s", peerAfterEnrollment.Config)
	}
}

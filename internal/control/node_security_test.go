package control

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func ensureFirewallScopesForTest(t *testing.T, service *Service) {
	t.Helper()
	masterVerifier, err := DeriveMasterKeyVerifier(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(make([]byte, 32), bytes.Repeat([]byte{'S'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema, service.EnsureRouteProfileEditSchema, service.EnsureRoutePolicySchema,
		service.EnsureNativeDNSSchema, service.EnsureFirewallScopeSchema,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnsureFirewallScopeSchemaPreservesSignedArtifacts(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRoutePolicyTestService(t, service)
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "scope-migration", CIDR: "10.124.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "scope-member"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("s", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('S'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	before, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallScopeSchema(); err != nil {
		t.Fatal(err)
	}
	after, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("v13 migration changed signed desired artifact:\nbefore=%#v\nafter=%#v", before, after)
	}
	var state State
	if err := service.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	last := state.Audit[len(state.Audit)-1]
	if state.Version != ControlStateVersionFirewallScopes || last.Action != "control.firewall_scope_schema_migrated" || last.Details["from_version"] != ControlStateVersionNativeDNS || last.Details["to_version"] != ControlStateVersionFirewallScopes {
		t.Fatalf("unexpected v13 migration state: version=%d audit=%#v", state.Version, last)
	}
}

func TestScopedFirewallCompilesDistinctEffectivePolicyPerNode(t *testing.T) {
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	ensureFirewallScopesForTest(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "scoped-policy", CIDR: "10.121.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := service.CreateNode(network.ID, CreateNodeInput{Name: "operator-node", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := service.CreateNode(network.ID, CreateNodeInput{Name: "client-node", Groups: []string{"clients"}})
	if err != nil {
		t.Fatal(err)
	}
	operatorToken := strings.Repeat("o", 42) + "A"
	clientToken := strings.Repeat("c", 42) + "A"
	if _, err := service.Enroll(context.Background(), operator.EnrollmentToken, testNebulaPublicKey('O'), HashToken(operatorToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), client.EnrollmentToken, testNebulaPublicKey('C'), HashToken(clientToken)); err != nil {
		t.Fatal(err)
	}

	input := FirewallPolicyInput{
		Inbound: []FirewallRule{
			{Proto: "tcp", Port: "22", Group: "all"},
			{Proto: "tcp", Port: "443", PeerNodeID: client.Node.ID, TargetGroup: "operators"},
			{Proto: "udp", Port: "53", Group: "operators", TargetNodeID: client.Node.ID},
		},
		Outbound: []FirewallRule{},
	}
	preview, err := service.PreviewFirewallPolicy(network.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.WouldChange || preview.RenderedFirewall != "" || len(preview.EffectiveNodes) != 2 || len(preview.PolicySHA256) != 64 {
		t.Fatalf("unexpected scoped preview: %#v", preview)
	}
	effective := make(map[string]EffectiveFirewallPolicyDocument)
	for _, document := range preview.EffectiveNodes {
		effective[document.NodeID] = document
	}
	operatorPolicy := effective[operator.Node.ID]
	clientPolicy := effective[client.Node.ID]
	if len(operatorPolicy.Inbound) != 2 || operatorPolicy.Inbound[1].Host != client.Node.IP || operatorPolicy.Inbound[1].PeerNodeID != "" || operatorPolicy.Inbound[1].TargetGroup != "" {
		t.Fatalf("operator effective policy was not compiled: %#v", operatorPolicy)
	}
	if len(clientPolicy.Inbound) != 2 || clientPolicy.Inbound[1].Group != "operators" || clientPolicy.Inbound[1].TargetNodeID != "" {
		t.Fatalf("client effective policy was not compiled: %#v", clientPolicy)
	}
	if operatorPolicy.SHA256 == clientPolicy.SHA256 || !strings.Contains(operatorPolicy.RenderedFirewall, "cidr: "+client.Node.IP+"/32") || strings.Contains(clientPolicy.RenderedFirewall, "port: 443") {
		t.Fatalf("node-specific rendered policies are not distinct: operator=%q client=%q", operatorPolicy.RenderedFirewall, clientPolicy.RenderedFirewall)
	}

	updated, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: 1, Inbound: input.Inbound, Outbound: input.Outbound})
	if err != nil || updated.ConfigRevision != 2 {
		t.Fatalf("scoped update failed: document=%#v err=%v", updated, err)
	}
	operatorConfig, err := service.AgentConfig(operatorToken)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := service.AgentConfig(clientToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(operatorConfig.Config, "port: 443") || strings.Contains(operatorConfig.Config, "port: 53") || !strings.Contains(clientConfig.Config, "port: 53") || strings.Contains(clientConfig.Config, "port: 443") {
		t.Fatalf("signed configs did not receive their effective policies")
	}

	other, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "other-policy", CIDR: "10.122.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := service.CreateNode(other.ID, CreateNodeInput{Name: "foreign-node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PreviewFirewallPolicy(network.ID, FirewallPolicyInput{
		Inbound: []FirewallRule{{Proto: "tcp", Port: "80", PeerNodeID: foreign.Node.ID}}, Outbound: []FirewallRule{},
	}); err == nil {
		t.Fatal("cross-network peer-node selector was accepted")
	}
}

func TestUpdateNodeGroupsReplacesCertificateAtomicallyAndReplays(t *testing.T) {
	originalIssuerNow := recoverySnapshotNow
	t.Cleanup(func() { recoverySnapshotNow = originalIssuerNow })
	base := time.Date(2026, 7, 23, 19, 0, 0, 0, time.UTC)
	recoverySnapshotNow = base
	issuer := &countingCertificateRotationIssuer{delegate: recoverySnapshotIssuer{}}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return recoverySnapshotNow }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "group-update", CIDR: "10.111.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "group-node", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("g", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('G'), HashToken(agentToken)); err != nil {
		t.Fatal(err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("load enrolled node: nodes=%#v err=%v", nodes, err)
	}
	before := nodes[0]
	beforePublicKey, err := publicKeyFromNodeCertificate(before)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := service.IssueAgentRecovery(before.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = recovery
	input := UpdateNodeGroupsInput{
		ExpectedConfigRevision: 1, ConfirmationName: before.Name,
		RequestID: "node-group-update-request-0001", Groups: []string{"clients", "database"},
	}
	recoverySnapshotNow = base.Add(time.Hour)
	callsBefore := issuer.calls
	receipt, err := service.UpdateNodeGroups(context.Background(), before.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(receipt.PreviousGroups, []string{"all", "operators"}) || !slices.Equal(receipt.Groups, []string{"all", "clients", "database"}) || receipt.ConfigRevision != 2 || receipt.CertificateGeneration != before.CertificateGeneration+1 || !receipt.PreviousCertificateBlocklisted || receipt.AgentRecoveryRecordsInvalidated != 1 {
		t.Fatalf("unexpected group update receipt: %#v", receipt)
	}
	afterNodes, err := service.Nodes(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	after := afterNodes[0]
	afterPublicKey, err := publicKeyFromNodeCertificate(after)
	if err != nil {
		t.Fatal(err)
	}
	if beforePublicKey != afterPublicKey || before.CertificateFingerprint == after.CertificateFingerprint || !slices.Equal(after.Groups, receipt.Groups) {
		t.Fatalf("group update did not preserve the key and replace certificate identity")
	}
	config, err := service.AgentConfig(agentToken)
	if err != nil || config.Revision != 2 {
		t.Fatalf("group update did not advance signed config: config=%#v err=%v", config, err)
	}
	replayed, err := service.UpdateNodeGroups(context.Background(), before.ID, input)
	if err != nil || replayed.RequestID != receipt.RequestID || replayed.CertificateGeneration != receipt.CertificateGeneration || issuer.calls != callsBefore+1 {
		t.Fatalf("group update replay was not exact: replay=%#v err=%v calls=%d", replayed, err, issuer.calls)
	}
}

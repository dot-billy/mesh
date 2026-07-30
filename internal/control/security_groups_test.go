package control

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

func ensureSecurityGroupsForTest(t *testing.T, service *Service) {
	t.Helper()
	ensureFirewallScopesForTest(t, service)
	if err := service.EnsureSecurityGroupSchema(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSecurityGroupSchemaDerivesExistingMembershipAndPolicyReferences(t *testing.T) {
	now := time.Date(2026, 7, 24, 14, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	ensureFirewallScopesForTest(t, service)

	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{
		Name: "group-migration", CIDR: "10.126.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "operator", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: network.ConfigRevision,
		Inbound:                []FirewallRule{{Proto: "tcp", Port: "22", Group: "auditors"}},
		Outbound:               []FirewallRule{},
	})
	if err != nil {
		t.Fatal(err)
	}

	var before State
	if err := service.store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureSecurityGroupSchema(); err != nil {
		t.Fatal(err)
	}

	document, err := service.NetworkSecurityGroups(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{document.Groups[0].Name, document.Groups[1].Name, document.Groups[2].Name}; !slices.Equal(got, []string{"all", "auditors", "operators"}) {
		t.Fatalf("derived security groups = %v", got)
	}
	if !slices.Equal(document.Groups[2].MemberNodeIDs, []string{created.Node.ID}) || document.Groups[2].PendingMembers != 1 {
		t.Fatalf("derived operator membership = %#v", document.Groups[2])
	}
	if document.Groups[1].PeerRuleReferences != 1 {
		t.Fatalf("derived firewall references = %#v", document.Groups[1])
	}

	var after State
	if err := service.store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if after.Version != ControlStateVersionSecurityGroups || after.Networks[0].ConfigRevision != updated.ConfigRevision ||
		after.Nodes[0].CertificateFingerprint != before.Nodes[0].CertificateFingerprint ||
		!slices.Equal(after.Nodes[0].Groups, before.Nodes[0].Groups) {
		t.Fatalf("v14 migration changed signed state: before=%#v after=%#v", before, after)
	}
	last := after.Audit[len(after.Audit)-1]
	if last.Action != "control.security_group_schema_migrated" ||
		last.Details["from_version"] != ControlStateVersionFirewallScopes ||
		last.Details["to_version"] != ControlStateVersionSecurityGroups {
		t.Fatalf("unexpected migration audit: %#v", last)
	}
	if err := service.EnsureSecurityGroupSchema(); err != nil {
		t.Fatal(err)
	}
	var repeated State
	if err := service.store.View(func(state State) error { repeated = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, repeated) {
		t.Fatal("idempotent security-group migration rewrote state")
	}
}

func TestNetworkSecurityGroupCatalogSupportsIndependentLifecycleAndDeleteGuards(t *testing.T) {
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	ensureSecurityGroupsForTest(t, service)

	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{
		Name: "managed-groups", CIDR: "10.127.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.CreateNetworkSecurityGroup(network.ID, CreateNetworkSecurityGroupInput{
		Name: "unused", Description: "Ready for future members",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Groups) != 2 || document.Groups[1].Name != "unused" || document.Groups[1].Description != "Ready for future members" {
		t.Fatalf("created catalog = %#v", document)
	}
	if _, err := service.CreateNetworkSecurityGroup(network.ID, CreateNetworkSecurityGroupInput{Name: "unused"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate group error = %v", err)
	}
	if _, err := service.CreateNetworkSecurityGroup(network.ID, CreateNetworkSecurityGroupInput{Name: "all"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("built-in group creation error = %v", err)
	}
	now = now.Add(time.Minute)
	document, err = service.UpdateNetworkSecurityGroup(network.ID, "unused", UpdateNetworkSecurityGroupInput{Description: "No members yet"})
	if err != nil || document.Groups[1].Description != "No members yet" {
		t.Fatalf("updated catalog = %#v err=%v", document, err)
	}

	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member", Groups: []string{"members"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeleteNetworkSecurityGroup(network.ID, "members", DeleteNetworkSecurityGroupInput{ConfirmationName: "members"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("member group delete error = %v", err)
	}
	if _, err := service.CreateNetworkSecurityGroup(network.ID, CreateNetworkSecurityGroupInput{Name: "policy-only"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: network.ConfigRevision,
		Inbound:                []FirewallRule{{Proto: "tcp", Port: "443", Group: "policy-only"}},
		Outbound:               []FirewallRule{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeleteNetworkSecurityGroup(network.ID, "policy-only", DeleteNetworkSecurityGroupInput{ConfirmationName: "policy-only"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("referenced group delete error = %v", err)
	}
	if _, err := service.DeleteNetworkSecurityGroup(network.ID, "unused", DeleteNetworkSecurityGroupInput{ConfirmationName: "wrong"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incorrect confirmation error = %v", err)
	}
	now = now.Add(time.Minute)
	document, err = service.DeleteNetworkSecurityGroup(network.ID, "unused", DeleteNetworkSecurityGroupInput{ConfirmationName: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range document.Groups {
		if group.Name == "unused" {
			t.Fatal("deleted group remains in catalog")
		}
	}

	var state State
	if err := service.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0, len(state.Audit))
	for _, event := range state.Audit {
		actions = append(actions, event.Action)
	}
	for _, action := range []string{"network.security_group_created", "network.security_group_updated", "network.security_group_deleted"} {
		if !slices.Contains(actions, action) {
			t.Fatalf("missing %s audit event in %v", action, actions)
		}
	}
}

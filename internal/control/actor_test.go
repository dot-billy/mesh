package control

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestActorValidationAndAttributedAuditDetails(t *testing.T) {
	actor := Actor{
		ID:        "oidc_" + strings.Repeat("A", 43),
		Kind:      ActorKindOIDCAdmin,
		SessionID: "session_01",
	}
	if err := validateActor(actor); err != nil {
		t.Fatalf("valid actor rejected: %v", err)
	}
	if LegacyAdminActor() != (Actor{ID: "legacy_admin", Kind: ActorKindLegacyAdmin}) {
		t.Fatalf("legacy administrator actor is not canonical: %#v", LegacyAdminActor())
	}
	if err := validateActor(Actor{ID: "node_01", Kind: ActorKindNodeAgent}); err != nil {
		t.Fatalf("valid node-agent actor rejected: %v", err)
	}

	for _, test := range []struct {
		name  string
		actor Actor
	}{
		{name: "missing id", actor: Actor{Kind: ActorKindOIDCAdmin}},
		{name: "missing kind", actor: Actor{ID: "legacy_admin"}},
		{name: "unknown kind", actor: Actor{ID: "legacy_admin", Kind: "administrator"}},
		{name: "noncanonical oidc last bits", actor: Actor{ID: "oidc_" + strings.Repeat("A", 42) + "B", Kind: ActorKindOIDCAdmin}},
		{name: "noncanonical legacy id", actor: Actor{ID: "other", Kind: ActorKindLegacyAdmin}},
		{name: "empty service record id", actor: Actor{ID: "service_", Kind: ActorKindServiceAccount}},
		{name: "empty break glass code id", actor: Actor{ID: "breakglass_", Kind: ActorKindBreakGlass}},
		{name: "node agent session", actor: Actor{ID: "node_01", Kind: ActorKindNodeAgent, SessionID: "session_01"}},
		{name: "invalid id character", actor: Actor{ID: "service_not.valid", Kind: ActorKindServiceAccount}},
		{name: "oversize id", actor: Actor{ID: "service_" + strings.Repeat("a", 121), Kind: ActorKindServiceAccount}},
		{name: "invalid session", actor: Actor{ID: "legacy_admin", Kind: ActorKindLegacyAdmin, SessionID: "not valid"}},
		{name: "oversize session", actor: Actor{ID: "legacy_admin", Kind: ActorKindLegacyAdmin, SessionID: strings.Repeat("s", 129)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateActor(test.actor); err == nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid actor returned %v", err)
			}
		})
	}

	details := map[string]any{"name": "network"}
	event, err := newAttributedAudit(time.Unix(1, 0).UTC(), "network.created", "network", "network_1", details, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 1 || details["actor_id"] != nil {
		t.Fatalf("actor injection mutated caller details: %#v", details)
	}
	assertAuditActor(t, event, actor)
	for _, key := range []string{auditActorIDKey, auditActorKindKey, auditActorSessionIDKey} {
		if _, err := newAttributedAudit(time.Now(), "test", "network", "network_1", map[string]any{key: "collision"}, actor); err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("reserved detail collision for %q returned %v", key, err)
		}
	}
}

func TestActorExplicitAdminMutationsAreAtomicAttributedAndIdempotent(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	actor := Actor{ID: "oidc_" + strings.Repeat("B", 42) + "A", Kind: ActorKindOIDCAdmin, SessionID: "session_actor_test"}
	network, err := service.CreateNetworkAs(context.Background(), actor, CreateNetworkInput{Name: "actor-policy", CIDR: "10.91.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{Name: "pending-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReissueEnrollmentAs(actor, pending.Node.ID); err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{Name: "active-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('A')
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, publicKey, HashToken(strings.Repeat("a", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueAgentRecoveryAs(actor, active.Node.ID); err != nil {
		t.Fatal(err)
	}
	current, err := service.GetFirewallPolicy(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	desired := UpdateFirewallPolicyInput{
		ExpectedConfigRevision: current.ConfigRevision,
		Inbound:                []FirewallRule{{Proto: "tcp", Port: "443", Group: "operators"}},
		Outbound:               []FirewallRule{},
	}
	updated, err := service.UpdateFirewallPolicyAs(actor, network.ID, desired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNodeAs(actor, active.Node.ID); err != nil {
		t.Fatal(err)
	}

	var state State
	if err := service.store.View(func(snapshot State) error { state = snapshot; return nil }); err != nil {
		t.Fatal(err)
	}
	expectedCounts := map[string]int{
		"network.created":                 1,
		"node.created":                    2,
		"node.enrollment_reissued":        1,
		"node.agent_recovery_issued":      1,
		"network.firewall_policy_updated": 1,
		"node.revoked":                    1,
	}
	actualCounts := map[string]int{}
	for _, event := range state.Audit {
		if _, expected := expectedCounts[event.Action]; !expected {
			continue
		}
		assertAuditActor(t, event, actor)
		actualCounts[event.Action]++
	}
	if !reflect.DeepEqual(actualCounts, expectedCounts) {
		t.Fatalf("attributed mutation counts=%v, want %v", actualCounts, expectedCounts)
	}

	beforeNoop := len(state.Audit)
	desired.ExpectedConfigRevision = current.ConfigRevision
	retried, err := service.UpdateFirewallPolicyAs(actor, network.ID, desired)
	if err != nil || retried.ConfigRevision < updated.ConfigRevision || !sameEffectiveFirewallPolicy(FirewallPolicy{Inbound: retried.Inbound, Outbound: retried.Outbound}, FirewallPolicy{Inbound: updated.Inbound, Outbound: updated.Outbound}) {
		t.Fatalf("same-policy stale retry failed: document=%#v err=%v", retried, err)
	}
	if _, err := service.CreateNodeAs(actor, network.ID, CreateNodeInput{Name: "pending-01"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("failed attributed mutation returned %v", err)
	}
	var afterNoop State
	_ = service.store.View(func(snapshot State) error { afterNoop = snapshot; return nil })
	if len(afterNoop.Audit) != beforeNoop {
		t.Fatalf("failed/no-op actor mutations appended %d audit events", len(afterNoop.Audit)-beforeNoop)
	}
}

func TestInvalidActorRejectsEveryAdminMutationWithoutStateChange(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "actor-atomic", CIDR: "10.92.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-01"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNode(network.ID, CreateNodeInput{Name: "active-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('C')
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, publicKey, HashToken(strings.Repeat("c", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	current, err := service.GetFirewallPolicy(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	bad := Actor{Kind: ActorKindOIDCAdmin, SessionID: "session"}
	calls := []func() error{
		func() error {
			_, err := service.CreateNetworkAs(context.Background(), bad, CreateNetworkInput{Name: "must-not-exist", CIDR: "10.93.0.0/24"})
			return err
		},
		func() error {
			_, err := service.CreateNodeAs(bad, network.ID, CreateNodeInput{Name: "must-not-exist"})
			return err
		},
		func() error { _, err := service.ReissueEnrollmentAs(bad, pending.Node.ID); return err },
		func() error {
			_, err := service.CancelPendingNodeAs(bad, pending.Node.ID, CancelPendingNodeInput{ConfirmationName: pending.Node.Name})
			return err
		},
		func() error { _, err := service.IssueAgentRecoveryAs(bad, active.Node.ID); return err },
		func() error {
			_, err := service.ReplaceNodeAs(bad, active.Node.ID, ReplaceNodeInput{ExpectedConfigRevision: current.ConfigRevision})
			return err
		},
		func() error {
			_, err := service.ArchiveNodeAs(bad, active.Node.ID, ArchiveNodeInput{ExpectedConfigRevision: current.ConfigRevision, ConfirmationName: active.Node.Name})
			return err
		},
		func() error {
			_, err := service.RotateNodeCertificateAs(context.Background(), bad, active.Node.ID, RotateNodeCertificateInput{ExpectedConfigRevision: current.ConfigRevision, ConfirmationName: active.Node.Name, RequestID: "invalid-actor-rotation"})
			return err
		},
		func() error {
			_, err := service.RevokeNodeWithReceiptAs(bad, active.Node.ID, RevokeNodeInput{ExpectedConfigRevision: current.ConfigRevision, ConfirmationName: active.Node.Name, RequestID: "invalid-actor-revocation"})
			return err
		},
		func() error {
			_, err := service.RetireNetworkAs(bad, network.ID, RetireNetworkInput{ExpectedConfigRevision: current.ConfigRevision, ConfirmationName: network.Name})
			return err
		},
		func() error { _, err := service.RevokeNodeAs(bad, active.Node.ID); return err },
		func() error {
			_, err := service.UpdateFirewallPolicyAs(bad, network.ID, UpdateFirewallPolicyInput{
				ExpectedConfigRevision: current.ConfigRevision,
				Inbound:                []FirewallRule{{Proto: "tcp", Port: "80", Host: "10.92.0.10"}},
				Outbound:               []FirewallRule{},
			})
			return err
		},
	}
	var before State
	_ = service.store.View(func(snapshot State) error { before = snapshot; return nil })
	for index, call := range calls {
		if err := call(); err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid-actor mutation %d returned %v", index+1, err)
		}
	}
	var after State
	_ = service.store.View(func(snapshot State) error { after = snapshot; return nil })
	if !reflect.DeepEqual(after, before) {
		t.Fatal("invalid actor changed persisted state")
	}
}

func TestPersistedAuditActorValidationAndHistoricalCompatibility(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, &countingIssuer{})
	historical, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "historical", CIDR: "10.94.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, details := range []map[string]any{
		{auditActorIDKey: "legacy_admin"},
		{auditActorIDKey: "legacy_admin", auditActorKindKey: ActorKindLegacyAdmin, auditActorSessionIDKey: 7},
		{auditActorIDKey: "legacy_admin", auditActorKindKey: "invalid", auditActorSessionIDKey: ""},
	} {
		err := store.Update(func(state *State) error {
			state.Audit[0].Details = details
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "invalid actor metadata") {
			t.Fatalf("invalid persisted actor details %#v returned %v", details, err)
		}
	}
	actor := Actor{ID: "service_automation", Kind: ActorKindServiceAccount}
	attributed, err := service.CreateNetworkAs(context.Background(), actor, CreateNetworkInput{Name: "attributed", CIDR: "10.95.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatalf("historical actorless audit failed to reopen: %v", err)
	}
	defer reopened.Close()
	var state State
	if err := reopened.View(func(snapshot State) error { state = snapshot; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(state.Audit) != 2 {
		t.Fatalf("historical audit count=%d", len(state.Audit))
	}
	for _, event := range state.Audit {
		switch event.ResourceID {
		case historical.ID:
			for _, key := range []string{auditActorIDKey, auditActorKindKey, auditActorSessionIDKey} {
				if _, exists := event.Details[key]; exists {
					t.Fatalf("historical actorless event unexpectedly contains %q", key)
				}
			}
		case attributed.ID:
			assertAuditActor(t, event, actor)
		default:
			t.Fatalf("unexpected persisted audit event: %#v", event)
		}
	}
}

func assertAuditActor(t *testing.T, event AuditEvent, actor Actor) {
	t.Helper()
	if event.Details[auditActorIDKey] != actor.ID || event.Details[auditActorKindKey] != actor.Kind || event.Details[auditActorSessionIDKey] != actor.SessionID {
		t.Fatalf("audit event %q actor details=%#v, want %#v", event.Action, event.Details, actor)
	}
}

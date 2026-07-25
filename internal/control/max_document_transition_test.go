//go:build postgresmaxdocgate

package control

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestValidateMaximumDocumentFirewallTransitionRequiresExactPreservation(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x41}, 32)
	box, err := NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := BuildMaximumDocumentFixture(context.Background(), MaximumDocumentFixtureOptions{
		Directory: t.TempDir(), MasterKey: masterKey, AdminToken: bytes.Repeat([]byte{'B'}, 43),
		At:                    time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		CanonicalMinimumBytes: 1 << 20, CanonicalMaximumBytes: 1536 << 10, ExactBytes: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := validateRecoverySnapshot(fixture.ExactBytes, box)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := cloneState(source)
	if err != nil {
		t.Fatal(err)
	}
	network := &terminal.Networks[0]
	updatedAt := network.ConfigUpdatedAt.Add(time.Second)
	oldFirewall := renderFirewallPolicy(network.FirewallPolicy)
	network.FirewallPolicy = FirewallPolicy{
		Mode: FirewallPolicyModeManaged, RendererVersion: FirewallRendererVersionV2,
		Inbound:  []FirewallRule{{Proto: "any", Port: "any", Group: "all"}},
		Outbound: []FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
	}
	network.ConfigRevision++
	network.ConfigUpdatedAt = updatedAt
	event, err := newAttributedAudit(updatedAt, "network.firewall_policy_updated", "network", network.ID, map[string]any{
		"old_sha256": ConfigDigest(oldFirewall), "new_sha256": ConfigDigest(renderFirewallPolicy(network.FirewallPolicy)),
		"inbound_rules": len(network.FirewallPolicy.Inbound), "outbound_rules": len(network.FirewallPolicy.Outbound),
		"config_revision": network.ConfigRevision,
	}, LegacyAdminActor())
	if err != nil {
		t.Fatal(err)
	}
	terminal.Audit = append(terminal.Audit, event)
	validTerminal, err := encodePersistedState(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaximumDocumentFirewallTransition(fixture.ExactBytes, validTerminal, box, fixture.NetworkID); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*State){
		"unaffected node": func(state *State) {
			state.Nodes[0].Name = "changed-but-valid"
		},
		"unaffected enrollment": func(state *State) {
			state.Enrollments[0].TokenHash = HashToken("different-maximum-document-enrollment")
		},
		"prior audit": func(state *State) {
			state.Audit[len(state.Audit)-2].Details["name"] = "changed-but-valid"
		},
		"unrelated network field": func(state *State) {
			state.Networks[0].Name = "changed-but-valid"
		},
		"appended firewall audit": func(state *State) {
			state.Audit[len(state.Audit)-1].Details["config_revision"] = float64(99)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate, err := cloneState(terminal)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			raw, err := encodePersistedState(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateMaximumDocumentFirewallTransition(fixture.ExactBytes, raw, box, fixture.NetworkID); err == nil {
				t.Fatal("accepted a control transition outside the exact firewall allowlist")
			}
		})
	}
}

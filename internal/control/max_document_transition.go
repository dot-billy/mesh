//go:build postgresmaxdocgate

package control

// This file contains the test-only semantic transition oracle used by the
// PostgreSQL maximum-document gate. Keeping it in package control lets the
// gate compare every private persisted field after the production recovery
// decoder has authenticated and validated both documents.

import (
	"errors"
	"fmt"
	"reflect"
)

// ValidateMaximumDocumentFirewallTransition proves that terminal differs from
// source only by the one production firewall mutation for networkID. Array
// order, every unrelated record and private field, and every prior audit event
// must remain identical.
func ValidateMaximumDocumentFirewallTransition(source, terminal []byte, box *SecretBox, networkID string) error {
	sourceState, err := validateRecoverySnapshot(source, box)
	if err != nil {
		return fmt.Errorf("validate maximum-document source control state: %w", err)
	}
	terminalState, err := validateRecoverySnapshot(terminal, box)
	if err != nil {
		return fmt.Errorf("validate maximum-document terminal control state: %w", err)
	}
	if networkID == "" || len(terminalState.Audit) != len(sourceState.Audit)+1 {
		return errors.New("maximum-document control transition did not append exactly one audit")
	}
	if !reflect.DeepEqual(terminalState.Audit[:len(sourceState.Audit)], sourceState.Audit) {
		return errors.New("maximum-document control transition changed a prior audit")
	}

	sourceIndex, terminalIndex := -1, -1
	for index := range sourceState.Networks {
		if sourceState.Networks[index].ID == networkID {
			if sourceIndex != -1 {
				return errors.New("maximum-document source control state contains duplicate target networks")
			}
			sourceIndex = index
		}
	}
	for index := range terminalState.Networks {
		if terminalState.Networks[index].ID == networkID {
			if terminalIndex != -1 {
				return errors.New("maximum-document terminal control state contains duplicate target networks")
			}
			terminalIndex = index
		}
	}
	if sourceIndex == -1 || terminalIndex == -1 {
		return errors.New("maximum-document control transition lost its target network")
	}
	sourceNetwork := sourceState.Networks[sourceIndex]
	terminalNetwork := terminalState.Networks[terminalIndex]
	expectedPolicy := FirewallPolicy{
		Mode: FirewallPolicyModeManaged, RendererVersion: FirewallRendererVersionV2,
		Inbound:  []FirewallRule{{Proto: "any", Port: "any", Group: "all"}},
		Outbound: []FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
	}
	if reflect.DeepEqual(sourceNetwork.FirewallPolicy, terminalNetwork.FirewallPolicy) ||
		!reflect.DeepEqual(terminalNetwork.FirewallPolicy, expectedPolicy) ||
		terminalNetwork.ConfigRevision != sourceNetwork.ConfigRevision+1 ||
		!terminalNetwork.ConfigUpdatedAt.After(sourceNetwork.ConfigUpdatedAt) {
		return errors.New("maximum-document control transition has an invalid firewall, revision, or update time")
	}

	appended := terminalState.Audit[len(sourceState.Audit)]
	expectedDetails := map[string]any{
		"old_sha256":       firewallPolicySHA256(sourceNetwork.FirewallPolicy),
		"new_sha256":       firewallPolicySHA256(terminalNetwork.FirewallPolicy),
		"inbound_rules":    float64(len(terminalNetwork.FirewallPolicy.Inbound)),
		"outbound_rules":   float64(len(terminalNetwork.FirewallPolicy.Outbound)),
		"config_revision":  float64(terminalNetwork.ConfigRevision),
		"actor_id":         LegacyAdminActor().ID,
		"actor_kind":       LegacyAdminActor().Kind,
		"actor_session_id": "",
	}
	if appended.Action != "network.firewall_policy_updated" || appended.Resource != "network" ||
		appended.ResourceID != networkID || !appended.At.Equal(terminalNetwork.ConfigUpdatedAt) ||
		!reflect.DeepEqual(appended.Details, expectedDetails) {
		return errors.New("maximum-document control transition appended an unexpected firewall audit")
	}

	// Normalize only the three permitted network fields and the one permitted
	// audit append. Exact equality after normalization proves every other array,
	// record, ordering decision, credential, certificate, and timestamp survived.
	terminalState.Networks[terminalIndex].FirewallPolicy = sourceNetwork.FirewallPolicy
	terminalState.Networks[terminalIndex].ConfigRevision = sourceNetwork.ConfigRevision
	terminalState.Networks[terminalIndex].ConfigUpdatedAt = sourceNetwork.ConfigUpdatedAt
	terminalState.Audit = sourceState.Audit
	if !reflect.DeepEqual(terminalState, sourceState) {
		return errors.New("maximum-document control transition changed state outside the allowed firewall mutation")
	}
	return nil
}

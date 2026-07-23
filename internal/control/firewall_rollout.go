package control

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	NetworkFirewallRolloutDocumentSchema = "mesh-network-firewall-rollout-v5"
	FirewallRolloutPhaseCanary           = "canary"
	FirewallRolloutPhasePaused           = "paused"
	ConfigApplyFailureCodeActivation     = "activation_failed"
	maxFirewallRolloutCanaries           = 16
)

// NetworkFirewallRollout is the crash-durable canary state for a firewall
// change. The active FirewallPolicy remains the rollback target until every
// selected canary proves that it applied the exact signed target config. The
// zero value is stable and renders FirewallPolicy to every node.
type NetworkFirewallRollout struct {
	Phase               string         `json:"phase,omitempty"`
	TargetPolicy        FirewallPolicy `json:"target_policy,omitempty"`
	CanaryNodeIDs       []string       `json:"canary_node_ids,omitempty"`
	StartedAt           time.Time      `json:"started_at,omitempty"`
	PausedAt            time.Time      `json:"paused_at,omitempty"`
	StageConfigRevision int64          `json:"stage_config_revision,omitempty"`
}

type UpdateNetworkFirewallRolloutInput struct {
	Action                 string         `json:"action"`
	ExpectedConfigRevision int64          `json:"expected_config_revision"`
	CanaryNodeIDs          []string       `json:"canary_node_ids,omitempty"`
	Inbound                []FirewallRule `json:"inbound,omitempty"`
	Outbound               []FirewallRule `json:"outbound,omitempty"`
}

type FirewallRolloutPolicyDocument struct {
	Mode             string                            `json:"mode"`
	RendererVersion  int                               `json:"renderer_version"`
	Inbound          []FirewallRule                    `json:"inbound"`
	Outbound         []FirewallRule                    `json:"outbound"`
	RenderedFirewall string                            `json:"rendered_firewall"`
	PolicySHA256     string                            `json:"policy_sha256"`
	EffectiveNodes   []EffectiveFirewallPolicyDocument `json:"effective_nodes"`
}

type FirewallRolloutNodeStatus struct {
	NodeID                       string `json:"node_id"`
	Name                         string `json:"name"`
	IP                           string `json:"ip"`
	Role                         string `json:"role"`
	Canary                       bool   `json:"canary"`
	AppliedConfigRevision        int64  `json:"applied_config_revision"`
	AppliedConfigSHA256          string `json:"applied_config_sha256"`
	DesiredConfigSHA256          string `json:"desired_config_sha256"`
	CertificateGeneration        int64  `json:"certificate_generation"`
	AppliedCertificateGeneration int64  `json:"applied_certificate_generation"`
	NebulaRunning                bool   `json:"nebula_running"`
	AgentStatus                  string `json:"agent_status"`
	Converged                    bool   `json:"converged"`
}

type FirewallRolloutTransition struct {
	Action     string    `json:"action"`
	At         time.Time `json:"at"`
	ReasonCode string    `json:"reason_code"`
	NodeID     string    `json:"node_id"`
}

type NetworkFirewallRolloutDocument struct {
	Schema                  string                         `json:"schema"`
	NetworkID               string                         `json:"network_id"`
	Phase                   string                         `json:"phase"`
	ConfigRevision          int64                          `json:"config_revision"`
	ConfigUpdatedAt         time.Time                      `json:"config_updated_at"`
	StageConfigRevision     int64                          `json:"stage_config_revision"`
	StartedAt               *time.Time                     `json:"started_at"`
	PausedAt                *time.Time                     `json:"paused_at"`
	CurrentPolicySHA256     string                         `json:"current_policy_sha256"`
	TargetPolicySHA256      string                         `json:"target_policy_sha256"`
	TargetPolicy            *FirewallRolloutPolicyDocument `json:"target_policy"`
	ActiveNodes             int                            `json:"active_nodes"`
	CanaryNodes             int                            `json:"canary_nodes"`
	ConvergedCanaries       int                            `json:"converged_canaries"`
	AvailableActions        []string                       `json:"available_actions"`
	Nodes                   []FirewallRolloutNodeStatus    `json:"nodes"`
	LastTransition          *FirewallRolloutTransition     `json:"last_transition"`
	AutomaticRollbackGuards []string                       `json:"automatic_rollback_guards"`
}

func stableFirewallRolloutPhase(phase string) string {
	if phase == "" {
		return "stable"
	}
	return phase
}

func zeroFirewallPolicy(policy FirewallPolicy) bool {
	return policy.Mode == "" && policy.RendererVersion == 0 && policy.Inbound == nil && policy.Outbound == nil
}

func zeroNetworkFirewallRollout(rollout NetworkFirewallRollout) bool {
	return rollout.Phase == "" && zeroFirewallPolicy(rollout.TargetPolicy) && rollout.CanaryNodeIDs == nil && rollout.StartedAt.IsZero() && rollout.PausedAt.IsZero() && rollout.StageConfigRevision == 0
}

func validateNetworkFirewallRollout(state State, network Network) error {
	rollout := network.FirewallRollout
	if rollout.Phase == "" {
		if !zeroNetworkFirewallRollout(rollout) {
			return errors.New("stable firewall rollout must have no transition metadata")
		}
		return nil
	}
	if rollout.Phase != FirewallRolloutPhaseCanary && (state.Version < ControlStateVersionFirewallPause || rollout.Phase != FirewallRolloutPhasePaused) {
		return errors.New("firewall rollout phase is invalid")
	}
	if state.Version < ControlStateVersionFirewallPause && !rollout.PausedAt.IsZero() {
		return errors.New("firewall rollout pause metadata exists before control state v8")
	}
	if (rollout.Phase == FirewallRolloutPhaseCanary && !rollout.PausedAt.IsZero()) || (rollout.Phase == FirewallRolloutPhasePaused && rollout.PausedAt.IsZero()) {
		return errors.New("firewall rollout pause metadata is inconsistent")
	}
	if network.CARotation.Phase != "" {
		return errors.New("firewall rollout cannot overlap a CA rotation")
	}
	if rollout.StartedAt.IsZero() || rollout.StageConfigRevision < 1 || rollout.StageConfigRevision > network.ConfigRevision {
		return errors.New("firewall rollout lifecycle metadata is invalid")
	}
	if err := validateStoredFirewallPolicy(rollout.TargetPolicy, network.CIDR); err != nil {
		return fmt.Errorf("target policy: %w", err)
	}
	if err := validateFirewallPolicyReferences(state, network, rollout.TargetPolicy); err != nil {
		return fmt.Errorf("target policy: %w", err)
	}
	if sameEffectiveFirewallPolicy(network.FirewallPolicy, rollout.TargetPolicy) {
		return errors.New("firewall rollout target equals the active policy")
	}
	if network.DNSSettings.Enabled && !firewallAllowsNetworkDNS(rollout.TargetPolicy, network.CIDR, network.DNSSettings.ListenPort) {
		return errors.New("firewall rollout target blocks managed network DNS")
	}
	if len(rollout.CanaryNodeIDs) < 1 || len(rollout.CanaryNodeIDs) > maxFirewallRolloutCanaries || !slices.IsSorted(rollout.CanaryNodeIDs) {
		return errors.New("firewall rollout canary selection is invalid")
	}
	for index, nodeID := range rollout.CanaryNodeIDs {
		if !validPersistedID(nodeID) || index > 0 && rollout.CanaryNodeIDs[index-1] == nodeID {
			return errors.New("firewall rollout canary selection is not canonical")
		}
		node, ok := findNode(state, nodeID)
		if !ok || node.NetworkID != network.ID || node.Status != "active" {
			return fmt.Errorf("firewall rollout canary %q is not an active node in the network", nodeID)
		}
	}
	return nil
}

func firewallPolicyForNode(network Network, node Node) FirewallPolicy {
	if network.FirewallRollout.Phase == FirewallRolloutPhaseCanary && slices.Contains(network.FirewallRollout.CanaryNodeIDs, node.ID) {
		return network.FirewallRollout.TargetPolicy
	}
	return network.FirewallPolicy
}

func firewallRolloutNodeConverged(state State, network Network, node Node) bool {
	if network.FirewallRollout.Phase != FirewallRolloutPhaseCanary || node.Status != "active" || !slices.Contains(network.FirewallRollout.CanaryNodeIDs, node.ID) {
		return false
	}
	return node.AppliedConfigRevision == network.ConfigRevision &&
		node.AppliedConfigSHA256 == ConfigDigest(renderConfig(state, network, node)) &&
		node.AppliedCertificateGeneration == node.CertificateGeneration &&
		node.ReportedCertificateFingerprint == node.CertificateFingerprint &&
		node.NebulaRunning
}

func firewallRolloutPolicyDocument(state State, network Network, policy FirewallPolicy) *FirewallRolloutPolicyDocument {
	policy = cloneFirewallPolicy(policy)
	rendered := ""
	if !firewallPolicyUsesNodeScopes(policy) {
		rendered = renderFirewallPolicy(policy)
	}
	return &FirewallRolloutPolicyDocument{
		Mode: policy.Mode, RendererVersion: policy.RendererVersion,
		Inbound: policy.Inbound, Outbound: policy.Outbound,
		RenderedFirewall: rendered, PolicySHA256: firewallPolicySHA256(policy),
		EffectiveNodes: effectiveFirewallPolicyDocuments(state, network, policy),
	}
}

func firewallRolloutLastTransition(state State, networkID string) *FirewallRolloutTransition {
	for index := len(state.Audit) - 1; index >= 0; index-- {
		event := state.Audit[index]
		if event.Resource != "network" || event.ResourceID != networkID {
			continue
		}
		action := ""
		switch event.Action {
		case "network.firewall_rollout_started":
			action = "started"
		case "network.firewall_rollout_canary_removed":
			action = "canary_removed"
		case "network.firewall_rollout_paused":
			action = "paused"
		case "network.firewall_rollout_resumed":
			action = "resumed"
		case "network.firewall_rollout_promoted":
			action = "promoted"
		case "network.firewall_rollout_rolled_back":
			action = "rolled_back"
		case "network.firewall_rollout_auto_rolled_back":
			action = "auto_rolled_back"
		default:
			continue
		}
		reasonCode, _ := event.Details["reason_code"].(string)
		nodeID, _ := event.Details["failed_node_id"].(string)
		if nodeID == "" {
			nodeID, _ = event.Details["node_id"].(string)
		}
		return &FirewallRolloutTransition{Action: action, At: event.At, ReasonCode: reasonCode, NodeID: nodeID}
	}
	return nil
}

func networkFirewallRolloutDocument(state State, network Network) NetworkFirewallRolloutDocument {
	doc := NetworkFirewallRolloutDocument{
		Schema: NetworkFirewallRolloutDocumentSchema, NetworkID: network.ID,
		Phase: stableFirewallRolloutPhase(network.FirewallRollout.Phase), ConfigRevision: network.ConfigRevision,
		ConfigUpdatedAt: network.ConfigUpdatedAt, StageConfigRevision: network.FirewallRollout.StageConfigRevision,
		StartedAt: optionalTime(network.FirewallRollout.StartedAt), PausedAt: optionalTime(network.FirewallRollout.PausedAt), CurrentPolicySHA256: firewallPolicySHA256(network.FirewallPolicy),
		AvailableActions: []string{}, Nodes: []FirewallRolloutNodeStatus{}, LastTransition: firewallRolloutLastTransition(state, network.ID),
		AutomaticRollbackGuards: []string{"activation_failed", "target_runtime_stopped"},
	}
	if network.FirewallRollout.Phase == FirewallRolloutPhaseCanary || network.FirewallRollout.Phase == FirewallRolloutPhasePaused {
		doc.TargetPolicySHA256 = firewallPolicySHA256(network.FirewallRollout.TargetPolicy)
		doc.TargetPolicy = firewallRolloutPolicyDocument(state, network, network.FirewallRollout.TargetPolicy)
	}
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID || node.Status != "active" {
			continue
		}
		canary := network.FirewallRollout.Phase != "" && slices.Contains(network.FirewallRollout.CanaryNodeIDs, node.ID)
		converged := canary && firewallRolloutNodeConverged(state, network, node)
		desiredDigest := ConfigDigest(renderConfig(state, network, node))
		doc.ActiveNodes++
		if canary {
			doc.CanaryNodes++
			if converged {
				doc.ConvergedCanaries++
			}
		}
		doc.Nodes = append(doc.Nodes, FirewallRolloutNodeStatus{
			NodeID: node.ID, Name: node.Name, IP: node.IP, Role: node.Role, Canary: canary,
			AppliedConfigRevision: node.AppliedConfigRevision, AppliedConfigSHA256: node.AppliedConfigSHA256,
			DesiredConfigSHA256: desiredDigest, CertificateGeneration: node.CertificateGeneration,
			AppliedCertificateGeneration: node.AppliedCertificateGeneration, NebulaRunning: node.NebulaRunning,
			AgentStatus: node.AgentStatus, Converged: converged,
		})
	}
	sort.Slice(doc.Nodes, func(left, right int) bool {
		if doc.Nodes[left].Name != doc.Nodes[right].Name {
			return doc.Nodes[left].Name < doc.Nodes[right].Name
		}
		return doc.Nodes[left].NodeID < doc.Nodes[right].NodeID
	})
	if network.FirewallRollout.Phase == FirewallRolloutPhaseCanary {
		if doc.CanaryNodes > 0 && doc.ConvergedCanaries == doc.CanaryNodes {
			doc.AvailableActions = append(doc.AvailableActions, "promote")
		}
		doc.AvailableActions = append(doc.AvailableActions, "pause", "rollback")
	} else if network.FirewallRollout.Phase == FirewallRolloutPhasePaused {
		doc.AvailableActions = append(doc.AvailableActions, "resume", "rollback")
	} else if network.CARotation.Phase == "" && !routeTransferActive(network.RouteTransfer) && !routeProfileEditActive(network.RouteProfileEdit) && doc.ActiveNodes > 0 {
		doc.AvailableActions = append(doc.AvailableActions, "start")
	}
	return doc
}

func autoRollbackFirewallRollout(state *State, network *Network, node Node, now time.Time, reasonCode string, evidence map[string]any) (NetworkFirewallRolloutDocument, error) {
	if network.FirewallRollout.Phase != FirewallRolloutPhaseCanary || !slices.Contains(network.FirewallRollout.CanaryNodeIDs, node.ID) {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: node is not a selected firewall canary", ErrConflict)
	}
	nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
	if err != nil {
		return NetworkFirewallRolloutDocument{}, err
	}
	details := map[string]any{
		"previous_config_revision": network.ConfigRevision,
		"config_revision":          nextRevision,
		"failed_node_id":           node.ID,
		"reason_code":              reasonCode,
		"canary_nodes":             len(network.FirewallRollout.CanaryNodeIDs),
		"retained_sha256":          firewallPolicySHA256(network.FirewallPolicy),
		"discarded_sha256":         firewallPolicySHA256(network.FirewallRollout.TargetPolicy),
	}
	for key, value := range evidence {
		details[key] = value
	}
	event, err := newAttributedAudit(now, "network.firewall_rollout_auto_rolled_back", "network", network.ID, details, Actor{ID: node.ID, Kind: ActorKindNodeAgent})
	if err != nil {
		return NetworkFirewallRolloutDocument{}, err
	}
	network.FirewallRollout = NetworkFirewallRollout{}
	network.ConfigRevision = nextRevision
	network.ConfigUpdatedAt = now
	state.Audit = append(state.Audit, event)
	return networkFirewallRolloutDocument(*state, *network), nil
}

func canonicalCanaryNodeIDs(input []string) ([]string, error) {
	if input == nil || len(input) < 1 || len(input) > maxFirewallRolloutCanaries {
		return nil, fmt.Errorf("%w: canary_node_ids must contain 1 through %d active nodes", ErrInvalid, maxFirewallRolloutCanaries)
	}
	result := append([]string{}, input...)
	for _, nodeID := range result {
		if !validPersistedID(nodeID) {
			return nil, fmt.Errorf("%w: canary_node_ids contains an invalid node ID", ErrInvalid)
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, fmt.Errorf("%w: canary_node_ids must not contain duplicates", ErrInvalid)
		}
	}
	return result, nil
}

func (s *Service) NetworkFirewallRollout(networkID string) (NetworkFirewallRolloutDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	var result NetworkFirewallRolloutDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = networkFirewallRolloutDocument(state, network)
		return nil
	})
	return result, err
}

func (s *Service) UpdateNetworkFirewallRollout(networkID string, input UpdateNetworkFirewallRolloutInput) (NetworkFirewallRolloutDocument, error) {
	return s.updateNetworkFirewallRollout(nil, networkID, input)
}

func (s *Service) UpdateNetworkFirewallRolloutAs(actor Actor, networkID string, input UpdateNetworkFirewallRolloutInput) (NetworkFirewallRolloutDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkFirewallRolloutDocument{}, err
	}
	return s.updateNetworkFirewallRollout(&actor, networkID, input)
}

func (s *Service) updateNetworkFirewallRollout(actor *Actor, networkID string, input UpdateNetworkFirewallRolloutInput) (NetworkFirewallRolloutDocument, error) {
	if !validPersistedID(networkID) || input.ExpectedConfigRevision < 1 {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: network ID and expected_config_revision are required", ErrInvalid)
	}
	if input.Action != "start" && input.Action != "promote" && input.Action != "pause" && input.Action != "resume" && input.Action != "rollback" {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: unsupported firewall rollout action", ErrInvalid)
	}
	if input.Action != "start" && (input.CanaryNodeIDs != nil || input.Inbound != nil || input.Outbound != nil) {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: only start accepts canary_node_ids, inbound, and outbound", ErrInvalid)
	}

	var canaryNodeIDs []string
	if input.Action == "start" {
		var err error
		canaryNodeIDs, err = canonicalCanaryNodeIDs(input.CanaryNodeIDs)
		if err != nil {
			return NetworkFirewallRolloutDocument{}, err
		}
		if input.Inbound == nil || input.Outbound == nil {
			return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: start requires inbound and outbound JSON arrays", ErrInvalid)
		}
	}

	now := s.now().UTC()
	if now.IsZero() {
		return NetworkFirewallRolloutDocument{}, errors.New("firewall rollout requires a valid timestamp")
	}
	var result NetworkFirewallRolloutDocument
	err := s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionFirewallPause && state.Version != ControlStateVersionRouteTransfer && state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: firewall rollout schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			if network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			details := map[string]any{"previous_config_revision": network.ConfigRevision, "config_revision": nextRevision}
			auditAction := ""
			switch input.Action {
			case "start":
				if network.CARotation.Phase != "" || network.FirewallRollout.Phase != "" || routeTransferActive(network.RouteTransfer) || routeProfileEditActive(network.RouteProfileEdit) {
					return fmt.Errorf("%w: firewall rollout can only start while CA and firewall state are stable", ErrConflict)
				}
				target, err := normalizeFirewallPolicy(FirewallPolicyInput{Inbound: input.Inbound, Outbound: input.Outbound}, network.CIDR)
				if err != nil {
					return err
				}
				if err := validateFirewallPolicyReferences(*state, *network, target); err != nil {
					return err
				}
				if firewallPolicyUsesNodeScopes(target) && state.Version < ControlStateVersionFirewallScopes {
					return fmt.Errorf("%w: firewall scope schema is not current", ErrConflict)
				}
				if sameEffectiveFirewallPolicy(network.FirewallPolicy, target) {
					return fmt.Errorf("%w: firewall rollout target must differ from the active policy", ErrConflict)
				}
				if network.DNSSettings.Enabled && !firewallAllowsNetworkDNS(target, network.CIDR, network.DNSSettings.ListenPort) {
					return fmt.Errorf("%w: firewall must keep UDP port %d available from all managed nodes while network DNS is enabled", ErrConflict, network.DNSSettings.ListenPort)
				}
				for _, nodeID := range canaryNodeIDs {
					node, ok := findNode(*state, nodeID)
					if !ok || node.NetworkID != network.ID || node.Status != "active" {
						return fmt.Errorf("%w: canary %q is not an active node in this network", ErrConflict, nodeID)
					}
				}
				network.FirewallRollout = NetworkFirewallRollout{
					Phase: FirewallRolloutPhaseCanary, TargetPolicy: cloneFirewallPolicy(target),
					CanaryNodeIDs: slices.Clone(canaryNodeIDs), StartedAt: now, StageConfigRevision: nextRevision,
				}
				auditAction = "network.firewall_rollout_started"
				details["old_sha256"] = firewallPolicySHA256(network.FirewallPolicy)
				details["target_sha256"] = firewallPolicySHA256(target)
				canaryAuditIDs := make([]any, len(canaryNodeIDs))
				for index, nodeID := range canaryNodeIDs {
					canaryAuditIDs[index] = nodeID
				}
				details["canary_node_ids"] = canaryAuditIDs
				details["canary_nodes"] = len(canaryNodeIDs)
				details["inbound_rules"] = len(target.Inbound)
				details["outbound_rules"] = len(target.Outbound)
			case "promote":
				if network.FirewallRollout.Phase != FirewallRolloutPhaseCanary {
					return fmt.Errorf("%w: no firewall canary is available to promote", ErrConflict)
				}
				for _, nodeID := range network.FirewallRollout.CanaryNodeIDs {
					node, ok := findNode(*state, nodeID)
					if !ok || !firewallRolloutNodeConverged(*state, *network, node) {
						return fmt.Errorf("%w: every canary must apply the exact signed target config before promotion", ErrConflict)
					}
				}
				target := cloneFirewallPolicy(network.FirewallRollout.TargetPolicy)
				details["old_sha256"] = firewallPolicySHA256(network.FirewallPolicy)
				details["new_sha256"] = firewallPolicySHA256(target)
				details["canary_nodes"] = len(network.FirewallRollout.CanaryNodeIDs)
				network.FirewallPolicy = target
				network.FirewallRollout = NetworkFirewallRollout{}
				auditAction = "network.firewall_rollout_promoted"
			case "pause":
				if network.FirewallRollout.Phase != FirewallRolloutPhaseCanary {
					return fmt.Errorf("%w: only an active firewall canary can be paused", ErrConflict)
				}
				network.FirewallRollout.Phase = FirewallRolloutPhasePaused
				network.FirewallRollout.PausedAt = now
				auditAction = "network.firewall_rollout_paused"
				details["target_sha256"] = firewallPolicySHA256(network.FirewallRollout.TargetPolicy)
				details["retained_sha256"] = firewallPolicySHA256(network.FirewallPolicy)
				details["canary_nodes"] = len(network.FirewallRollout.CanaryNodeIDs)
			case "resume":
				if network.FirewallRollout.Phase != FirewallRolloutPhasePaused {
					return fmt.Errorf("%w: only a paused firewall rollout can be resumed", ErrConflict)
				}
				network.FirewallRollout.Phase = FirewallRolloutPhaseCanary
				network.FirewallRollout.PausedAt = time.Time{}
				network.FirewallRollout.StageConfigRevision = nextRevision
				auditAction = "network.firewall_rollout_resumed"
				details["target_sha256"] = firewallPolicySHA256(network.FirewallRollout.TargetPolicy)
				details["canary_nodes"] = len(network.FirewallRollout.CanaryNodeIDs)
			case "rollback":
				if network.FirewallRollout.Phase != FirewallRolloutPhaseCanary && network.FirewallRollout.Phase != FirewallRolloutPhasePaused {
					return fmt.Errorf("%w: no firewall canary is available to roll back", ErrConflict)
				}
				details["retained_sha256"] = firewallPolicySHA256(network.FirewallPolicy)
				details["discarded_sha256"] = firewallPolicySHA256(network.FirewallRollout.TargetPolicy)
				details["canary_nodes"] = len(network.FirewallRollout.CanaryNodeIDs)
				network.FirewallRollout = NetworkFirewallRollout{}
				auditAction = "network.firewall_rollout_rolled_back"
			}
			event, err := newOptionalAttributedAudit(now, auditAction, "network", network.ID, details, actor)
			if err != nil {
				return err
			}
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			state.Audit = append(state.Audit, event)
			result = networkFirewallRolloutDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

// ReportConfigApplyFailure accepts only explicit, current, node-correlated
// activation failure evidence. Missing heartbeats, stale reports, generic
// degradation, and failures from non-canary nodes cannot trigger rollback.
func (s *Service) ReportConfigApplyFailure(token string, input ConfigApplyFailureInput) (NetworkFirewallRolloutDocument, error) {
	token = strings.TrimSpace(token)
	input.AttemptedConfigSHA256 = strings.TrimSpace(input.AttemptedConfigSHA256)
	input.FailureCode = strings.TrimSpace(input.FailureCode)
	if !ValidBearerToken(token) {
		return NetworkFirewallRolloutDocument{}, ErrUnauthorized
	}
	if input.AttemptedConfigRevision < 1 || !fingerprintPattern.MatchString(input.AttemptedConfigSHA256) || input.FailureCode != ConfigApplyFailureCodeActivation {
		return NetworkFirewallRolloutDocument{}, fmt.Errorf("%w: exact attempted revision, digest, and supported failure_code are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NetworkFirewallRolloutDocument{}, errors.New("config activation failure requires a valid timestamp")
	}
	tokenHash := HashToken(token)
	if _, err := s.preflightAgentCredential(tokenHash, now); err != nil {
		return NetworkFirewallRolloutDocument{}, err
	}
	var result NetworkFirewallRolloutDocument
	err := s.updateState(func(state *State) error {
		for nodeIndex := range state.Nodes {
			node := &state.Nodes[nodeIndex]
			matched, _ := agentCredentialMatch(*node, tokenHash, now)
			if node.Status != "active" || !matched {
				continue
			}
			for networkIndex := range state.Networks {
				network := &state.Networks[networkIndex]
				if network.ID != node.NetworkID {
					continue
				}
				if input.AttemptedConfigRevision != network.ConfigRevision {
					return fmt.Errorf("%w: activation failure does not match the current rollout revision", ErrConflict)
				}
				desiredSHA256 := ConfigDigest(renderConfig(*state, *network, *node))
				if input.AttemptedConfigSHA256 != desiredSHA256 {
					return fmt.Errorf("%w: activation failure does not match the current signed canary artifact", ErrConflict)
				}
				var err error
				result, err = autoRollbackFirewallRollout(state, network, *node, now, "canary_config_activation_failed", map[string]any{
					"failed_config_revision": input.AttemptedConfigRevision,
					"failed_config_sha256":   input.AttemptedConfigSHA256,
					"failure_code":           input.FailureCode,
				})
				if err != nil {
					return err
				}
				return nil
			}
			return errors.New("authoritative node network is missing")
		}
		return ErrUnauthorized
	})
	return result, err
}

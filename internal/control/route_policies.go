package control

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	NetworkRoutePoliciesDocumentSchema = "mesh-network-route-policies-v1"
	maxRoutePolicyGateways             = 8
	maxRoutePolicyWeight               = 1000
	maxRoutePolicyMTU                  = 65535
)

type UpdateNetworkRoutePolicyInput struct {
	Prefix                 string                      `json:"prefix"`
	Gateways               []NetworkRoutePolicyGateway `json:"gateways"`
	MTU                    int                         `json:"mtu"`
	Metric                 int                         `json:"metric"`
	ExpectedConfigRevision int64                       `json:"expected_config_revision"`
	RequestID              string                      `json:"request_id"`
}

type NetworkRoutePolicyGatewayDocument struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Weight int    `json:"weight"`
}

type NetworkRoutePolicyDocument struct {
	Prefix           string                              `json:"prefix"`
	Gateways         []NetworkRoutePolicyGatewayDocument `json:"gateways"`
	MTU              int                                 `json:"mtu"`
	Metric           int                                 `json:"metric"`
	Install          bool                                `json:"install"`
	LastRequestID    string                              `json:"last_request_id"`
	PolicyRevision   int64                               `json:"policy_revision"`
	UpdatedAt        *time.Time                          `json:"updated_at"`
	AvailableActions []string                            `json:"available_actions"`
}

type NetworkRoutePoliciesDocument struct {
	Schema           string                       `json:"schema"`
	NetworkID        string                       `json:"network_id"`
	ConfigRevision   int64                        `json:"config_revision"`
	Policies         []NetworkRoutePolicyDocument `json:"policies"`
	AvailableActions []string                     `json:"available_actions"`
}

func cloneNetworkRoutePolicies(values []NetworkRoutePolicy) []NetworkRoutePolicy {
	if values == nil {
		return nil
	}
	result := slices.Clone(values)
	for index := range result {
		result[index].Gateways = slices.Clone(values[index].Gateways)
	}
	return result
}

func normalizeRoutePolicyGatewayInput(values []NetworkRoutePolicyGateway) ([]NetworkRoutePolicyGateway, error) {
	if len(values) < 1 || len(values) > maxRoutePolicyGateways {
		return nil, fmt.Errorf("a route policy requires 1-%d gateways", maxRoutePolicyGateways)
	}
	result := slices.Clone(values)
	seen := make(map[string]struct{}, len(result))
	for index := range result {
		result[index].NodeID = strings.TrimSpace(result[index].NodeID)
		if !validPersistedID(result[index].NodeID) {
			return nil, fmt.Errorf("gateway %d has an invalid node_id", index+1)
		}
		if result[index].Weight < 1 || result[index].Weight > maxRoutePolicyWeight {
			return nil, fmt.Errorf("gateway %d weight must be in range 1-%d", index+1, maxRoutePolicyWeight)
		}
		if _, exists := seen[result[index].NodeID]; exists {
			return nil, fmt.Errorf("gateway node %s is duplicated", result[index].NodeID)
		}
		seen[result[index].NodeID] = struct{}{}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NodeID < result[j].NodeID })
	return result, nil
}

func validateRoutePolicyControls(mtu, metric int) error {
	if mtu != 0 && (mtu < 500 || mtu > maxRoutePolicyMTU) {
		return fmt.Errorf("MTU must be 0 or in range 500-%d", maxRoutePolicyMTU)
	}
	if metric < 0 || int64(metric) > int64(math.MaxInt32) {
		return fmt.Errorf("metric must be in range 0-%d", math.MaxInt32)
	}
	return nil
}

func activeRouteOwners(state State, networkID, prefix string) []Node {
	owners := make([]Node, 0, maxRoutePolicyGateways)
	for _, node := range state.Nodes {
		if node.NetworkID == networkID && node.Status == "active" && node.EnrolledAt != nil && slices.Contains(node.RoutedSubnets, prefix) {
			owners = append(owners, node)
		}
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].ID < owners[j].ID })
	return owners
}

func storedRoutePolicy(network Network, prefix string) (NetworkRoutePolicy, bool) {
	index, found := slices.BinarySearchFunc(network.RoutePolicies, prefix, func(policy NetworkRoutePolicy, target string) int {
		return strings.Compare(policy.Prefix, target)
	})
	if !found {
		return NetworkRoutePolicy{}, false
	}
	return network.RoutePolicies[index], true
}

func effectiveRoutePolicy(state State, network Network, prefix string) NetworkRoutePolicy {
	owners := activeRouteOwners(state, network.ID, prefix)
	policy, stored := storedRoutePolicy(network, prefix)
	weights := make(map[string]int, len(policy.Gateways))
	if stored {
		for _, gateway := range policy.Gateways {
			weights[gateway.NodeID] = gateway.Weight
		}
	} else {
		policy = NetworkRoutePolicy{Prefix: prefix}
	}
	policy.Gateways = make([]NetworkRoutePolicyGateway, len(owners))
	for index, owner := range owners {
		weight := weights[owner.ID]
		if weight == 0 {
			weight = 1
		}
		policy.Gateways[index] = NetworkRoutePolicyGateway{NodeID: owner.ID, Weight: weight}
	}
	return policy
}

func routePolicyOwnersMatch(gateways []NetworkRoutePolicyGateway, owners []Node) bool {
	if len(gateways) != len(owners) {
		return false
	}
	for index := range gateways {
		if gateways[index].NodeID != owners[index].ID {
			return false
		}
	}
	return true
}

func routePolicySettingsEqual(policy NetworkRoutePolicy, gateways []NetworkRoutePolicyGateway, mtu, metric int) bool {
	return policy.MTU == mtu && policy.Metric == metric && slices.Equal(policy.Gateways, gateways)
}

func networkRoutePolicyUpdateAvailable(network Network) bool {
	return network.CARotation.Phase == "" && network.FirewallRollout.Phase == "" &&
		routeTransferTerminal(network.RouteTransfer) && routeProfileEditTerminal(network.RouteProfileEdit)
}

func liveRoutedPrefixes(state State, networkID string) []string {
	set := map[string]struct{}{}
	for _, node := range state.Nodes {
		if node.NetworkID != networkID || node.Status != "active" || node.EnrolledAt == nil {
			continue
		}
		for _, prefix := range node.RoutedSubnets {
			set[prefix] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := netip.ParsePrefix(result[i])
		right, _ := netip.ParsePrefix(result[j])
		return compareIPv4Prefixes(left, right) < 0
	})
	return result
}

func networkRoutePoliciesDocument(state State, network Network) NetworkRoutePoliciesDocument {
	document := NetworkRoutePoliciesDocument{
		Schema: NetworkRoutePoliciesDocumentSchema, NetworkID: network.ID,
		ConfigRevision: network.ConfigRevision, Policies: []NetworkRoutePolicyDocument{}, AvailableActions: []string{},
	}
	if networkRoutePolicyUpdateAvailable(network) {
		document.AvailableActions = append(document.AvailableActions, "update")
	}
	for _, prefix := range liveRoutedPrefixes(state, network.ID) {
		policy := effectiveRoutePolicy(state, network, prefix)
		item := NetworkRoutePolicyDocument{
			Prefix: prefix, MTU: policy.MTU, Metric: policy.Metric, Install: true,
			Gateways: []NetworkRoutePolicyGatewayDocument{}, AvailableActions: []string{},
		}
		if networkRoutePolicyUpdateAvailable(network) {
			item.AvailableActions = append(item.AvailableActions, "update")
		}
		if policy.RequestID != "" {
			item.LastRequestID, item.PolicyRevision = policy.RequestID, policy.ConfigRevision
			updatedAt := policy.UpdatedAt
			item.UpdatedAt = &updatedAt
		}
		for _, gateway := range policy.Gateways {
			node, ok := findNode(state, gateway.NodeID)
			if !ok {
				continue
			}
			item.Gateways = append(item.Gateways, NetworkRoutePolicyGatewayDocument{
				NodeID: node.ID, Name: node.Name, IP: node.IP, Weight: gateway.Weight,
			})
		}
		document.Policies = append(document.Policies, item)
	}
	return document
}

func (s *Service) NetworkRoutePolicies(networkID string) (NetworkRoutePoliciesDocument, error) {
	networkID = strings.TrimSpace(networkID)
	if !validPersistedID(networkID) {
		return NetworkRoutePoliciesDocument{}, fmt.Errorf("%w: network ID is invalid", ErrInvalid)
	}
	var result NetworkRoutePoliciesDocument
	err := s.viewState(func(state State) error {
		if state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-policy schema is not current", ErrConflict)
		}
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = networkRoutePoliciesDocument(state, network)
		return nil
	})
	return result, err
}

func (s *Service) UpdateNetworkRoutePolicy(networkID string, input UpdateNetworkRoutePolicyInput) (NetworkRoutePoliciesDocument, error) {
	return s.updateNetworkRoutePolicy(nil, networkID, input)
}

func (s *Service) UpdateNetworkRoutePolicyAs(actor Actor, networkID string, input UpdateNetworkRoutePolicyInput) (NetworkRoutePoliciesDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkRoutePoliciesDocument{}, err
	}
	return s.updateNetworkRoutePolicy(&actor, networkID, input)
}

func (s *Service) updateNetworkRoutePolicy(actor *Actor, networkID string, input UpdateNetworkRoutePolicyInput) (NetworkRoutePoliciesDocument, error) {
	networkID, input.Prefix, input.RequestID = strings.TrimSpace(networkID), strings.TrimSpace(input.Prefix), strings.TrimSpace(input.RequestID)
	prefix, prefixErr := parseCanonicalRoutedSubnet(input.Prefix)
	gateways, gatewayErr := normalizeRoutePolicyGatewayInput(input.Gateways)
	controlsErr := validateRoutePolicyControls(input.MTU, input.Metric)
	if !validPersistedID(networkID) || prefixErr != nil || gatewayErr != nil || controlsErr != nil || input.ExpectedConfigRevision < 1 || !validRouteTransferRequestID(input.RequestID) {
		return NetworkRoutePoliciesDocument{}, fmt.Errorf("%w: canonical prefix, complete gateways, bounded controls, expected_config_revision, and a 16-128 character request_id are required", ErrInvalid)
	}
	input.Prefix = prefix.String()
	now := s.now().UTC()
	if now.IsZero() {
		return NetworkRoutePoliciesDocument{}, errors.New("route-policy update requires a valid timestamp")
	}
	var result NetworkRoutePoliciesDocument
	err := s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-policy schema is not current", ErrConflict)
		}
		for networkIndex := range state.Networks {
			network := &state.Networks[networkIndex]
			if network.ID != networkID {
				continue
			}
			owners := activeRouteOwners(*state, network.ID, input.Prefix)
			if len(owners) == 0 {
				return fmt.Errorf("%w: routed prefix is not active in this network", ErrNotFound)
			}
			if !routePolicyOwnersMatch(gateways, owners) {
				return fmt.Errorf("%w: gateways must exactly match the current active certificate owners", ErrConflict)
			}
			if existing, found := storedRoutePolicy(*network, input.Prefix); found && existing.RequestID == input.RequestID {
				if !routePolicySettingsEqual(existing, gateways, input.MTU, input.Metric) {
					return fmt.Errorf("%w: request_id is already bound to different route-policy input", ErrConflict)
				}
				result = networkRoutePoliciesDocument(*state, *network)
				return nil
			}
			if !networkRoutePolicyUpdateAvailable(*network) || network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: network is not at the requested stable revision", ErrConflict)
			}
			nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
			if revisionErr != nil {
				return revisionErr
			}
			policy := NetworkRoutePolicy{
				Prefix: input.Prefix, Gateways: gateways, MTU: input.MTU, Metric: input.Metric,
				RequestID: input.RequestID, ConfigRevision: nextRevision, UpdatedAt: now,
			}
			index, found := slices.BinarySearchFunc(network.RoutePolicies, input.Prefix, func(candidate NetworkRoutePolicy, target string) int {
				return strings.Compare(candidate.Prefix, target)
			})
			if found {
				network.RoutePolicies[index] = policy
			} else {
				network.RoutePolicies = append(network.RoutePolicies, NetworkRoutePolicy{})
				copy(network.RoutePolicies[index+1:], network.RoutePolicies[index:])
				network.RoutePolicies[index] = policy
			}
			network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
			event, auditErr := newOptionalAttributedAudit(now, "network.route_policy_updated", "network", network.ID, map[string]any{
				"request_id": input.RequestID, "prefix": input.Prefix, "gateway_count": len(gateways),
				"mtu": input.MTU, "metric": input.Metric,
				"previous_config_revision": input.ExpectedConfigRevision, "config_revision": nextRevision,
			}, actor)
			if auditErr != nil {
				return auditErr
			}
			state.Audit = append(state.Audit, event)
			result = networkRoutePoliciesDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

// reconcileNetworkRoutePolicies preserves controls and surviving weights after
// an atomic ownership change while making the stored gateway set exactly match
// current active certificate owners. The last direct policy receipt remains
// durable; a replay whose complete gateway input is now stale fails closed.
func reconcileNetworkRoutePolicies(state *State, network *Network) {
	if state == nil || network == nil || len(network.RoutePolicies) == 0 {
		return
	}
	result := make([]NetworkRoutePolicy, 0, len(network.RoutePolicies))
	for _, policy := range network.RoutePolicies {
		owners := activeRouteOwners(*state, network.ID, policy.Prefix)
		if len(owners) == 0 {
			continue
		}
		weights := make(map[string]int, len(policy.Gateways))
		for _, gateway := range policy.Gateways {
			weights[gateway.NodeID] = gateway.Weight
		}
		policy.Gateways = make([]NetworkRoutePolicyGateway, len(owners))
		for index, owner := range owners {
			weight := weights[owner.ID]
			if weight == 0 {
				weight = 1
			}
			policy.Gateways[index] = NetworkRoutePolicyGateway{NodeID: owner.ID, Weight: weight}
		}
		result = append(result, policy)
	}
	network.RoutePolicies = result
}

func validateNetworkRoutePolicies(state State, network Network) error {
	previous := ""
	for _, policy := range network.RoutePolicies {
		prefix, err := parseCanonicalRoutedSubnet(policy.Prefix)
		if err != nil || prefix.String() != policy.Prefix || previous != "" && previous >= policy.Prefix {
			return errors.New("route policies are not canonical and deterministically ordered")
		}
		previous = policy.Prefix
		if err := validateRoutePolicyControls(policy.MTU, policy.Metric); err != nil {
			return fmt.Errorf("route policy %s controls: %w", policy.Prefix, err)
		}
		gateways, err := normalizeRoutePolicyGatewayInput(policy.Gateways)
		if err != nil || !slices.Equal(gateways, policy.Gateways) {
			return fmt.Errorf("route policy %s gateways are invalid or non-canonical", policy.Prefix)
		}
		owners := activeRouteOwners(state, network.ID, policy.Prefix)
		if !routePolicyOwnersMatch(policy.Gateways, owners) {
			return fmt.Errorf("route policy %s gateways do not match active certificate owners", policy.Prefix)
		}
		if !validRouteTransferRequestID(policy.RequestID) || policy.ConfigRevision < 1 || policy.ConfigRevision > network.ConfigRevision || policy.UpdatedAt.IsZero() {
			return fmt.Errorf("route policy %s receipt metadata is invalid", policy.Prefix)
		}
	}
	return nil
}

package control

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	maxNetworkSecurityGroups       = 256
	maxSecurityGroupDescriptionLen = 256
)

// NetworkSecurityGroupSummary is the operator-facing projection of one
// network-level group definition and its current certificate membership.
type NetworkSecurityGroupSummary struct {
	Name                 string     `json:"name"`
	Description          string     `json:"description,omitempty"`
	Builtin              bool       `json:"builtin"`
	MemberNodeIDs        []string   `json:"member_node_ids"`
	ActiveMembers        int        `json:"active_members"`
	PendingMembers       int        `json:"pending_members"`
	PeerRuleReferences   int        `json:"peer_rule_references"`
	TargetRuleReferences int        `json:"target_rule_references"`
	CreatedAt            *time.Time `json:"created_at,omitempty"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
}

type NetworkSecurityGroupsDocument struct {
	NetworkID string                        `json:"network_id"`
	Groups    []NetworkSecurityGroupSummary `json:"groups"`
}

type CreateNetworkSecurityGroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type UpdateNetworkSecurityGroupInput struct {
	Description string `json:"description,omitempty"`
}

type DeleteNetworkSecurityGroupInput struct {
	ConfirmationName string `json:"confirmation_name"`
}

func normalizeSecurityGroupDescription(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !validBoundedPlainText(value, maxSecurityGroupDescriptionLen, true) {
		return "", fmt.Errorf("%w: description must be at most %d bytes of plain text", ErrInvalid, maxSecurityGroupDescriptionLen)
	}
	return value, nil
}

func validManagedSecurityGroupName(name string) bool {
	return groupPattern.MatchString(name) && name != "all" && name != "any"
}

func cloneNetworkSecurityGroups(groups []NetworkSecurityGroup) []NetworkSecurityGroup {
	if groups == nil {
		return nil
	}
	return append([]NetworkSecurityGroup(nil), groups...)
}

func validateNetworkSecurityGroups(groups []NetworkSecurityGroup) error {
	if len(groups) > maxNetworkSecurityGroups {
		return fmt.Errorf("security-group catalog exceeds %d entries", maxNetworkSecurityGroups)
	}
	previous := ""
	for index, group := range groups {
		if !validManagedSecurityGroupName(group.Name) {
			return fmt.Errorf("security group %d has an invalid name", index)
		}
		if index > 0 && previous >= group.Name {
			return fmt.Errorf("security groups are not uniquely sorted")
		}
		description, err := normalizeSecurityGroupDescription(group.Description)
		if err != nil || description != group.Description {
			return fmt.Errorf("security group %q has an invalid description", group.Name)
		}
		if group.CreatedAt.IsZero() || group.UpdatedAt.IsZero() || group.UpdatedAt.Before(group.CreatedAt) {
			return fmt.Errorf("security group %q has invalid lifecycle metadata", group.Name)
		}
		previous = group.Name
	}
	return nil
}

func managedSecurityGroupNamesFromPolicy(policy FirewallPolicy) []string {
	names := []string{}
	for _, rules := range [][]FirewallRule{policy.Inbound, policy.Outbound} {
		for _, rule := range rules {
			for _, name := range []string{rule.Group, rule.TargetGroup} {
				if validManagedSecurityGroupName(name) && !slices.Contains(names, name) {
					names = append(names, name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

func derivedManagedSecurityGroupNames(state State, network Network) []string {
	names := []string{}
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID {
			continue
		}
		for _, name := range node.Groups {
			if validManagedSecurityGroupName(name) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	for _, policy := range []FirewallPolicy{network.FirewallPolicy, network.FirewallRollout.TargetPolicy} {
		for _, name := range managedSecurityGroupNamesFromPolicy(policy) {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func ensureSecurityGroupDefinitions(network *Network, names []string, now time.Time) error {
	for _, name := range names {
		if !validManagedSecurityGroupName(name) || securityGroupExists(*network, name) {
			continue
		}
		if len(network.SecurityGroups) >= maxNetworkSecurityGroups {
			return fmt.Errorf("%w: network may have at most %d security groups", ErrConflict, maxNetworkSecurityGroups)
		}
		network.SecurityGroups = append(network.SecurityGroups, NetworkSecurityGroup{Name: name, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(network.SecurityGroups, func(left, right int) bool {
		return network.SecurityGroups[left].Name < network.SecurityGroups[right].Name
	})
	return nil
}

func securityGroupIndex(network Network, name string) int {
	return sort.Search(len(network.SecurityGroups), func(index int) bool {
		return network.SecurityGroups[index].Name >= name
	})
}

func securityGroupExists(network Network, name string) bool {
	if name == "all" {
		return true
	}
	index := securityGroupIndex(network, name)
	return index < len(network.SecurityGroups) && network.SecurityGroups[index].Name == name
}

func firewallGroupReferenceCounts(policy FirewallPolicy, name string) (peer, target int) {
	for _, rules := range [][]FirewallRule{policy.Inbound, policy.Outbound} {
		for _, rule := range rules {
			if rule.Group == name {
				peer++
			}
			if rule.TargetGroup == name {
				target++
			}
		}
	}
	return peer, target
}

func securityGroupSummary(state State, network Network, definition *NetworkSecurityGroup, name string) NetworkSecurityGroupSummary {
	summary := NetworkSecurityGroupSummary{Name: name, Builtin: name == "all", MemberNodeIDs: []string{}}
	if definition != nil {
		summary.Description = definition.Description
		createdAt, updatedAt := definition.CreatedAt, definition.UpdatedAt
		summary.CreatedAt, summary.UpdatedAt = &createdAt, &updatedAt
	}
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID || node.Status == "revoked" || !slices.Contains(node.Groups, name) {
			continue
		}
		summary.MemberNodeIDs = append(summary.MemberNodeIDs, node.ID)
		if node.Status == "active" {
			summary.ActiveMembers++
		} else {
			summary.PendingMembers++
		}
	}
	sort.Strings(summary.MemberNodeIDs)
	summary.PeerRuleReferences, summary.TargetRuleReferences = firewallGroupReferenceCounts(network.FirewallPolicy, name)
	if network.FirewallRollout.Phase != "" {
		peer, target := firewallGroupReferenceCounts(network.FirewallRollout.TargetPolicy, name)
		summary.PeerRuleReferences += peer
		summary.TargetRuleReferences += target
	}
	return summary
}

func networkSecurityGroupsDocument(state State, network Network) NetworkSecurityGroupsDocument {
	groups := make([]NetworkSecurityGroupSummary, 0, len(network.SecurityGroups)+1)
	groups = append(groups, securityGroupSummary(state, network, nil, "all"))
	for index := range network.SecurityGroups {
		definition := &network.SecurityGroups[index]
		groups = append(groups, securityGroupSummary(state, network, definition, definition.Name))
	}
	return NetworkSecurityGroupsDocument{NetworkID: network.ID, Groups: groups}
}

func (s *Service) NetworkSecurityGroups(networkID string) (NetworkSecurityGroupsDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: network ID is invalid", ErrInvalid)
	}
	var document NetworkSecurityGroupsDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		if state.Version != ControlStateVersionSecurityGroups {
			return fmt.Errorf("%w: security-group catalog requires control state v%d", ErrConflict, ControlStateVersionSecurityGroups)
		}
		document = networkSecurityGroupsDocument(state, network)
		return nil
	})
	return document, err
}

func (s *Service) CreateNetworkSecurityGroupAs(actor Actor, networkID string, input CreateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkSecurityGroupsDocument{}, err
	}
	return s.createNetworkSecurityGroup(&actor, networkID, input)
}

func (s *Service) CreateNetworkSecurityGroup(networkID string, input CreateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	return s.createNetworkSecurityGroup(nil, networkID, input)
}

func (s *Service) createNetworkSecurityGroup(actor *Actor, networkID string, input CreateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	name := strings.TrimSpace(input.Name)
	description, err := normalizeSecurityGroupDescription(input.Description)
	if !validPersistedID(networkID) || !validManagedSecurityGroupName(name) || name != input.Name || err != nil {
		if err != nil {
			return NetworkSecurityGroupsDocument{}, err
		}
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: network ID and a canonical group name other than all or any are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: security-group creation requires a valid timestamp", ErrInvalid)
	}
	var document NetworkSecurityGroupsDocument
	err = s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionSecurityGroups {
			return fmt.Errorf("%w: security-group catalog requires control state v%d", ErrConflict, ControlStateVersionSecurityGroups)
		}
		network, ok := findNetworkPointer(state, networkID)
		if !ok {
			return ErrNotFound
		}
		if securityGroupExists(*network, name) {
			return fmt.Errorf("%w: security group %q already exists", ErrConflict, name)
		}
		if len(network.SecurityGroups) >= maxNetworkSecurityGroups {
			return fmt.Errorf("%w: network may have at most %d security groups", ErrConflict, maxNetworkSecurityGroups)
		}
		network.SecurityGroups = append(network.SecurityGroups, NetworkSecurityGroup{Name: name, Description: description, CreatedAt: now, UpdatedAt: now})
		sort.Slice(network.SecurityGroups, func(left, right int) bool {
			return network.SecurityGroups[left].Name < network.SecurityGroups[right].Name
		})
		event, eventErr := newOptionalAttributedAudit(now, "network.security_group_created", "network", network.ID, map[string]any{"group": name, "description": description}, actor)
		if eventErr != nil {
			return eventErr
		}
		state.Audit = append(state.Audit, event)
		document = networkSecurityGroupsDocument(*state, *network)
		return nil
	})
	return document, err
}

func (s *Service) UpdateNetworkSecurityGroupAs(actor Actor, networkID, groupName string, input UpdateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkSecurityGroupsDocument{}, err
	}
	return s.updateNetworkSecurityGroup(&actor, networkID, groupName, input)
}

func (s *Service) UpdateNetworkSecurityGroup(networkID, groupName string, input UpdateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	return s.updateNetworkSecurityGroup(nil, networkID, groupName, input)
}

func (s *Service) updateNetworkSecurityGroup(actor *Actor, networkID, groupName string, input UpdateNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	description, err := normalizeSecurityGroupDescription(input.Description)
	if !validPersistedID(networkID) || !validManagedSecurityGroupName(groupName) || err != nil {
		if err != nil {
			return NetworkSecurityGroupsDocument{}, err
		}
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: network ID and managed group name are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: security-group update requires a valid timestamp", ErrInvalid)
	}
	var document NetworkSecurityGroupsDocument
	err = s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionSecurityGroups {
			return fmt.Errorf("%w: security-group catalog requires control state v%d", ErrConflict, ControlStateVersionSecurityGroups)
		}
		network, ok := findNetworkPointer(state, networkID)
		if !ok {
			return ErrNotFound
		}
		index := securityGroupIndex(*network, groupName)
		if index >= len(network.SecurityGroups) || network.SecurityGroups[index].Name != groupName {
			return ErrNotFound
		}
		if network.SecurityGroups[index].Description == description {
			document = networkSecurityGroupsDocument(*state, *network)
			return nil
		}
		network.SecurityGroups[index].Description = description
		network.SecurityGroups[index].UpdatedAt = now
		event, eventErr := newOptionalAttributedAudit(now, "network.security_group_updated", "network", network.ID, map[string]any{"group": groupName, "description": description}, actor)
		if eventErr != nil {
			return eventErr
		}
		state.Audit = append(state.Audit, event)
		document = networkSecurityGroupsDocument(*state, *network)
		return nil
	})
	return document, err
}

func (s *Service) DeleteNetworkSecurityGroupAs(actor Actor, networkID, groupName string, input DeleteNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkSecurityGroupsDocument{}, err
	}
	return s.deleteNetworkSecurityGroup(&actor, networkID, groupName, input)
}

func (s *Service) DeleteNetworkSecurityGroup(networkID, groupName string, input DeleteNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	return s.deleteNetworkSecurityGroup(nil, networkID, groupName, input)
}

func (s *Service) deleteNetworkSecurityGroup(actor *Actor, networkID, groupName string, input DeleteNetworkSecurityGroupInput) (NetworkSecurityGroupsDocument, error) {
	if !validPersistedID(networkID) || !validManagedSecurityGroupName(groupName) || input.ConfirmationName != groupName {
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: network ID, managed group name, and exact confirmation_name are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NetworkSecurityGroupsDocument{}, fmt.Errorf("%w: security-group deletion requires a valid timestamp", ErrInvalid)
	}
	var document NetworkSecurityGroupsDocument
	err := s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionSecurityGroups {
			return fmt.Errorf("%w: security-group catalog requires control state v%d", ErrConflict, ControlStateVersionSecurityGroups)
		}
		network, ok := findNetworkPointer(state, networkID)
		if !ok {
			return ErrNotFound
		}
		index := securityGroupIndex(*network, groupName)
		if index >= len(network.SecurityGroups) || network.SecurityGroups[index].Name != groupName {
			return ErrNotFound
		}
		summary := securityGroupSummary(*state, *network, &network.SecurityGroups[index], groupName)
		if len(summary.MemberNodeIDs) > 0 || summary.PeerRuleReferences > 0 || summary.TargetRuleReferences > 0 {
			return fmt.Errorf("%w: security group still has node membership or firewall references", ErrConflict)
		}
		network.SecurityGroups = slices.Delete(network.SecurityGroups, index, index+1)
		event, eventErr := newOptionalAttributedAudit(now, "network.security_group_deleted", "network", network.ID, map[string]any{"group": groupName}, actor)
		if eventErr != nil {
			return eventErr
		}
		state.Audit = append(state.Audit, event)
		document = networkSecurityGroupsDocument(*state, *network)
		return nil
	})
	return document, err
}

func findNetworkPointer(state *State, networkID string) (*Network, bool) {
	for index := range state.Networks {
		if state.Networks[index].ID == networkID {
			return &state.Networks[index], true
		}
	}
	return nil, false
}

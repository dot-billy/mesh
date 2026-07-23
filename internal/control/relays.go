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
	MaxNetworkRelayNodes        = 8
	NetworkRelaysDocumentSchema = "mesh-network-relays-v1"
)

// NetworkRelaySettings selects the managed nodes that accept Slack Nebula
// relay requests for a network. Any managed node may be selected because
// Nebula discovers relay endpoints through its lighthouses; operators remain
// responsible for placing relays where both sides can establish a direct
// tunnel to them.
type NetworkRelaySettings struct {
	Enabled      bool     `json:"enabled"`
	RelayNodeIDs []string `json:"relay_node_ids"`
}

type UpdateNetworkRelaysInput struct {
	ExpectedConfigRevision int64    `json:"expected_config_revision"`
	Enabled                bool     `json:"enabled"`
	RelayNodeIDs           []string `json:"relay_node_ids"`
}

type NetworkRelay struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Role   string `json:"role"`
}

type NetworkRelaysDocument struct {
	Schema          string         `json:"schema"`
	NetworkID       string         `json:"network_id"`
	NetworkCIDR     string         `json:"network_cidr"`
	Enabled         bool           `json:"enabled"`
	RelayNodeIDs    []string       `json:"relay_node_ids"`
	ActiveRelays    []NetworkRelay `json:"active_relays"`
	MaxRelayNodes   int            `json:"max_relay_nodes"`
	ConfigRevision  int64          `json:"config_revision"`
	ConfigUpdatedAt time.Time      `json:"config_updated_at"`
}

func defaultNetworkRelaySettings() NetworkRelaySettings {
	return NetworkRelaySettings{RelayNodeIDs: []string{}}
}

func effectiveNetworkRelaySettings(settings NetworkRelaySettings) NetworkRelaySettings {
	if settings.RelayNodeIDs == nil && !settings.Enabled {
		return defaultNetworkRelaySettings()
	}
	settings.RelayNodeIDs = slices.Clone(settings.RelayNodeIDs)
	return settings
}

func cloneNetworkRelaySettings(settings NetworkRelaySettings) NetworkRelaySettings {
	settings.RelayNodeIDs = slices.Clone(settings.RelayNodeIDs)
	return settings
}

func normalizeNetworkRelaySettings(enabled bool, relayNodeIDs []string) (NetworkRelaySettings, error) {
	if relayNodeIDs == nil {
		return NetworkRelaySettings{}, fmt.Errorf("%w: relay_node_ids must be a JSON array", ErrInvalid)
	}
	if !enabled {
		if len(relayNodeIDs) != 0 {
			return NetworkRelaySettings{}, fmt.Errorf("%w: disabled relay settings must have no relay nodes", ErrInvalid)
		}
		return defaultNetworkRelaySettings(), nil
	}
	if len(relayNodeIDs) == 0 || len(relayNodeIDs) > MaxNetworkRelayNodes {
		return NetworkRelaySettings{}, fmt.Errorf("%w: enabled relay settings require 1-%d relay nodes", ErrInvalid, MaxNetworkRelayNodes)
	}
	normalized := slices.Clone(relayNodeIDs)
	for index, nodeID := range normalized {
		if !validPersistedID(nodeID) {
			return NetworkRelaySettings{}, fmt.Errorf("%w: relay node %d has an invalid ID", ErrInvalid, index+1)
		}
	}
	sort.Strings(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return NetworkRelaySettings{}, fmt.Errorf("%w: relay node IDs must be unique", ErrInvalid)
		}
	}
	return NetworkRelaySettings{Enabled: true, RelayNodeIDs: normalized}, nil
}

func validateNetworkRelaySettings(state State, network Network) error {
	settings := network.RelaySettings
	if settings.RelayNodeIDs == nil {
		return errors.New("relay node IDs must be an array")
	}
	normalized, err := normalizeNetworkRelaySettings(settings.Enabled, settings.RelayNodeIDs)
	if err != nil {
		return err
	}
	if settings.Enabled != normalized.Enabled || !slices.Equal(settings.RelayNodeIDs, normalized.RelayNodeIDs) {
		return errors.New("relay settings are not canonical")
	}
	for _, nodeID := range settings.RelayNodeIDs {
		node, ok := findNode(state, nodeID)
		if !ok || node.NetworkID != network.ID {
			return fmt.Errorf("relay node %q does not belong to the network", nodeID)
		}
		if node.Status == "revoked" {
			return fmt.Errorf("relay node %q is revoked", nodeID)
		}
	}
	return nil
}

func activeNetworkRelays(state State, network Network) []NetworkRelay {
	settings := effectiveNetworkRelaySettings(network.RelaySettings)
	if !settings.Enabled {
		return []NetworkRelay{}
	}
	selected := make(map[string]struct{}, len(settings.RelayNodeIDs))
	for _, nodeID := range settings.RelayNodeIDs {
		selected[nodeID] = struct{}{}
	}
	relays := []NetworkRelay{}
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID || node.Status != "active" {
			continue
		}
		if _, ok := selected[node.ID]; !ok {
			continue
		}
		relays = append(relays, NetworkRelay{NodeID: node.ID, Name: node.Name, IP: node.IP, Role: node.Role})
	}
	sort.Slice(relays, func(i, j int) bool {
		if relays[i].Name != relays[j].Name {
			return relays[i].Name < relays[j].Name
		}
		return relays[i].NodeID < relays[j].NodeID
	})
	return relays
}

func networkRelaysDocument(state State, network Network) NetworkRelaysDocument {
	settings := effectiveNetworkRelaySettings(network.RelaySettings)
	return NetworkRelaysDocument{
		Schema: NetworkRelaysDocumentSchema, NetworkID: network.ID, NetworkCIDR: network.CIDR,
		Enabled: settings.Enabled, RelayNodeIDs: settings.RelayNodeIDs,
		ActiveRelays: activeNetworkRelays(state, network), MaxRelayNodes: MaxNetworkRelayNodes,
		ConfigRevision: network.ConfigRevision, ConfigUpdatedAt: network.ConfigUpdatedAt,
	}
}

func validateRelaySelection(state State, networkID string, settings NetworkRelaySettings) error {
	network, ok := findNetwork(state, networkID)
	if !ok {
		return ErrNotFound
	}
	network.RelaySettings = settings
	if err := validateNetworkRelaySettings(state, network); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func relaySettingsDigest(settings NetworkRelaySettings) string {
	return ConfigDigest(fmt.Sprintf("enabled=%t\n%s", settings.Enabled, strings.Join(settings.RelayNodeIDs, "\n")))
}

func (s *Service) NetworkRelays(networkID string) (NetworkRelaysDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkRelaysDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	var result NetworkRelaysDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = networkRelaysDocument(state, network)
		return nil
	})
	return result, err
}

func (s *Service) UpdateNetworkRelays(networkID string, input UpdateNetworkRelaysInput) (NetworkRelaysDocument, error) {
	return s.updateNetworkRelays(nil, networkID, input)
}

func (s *Service) UpdateNetworkRelaysAs(actor Actor, networkID string, input UpdateNetworkRelaysInput) (NetworkRelaysDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkRelaysDocument{}, err
	}
	return s.updateNetworkRelays(&actor, networkID, input)
}

func (s *Service) updateNetworkRelays(actor *Actor, networkID string, input UpdateNetworkRelaysInput) (NetworkRelaysDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkRelaysDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	if input.ExpectedConfigRevision < 1 {
		return NetworkRelaysDocument{}, fmt.Errorf("%w: expected_config_revision must be positive", ErrInvalid)
	}
	desired, err := normalizeNetworkRelaySettings(input.Enabled, input.RelayNodeIDs)
	if err != nil {
		return NetworkRelaysDocument{}, err
	}
	var result NetworkRelaysDocument
	now := s.now().UTC()
	err = s.updateState(func(state *State) error {
		if state.Version < ControlStateVersionNetworkRelays || state.Version > ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: network relay schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			if err := validateRelaySelection(*state, networkID, desired); err != nil {
				return err
			}
			if desired.Enabled == network.RelaySettings.Enabled && slices.Equal(desired.RelayNodeIDs, network.RelaySettings.RelayNodeIDs) {
				result = networkRelaysDocument(*state, *network)
				return nil
			}
			if network.FirewallRollout.Phase != "" {
				return fmt.Errorf("%w: network relay settings cannot change during a firewall canary rollout", ErrConflict)
			}
			if input.ExpectedConfigRevision != network.ConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			if now.IsZero() {
				return errors.New("network relay update requires a valid timestamp")
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			event, err := newOptionalAttributedAudit(now, "network.relay_settings_updated", "network", network.ID, map[string]any{
				"old_sha256": relaySettingsDigest(network.RelaySettings), "new_sha256": relaySettingsDigest(desired),
				"old_relay_nodes": len(network.RelaySettings.RelayNodeIDs), "relay_nodes": len(desired.RelayNodeIDs),
				"enabled": desired.Enabled, "config_revision": nextRevision,
			}, actor)
			if err != nil {
				return err
			}
			network.RelaySettings = cloneNetworkRelaySettings(desired)
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			state.Audit = append(state.Audit, event)
			result = networkRelaysDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

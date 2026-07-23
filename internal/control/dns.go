package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DefaultNetworkDNSPort    = 53
	NetworkDNSDocumentSchema = "mesh-network-dns-v1"
	NativeDNSPolicySchema    = "mesh-native-dns-v1"
	NativeDNSPolicyPrefix    = "# mesh-native-dns-v1 "
	maxNativeDNSResolvers    = 8
)

var nativeDNSDomainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NetworkDNSSettings controls Slack Nebula's authoritative certificate-name
// responder on this network's lighthouses. Mesh always binds the responder to
// each lighthouse's own overlay IP; underlay and wildcard binds are not part
// of the managed surface.
type NetworkDNSSettings struct {
	Enabled        bool   `json:"enabled"`
	ListenPort     int    `json:"listen_port"`
	NativeResolver bool   `json:"native_resolver,omitempty"`
	SearchDomain   string `json:"search_domain,omitempty"`
}

type UpdateNetworkDNSInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	Enabled                bool   `json:"enabled"`
	ListenPort             int    `json:"listen_port"`
	NativeResolver         bool   `json:"native_resolver"`
	SearchDomain           string `json:"search_domain"`
}

type NetworkDNSResolver struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
}

type NetworkDNSDocument struct {
	Schema          string               `json:"schema"`
	NetworkID       string               `json:"network_id"`
	NetworkCIDR     string               `json:"network_cidr"`
	Enabled         bool                 `json:"enabled"`
	ListenPort      int                  `json:"listen_port"`
	NativeResolver  bool                 `json:"native_resolver"`
	SearchDomain    string               `json:"search_domain"`
	FirewallReady   bool                 `json:"firewall_ready"`
	Resolvers       []NetworkDNSResolver `json:"resolvers"`
	ConfigRevision  int64                `json:"config_revision"`
	ConfigUpdatedAt time.Time            `json:"config_updated_at"`
}

// NativeDNSPolicy is embedded in the already signed Nebula configuration.
// It is deliberately node-specific: the agent can bind only the authenticated
// local overlay address and can forward only to the bounded active resolver
// inventory selected by the control plane.
type NativeDNSPolicy struct {
	Schema       string              `json:"schema"`
	LocalIP      string              `json:"local_ip"`
	NetworkCIDR  string              `json:"network_cidr"`
	SearchDomain string              `json:"search_domain"`
	Resolvers    []NativeDNSResolver `json:"resolvers"`
}

type NativeDNSResolver struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func defaultNetworkDNSSettings() NetworkDNSSettings {
	return NetworkDNSSettings{ListenPort: DefaultNetworkDNSPort}
}

func effectiveNetworkDNSSettings(settings NetworkDNSSettings) NetworkDNSSettings {
	if settings == (NetworkDNSSettings{}) {
		return defaultNetworkDNSSettings()
	}
	return settings
}

func normalizeNetworkDNSSettings(enabled bool, listenPort int, nativeResolver bool, searchDomain string, nebulaListenPort int) (NetworkDNSSettings, error) {
	settings := NetworkDNSSettings{
		Enabled: enabled, ListenPort: listenPort, NativeResolver: nativeResolver,
		SearchDomain: searchDomain,
	}
	if err := validateNetworkDNSSettings(settings, nebulaListenPort); err != nil {
		return NetworkDNSSettings{}, err
	}
	return settings, nil
}

func validateNetworkDNSSettings(settings NetworkDNSSettings, nebulaListenPort int) error {
	if settings.ListenPort < 1 || settings.ListenPort > 65535 {
		return fmt.Errorf("%w: DNS listen port must be 1-65535", ErrInvalid)
	}
	if !settings.Enabled && settings.ListenPort != DefaultNetworkDNSPort {
		return fmt.Errorf("%w: disabled DNS settings must use the default port %d", ErrInvalid, DefaultNetworkDNSPort)
	}
	if settings.Enabled && settings.ListenPort == nebulaListenPort {
		return fmt.Errorf("%w: DNS and Nebula listeners cannot use the same UDP port", ErrInvalid)
	}
	if !settings.Enabled && (settings.NativeResolver || settings.SearchDomain != "") {
		return fmt.Errorf("%w: disabled DNS cannot configure native resolver integration", ErrInvalid)
	}
	if settings.NativeResolver {
		if err := validateNativeDNSDomain(settings.SearchDomain); err != nil {
			return err
		}
	} else if settings.SearchDomain != "" {
		return fmt.Errorf("%w: search domain requires native resolver integration", ErrInvalid)
	}
	return nil
}

func validateNativeDNSDomain(value string) error {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") || value != strings.ToLower(value) {
		return fmt.Errorf("%w: native DNS search domain must be a lowercase canonical DNS name", ErrInvalid)
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !nativeDNSDomainLabelPattern.MatchString(label) {
			return fmt.Errorf("%w: native DNS search domain contains an invalid label", ErrInvalid)
		}
	}
	if value == "local" || strings.HasSuffix(value, ".local") {
		return fmt.Errorf("%w: .local is reserved for multicast DNS", ErrInvalid)
	}
	return nil
}

func firewallAllowsNetworkDNS(policy FirewallPolicy, networkCIDR string, port int) bool {
	network, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return false
	}
	for _, rule := range policy.Inbound {
		if rule.TargetGroup != "" || rule.TargetNodeID != "" {
			continue
		}
		if rule.Proto != "any" && rule.Proto != "udp" {
			continue
		}
		parsedPort, err := parseCanonicalFirewallPort(rule.Port)
		if err != nil || !parsedPort.any && (port < parsedPort.start || port > parsedPort.end) {
			continue
		}
		selectorCoversNetwork := rule.Group == "all" || rule.Host == "any" || rule.Host == network.String()
		if selectorCoversNetwork {
			return true
		}
	}
	return false
}

func validateNetworkDNSInvariant(network Network) error {
	if err := validateNetworkDNSSettings(network.DNSSettings, network.ListenPort); err != nil {
		return err
	}
	if network.DNSSettings.Enabled && !firewallAllowsNetworkDNS(network.FirewallPolicy, network.CIDR, network.DNSSettings.ListenPort) {
		return errors.New("enabled network DNS is not permitted by an inbound UDP rule covering all managed nodes")
	}
	return nil
}

func networkDNSDocument(state State, network Network) NetworkDNSDocument {
	settings := effectiveNetworkDNSSettings(network.DNSSettings)
	resolvers := []NetworkDNSResolver{}
	if settings.Enabled {
		for _, node := range state.Nodes {
			if node.NetworkID == network.ID && node.Role == "lighthouse" && node.Status == "active" {
				resolvers = append(resolvers, NetworkDNSResolver{NodeID: node.ID, Name: node.Name, IP: node.IP})
			}
		}
	}
	sort.Slice(resolvers, func(i, j int) bool {
		if resolvers[i].Name != resolvers[j].Name {
			return resolvers[i].Name < resolvers[j].Name
		}
		return resolvers[i].NodeID < resolvers[j].NodeID
	})
	return NetworkDNSDocument{
		Schema: NetworkDNSDocumentSchema, NetworkID: network.ID, NetworkCIDR: network.CIDR,
		Enabled: settings.Enabled, ListenPort: settings.ListenPort,
		NativeResolver: settings.NativeResolver, SearchDomain: settings.SearchDomain,
		FirewallReady: firewallAllowsNetworkDNS(network.FirewallPolicy, network.CIDR, settings.ListenPort),
		Resolvers:     resolvers, ConfigRevision: network.ConfigRevision, ConfigUpdatedAt: network.ConfigUpdatedAt,
	}
}

func (s *Service) NetworkDNS(networkID string) (NetworkDNSDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkDNSDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	var result NetworkDNSDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = networkDNSDocument(state, network)
		return nil
	})
	return result, err
}

func (s *Service) UpdateNetworkDNS(networkID string, input UpdateNetworkDNSInput) (NetworkDNSDocument, error) {
	return s.updateNetworkDNS(nil, networkID, input)
}

func (s *Service) UpdateNetworkDNSAs(actor Actor, networkID string, input UpdateNetworkDNSInput) (NetworkDNSDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkDNSDocument{}, err
	}
	return s.updateNetworkDNS(&actor, networkID, input)
}

func (s *Service) updateNetworkDNS(actor *Actor, networkID string, input UpdateNetworkDNSInput) (NetworkDNSDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkDNSDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	if input.ExpectedConfigRevision < 1 {
		return NetworkDNSDocument{}, fmt.Errorf("%w: expected_config_revision must be positive", ErrInvalid)
	}
	var result NetworkDNSDocument
	now := s.now().UTC()
	err := s.updateState(func(state *State) error {
		if state.Version < ControlStateVersionNetworkRelays || state.Version > ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: network DNS schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			desired, err := normalizeNetworkDNSSettings(input.Enabled, input.ListenPort, input.NativeResolver, input.SearchDomain, network.ListenPort)
			if err != nil {
				return err
			}
			if desired == network.DNSSettings {
				result = networkDNSDocument(*state, *network)
				return nil
			}
			if network.FirewallRollout.Phase != "" {
				return fmt.Errorf("%w: network DNS cannot change during a firewall canary rollout", ErrConflict)
			}
			if input.ExpectedConfigRevision != network.ConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			if desired.Enabled && !firewallAllowsNetworkDNS(network.FirewallPolicy, network.CIDR, desired.ListenPort) {
				return fmt.Errorf("%w: inbound firewall must allow UDP port %d from group all, host any, or the complete network CIDR before DNS can be enabled", ErrConflict, desired.ListenPort)
			}
			if now.IsZero() {
				return errors.New("network DNS update requires a valid timestamp")
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			event, err := newOptionalAttributedAudit(now, "network.dns_settings_updated", "network", network.ID, map[string]any{
				"old_enabled": network.DNSSettings.Enabled, "enabled": desired.Enabled,
				"old_listen_port": network.DNSSettings.ListenPort, "listen_port": desired.ListenPort,
				"old_native_resolver": network.DNSSettings.NativeResolver, "native_resolver": desired.NativeResolver,
				"old_search_domain": network.DNSSettings.SearchDomain, "search_domain": desired.SearchDomain,
				"config_revision": nextRevision,
			}, actor)
			if err != nil {
				return err
			}
			network.DNSSettings = desired
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			state.Audit = append(state.Audit, event)
			result = networkDNSDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func nativeDNSPolicy(state State, network Network, node Node) (NativeDNSPolicy, bool) {
	settings := effectiveNetworkDNSSettings(network.DNSSettings)
	if !settings.Enabled || !settings.NativeResolver {
		return NativeDNSPolicy{}, false
	}
	resolvers := make([]NativeDNSResolver, 0, maxNativeDNSResolvers)
	for _, candidate := range state.Nodes {
		if candidate.NetworkID == network.ID && candidate.Role == "lighthouse" && candidate.Status == "active" {
			resolvers = append(resolvers, NativeDNSResolver{IP: candidate.IP, Port: settings.ListenPort})
		}
	}
	sort.Slice(resolvers, func(i, j int) bool { return resolvers[i].IP < resolvers[j].IP })
	if len(resolvers) > maxNativeDNSResolvers {
		resolvers = resolvers[:maxNativeDNSResolvers]
	}
	return NativeDNSPolicy{
		Schema: NativeDNSPolicySchema, LocalIP: node.IP, NetworkCIDR: network.CIDR,
		SearchDomain: settings.SearchDomain, Resolvers: resolvers,
	}, true
}

func renderNativeDNSPolicy(state State, network Network, node Node) string {
	policy, enabled := nativeDNSPolicy(state, network, node)
	if !enabled {
		return ""
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		panic("encode validated native DNS policy: " + err.Error())
	}
	return NativeDNSPolicyPrefix + base64.RawURLEncoding.EncodeToString(raw) + "\n"
}

// ParseNativeDNSPolicy extracts at most one strict authenticated policy from
// exact signed configuration bytes. A missing line is the legacy/disabled
// state; malformed or duplicate projections fail closed.
func ParseNativeDNSPolicy(config string) (NativeDNSPolicy, bool, error) {
	var encoded string
	found := false
	for _, line := range strings.Split(config, "\n") {
		if !strings.HasPrefix(line, NativeDNSPolicyPrefix) {
			continue
		}
		if found {
			return NativeDNSPolicy{}, false, errors.New("signed config contains duplicate native DNS policies")
		}
		found = true
		encoded = strings.TrimPrefix(line, NativeDNSPolicyPrefix)
	}
	if !found {
		return NativeDNSPolicy{}, false, nil
	}
	if encoded == "" {
		return NativeDNSPolicy{}, false, errors.New("signed config native DNS policy encoding is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return NativeDNSPolicy{}, false, errors.New("signed config native DNS policy encoding is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy NativeDNSPolicy
	if err := decoder.Decode(&policy); err != nil {
		return NativeDNSPolicy{}, false, errors.New("signed config native DNS policy document is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return NativeDNSPolicy{}, false, errors.New("signed config native DNS policy has trailing data")
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, raw) {
		return NativeDNSPolicy{}, false, errors.New("signed config native DNS policy is not canonical")
	}
	if err := validateNativeDNSPolicy(policy); err != nil {
		return NativeDNSPolicy{}, false, err
	}
	return policy, true, nil
}

func validateNativeDNSPolicy(policy NativeDNSPolicy) error {
	if policy.Schema != NativeDNSPolicySchema {
		return errors.New("signed config native DNS policy schema is unsupported")
	}
	local, err := netip.ParseAddr(policy.LocalIP)
	if err != nil || !local.Is4() || local.String() != policy.LocalIP {
		return errors.New("signed config native DNS local address is invalid")
	}
	network, err := netip.ParsePrefix(policy.NetworkCIDR)
	if err != nil || !network.Addr().Is4() || network != network.Masked() || network.String() != policy.NetworkCIDR || !network.Contains(local) {
		return errors.New("signed config native DNS network is invalid")
	}
	if err := validateNativeDNSDomain(policy.SearchDomain); err != nil {
		return errors.New("signed config native DNS search domain is invalid")
	}
	if len(policy.Resolvers) == 0 || len(policy.Resolvers) > maxNativeDNSResolvers {
		return errors.New("signed config native DNS resolver inventory is invalid")
	}
	previous := ""
	for _, resolver := range policy.Resolvers {
		address, err := netip.ParseAddr(resolver.IP)
		if err != nil || !address.Is4() || address.String() != resolver.IP || !network.Contains(address) || resolver.Port < 1 || resolver.Port > 65535 || (previous != "" && previous >= resolver.IP) {
			return errors.New("signed config native DNS resolver is invalid or unordered")
		}
		previous = resolver.IP
	}
	return nil
}

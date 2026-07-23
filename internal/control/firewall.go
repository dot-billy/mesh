package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	FirewallPolicyModeLegacyDefault = "legacy-default"
	FirewallPolicyModeManaged       = "managed"
	FirewallRendererVersionV1       = 1
	FirewallRendererVersionV2       = 2

	currentFirewallRendererVersion = FirewallRendererVersionV2

	maxFirewallRulesPerDirection = 128
	maxFirewallExpandedPortSlots = 16 << 10
)

// FirewallRule separates the peer selector from the local-node target. Exactly
// one of Group, Host, or PeerNodeID selects the remote peer. An empty local
// target applies to every node; otherwise exactly one of TargetGroup or
// TargetNodeID selects the nodes that receive the rule.
type FirewallRule struct {
	Proto        string `json:"proto"`
	Port         string `json:"port"`
	Group        string `json:"group,omitempty"`
	Host         string `json:"host,omitempty"`
	PeerNodeID   string `json:"peer_node_id,omitempty"`
	TargetGroup  string `json:"target_group,omitempty"`
	TargetNodeID string `json:"target_node_id,omitempty"`
}

// FirewallPolicy is persisted per network. LegacyDefault is an explicit
// compatibility state for networks written before managed firewall policy
// existed; it is required to contain the exact historical connectivity rules.
type FirewallPolicy struct {
	Mode            string         `json:"mode"`
	RendererVersion int            `json:"renderer_version"`
	Inbound         []FirewallRule `json:"inbound"`
	Outbound        []FirewallRule `json:"outbound"`
}

type FirewallPolicyInput struct {
	Inbound  []FirewallRule `json:"inbound"`
	Outbound []FirewallRule `json:"outbound"`
}

type UpdateFirewallPolicyInput struct {
	ExpectedConfigRevision int64          `json:"expected_config_revision"`
	Inbound                []FirewallRule `json:"inbound"`
	Outbound               []FirewallRule `json:"outbound"`
}

type FirewallPolicyDocument struct {
	NetworkID        string                            `json:"network_id"`
	Mode             string                            `json:"mode"`
	RendererVersion  int                               `json:"renderer_version"`
	Inbound          []FirewallRule                    `json:"inbound"`
	Outbound         []FirewallRule                    `json:"outbound"`
	ConfigRevision   int64                             `json:"config_revision"`
	ConfigUpdatedAt  time.Time                         `json:"config_updated_at"`
	RenderedFirewall string                            `json:"rendered_firewall"`
	PolicySHA256     string                            `json:"policy_sha256"`
	EffectiveNodes   []EffectiveFirewallPolicyDocument `json:"effective_nodes"`
}

type FirewallPolicyPreview struct {
	FirewallPolicyDocument
	WouldChange            bool  `json:"would_change"`
	ProposedConfigRevision int64 `json:"proposed_config_revision"`
}

// EffectiveFirewallPolicyDocument is the exact compiled policy a node will
// receive after local targets are filtered and peer-node selectors are
// resolved to the peer's current overlay address.
type EffectiveFirewallPolicyDocument struct {
	NodeID           string         `json:"node_id"`
	Name             string         `json:"name"`
	IP               string         `json:"ip"`
	Groups           []string       `json:"groups"`
	Inbound          []FirewallRule `json:"inbound"`
	Outbound         []FirewallRule `json:"outbound"`
	RenderedFirewall string         `json:"rendered_firewall"`
	SHA256           string         `json:"sha256"`
}

type parsedFirewallPort struct {
	start int
	end   int
	any   bool
}

func legacyDefaultFirewallPolicy() FirewallPolicy {
	return FirewallPolicy{
		Mode:            FirewallPolicyModeLegacyDefault,
		RendererVersion: FirewallRendererVersionV1,
		Inbound:         []FirewallRule{{Proto: "any", Port: "any", Group: "all"}},
		Outbound:        []FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
	}
}

func defaultManagedFirewallPolicy() FirewallPolicy {
	policy := legacyDefaultFirewallPolicy()
	policy.Mode = FirewallPolicyModeManaged
	policy.RendererVersion = currentFirewallRendererVersion
	return policy
}

func cloneFirewallPolicy(policy FirewallPolicy) FirewallPolicy {
	policy.Inbound = cloneFirewallRules(policy.Inbound)
	policy.Outbound = cloneFirewallRules(policy.Outbound)
	return policy
}

func firewallPolicyInput(policy FirewallPolicy) FirewallPolicyInput {
	return FirewallPolicyInput{
		Inbound:  cloneFirewallRules(policy.Inbound),
		Outbound: cloneFirewallRules(policy.Outbound),
	}
}

func cloneFirewallRules(rules []FirewallRule) []FirewallRule {
	if rules == nil {
		return nil
	}
	return append([]FirewallRule{}, rules...)
}

func normalizeFirewallPolicy(input FirewallPolicyInput, networkCIDR string) (FirewallPolicy, error) {
	if input.Inbound == nil || input.Outbound == nil {
		return FirewallPolicy{}, fmt.Errorf("%w: inbound and outbound must each be a JSON array", ErrInvalid)
	}
	if len(input.Inbound) > maxFirewallRulesPerDirection {
		return FirewallPolicy{}, fmt.Errorf("%w: inbound firewall rules exceed the %d-rule limit", ErrInvalid, maxFirewallRulesPerDirection)
	}
	if len(input.Outbound) > maxFirewallRulesPerDirection {
		return FirewallPolicy{}, fmt.Errorf("%w: outbound firewall rules exceed the %d-rule limit", ErrInvalid, maxFirewallRulesPerDirection)
	}
	network, err := netip.ParsePrefix(networkCIDR)
	if err != nil || !network.Addr().Is4() || network != network.Masked() {
		return FirewallPolicy{}, errors.New("network has an invalid canonical IPv4 CIDR")
	}
	policy := FirewallPolicy{Mode: FirewallPolicyModeManaged, RendererVersion: currentFirewallRendererVersion}
	expandedSlots := 0
	policy.Inbound, expandedSlots, err = normalizeFirewallRules("inbound", input.Inbound, network, expandedSlots)
	if err != nil {
		return FirewallPolicy{}, err
	}
	policy.Outbound, expandedSlots, err = normalizeFirewallRules("outbound", input.Outbound, network, expandedSlots)
	if err != nil {
		return FirewallPolicy{}, err
	}
	if expandedSlots > maxFirewallExpandedPortSlots {
		return FirewallPolicy{}, fmt.Errorf("%w: firewall rules expand to more than %d port slots", ErrInvalid, maxFirewallExpandedPortSlots)
	}
	return policy, nil
}

func normalizeFirewallRules(direction string, rules []FirewallRule, network netip.Prefix, expandedSlots int) ([]FirewallRule, int, error) {
	normalized := make([]FirewallRule, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for index, candidate := range rules {
		rule, port, selectorKey, err := normalizeFirewallRule(candidate, network)
		if err != nil {
			return nil, expandedSlots, fmt.Errorf("%w: %s firewall rule %d: %v", ErrInvalid, direction, index+1, err)
		}
		expandedSlots += port.end - port.start + 1
		if expandedSlots > maxFirewallExpandedPortSlots {
			return nil, expandedSlots, fmt.Errorf("%w: firewall rules expand to more than %d port slots", ErrInvalid, maxFirewallExpandedPortSlots)
		}
		key := rule.Proto + "\x00" + rule.Port + "\x00" + selectorKey
		if _, duplicate := seen[key]; duplicate {
			return nil, expandedSlots, fmt.Errorf("%w: %s firewall rule %d duplicates an equivalent rule", ErrInvalid, direction, index+1)
		}
		seen[key] = struct{}{}
		normalized[index] = rule
	}
	sort.Slice(normalized, func(left, right int) bool {
		return firewallRuleSortKey(normalized[left]) < firewallRuleSortKey(normalized[right])
	})
	return normalized, expandedSlots, nil
}

func normalizeFirewallRule(rule FirewallRule, network netip.Prefix) (FirewallRule, parsedFirewallPort, string, error) {
	if strings.TrimSpace(rule.Proto) != rule.Proto {
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("proto must not contain surrounding whitespace")
	}
	switch rule.Proto {
	case "any", "tcp", "udp", "icmp":
	default:
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("proto must be any, tcp, udp, or icmp")
	}
	port, err := parseCanonicalFirewallPort(rule.Port)
	if err != nil {
		return FirewallRule{}, parsedFirewallPort{}, "", err
	}
	if rule.Proto == "icmp" && !port.any {
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("icmp rules require port any")
	}

	hasGroup, hasHost, hasPeerNode := rule.Group != "", rule.Host != "", rule.PeerNodeID != ""
	selectorCount := 0
	for _, present := range []bool{hasGroup, hasHost, hasPeerNode} {
		if present {
			selectorCount++
		}
	}
	if selectorCount != 1 {
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("exactly one of group, host, or peer_node_id must be provided")
	}
	if rule.TargetGroup != "" && rule.TargetNodeID != "" {
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("target_group and target_node_id are mutually exclusive")
	}
	if rule.TargetGroup != "" {
		if strings.TrimSpace(rule.TargetGroup) != rule.TargetGroup || !groupPattern.MatchString(rule.TargetGroup) || rule.TargetGroup == "all" {
			return FirewallRule{}, parsedFirewallPort{}, "", errors.New("target_group must match the certificate-group grammar, must not be all, and be at most 32 characters")
		}
	}
	if rule.TargetNodeID != "" && !validPersistedID(rule.TargetNodeID) {
		return FirewallRule{}, parsedFirewallPort{}, "", errors.New("target_node_id must be a valid node ID")
	}
	targetKey := "\x00target\x00all"
	if rule.TargetGroup != "" {
		targetKey = "\x00target_group\x00" + rule.TargetGroup
	} else if rule.TargetNodeID != "" {
		targetKey = "\x00target_node\x00" + rule.TargetNodeID
	}
	if hasGroup {
		if strings.TrimSpace(rule.Group) != rule.Group || !groupPattern.MatchString(rule.Group) {
			return FirewallRule{}, parsedFirewallPort{}, "", errors.New("group must match the certificate-group grammar and be at most 32 characters")
		}
		if rule.Group == "any" {
			return FirewallRule{}, parsedFirewallPort{}, "", errors.New("group any is a wildcard; use host any explicitly")
		}
		return rule, port, "group\x00" + rule.Group + targetKey, nil
	}
	if hasPeerNode {
		if !validPersistedID(rule.PeerNodeID) {
			return FirewallRule{}, parsedFirewallPort{}, "", errors.New("peer_node_id must be a valid node ID")
		}
		return rule, port, "peer_node\x00" + rule.PeerNodeID + targetKey, nil
	}

	host, selectorKey, err := normalizeFirewallHost(rule.Host, network)
	if err != nil {
		return FirewallRule{}, parsedFirewallPort{}, "", err
	}
	rule.Host = host
	return rule, port, selectorKey + targetKey, nil
}

func normalizeFirewallHost(value string, network netip.Prefix) (string, string, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return "", "", errors.New("host must be any, a canonical IPv4 address, or a canonical IPv4 CIDR")
	}
	if value == "any" {
		return value, "host\x00any", nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if !address.Is4() || address.String() != value || !network.Contains(address) {
			return "", "", errors.New("host IPv4 address must be canonical and contained in the network CIDR")
		}
		return address.String(), "cidr\x00" + netip.PrefixFrom(address, 32).String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value || prefix.Bits() < network.Bits() || !network.Contains(prefix.Addr()) {
		return "", "", errors.New("host CIDR must be canonical IPv4 and contained in the network CIDR")
	}
	if prefix.Bits() == 32 {
		return prefix.Addr().String(), "cidr\x00" + prefix.String(), nil
	}
	return prefix.String(), "cidr\x00" + prefix.String(), nil
}

func parseCanonicalFirewallPort(value string) (parsedFirewallPort, error) {
	if value == "any" {
		return parsedFirewallPort{any: true}, nil
	}
	if strings.TrimSpace(value) != value || value == "" || strings.Count(value, "-") > 1 {
		return parsedFirewallPort{}, errors.New("port must be any, a canonical port, or a canonical port range")
	}
	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		start, err := parseCanonicalPortNumber(parts[0])
		if err != nil {
			return parsedFirewallPort{}, err
		}
		end, err := parseCanonicalPortNumber(parts[1])
		if err != nil {
			return parsedFirewallPort{}, err
		}
		if start >= end {
			return parsedFirewallPort{}, errors.New("port range must be ascending and contain more than one port")
		}
		return parsedFirewallPort{start: start, end: end}, nil
	}
	port, err := parseCanonicalPortNumber(value)
	if err != nil {
		return parsedFirewallPort{}, err
	}
	return parsedFirewallPort{start: port, end: port}, nil
}

func parseCanonicalPortNumber(value string) (int, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("port numbers must be canonical decimal values from 1 through 65535")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("port numbers must be canonical decimal values from 1 through 65535")
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
		return 0, errors.New("port numbers must be canonical decimal values from 1 through 65535")
	}
	return port, nil
}

func firewallRuleSortKey(rule FirewallRule) string {
	protoRank := map[string]string{"any": "0", "icmp": "1", "tcp": "2", "udp": "3"}[rule.Proto]
	port, _ := parseCanonicalFirewallPort(rule.Port)
	portKey := "0"
	if !port.any {
		portKey = fmt.Sprintf("1%05d%05d", port.start, port.end)
	}
	selectorKey := "group\x00" + rule.Group
	if rule.Host != "" {
		selectorKey = "host\x00" + rule.Host
	} else if rule.PeerNodeID != "" {
		selectorKey = "peer_node\x00" + rule.PeerNodeID
	}
	targetKey := "target\x00all"
	if rule.TargetGroup != "" {
		targetKey = "target_group\x00" + rule.TargetGroup
	} else if rule.TargetNodeID != "" {
		targetKey = "target_node\x00" + rule.TargetNodeID
	}
	return targetKey + "\x00" + protoRank + "\x00" + portKey + "\x00" + selectorKey
}

func validateStoredFirewallPolicy(policy FirewallPolicy, networkCIDR string) error {
	if policy.Mode != FirewallPolicyModeLegacyDefault && policy.Mode != FirewallPolicyModeManaged {
		return fmt.Errorf("unsupported firewall policy mode %q", policy.Mode)
	}
	if policy.RendererVersion != FirewallRendererVersionV1 && policy.RendererVersion != FirewallRendererVersionV2 {
		return fmt.Errorf("unsupported firewall renderer version %d", policy.RendererVersion)
	}
	if policy.Mode == FirewallPolicyModeLegacyDefault && policy.RendererVersion != FirewallRendererVersionV1 {
		return errors.New("legacy-default firewall policy must use the historical renderer version")
	}
	normalized, err := normalizeFirewallPolicy(firewallPolicyInput(policy), networkCIDR)
	if err != nil {
		return err
	}
	if policy.Inbound == nil || policy.Outbound == nil || !slices.Equal(policy.Inbound, normalized.Inbound) || !slices.Equal(policy.Outbound, normalized.Outbound) {
		return errors.New("firewall policy rules are not canonical")
	}
	if policy.Mode == FirewallPolicyModeLegacyDefault {
		legacy := legacyDefaultFirewallPolicy()
		if !sameEffectiveFirewallPolicy(policy, legacy) {
			return errors.New("legacy-default firewall policy differs from the historical connectivity policy")
		}
	}
	return nil
}

func sameEffectiveFirewallPolicy(left, right FirewallPolicy) bool {
	return slices.Equal(left.Inbound, right.Inbound) && slices.Equal(left.Outbound, right.Outbound)
}

func firewallPolicyUsesNodeScopes(policy FirewallPolicy) bool {
	for _, rules := range [][]FirewallRule{policy.Inbound, policy.Outbound} {
		for _, rule := range rules {
			if rule.PeerNodeID != "" || rule.TargetGroup != "" || rule.TargetNodeID != "" {
				return true
			}
		}
	}
	return false
}

func firewallPolicyReferencesNode(policy FirewallPolicy, nodeID string) bool {
	for _, rules := range [][]FirewallRule{policy.Inbound, policy.Outbound} {
		for _, rule := range rules {
			if rule.PeerNodeID == nodeID || rule.TargetNodeID == nodeID {
				return true
			}
		}
	}
	return false
}

func replaceFirewallPolicyNodeReferences(policy *FirewallPolicy, oldNodeID, newNodeID string) int {
	replaced := 0
	for _, rules := range []*[]FirewallRule{&policy.Inbound, &policy.Outbound} {
		for index := range *rules {
			rule := &(*rules)[index]
			if rule.PeerNodeID == oldNodeID {
				rule.PeerNodeID = newNodeID
				replaced++
			}
			if rule.TargetNodeID == oldNodeID {
				rule.TargetNodeID = newNodeID
				replaced++
			}
		}
	}
	return replaced
}

func firewallPolicySHA256(policy FirewallPolicy) string {
	if !firewallPolicyUsesNodeScopes(policy) {
		return ConfigDigest(renderFirewallPolicy(policy))
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		// FirewallPolicy contains only JSON-safe scalar fields and slices.
		return ConfigDigest("mesh-firewall-policy-invalid")
	}
	return ConfigDigest("mesh-firewall-policy-v1\n" + string(canonical))
}

func renderFirewallPolicy(policy FirewallPolicy) string {
	return renderFirewallPolicyForNode(policy, nil)
}

// renderFirewallPolicyForNode keeps ordinary overlay rules unchanged and, on
// a gateway certificate, explicitly repeats each inbound rule for every exact
// routed destination. Nebula 1.10.3 defaults local_cidr to the certificate's
// overlay network when unsafe networks are present. Explicit copies preserve
// the operator's protocol, port, and peer selector without enabling the
// deprecated default_local_cidr_any broadening switch.
func renderFirewallPolicyForNode(policy FirewallPolicy, routedSubnets []string) string {
	var builder strings.Builder
	builder.WriteString("firewall:\n")
	renderFirewallDirection(&builder, "outbound", policy.Outbound, policy.RendererVersion, nil)
	renderFirewallDirection(&builder, "inbound", policy.Inbound, policy.RendererVersion, routedSubnets)
	return builder.String()
}

func renderFirewallDirection(builder *strings.Builder, direction string, rules []FirewallRule, rendererVersion int, routedSubnets []string) {
	if len(rules) == 0 {
		fmt.Fprintf(builder, "  %s: []\n", direction)
		return
	}
	fmt.Fprintf(builder, "  %s:\n", direction)
	for _, rule := range rules {
		renderFirewallRule(builder, rule, rendererVersion, "")
		for _, routedSubnet := range routedSubnets {
			renderFirewallRule(builder, rule, rendererVersion, routedSubnet)
		}
	}
}

func renderFirewallRule(builder *strings.Builder, rule FirewallRule, rendererVersion int, localCIDR string) {
	fmt.Fprintf(builder, "    - port: %s\n      proto: %s\n", rule.Port, rule.Proto)
	switch {
	case rule.Group != "":
		if rendererVersion >= FirewallRendererVersionV2 {
			// The accepted certificate-group grammar includes plain YAML
			// scalars such as False, null, 001, and ISO dates. Nebula v1.10.3
			// decodes rules through yaml.v3 into map[string]any before it
			// stringifies values, so leaving those names bare can silently
			// select a different certificate group. V2 always quotes groups.
			fmt.Fprintf(builder, "      group: %q\n", rule.Group)
		} else {
			// V1 is retained only to reproduce already-signed historical
			// configs exactly until startup migration can persist v2 and, when
			// the rendered bytes change, advance the signed revision atomically.
			fmt.Fprintf(builder, "      group: %s\n", rule.Group)
		}
	case rule.Host == "any":
		builder.WriteString("      host: any\n")
	case rule.PeerNodeID != "":
		// Source policies must be compiled before rendering. This impossible
		// exact address is a fail-closed defense if corrupt state reaches here.
		builder.WriteString("      cidr: 0.0.0.0/32\n")
	case strings.Contains(rule.Host, "/"):
		fmt.Fprintf(builder, "      cidr: %s\n", rule.Host)
	default:
		fmt.Fprintf(builder, "      cidr: %s/32\n", rule.Host)
	}
	if localCIDR != "" {
		fmt.Fprintf(builder, "      local_cidr: %s\n", localCIDR)
	}
}

// upgradeFirewallRenderer prepares an explicitly managed v1 policy for the
// current renderer. The second return value reports whether the exact rendered
// firewall bytes change, allowing the caller to advance the signed network
// revision only when required. Legacy-default policies remain historical v1
// until an operator submits an explicit managed policy.
func upgradeFirewallRenderer(policy FirewallPolicy) (FirewallPolicy, bool, error) {
	upgraded := cloneFirewallPolicy(policy)
	switch {
	case upgraded.Mode == FirewallPolicyModeLegacyDefault:
		if upgraded.RendererVersion != FirewallRendererVersionV1 {
			return FirewallPolicy{}, false, errors.New("legacy-default firewall policy must use the historical renderer version")
		}
		return upgraded, false, nil
	case upgraded.Mode != FirewallPolicyModeManaged:
		return FirewallPolicy{}, false, fmt.Errorf("unsupported firewall policy mode %q", upgraded.Mode)
	case upgraded.RendererVersion == currentFirewallRendererVersion:
		return upgraded, false, nil
	case upgraded.RendererVersion != FirewallRendererVersionV1:
		return FirewallPolicy{}, false, fmt.Errorf("unsupported firewall renderer version %d", upgraded.RendererVersion)
	}

	before := renderFirewallPolicy(upgraded)
	upgraded.RendererVersion = currentFirewallRendererVersion
	return upgraded, before != renderFirewallPolicy(upgraded), nil
}

func firewallRuleTargetsNode(rule FirewallRule, node Node) bool {
	if rule.TargetNodeID != "" {
		return rule.TargetNodeID == node.ID
	}
	if rule.TargetGroup != "" {
		return slices.Contains(node.Groups, rule.TargetGroup)
	}
	return true
}

func compileFirewallRulesForNode(state State, node Node, rules []FirewallRule) []FirewallRule {
	compiled := make([]FirewallRule, 0, len(rules))
	for _, source := range rules {
		if !firewallRuleTargetsNode(source, node) {
			continue
		}
		rule := source
		rule.TargetGroup = ""
		rule.TargetNodeID = ""
		if rule.PeerNodeID != "" {
			peer, ok := findNode(state, rule.PeerNodeID)
			if !ok || peer.NetworkID != node.NetworkID {
				// State validation normally makes this impossible. Omitting the
				// unresolved rule fails closed if a damaged snapshot is rendered.
				continue
			}
			rule.PeerNodeID = ""
			rule.Host = peer.IP
		}
		compiled = append(compiled, rule)
	}
	return compiled
}

func effectiveFirewallPolicyForNode(state State, node Node, policy FirewallPolicy) FirewallPolicy {
	effective := cloneFirewallPolicy(policy)
	effective.Inbound = compileFirewallRulesForNode(state, node, policy.Inbound)
	effective.Outbound = compileFirewallRulesForNode(state, node, policy.Outbound)
	return effective
}

func validateFirewallPolicyReferences(state State, network Network, policy FirewallPolicy) error {
	for direction, rules := range map[string][]FirewallRule{"inbound": policy.Inbound, "outbound": policy.Outbound} {
		for index, rule := range rules {
			for field, nodeID := range map[string]string{"peer_node_id": rule.PeerNodeID, "target_node_id": rule.TargetNodeID} {
				if nodeID == "" {
					continue
				}
				node, ok := findNode(state, nodeID)
				if !ok || node.NetworkID != network.ID {
					return fmt.Errorf("%w: %s firewall rule %d %s must reference a node in this network", ErrInvalid, direction, index+1, field)
				}
			}
		}
	}
	return nil
}

func effectiveFirewallPolicyDocuments(state State, network Network, policy FirewallPolicy) []EffectiveFirewallPolicyDocument {
	documents := []EffectiveFirewallPolicyDocument{}
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID || node.Status != "active" {
			continue
		}
		effective := effectiveFirewallPolicyForNode(state, node, policy)
		rendered := renderFirewallPolicyForNode(effective, certificateRoutedSubnets(network, node))
		documents = append(documents, EffectiveFirewallPolicyDocument{
			NodeID: node.ID, Name: node.Name, IP: node.IP, Groups: slices.Clone(node.Groups),
			Inbound: effective.Inbound, Outbound: effective.Outbound,
			RenderedFirewall: rendered, SHA256: ConfigDigest(rendered),
		})
	}
	sort.Slice(documents, func(i, j int) bool {
		if documents[i].Name != documents[j].Name {
			return documents[i].Name < documents[j].Name
		}
		return documents[i].NodeID < documents[j].NodeID
	})
	return documents
}

func firewallPolicyDocument(state State, network Network, policy FirewallPolicy) FirewallPolicyDocument {
	policy = cloneFirewallPolicy(policy)
	rendered := ""
	if !firewallPolicyUsesNodeScopes(policy) {
		rendered = renderFirewallPolicy(policy)
	}
	return FirewallPolicyDocument{
		NetworkID: network.ID, Mode: policy.Mode, RendererVersion: policy.RendererVersion,
		Inbound: policy.Inbound, Outbound: policy.Outbound,
		ConfigRevision: network.ConfigRevision, ConfigUpdatedAt: network.ConfigUpdatedAt,
		RenderedFirewall: rendered, PolicySHA256: firewallPolicySHA256(policy),
		EffectiveNodes: effectiveFirewallPolicyDocuments(state, network, policy),
	}
}

func nextConfigRevision(current int64, changed bool) (int64, error) {
	if !changed {
		return current, nil
	}
	if current == math.MaxInt64 {
		return 0, fmt.Errorf("%w: network config revision is exhausted", ErrConflict)
	}
	return current + 1, nil
}

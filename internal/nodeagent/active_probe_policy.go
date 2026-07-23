package nodeagent

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"mesh/internal/runtimeobserver"
)

const maxActiveProbeTargets = 8

type activeProbePlan struct {
	localAddress netip.Addr
	targets      []netip.Addr
}

type activeProbeFirewallRule struct {
	proto    string
	hostAny  bool
	groupAll bool
	cidr     netip.Prefix
}

// activeProbePlanFromVerifiedBundle is the no-I/O policy gate for future
// active overlay probes. The caller must supply the active Bundle returned by
// loadReconciledState; this function revalidates the certificate/topology and
// accepts only Mesh's exact signed static-map and firewall renderer grammar.
func activeProbePlanFromVerifiedBundle(bundle Bundle) (activeProbePlan, error) {
	topology, err := verifiedRuntimeTopologyFromBundle(bundle)
	if err != nil {
		return activeProbePlan{}, err
	}
	staticHosts, err := parseSignedStaticHostMap(bundle.SignedConfig, topology.network)
	if err != nil {
		return activeProbePlan{}, err
	}
	rules, err := parseSignedOutboundFirewall(bundle.SignedConfig, topology.network)
	if err != nil {
		return activeProbePlan{}, err
	}

	lighthouses := append([]netip.Addr(nil), topology.lighthouses...)
	sort.Slice(lighthouses, func(left, right int) bool {
		leftBytes := lighthouses[left].As4()
		rightBytes := lighthouses[right].As4()
		return bytes.Compare(leftBytes[:], rightBytes[:]) < 0
	})
	plan := activeProbePlan{localAddress: topology.localAddress, targets: make([]netip.Addr, 0, min(len(lighthouses), maxActiveProbeTargets))}
	for _, lighthouse := range lighthouses {
		if lighthouse == topology.localAddress {
			return activeProbePlan{}, runtimeobserver.ErrProtocol
		}
		if _, found := staticHosts[lighthouse]; !found {
			return activeProbePlan{}, runtimeobserver.ErrProtocol
		}
		if activeProbeTargetAllowed(lighthouse, rules) && len(plan.targets) < maxActiveProbeTargets {
			plan.targets = append(plan.targets, lighthouse)
		}
	}
	return plan, nil
}

func parseSignedStaticHostMap(config string, network netip.Prefix) (map[netip.Addr]struct{}, error) {
	endpoints, err := parseSignedStaticHostEndpoints(config, network)
	if err != nil {
		return nil, err
	}
	hosts := make(map[netip.Addr]struct{}, len(endpoints))
	for address := range endpoints {
		hosts[address] = struct{}{}
	}
	return hosts, nil
}

func parseSignedStaticHostEndpoints(config string, network netip.Prefix) (map[netip.Addr]string, error) {
	lines, start, end, err := signedConfigSection(config, "static_host_map:")
	if err != nil {
		return nil, err
	}
	hosts := make(map[netip.Addr]string, end-start)
	for index := start; index < end; index++ {
		line := lines[index]
		if !strings.HasPrefix(line, "  \"") || strings.HasPrefix(line, "   ") {
			return nil, runtimeobserver.ErrProtocol
		}
		separator := strings.Index(line[2:], ": [")
		if separator < 0 || !strings.HasSuffix(line, "]") {
			return nil, runtimeobserver.ErrProtocol
		}
		separator += 2
		keyRaw := line[2:separator]
		endpointRaw := line[separator+3 : len(line)-1]
		var key, endpoint string
		if json.Unmarshal([]byte(keyRaw), &key) != nil || strconv.Quote(key) != keyRaw ||
			json.Unmarshal([]byte(endpointRaw), &endpoint) != nil || strconv.Quote(endpoint) != endpointRaw || endpoint == "" {
			return nil, runtimeobserver.ErrProtocol
		}
		address, parseErr := netip.ParseAddr(key)
		if parseErr != nil || !address.Is4() || address.String() != key || !network.Contains(address) {
			return nil, runtimeobserver.ErrProtocol
		}
		if _, duplicate := hosts[address]; duplicate {
			return nil, runtimeobserver.ErrProtocol
		}
		hosts[address] = endpoint
	}
	return hosts, nil
}

func parseSignedOutboundFirewall(config string, network netip.Prefix) ([]activeProbeFirewallRule, error) {
	lines, start, end, err := signedConfigSection(config, "firewall:")
	if err != nil {
		return nil, err
	}
	rules, next, err := parseSignedFirewallDirection(lines, start, end, "outbound", network)
	if err != nil {
		return nil, err
	}
	_, next, err = parseSignedFirewallDirection(lines, next, end, "inbound", network)
	if err != nil || next != end {
		return nil, runtimeobserver.ErrProtocol
	}
	return rules, nil
}

func parseSignedFirewallDirection(lines []string, start, end int, direction string, network netip.Prefix) ([]activeProbeFirewallRule, int, error) {
	if start >= end {
		return nil, start, runtimeobserver.ErrProtocol
	}
	emptyHeader := "  " + direction + ": []"
	header := "  " + direction + ":"
	if lines[start] == emptyHeader {
		return []activeProbeFirewallRule{}, start + 1, nil
	}
	if lines[start] != header {
		return nil, start, runtimeobserver.ErrProtocol
	}
	rules := make([]activeProbeFirewallRule, 0, 2)
	index := start + 1
	for index < end && strings.HasPrefix(lines[index], "    - ") {
		if index+2 >= end || !strings.HasPrefix(lines[index], "    - port: ") || !strings.HasPrefix(lines[index+1], "      proto: ") {
			return nil, index, runtimeobserver.ErrProtocol
		}
		port := strings.TrimPrefix(lines[index], "    - port: ")
		proto := strings.TrimPrefix(lines[index+1], "      proto: ")
		if !validRenderedFirewallPort(port) || (proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp") {
			return nil, index, runtimeobserver.ErrProtocol
		}
		rule := activeProbeFirewallRule{proto: proto}
		selector := lines[index+2]
		switch {
		case selector == "      host: any":
			rule.hostAny = true
		case strings.HasPrefix(selector, "      cidr: "):
			value := strings.TrimPrefix(selector, "      cidr: ")
			prefix, parseErr := netip.ParsePrefix(value)
			if parseErr != nil || !prefix.Addr().Is4() || prefix.String() != value || prefix != prefix.Masked() || !network.Contains(prefix.Addr()) || prefix.Bits() < network.Bits() {
				return nil, index, runtimeobserver.ErrProtocol
			}
			rule.cidr = prefix
		case strings.HasPrefix(selector, "      group: "):
			value := strings.TrimPrefix(selector, "      group: ")
			group, valid := renderedFirewallGroup(value)
			if !valid {
				return nil, index, runtimeobserver.ErrProtocol
			}
			rule.groupAll = group == "all"
		default:
			return nil, index, runtimeobserver.ErrProtocol
		}
		if port != "any" {
			rule.hostAny = false
			rule.groupAll = false
			rule.cidr = netip.Prefix{}
		}
		rules = append(rules, rule)
		index += 3
	}
	if len(rules) == 0 {
		return nil, index, runtimeobserver.ErrProtocol
	}
	return rules, index, nil
}

func activeProbeTargetAllowed(target netip.Addr, rules []activeProbeFirewallRule) bool {
	for _, rule := range rules {
		if rule.proto != "any" && rule.proto != "icmp" {
			continue
		}
		if rule.hostAny || rule.groupAll || (rule.cidr.IsValid() && rule.cidr.Contains(target)) {
			return true
		}
	}
	return false
}

func signedConfigSection(config, header string) ([]string, int, int, error) {
	if config == "" || len(config) > maxBundleFileSize || !utf8ValidSignedConfig(config) {
		return nil, 0, 0, runtimeobserver.ErrProtocol
	}
	lines := strings.Split(config, "\n")
	headerIndex := -1
	for index, line := range lines {
		if line == header {
			if headerIndex != -1 {
				return nil, 0, 0, runtimeobserver.ErrProtocol
			}
			headerIndex = index
		}
	}
	if headerIndex == -1 {
		return nil, 0, 0, runtimeobserver.ErrProtocol
	}
	end := len(lines)
	for index := headerIndex + 1; index < len(lines); index++ {
		if lines[index] != "" && lines[index][0] != ' ' {
			end = index
			break
		}
	}
	return lines, headerIndex + 1, end, nil
}

func utf8ValidSignedConfig(config string) bool {
	return utf8.ValidString(config) && !strings.ContainsRune(config, '\r') && !strings.ContainsRune(config, '\x00')
}

func validRenderedFirewallPort(value string) bool {
	if value == "any" {
		return true
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return false
	}
	previous := 0
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 1 || parsed > 65535 || strconv.Itoa(parsed) != part || (index == 1 && parsed < previous) {
			return false
		}
		previous = parsed
	}
	return true
}

func renderedFirewallGroup(raw string) (string, bool) {
	var group string
	if json.Unmarshal([]byte(raw), &group) == nil && strconv.Quote(group) == raw {
		return group, validProbeGroup(group)
	}
	return raw, validProbeGroup(raw)
}

func validProbeGroup(group string) bool {
	if len(group) < 1 || len(group) > 32 {
		return false
	}
	for index, character := range group {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (index > 0 && (character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

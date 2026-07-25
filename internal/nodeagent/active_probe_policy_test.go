package nodeagent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"mesh/internal/runtimeobserver"
)

func TestActiveProbePlanMatchesOnlyProvedOutboundICMPPolicy(t *testing.T) {
	tests := []struct {
		name        string
		outbound    []string
		inbound     []string
		wantTargets []netip.Addr
	}{
		{name: "host any", outbound: []string{probeFirewallRule("icmp", "host: any")}, wantTargets: probeAddresses("10.42.0.1", "10.42.0.2")},
		{name: "any protocol", outbound: []string{probeFirewallRule("any", "host: any")}, wantTargets: probeAddresses("10.42.0.1", "10.42.0.2")},
		{name: "matching cidr", outbound: []string{probeFirewallRule("icmp", "cidr: 10.42.0.1/32")}, wantTargets: probeAddresses("10.42.0.1")},
		{name: "implicit all group", outbound: []string{probeFirewallRule("icmp", `group: "all"`)}, wantTargets: probeAddresses("10.42.0.1", "10.42.0.2")},
		{name: "tcp denies icmp", outbound: []string{probeFirewallRule("tcp", "host: any")}},
		{name: "inbound does not authorize request", inbound: []string{probeFirewallRule("icmp", "host: any")}},
		{name: "nonmatching cidr", outbound: []string{probeFirewallRule("icmp", "cidr: 10.42.0.20/32")}},
		{name: "unproved remote group", outbound: []string{probeFirewallRule("icmp", `group: "operators"`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := activeProbeConfig([]string{"10.42.0.1", "10.42.0.2"}, []string{"10.42.0.1", "10.42.0.2"}, test.outbound, test.inbound)
			bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, config)
			plan, err := activeProbePlanFromVerifiedBundle(bundle)
			if err != nil {
				t.Fatalf("activeProbePlanFromVerifiedBundle: %v", err)
			}
			if plan.localAddress != netip.MustParseAddr("10.42.0.9") || !slices.Equal(plan.targets, test.wantTargets) {
				t.Fatalf("plan = %#v, want local 10.42.0.9 targets %v", plan, test.wantTargets)
			}
		})
	}
}

func TestActiveProbePlanNoRemoteLighthouseIsNotEligible(t *testing.T) {
	config := activeProbeConfig(nil, nil, []string{probeFirewallRule("icmp", "host: any")}, nil)
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, config)
	plan, err := activeProbePlanFromVerifiedBundle(bundle)
	if err != nil || plan.localAddress != netip.MustParseAddr("10.42.0.9") || len(plan.targets) != 0 {
		t.Fatalf("empty plan = %#v, err=%v", plan, err)
	}
}

func TestActiveProbePlanRejectsUnprovedOrMalformedSignedTopology(t *testing.T) {
	tests := map[string]string{
		"lighthouse missing static map": activeProbeConfig([]string{"10.42.0.1"}, nil, []string{probeFirewallRule("icmp", "host: any")}, nil),
		"duplicate static key":          activeProbeConfig([]string{"10.42.0.1"}, []string{"10.42.0.1", "10.42.0.1"}, []string{probeFirewallRule("icmp", "host: any")}, nil),
		"duplicate firewall section":    activeProbeConfig([]string{"10.42.0.1"}, []string{"10.42.0.1"}, []string{probeFirewallRule("icmp", "host: any")}, nil) + "firewall:\n  outbound: []\n  inbound: []\n",
		"alternate yaml selector":       activeProbeConfig([]string{"10.42.0.1"}, []string{"10.42.0.1"}, []string{probeFirewallRule("icmp", `group: 'all'`)}, nil),
		"noncanonical static key":       strings.Replace(activeProbeConfig([]string{"10.42.0.1"}, []string{"10.42.0.1"}, []string{probeFirewallRule("icmp", "host: any")}, nil), `"10.42.0.1":`, `10.42.0.1:`, 1),
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, config)
			if _, err := activeProbePlanFromVerifiedBundle(bundle); !errors.Is(err, runtimeobserver.ErrProtocol) {
				t.Fatalf("invalid signed topology returned %v", err)
			}
		})
	}
}

func TestActiveProbePlanCapsTargetsInNumericOrder(t *testing.T) {
	hosts := []string{"10.42.0.9", "10.42.0.7", "10.42.0.5", "10.42.0.3", "10.42.0.1", "10.42.0.8", "10.42.0.6", "10.42.0.4", "10.42.0.2"}
	config := activeProbeConfig(hosts, hosts, []string{probeFirewallRule("icmp", "host: any")}, nil)
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.20/24")}, config)
	plan, err := activeProbePlanFromVerifiedBundle(bundle)
	want := probeAddresses("10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4", "10.42.0.5", "10.42.0.6", "10.42.0.7", "10.42.0.8")
	if err != nil || !slices.Equal(plan.targets, want) {
		t.Fatalf("bounded plan = %#v, err=%v, want %v", plan, err, want)
	}
}

func activeProbeConfig(lighthouses, staticHosts, outbound, inbound []string) string {
	var builder strings.Builder
	builder.WriteString("pki:\n  ca: /etc/nebula/ca.crt\n  cert: /etc/nebula/host.crt\n  key: /etc/nebula/host.key\n  disconnect_invalid: true\nstatic_host_map:\n")
	for index, host := range staticHosts {
		fmt.Fprintf(&builder, "  %q: [%q]\n", host, fmt.Sprintf("192.0.2.%d:4242", index+1))
	}
	builder.WriteString("lighthouse:\n  am_lighthouse: false\n  interval: 60\n")
	if len(lighthouses) == 0 {
		builder.WriteString("  hosts: []\n")
	} else {
		builder.WriteString("  hosts:\n")
		for _, host := range lighthouses {
			fmt.Fprintf(&builder, "    - %q\n", host)
		}
	}
	builder.WriteString("listen:\n  host: 0.0.0.0\n  port: 4242\npunchy:\n  punch: true\nfirewall:\n")
	writeProbeFirewallDirection(&builder, "outbound", outbound)
	writeProbeFirewallDirection(&builder, "inbound", inbound)
	builder.WriteString("logging:\n  level: info\n  format: json\n")
	return builder.String()
}

func writeProbeFirewallDirection(builder *strings.Builder, direction string, rules []string) {
	if len(rules) == 0 {
		fmt.Fprintf(builder, "  %s: []\n", direction)
		return
	}
	fmt.Fprintf(builder, "  %s:\n", direction)
	for _, rule := range rules {
		builder.WriteString(rule)
	}
}

func probeFirewallRule(proto, selector string) string {
	return fmt.Sprintf("    - port: any\n      proto: %s\n      %s\n", proto, selector)
}

func probeAddresses(values ...string) []netip.Addr {
	result := make([]netip.Addr, len(values))
	for index, value := range values {
		result[index] = netip.MustParseAddr(value)
	}
	return result
}

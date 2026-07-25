package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newNetworkDNSTestService(t *testing.T, migrateDNS bool) (*Service, *Store) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x64}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &countingIssuer{}
	service := NewService(store, box, issuer)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	issuer.now = service.now
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'N'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if migrateDNS {
		if err := service.EnsureNetworkDNSSchema(); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureNetworkRelaySchema(); err != nil {
			t.Fatal(err)
		}
	}
	return service, store
}

func TestEnsureNetworkDNSSchemaMigratesDisabledWithoutChangingSignedRevision(t *testing.T) {
	service, store := newNetworkDNSTestService(t, false)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "dns-migration", CIDR: "10.80.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if network.DNSSettings != (NetworkDNSSettings{}) {
		t.Fatalf("topology-v3 network unexpectedly carried DNS settings: %#v", network.DNSSettings)
	}
	beforeRevision, beforeUpdatedAt := network.ConfigRevision, network.ConfigUpdatedAt
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	var migrated State
	if err := store.View(func(state State) error { migrated = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != ControlStateVersionNetworkDNS || len(migrated.Networks) != 1 || migrated.Networks[0].DNSSettings != defaultNetworkDNSSettings() {
		t.Fatalf("unexpected DNS migration: version=%d networks=%#v", migrated.Version, migrated.Networks)
	}
	if migrated.Networks[0].ConfigRevision != beforeRevision || !migrated.Networks[0].ConfigUpdatedAt.Equal(beforeUpdatedAt) {
		t.Fatal("disabled DNS schema migration changed signed configuration lifecycle")
	}
	last := migrated.Audit[len(migrated.Audit)-1]
	if last.Action != "control.network_dns_schema_migrated" || last.Details["from_version"] != ControlStateVersionTopology || last.Details["to_version"] != ControlStateVersionNetworkDNS || last.Details["networks"] != 1 {
		t.Fatalf("unexpected DNS migration audit: %#v", last)
	}
	infoBefore, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatalf("topology startup step rejected current DNS schema: %v", err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) {
		t.Fatal("idempotent DNS schema migration rewrote the state file")
	}
}

func TestNetworkDNSLifecycleRendersOnlyLighthousesAndPreservesFirewallAccess(t *testing.T) {
	service, _ := newNetworkDNSTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "dns-lifecycle", CIDR: "10.81.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.NetworkDNS(network.ID)
	if err != nil || document.Schema != NetworkDNSDocumentSchema || document.Enabled || document.ListenPort != DefaultNetworkDNSPort || !document.FirewallReady || len(document.Resolvers) != 0 {
		t.Fatalf("unexpected initial DNS document: %#v err=%v", document, err)
	}

	lighthouse, err := service.CreateNode(network.ID, CreateNodeInput{Name: "lighthouse-dns", Role: "lighthouse", PublicEndpoint: "198.51.100.81:4242"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-dns"})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353})
	if err != nil || !enabled.Enabled || enabled.ListenPort != 5353 || enabled.ConfigRevision != network.ConfigRevision+1 || len(enabled.Resolvers) != 0 {
		t.Fatalf("enable DNS result=%#v err=%v", enabled, err)
	}
	// An identical retry is safe even if its expected revision is stale.
	replayed, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353})
	if err != nil || replayed.ConfigRevision != enabled.ConfigRevision {
		t.Fatalf("DNS update retry was not idempotent: %#v err=%v", replayed, err)
	}

	lighthouseToken := strings.Repeat("l", 42) + "A"
	lighthouseBundle, err := service.Enroll(context.Background(), lighthouse.EnrollmentToken, testNebulaPublicKey('L'), HashToken(lighthouseToken))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lighthouseBundle.Config, fmt.Sprintf("  serve_dns: true\n  dns:\n    host: %q\n    port: 5353\n", lighthouse.Node.IP)) {
		t.Fatalf("lighthouse config omitted exact DNS listener:\n%s", lighthouseBundle.Config)
	}
	memberToken := strings.Repeat("m", 42) + "A"
	memberBundle, err := service.Enroll(context.Background(), member.EnrollmentToken, testNebulaPublicKey('M'), HashToken(memberToken))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(memberBundle.Config, "serve_dns") || strings.Contains(memberBundle.Config, "\n  dns:\n") {
		t.Fatalf("member config was allowed to serve DNS:\n%s", memberBundle.Config)
	}
	document, err = service.NetworkDNS(network.ID)
	if err != nil || len(document.Resolvers) != 1 || document.Resolvers[0].NodeID != lighthouse.Node.ID || document.Resolvers[0].IP != lighthouse.Node.IP {
		t.Fatalf("active resolver projection=%#v err=%v", document, err)
	}

	restrictive := FirewallPolicyInput{
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "all"}},
		Outbound: []FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
	}
	if _, err := service.PreviewFirewallPolicy(network.ID, restrictive); !errors.Is(err, ErrConflict) {
		t.Fatalf("preview allowed DNS firewall access removal: %v", err)
	}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: document.ConfigRevision, Inbound: restrictive.Inbound, Outbound: restrictive.Outbound}); !errors.Is(err, ErrConflict) {
		t.Fatalf("update allowed DNS firewall access removal: %v", err)
	}

	disabled, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: document.ConfigRevision, Enabled: false, ListenPort: DefaultNetworkDNSPort})
	if err != nil || disabled.Enabled || disabled.ConfigRevision != document.ConfigRevision+1 || len(disabled.Resolvers) != 0 {
		t.Fatalf("disable DNS result=%#v err=%v", disabled, err)
	}
	disabledLighthouseConfig, err := service.AgentConfig(lighthouseToken)
	if err != nil || disabledLighthouseConfig.Revision != disabled.ConfigRevision {
		t.Fatalf("disabled lighthouse config=%#v err=%v", disabledLighthouseConfig, err)
	}
	if strings.Contains(disabledLighthouseConfig.Config, "serve_dns") || strings.Contains(disabledLighthouseConfig.Config, "\n  dns:\n") {
		t.Fatalf("disabled DNS remained in the lighthouse's next signed config:\n%s", disabledLighthouseConfig.Config)
	}
	disabledMemberConfig, err := service.AgentConfig(memberToken)
	if err != nil || disabledMemberConfig.Revision != disabled.ConfigRevision || strings.Contains(disabledMemberConfig.Config, "serve_dns") || strings.Contains(disabledMemberConfig.Config, "\n  dns:\n") {
		t.Fatalf("disabled member config=%#v err=%v", disabledMemberConfig, err)
	}
	policy, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: disabled.ConfigRevision, Inbound: restrictive.Inbound, Outbound: restrictive.Outbound})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: policy.ConfigRevision, Enabled: true, ListenPort: 5353}); !errors.Is(err, ErrConflict) {
		t.Fatalf("enabled DNS without complete firewall access: %v", err)
	}
	withDNS := restrictive
	withDNS.Inbound = append(withDNS.Inbound, FirewallRule{Proto: "udp", Port: "5353", Group: "all"})
	policy, err = service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: policy.ConfigRevision, Inbound: withDNS.Inbound, Outbound: withDNS.Outbound})
	if err != nil {
		t.Fatal(err)
	}
	reenabled, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: policy.ConfigRevision, Enabled: true, ListenPort: 5353})
	if err != nil {
		t.Fatalf("DNS did not enable after explicit UDP access: %v", err)
	}
	reenabledLighthouseConfig, err := service.AgentConfig(lighthouseToken)
	if err != nil || reenabledLighthouseConfig.Revision != reenabled.ConfigRevision || !strings.Contains(reenabledLighthouseConfig.Config, fmt.Sprintf("  serve_dns: true\n  dns:\n    host: %q\n    port: 5353\n", lighthouse.Node.IP)) {
		t.Fatalf("re-enabled lighthouse config=%#v err=%v", reenabledLighthouseConfig, err)
	}
	reenabledMemberConfig, err := service.AgentConfig(memberToken)
	if err != nil || reenabledMemberConfig.Revision != reenabled.ConfigRevision || strings.Contains(reenabledMemberConfig.Config, "serve_dns") || strings.Contains(reenabledMemberConfig.Config, "\n  dns:\n") {
		t.Fatalf("re-enabled member config=%#v err=%v", reenabledMemberConfig, err)
	}
}

func TestFirewallAllowsNetworkDNSOnlyWithCompletePeerCoverage(t *testing.T) {
	const networkCIDR = "10.83.0.0/24"
	for _, test := range []struct {
		name    string
		rule    FirewallRule
		allowed bool
	}{
		{name: "all group exact port", rule: FirewallRule{Proto: "udp", Port: "5353", Group: "all"}, allowed: true},
		{name: "any host covering range", rule: FirewallRule{Proto: "any", Port: "5300-5400", Host: "any"}, allowed: true},
		{name: "complete network CIDR", rule: FirewallRule{Proto: "udp", Port: "any", Host: networkCIDR}, allowed: true},
		{name: "other group", rule: FirewallRule{Proto: "udp", Port: "5353", Group: "dns-clients"}},
		{name: "individual host", rule: FirewallRule{Proto: "udp", Port: "5353", Host: "10.83.0.10"}},
		{name: "narrow CIDR", rule: FirewallRule{Proto: "udp", Port: "5353", Host: "10.83.0.0/25"}},
		{name: "wrong protocol", rule: FirewallRule{Proto: "tcp", Port: "5353", Group: "all"}},
		{name: "wrong port", rule: FirewallRule{Proto: "udp", Port: "5354", Host: "any"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := normalizeFirewallPolicy(FirewallPolicyInput{Inbound: []FirewallRule{test.rule}, Outbound: []FirewallRule{}}, networkCIDR)
			if err != nil {
				t.Fatal(err)
			}
			if allowed := firewallAllowsNetworkDNS(policy, networkCIDR, 5353); allowed != test.allowed {
				t.Fatalf("firewallAllowsNetworkDNS=%t, want %t for %#v", allowed, test.allowed, policy.Inbound)
			}
		})
	}
}

func TestNetworkDNSRejectsAmbiguousPortsAndStaleMutations(t *testing.T) {
	service, _ := newNetworkDNSTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "dns-validation", CIDR: "10.82.0.0/24", ListenPort: 4242})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]UpdateNetworkDNSInput{
		"zero":            {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 0},
		"too high":        {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 65536},
		"socket conflict": {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 4242},
		"disabled custom": {ExpectedConfigRevision: network.ConfigRevision, Enabled: false, ListenPort: 5353},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.UpdateNetworkDNS(network.ID, input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid DNS input returned %v", err)
			}
		})
	}
	updated, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5354}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale DNS mutation returned %v after revision %d", err, updated.ConfigRevision)
	}
}

package control

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func newNativeDNSTestService(t *testing.T) (*Service, *Store) {
	t.Helper()
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRoutePolicyTestService(t, service)
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	return service, service.store
}

func TestEnsureNativeDNSSchemaPreservesSignedArtifactsAndIsWriteFree(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRoutePolicyTestService(t, service)
	store := service.store
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "native-migration", CIDR: "10.143.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "native-member", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("n", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('N'), HashToken(agentToken)); err != nil {
		t.Fatal(err)
	}
	before, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	after, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("v12 migration changed signed desired artifact:\nbefore=%#v\nafter=%#v", before, after)
	}
	var state State
	if err := store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	if state.Version != ControlStateVersionNativeDNS || state.Networks[0].DNSSettings.NativeResolver || state.Networks[0].DNSSettings.SearchDomain != "" {
		t.Fatalf("unexpected native DNS migration: %#v", state)
	}
	last := state.Audit[len(state.Audit)-1]
	if last.Action != "control.native_dns_schema_migrated" || last.Details["from_version"] != ControlStateVersionRoutePolicies || last.Details["to_version"] != ControlStateVersionNativeDNS {
		t.Fatalf("unexpected native DNS migration audit: %#v", last)
	}
	beforeRaw, err := readPersistedState(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	afterRaw, err := readPersistedState(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatal("idempotent native DNS migration rewrote the store")
	}
}

func TestNativeDNSLifecycleRendersStrictNodeSpecificSignedPolicy(t *testing.T) {
	service, _ := newNativeDNSTestService(t)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "native-policy", CIDR: "10.144.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	lighthouse, err := service.CreateNode(network.ID, CreateNodeInput{Name: "lighthouse-native", Role: "lighthouse", PublicEndpoint: "198.51.100.144:4242"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-native", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{
		ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353,
		NativeResolver: true, SearchDomain: "corp.mesh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.NativeResolver || updated.SearchDomain != "corp.mesh" {
		t.Fatalf("native settings were not projected: %#v", updated)
	}
	lighthouseToken := strings.Repeat("h", 42) + "A"
	lighthouseBundle, err := service.Enroll(context.Background(), lighthouse.EnrollmentToken, testNebulaPublicKey('H'), HashToken(lighthouseToken))
	if err != nil {
		t.Fatal(err)
	}
	memberToken := strings.Repeat("m", 42) + "A"
	memberBundle, err := service.Enroll(context.Background(), member.EnrollmentToken, testNebulaPublicKey('M'), HashToken(memberToken))
	if err != nil {
		t.Fatal(err)
	}
	for label, bundle := range map[string]EnrollmentBundle{"lighthouse": lighthouseBundle, "member": memberBundle} {
		policy, present, err := ParseNativeDNSPolicy(bundle.Config)
		if err != nil || !present {
			t.Fatalf("%s signed config policy present=%t err=%v\n%s", label, present, err, bundle.Config)
		}
		if policy.Schema != NativeDNSPolicySchema || policy.LocalIP != bundle.Node.IP || policy.NetworkCIDR != network.CIDR || policy.SearchDomain != "corp.mesh" || len(policy.Resolvers) != 1 || policy.Resolvers[0] != (NativeDNSResolver{IP: lighthouse.Node.IP, Port: 5353}) {
			t.Fatalf("%s policy=%#v", label, policy)
		}
	}
	heartbeat := HeartbeatInput{
		AgentVersion: "native-dns-test", NebulaVersion: "1.10.3",
		AppliedConfigRevision: memberBundle.ConfigRevision, AppliedConfigSHA256: memberBundle.ConfigSHA256,
		CertificateFingerprint: memberBundle.CertificateFingerprint, CertificateGeneration: memberBundle.CertificateGeneration,
		NebulaRunning: true, Status: "healthy", BootID: "boot-native", Sequence: 1,
	}
	if _, err := service.Heartbeat(memberToken, heartbeat); !errors.Is(err, ErrConflict) {
		t.Fatalf("current native DNS artifact was acknowledged without host integration: %v", err)
	}
	heartbeat.NativeDNSActive = true
	acknowledged, err := service.Heartbeat(memberToken, heartbeat)
	if err != nil || !acknowledged.NativeDNSActive {
		t.Fatalf("native DNS heartbeat acknowledgment=%#v err=%v", acknowledged, err)
	}
	current, err := service.NetworkDNS(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: current.ConfigRevision, Enabled: false, ListenPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	config, err := service.AgentConfig(memberToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := ParseNativeDNSPolicy(config.Config); err != nil || present || strings.Contains(config.Config, NativeDNSPolicyPrefix) {
		t.Fatalf("disabled native policy remained present=%t err=%v\n%s", present, err, config.Config)
	}
	if disabled.NativeResolver || disabled.SearchDomain != "" {
		t.Fatalf("disable did not clear native resolver state: %#v", disabled)
	}
}

func TestNativeDNSRejectsUnsafeDomainsAndMalformedSignedPolicies(t *testing.T) {
	service, _ := newNativeDNSTestService(t)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "native-validation", CIDR: "10.145.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"", "Corp.mesh", " corp.mesh", "corp.mesh ", "bad_domain.mesh", "-bad.mesh", "bad-.mesh", "local", "corp.local", strings.Repeat("a", 64) + ".mesh"} {
		_, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{
			ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353,
			NativeResolver: true, SearchDomain: domain,
		})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("domain %q returned %v", domain, err)
		}
	}
	if _, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, ListenPort: 5353, SearchDomain: "corp.mesh"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("search domain without native integration returned %v", err)
	}
	for _, config := range []string{
		NativeDNSPolicyPrefix + "\n",
		NativeDNSPolicyPrefix + "\n" + NativeDNSPolicyPrefix + "e30\n",
		NativeDNSPolicyPrefix + "not-base64\n",
		NativeDNSPolicyPrefix + "e30\n",
		NativeDNSPolicyPrefix + "e30\n" + NativeDNSPolicyPrefix + "e30\n",
	} {
		if _, _, err := ParseNativeDNSPolicy(config); err == nil {
			t.Fatalf("malformed signed policy was accepted: %q", config)
		}
	}
}

package control

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/runtimetelemetry"
)

type readinessTestResolver struct {
	mu      sync.Mutex
	results map[string][]string
	errors  map[string]error
	calls   []string
}

func (r *readinessTestResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, host)
	values := append([]string(nil), r.results[host]...)
	return values, r.errors[host]
}

func (r *readinessTestResolver) calledHosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := append([]string(nil), r.calls...)
	return result
}

func TestNetworkReadinessSeparatesConfiguredAndExternalEvidence(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	resolver := &readinessTestResolver{results: map[string][]string{
		"LH.Example.": {"203.0.113.10", "2001:db8::10", "203.0.113.10", "not-an-ip"},
	}}
	service.endpointResolver = resolver
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "readiness", CIDR: "10.210.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateNode(network.ID, CreateNodeInput{Name: "alpha-lighthouse", Role: "lighthouse", PublicEndpoint: "LH.Example.:4242"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateNode(network.ID, CreateNodeInput{Name: "beta-lighthouse", Role: "lighthouse", PublicEndpoint: "198.51.100.20:4242"})
	if err != nil {
		t.Fatal(err)
	}
	for index, created := range []CreatedNode{first, second} {
		token := strings.Repeat(string(rune('a'+index)), 42) + "A"
		if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey(byte('A'+index)), HashToken(token)); err != nil {
			t.Fatalf("enroll lighthouse %d: %v", index, err)
		}
	}
	beforeAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.NetworkReadiness(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != NetworkReadinessSchemaV6 || !report.GeneratedAt.Equal(now) || report.Overall != NetworkReadinessOverallVerificationRequired {
		t.Fatalf("unexpected readiness identity: %#v", report)
	}
	if !report.Projection.Complete || report.Projection.ObservedLighthouses != 2 || report.Projection.IncludedLighthouses != 2 || report.Projection.LighthouseLimit != maxNetworkReadinessLighthouses {
		t.Fatalf("unexpected projection: %#v", report.Projection)
	}
	if report.Checks.ManagedRouteOverlap.Status != NetworkReadinessPass || report.Checks.ManagedRouteOverlap.EvidenceSource != "control_inventory" || report.Checks.ManagedRouteOverlap.OverlappingNetworkCount != 0 {
		t.Fatalf("unexpected managed-route check: %#v", report.Checks.ManagedRouteOverlap)
	}
	if route := report.Checks.ClientRouteOverlap; route.Status != NetworkReadinessUnknown || route.EvidenceSource != "not_observed" || route.ObservedNodes != 0 || route.RequiredNodes != 2 || route.OverlappingNodes != 0 || route.FreshnessWindowSeconds != 90 || route.EvidenceAt != nil {
		t.Fatalf("client-route check fabricated evidence: %#v", report.Checks.ClientRouteOverlap)
	}
	if redundancy := report.Checks.LighthouseRedundancy; redundancy.Status != NetworkReadinessPass || redundancy.ConfiguredLighthouses != 2 || redundancy.ActiveLighthouses != 2 || redundancy.RequiredLighthouses != 2 {
		t.Fatalf("unexpected redundancy check: %#v", redundancy)
	}
	if dns := report.Checks.DNSResolution; dns.Status != NetworkReadinessPass || dns.DNSNames != 1 || dns.ResolvedDNSNames != 1 || dns.UnresolvedDNSNames != 0 {
		t.Fatalf("unexpected DNS check: %#v", dns)
	}
	if udp := report.Checks.PublicUDPReachability; udp.Status != NetworkReadinessUnknown || udp.EvidenceSource != "not_observed" || udp.ObservedMembers != 0 || udp.VerifiedLighthouses != 0 || udp.RequiredLighthouses != 2 || udp.FreshnessWindowSeconds != 30 || udp.EvidenceAt != nil {
		t.Fatalf("UDP check fabricated delivery evidence: %#v", udp)
	}
	if len(report.Lighthouses) != 2 || report.Lighthouses[0].Name != "alpha-lighthouse" || report.Lighthouses[0].EndpointHostType != "dns" || report.Lighthouses[0].DNSResolution != "resolved" || report.Lighthouses[0].ResolvedAddressCount != 2 || report.Lighthouses[1].EndpointHostType != "ipv4" || report.Lighthouses[1].DNSResolution != "not_applicable" {
		t.Fatalf("unexpected lighthouse evidence: %#v", report.Lighthouses)
	}
	if got := resolver.calledHosts(); !reflect.DeepEqual(got, []string{"LH.Example."}) {
		t.Fatalf("resolver calls = %#v", got)
	}
	afterAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterAudit, beforeAudit) {
		t.Fatal("readiness projection mutated audit history")
	}
}

func TestNetworkReadinessBlocksUnresolvedDNSAndMissingActiveLighthouse(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	service.endpointResolver = &readinessTestResolver{errors: map[string]error{"missing.example": errors.New("private resolver diagnostic")}}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "blocked-readiness", CIDR: "10.211.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-lighthouse", Role: "lighthouse", PublicEndpoint: "missing.example:4242"}); err != nil {
		t.Fatal(err)
	}
	report, err := service.NetworkReadiness(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != NetworkReadinessOverallBlocked || report.Checks.LighthouseRedundancy.Status != NetworkReadinessBlocked || report.Checks.DNSResolution.Status != NetworkReadinessBlocked || report.Checks.DNSResolution.UnresolvedDNSNames != 1 {
		t.Fatalf("unready network was not blocked: %#v", report)
	}
	if strings.Contains(report.Checks.DNSResolution.Summary, "private resolver diagnostic") {
		t.Fatal("private DNS error leaked through readiness report")
	}
}

func TestNetworkReadinessProjectionLimitFailsClosed(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	resolver := &readinessTestResolver{}
	service.endpointResolver = resolver
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "bounded-readiness", CIDR: "10.212.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxNetworkReadinessLighthouses+1; index++ {
		_, err := service.CreateNode(network.ID, CreateNodeInput{Name: fmtReadinessNodeName(index), Role: "lighthouse", PublicEndpoint: "198.51.100.30:4242"})
		if err != nil {
			t.Fatalf("create lighthouse %d: %v", index, err)
		}
	}
	report, err := service.NetworkReadiness(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Projection.Complete || report.Projection.ObservedLighthouses != maxNetworkReadinessLighthouses+1 || report.Projection.IncludedLighthouses != maxNetworkReadinessLighthouses || len(report.Lighthouses) != maxNetworkReadinessLighthouses || report.Checks.DNSResolution.Status != NetworkReadinessBlocked || report.Overall != NetworkReadinessOverallBlocked {
		t.Fatalf("oversized readiness did not fail closed: %#v", report)
	}
	if calls := resolver.calledHosts(); len(calls) != 0 {
		t.Fatalf("IP-only readiness performed DNS calls: %#v", calls)
	}
}

func TestNetworkReadinessRejectsUnknownNetworkAndCanceledRequest(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	if _, err := service.NetworkReadiness(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing network returned %v", err)
	}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "cancel-readiness", CIDR: "10.213.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "dns-lighthouse", Role: "lighthouse", PublicEndpoint: "cancel.example:4242"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.NetworkReadiness(ctx, network.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness returned %v", err)
	}
	if _, err := service.NetworkReadiness(nil, network.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil-context readiness returned %v", err)
	}
}

func TestReadinessTopologyGroupsSitesAndRequiresIndependentLighthouseDomains(t *testing.T) {
	snapshot := readinessSnapshot{nodes: []Node{
		{ID: "lh-a", Name: "lh-a", Role: "lighthouse", Status: "active", Site: "aws-use1", FailureDomain: "aws-use1a"},
		{ID: "member-a", Name: "member-a", Role: "member", Status: "active", Site: "aws-use1", FailureDomain: "aws-use1a"},
		{ID: "lh-b", Name: "lh-b", Role: "lighthouse", Status: "active", Site: "gcp-use1", FailureDomain: "gcp-use1-b"},
		{ID: "pending", Name: "pending", Role: "member", Status: "pending", Site: "gcp-use1", FailureDomain: "gcp-use1-b"},
		{ID: "revoked", Name: "revoked", Role: "lighthouse", Status: "revoked", Site: "old-site", FailureDomain: "old-domain"},
	}}
	check, sites := deriveReadinessTopology(snapshot)
	if check.Status != NetworkReadinessPass || check.ConfiguredSites != 2 || check.ActiveSites != 2 || check.ActiveNodes != 3 || check.AssignedActiveNodes != 3 || check.ActiveLighthouses != 2 || check.AssignedActiveLighthouses != 2 || check.DistinctLighthouseFailureDomains != 2 || check.RequiredLighthouseFailureDomains != 2 {
		t.Fatalf("independent topology did not pass: %#v", check)
	}
	if len(sites) != 2 || sites[0].Name != "aws-use1" || sites[0].ConfiguredNodes != 2 || sites[0].ActiveMembers != 1 || sites[0].ActiveLighthouses != 1 || !reflect.DeepEqual(sites[0].FailureDomains, []string{"aws-use1a"}) || sites[1].Name != "gcp-use1" || sites[1].ConfiguredNodes != 2 {
		t.Fatalf("site grouping is not canonical: %#v", sites)
	}

	shared := snapshot
	shared.nodes = append([]Node(nil), snapshot.nodes...)
	shared.nodes[2].FailureDomain = "aws-use1a"
	check, _ = deriveReadinessTopology(shared)
	if check.Status != NetworkReadinessWarning || check.DistinctLighthouseFailureDomains != 1 {
		t.Fatalf("shared lighthouse domain did not warn: %#v", check)
	}

	unassigned := snapshot
	unassigned.nodes = append([]Node(nil), snapshot.nodes...)
	unassigned.nodes[1].Site = ""
	unassigned.nodes[1].FailureDomain = ""
	check, sites = deriveReadinessTopology(unassigned)
	if check.Status != NetworkReadinessWarning || check.AssignedActiveNodes != 2 || len(sites) != 3 || sites[2].Name != UnassignedTopologyLabel {
		t.Fatalf("unassigned active node did not remain explicit: check=%#v sites=%#v", check, sites)
	}
}

func TestReadinessUDPRequiresFreshExactAllTargetEvidence(t *testing.T) {
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	age := uint64(1_000)
	snapshot := readinessSnapshot{
		network: Network{ID: "network-1", CIDR: "10.214.0.0/24", ListenPort: 4242, FirewallPolicy: defaultManagedFirewallPolicy()},
		nodes: []Node{
			{ID: "lighthouse-1", NetworkID: "network-1", IP: "10.214.0.1", Role: "lighthouse", Status: "active"},
			{ID: "lighthouse-2", NetworkID: "network-1", IP: "10.214.0.2", Role: "lighthouse", Status: "active"},
			{ID: "member-1", NetworkID: "network-1", IP: "10.214.0.3", Role: "member", Status: "active", HeartbeatSequence: 7},
		},
		lighthouses: []Node{
			{ID: "lighthouse-1", NetworkID: "network-1", IP: "10.214.0.1", Role: "lighthouse", Status: "active"},
			{ID: "lighthouse-2", NetworkID: "network-1", IP: "10.214.0.2", Role: "lighthouse", Status: "active"},
		},
		health: FleetHealthReport{Nodes: []FleetNodeHealth{
			{ID: "lighthouse-1", Role: "lighthouse"},
			{ID: "lighthouse-2", Role: "lighthouse"},
			{ID: "member-1", Role: "member", Operational: true, HeartbeatSequence: 7},
		}},
		generatedAt: now,
	}
	record := runtimetelemetry.Record{
		NodeID: "member-1", HeartbeatSequence: 7, ReceivedAt: now.Add(-2 * time.Second),
		ProcessContinuity: runtimetelemetry.ContinuityUnavailable,
		Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV2, State: runtimetelemetry.StateUnknown},
		ActiveProbe: runtimetelemetry.ActiveProbeResult{
			Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
			SampleAgeMS: &age, Attempted: 2, Replied: 2, DurationMS: 250,
		},
		ProbeTransition: runtimetelemetry.ProbeTransitionUnclassified,
		RouteOverlap:    runtimetelemetry.UnsupportedRouteOverlap(), EndpointDNS: runtimetelemetry.UnsupportedEndpointDNS(),
	}

	got := deriveReadinessUDP(snapshot, []runtimetelemetry.Record{record}, 2)
	wantEvidenceAt := now.Add(-3 * time.Second)
	if got.Status != NetworkReadinessPass || got.EvidenceSource != "authenticated_member_active_probe" || got.ObservedMembers != 1 || got.RequiredMembers != 1 || got.VerifiedLighthouses != 2 || got.RequiredLighthouses != 2 || got.EvidenceAt == nil || !got.EvidenceAt.Equal(wantEvidenceAt) {
		t.Fatalf("fresh exact evidence did not pass: %#v", got)
	}

	multiMember := snapshot
	multiMember.nodes = append(append([]Node(nil), snapshot.nodes...), Node{ID: "member-2", NetworkID: "network-1", IP: "10.214.0.4", Role: "member", Status: "active", HeartbeatSequence: 8})
	multiMember.health.Nodes = append(append([]FleetNodeHealth(nil), snapshot.health.Nodes...), FleetNodeHealth{ID: "member-2", Role: "member", Operational: true, HeartbeatSequence: 8})
	partialMembers := deriveReadinessUDP(multiMember, []runtimetelemetry.Record{record}, 2)
	if partialMembers.Status != NetworkReadinessUnknown || partialMembers.RequiredMembers != 2 || partialMembers.ObservedMembers != 0 || partialMembers.EvidenceAt != nil {
		t.Fatalf("one member masked missing multi-member evidence: %#v", partialMembers)
	}
	secondRecord := record
	secondRecord.NodeID = "member-2"
	secondRecord.HeartbeatSequence = 8
	secondRecord.ReceivedAt = now.Add(-4 * time.Second)
	completeMembers := deriveReadinessUDP(multiMember, []runtimetelemetry.Record{record, secondRecord}, 2)
	if completeMembers.Status != NetworkReadinessPass || completeMembers.ObservedMembers != 2 || completeMembers.RequiredMembers != 2 || completeMembers.EvidenceAt == nil || !completeMembers.EvidenceAt.Equal(now.Add(-5*time.Second)) {
		t.Fatalf("complete multi-member evidence did not pass: %#v", completeMembers)
	}

	tests := []struct {
		name     string
		mutate   func(*readinessSnapshot, *runtimetelemetry.Record)
		records  func(runtimetelemetry.Record) []runtimetelemetry.Record
		required int
	}{
		{name: "partial reply", mutate: func(_ *readinessSnapshot, value *runtimetelemetry.Record) { value.ActiveProbe.Replied = 1 }, required: 2},
		{name: "stale effective sample", mutate: func(_ *readinessSnapshot, value *runtimetelemetry.Record) {
			value.ReceivedAt = now.Add(-30 * time.Second)
		}, required: 2},
		{name: "heartbeat mismatch", mutate: func(_ *readinessSnapshot, value *runtimetelemetry.Record) { value.HeartbeatSequence = 6 }, required: 2},
		{name: "member not operational", mutate: func(value *readinessSnapshot, _ *runtimetelemetry.Record) { value.health.Nodes[2].Operational = false }, required: 2},
		{name: "firewall denies probe", mutate: func(value *readinessSnapshot, _ *runtimetelemetry.Record) {
			value.network.FirewallPolicy.Outbound = []FirewallRule{{Proto: "tcp", Port: "any", Host: "any"}}
		}, required: 2},
		{name: "duplicate member record", records: func(value runtimetelemetry.Record) []runtimetelemetry.Record {
			return []runtimetelemetry.Record{value, value}
		}, required: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateSnapshot := snapshot
			candidateSnapshot.nodes = append([]Node(nil), snapshot.nodes...)
			candidateSnapshot.lighthouses = append([]Node(nil), snapshot.lighthouses...)
			candidateSnapshot.health.Nodes = append([]FleetNodeHealth(nil), snapshot.health.Nodes...)
			candidateRecord := record
			if test.mutate != nil {
				test.mutate(&candidateSnapshot, &candidateRecord)
			}
			records := []runtimetelemetry.Record{candidateRecord}
			if test.records != nil {
				records = test.records(candidateRecord)
			}
			result := deriveReadinessUDP(candidateSnapshot, records, test.required)
			if result.Status != NetworkReadinessUnknown || result.EvidenceSource != "not_observed" || result.ObservedMembers != 0 || result.VerifiedLighthouses != 0 || result.EvidenceAt != nil {
				t.Fatalf("unsafe evidence was accepted: %#v", result)
			}
		})
	}
}

func TestReadinessUDPRejectsMoreTargetsThanTheSignedProbeCanCover(t *testing.T) {
	now := time.Date(2026, 7, 20, 16, 30, 0, 0, time.UTC)
	snapshot := readinessSnapshot{
		network:     Network{ID: "network-1", CIDR: "10.215.0.0/24", ListenPort: 4242, FirewallPolicy: defaultManagedFirewallPolicy()},
		generatedAt: now,
	}
	for index := 1; index <= int(runtimetelemetry.MaxActiveProbeTargets)+1; index++ {
		lighthouse := Node{ID: fmtReadinessNodeName(index), NetworkID: "network-1", IP: "10.215.0." + fmtReadinessNodeOctet(index), Role: "lighthouse", Status: "active"}
		snapshot.nodes = append(snapshot.nodes, lighthouse)
		snapshot.lighthouses = append(snapshot.lighthouses, lighthouse)
	}
	result := deriveReadinessUDP(snapshot, nil, len(snapshot.lighthouses))
	if result.Status != NetworkReadinessUnknown || result.RequiredLighthouses != 9 || result.VerifiedLighthouses != 0 || result.EvidenceAt != nil {
		t.Fatalf("an unbounded target set produced evidence: %#v", result)
	}
}

func TestReadinessClientRoutesRequireEveryFreshOperationalActiveNode(t *testing.T) {
	now := time.Date(2026, 7, 20, 17, 0, 0, 0, time.UTC)
	snapshot := readinessSnapshot{
		network: Network{ID: "network-1", CIDR: "10.216.0.0/24", ListenPort: 4242, FirewallPolicy: defaultManagedFirewallPolicy()},
		nodes: []Node{
			{ID: "lighthouse-1", NetworkID: "network-1", Role: "lighthouse", Status: "active", HeartbeatSequence: 4},
			{ID: "member-1", NetworkID: "network-1", Role: "member", Status: "active", HeartbeatSequence: 7},
		},
		health: FleetHealthReport{Nodes: []FleetNodeHealth{
			{ID: "lighthouse-1", Role: "lighthouse", Operational: true, HeartbeatSequence: 4},
			{ID: "member-1", Role: "member", Operational: true, HeartbeatSequence: 7},
		}},
		generatedAt: now,
	}
	record := func(nodeID string, sequence int64, receivedAt time.Time, overlap bool) runtimetelemetry.Record {
		return runtimetelemetry.Record{
			NodeID: nodeID, HeartbeatSequence: sequence, ReceivedAt: receivedAt,
			ProcessContinuity: runtimetelemetry.ContinuityUnavailable,
			Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV2, State: runtimetelemetry.StateUnknown},
			ActiveProbe:       runtimetelemetry.UnsupportedActiveProbe(),
			ProbeTransition:   runtimetelemetry.ProbeTransitionUnavailable,
			RouteOverlap:      runtimetelemetry.ObservedRouteOverlap(overlap),
			EndpointDNS:       runtimetelemetry.UnsupportedEndpointDNS(),
		}
	}
	records := []runtimetelemetry.Record{
		record("lighthouse-1", 4, now.Add(-2*time.Second), false),
		record("member-1", 7, now.Add(-3*time.Second), false),
	}
	oneSecond := uint64(1_000)
	records[0].RouteOverlap.SampleAgeMS = &oneSecond
	records[1].RouteOverlap.SampleAgeMS = &oneSecond
	result := deriveReadinessClientRoutes(snapshot, records)
	wantEvidenceAt := now.Add(-4 * time.Second)
	if result.Status != NetworkReadinessPass || result.EvidenceSource != "authenticated_node_route_inventory" || result.ObservedNodes != 2 || result.RequiredNodes != 2 || result.OverlappingNodes != 0 || result.EvidenceAt == nil || !result.EvidenceAt.Equal(wantEvidenceAt) {
		t.Fatalf("complete no-overlap evidence did not pass: %#v", result)
	}

	blockedRecords := append([]runtimetelemetry.Record(nil), records...)
	blockedRecords[1].RouteOverlap = runtimetelemetry.ObservedRouteOverlap(true)
	blocked := deriveReadinessClientRoutes(snapshot, blockedRecords)
	if blocked.Status != NetworkReadinessBlocked || blocked.EvidenceSource != "authenticated_node_route_inventory" || blocked.ObservedNodes != 2 || blocked.OverlappingNodes != 1 || blocked.EvidenceAt == nil {
		t.Fatalf("observed overlap did not block: %#v", blocked)
	}

	tests := []struct {
		name   string
		mutate func(*readinessSnapshot, []runtimetelemetry.Record) []runtimetelemetry.Record
	}{
		{name: "missing node", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			return values[:1]
		}},
		{name: "stale node", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].ReceivedAt = now.Add(-90 * time.Second)
			return values
		}},
		{name: "sequence mismatch", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].HeartbeatSequence = 6
			return values
		}},
		{name: "nonoperational node", mutate: func(value *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			value.health.Nodes[1].Operational = false
			return values
		}},
		{name: "duplicate record", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			return append(values, values[1])
		}},
		{name: "unsupported platform", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].RouteOverlap = runtimetelemetry.UnsupportedRouteOverlap()
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateSnapshot := snapshot
			candidateSnapshot.health.Nodes = append([]FleetNodeHealth(nil), snapshot.health.Nodes...)
			candidateRecords := append([]runtimetelemetry.Record(nil), records...)
			candidateRecords = test.mutate(&candidateSnapshot, candidateRecords)
			got := deriveReadinessClientRoutes(candidateSnapshot, candidateRecords)
			if got.Status != NetworkReadinessUnknown || got.EvidenceSource != "not_observed" || got.ObservedNodes != 0 || got.RequiredNodes != 2 || got.OverlappingNodes != 0 || got.EvidenceAt != nil {
				t.Fatalf("incomplete evidence was accepted: %#v", got)
			}
		})
	}
}

func TestReadinessMemberDNSRequiresEveryFreshOperationalMember(t *testing.T) {
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	snapshot := readinessSnapshot{
		network: Network{ID: "network-1", CIDR: "10.217.0.0/24", ListenPort: 4242},
		nodes: []Node{
			{ID: "lighthouse-1", NetworkID: "network-1", Role: "lighthouse", Status: "active", HeartbeatSequence: 4},
			{ID: "member-1", NetworkID: "network-1", Role: "member", Status: "active", HeartbeatSequence: 7},
			{ID: "member-2", NetworkID: "network-1", Role: "member", Status: "active", HeartbeatSequence: 9},
		},
		health: FleetHealthReport{Nodes: []FleetNodeHealth{
			{ID: "lighthouse-1", Role: "lighthouse", Operational: true, HeartbeatSequence: 4},
			{ID: "member-1", Role: "member", Operational: true, HeartbeatSequence: 7},
			{ID: "member-2", Role: "member", Operational: true, HeartbeatSequence: 9},
		}},
		generatedAt: now,
	}
	record := func(nodeID string, sequence int64, receivedAt time.Time, resolved uint64) runtimetelemetry.Record {
		return runtimetelemetry.Record{
			NodeID: nodeID, HeartbeatSequence: sequence, ReceivedAt: receivedAt,
			ProcessContinuity: runtimetelemetry.ContinuityUnavailable,
			Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV2, State: runtimetelemetry.StateUnknown},
			ActiveProbe:       runtimetelemetry.UnsupportedActiveProbe(),
			ProbeTransition:   runtimetelemetry.ProbeTransitionUnavailable,
			RouteOverlap:      runtimetelemetry.UnsupportedRouteOverlap(),
			EndpointDNS:       runtimetelemetry.ObservedEndpointDNS(1, resolved),
		}
	}
	records := []runtimetelemetry.Record{
		record("member-1", 7, now.Add(-2*time.Second), 1),
		record("member-2", 9, now.Add(-3*time.Second), 1),
	}
	oneSecond := uint64(1_000)
	records[0].EndpointDNS.SampleAgeMS = &oneSecond
	records[1].EndpointDNS.SampleAgeMS = &oneSecond
	result := deriveReadinessMemberDNS(snapshot, records, 1)
	if result.Status != NetworkReadinessPass || result.EvidenceSource != "authenticated_member_dns_resolution" || result.ObservedMembers != 2 || result.RequiredMembers != 2 || result.FailingMembers != 0 || result.DNSNames != 1 || result.EvidenceAt == nil || !result.EvidenceAt.Equal(now.Add(-4*time.Second)) {
		t.Fatalf("complete member DNS evidence did not pass: %#v", result)
	}

	blockedRecords := append([]runtimetelemetry.Record(nil), records...)
	blockedRecords[1].EndpointDNS = runtimetelemetry.ObservedEndpointDNS(1, 0)
	blocked := deriveReadinessMemberDNS(snapshot, blockedRecords, 1)
	if blocked.Status != NetworkReadinessBlocked || blocked.EvidenceSource != "authenticated_member_dns_resolution" || blocked.ObservedMembers != 2 || blocked.FailingMembers != 1 || blocked.EvidenceAt == nil {
		t.Fatalf("observed member DNS failure did not block: %#v", blocked)
	}

	tests := []struct {
		name   string
		mutate func(*readinessSnapshot, []runtimetelemetry.Record) []runtimetelemetry.Record
	}{
		{name: "missing member", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			return values[:1]
		}},
		{name: "stale member", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].ReceivedAt = now.Add(-90 * time.Second)
			return values
		}},
		{name: "sequence mismatch", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].HeartbeatSequence = 8
			return values
		}},
		{name: "nonoperational member", mutate: func(value *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			value.health.Nodes[2].Operational = false
			return values
		}},
		{name: "duplicate record", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			return append(values, values[1])
		}},
		{name: "unsupported resolver", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].EndpointDNS = runtimetelemetry.UnsupportedEndpointDNS()
			return values
		}},
		{name: "wrong configured count", mutate: func(_ *readinessSnapshot, values []runtimetelemetry.Record) []runtimetelemetry.Record {
			values[1].EndpointDNS = runtimetelemetry.ObservedEndpointDNS(2, 2)
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateSnapshot := snapshot
			candidateSnapshot.health.Nodes = append([]FleetNodeHealth(nil), snapshot.health.Nodes...)
			candidateRecords := append([]runtimetelemetry.Record(nil), records...)
			candidateRecords = test.mutate(&candidateSnapshot, candidateRecords)
			got := deriveReadinessMemberDNS(candidateSnapshot, candidateRecords, 1)
			if got.Status != NetworkReadinessUnknown || got.EvidenceSource != "not_observed" || got.ObservedMembers != 0 || got.RequiredMembers != 2 || got.FailingMembers != 0 || got.EvidenceAt != nil {
				t.Fatalf("incomplete member DNS evidence was accepted: %#v", got)
			}
		})
	}
}

func fmtReadinessNodeName(index int) string {
	const digits = "0123456789"
	if index < 10 {
		return "lighthouse-0" + string(digits[index])
	}
	return "lighthouse-" + string(digits[index/10]) + string(digits[index%10])
}

func fmtReadinessNodeOctet(index int) string {
	const digits = "0123456789"
	if index < 10 {
		return string(digits[index])
	}
	return string(digits[index/10]) + string(digits[index%10])
}

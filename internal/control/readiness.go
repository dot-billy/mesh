package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"mesh/internal/runtimetelemetry"
)

const (
	NetworkReadinessSchemaV2 = "mesh-network-readiness-v2"
	NetworkReadinessSchemaV3 = "mesh-network-readiness-v3"
	NetworkReadinessSchemaV4 = "mesh-network-readiness-v4"
	NetworkReadinessSchemaV5 = "mesh-network-readiness-v5"
	NetworkReadinessSchemaV6 = "mesh-network-readiness-v6"

	NetworkReadinessPass    = "pass"
	NetworkReadinessWarning = "warning"
	NetworkReadinessBlocked = "blocked"
	NetworkReadinessUnknown = "unknown"

	NetworkReadinessOverallBlocked              = "blocked"
	NetworkReadinessOverallVerificationRequired = "verification_required"
	NetworkReadinessOverallReady                = "ready"

	maxNetworkReadinessLighthouses = 64
	maxReadinessResolvedAddresses  = 16
	maxConcurrentReadinessLookups  = 4
	networkReadinessDNSTimeout     = 3 * time.Second
)

type endpointHostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

// NetworkReadinessReport is a read-only deployment projection. Its evidence
// sources are intentionally explicit: configuration and control inventory can
// be authoritative, DNS is only observed from the control-plane resolver,
// route safety requires fresh current evidence from every active node, and
// public UDP passes only from fresh current all-lighthouse member probes.
type NetworkReadinessReport struct {
	Schema      string                  `json:"schema"`
	GeneratedAt time.Time               `json:"generated_at"`
	Overall     string                  `json:"overall"`
	Network     NetworkReadinessNetwork `json:"network"`
	Projection  ReadinessProjection     `json:"projection"`
	Checks      NetworkReadinessChecks  `json:"checks"`
	Lighthouses []ReadinessLighthouse   `json:"lighthouses"`
	Sites       []ReadinessSite         `json:"sites"`
}

type NetworkReadinessNetwork struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CIDR       string `json:"cidr"`
	ListenPort int    `json:"listen_port"`
}

type ReadinessProjection struct {
	Complete            bool `json:"complete"`
	ObservedLighthouses int  `json:"observed_lighthouses"`
	IncludedLighthouses int  `json:"included_lighthouses"`
	LighthouseLimit     int  `json:"lighthouse_limit"`
}

type NetworkReadinessChecks struct {
	ManagedRouteOverlap   ReadinessRouteCheck       `json:"managed_route_overlap"`
	ClientRouteOverlap    ReadinessClientRouteCheck `json:"client_route_overlap"`
	LighthouseRedundancy  ReadinessRedundancyCheck  `json:"lighthouse_redundancy"`
	TopologyDiversity     ReadinessTopologyCheck    `json:"topology_diversity"`
	DNSResolution         ReadinessDNSCheck         `json:"dns_resolution"`
	MemberDNSResolution   ReadinessMemberDNSCheck   `json:"member_dns_resolution"`
	PublicUDPReachability ReadinessUDPCheck         `json:"public_udp_reachability"`
}

type ReadinessRouteCheck struct {
	Status                  string `json:"status"`
	EvidenceSource          string `json:"evidence_source"`
	OverlappingNetworkCount int    `json:"overlapping_network_count"`
	Summary                 string `json:"summary"`
	Action                  string `json:"action"`
}

type ReadinessExternalCheck struct {
	Status         string `json:"status"`
	EvidenceSource string `json:"evidence_source"`
	Summary        string `json:"summary"`
	Action         string `json:"action"`
}

type ReadinessClientRouteCheck struct {
	Status                 string     `json:"status"`
	EvidenceSource         string     `json:"evidence_source"`
	ObservedNodes          int        `json:"observed_nodes"`
	RequiredNodes          int        `json:"required_nodes"`
	OverlappingNodes       int        `json:"overlapping_nodes"`
	FreshnessWindowSeconds int64      `json:"freshness_window_seconds"`
	EvidenceAt             *time.Time `json:"evidence_at"`
	Summary                string     `json:"summary"`
	Action                 string     `json:"action"`
}

type ReadinessRedundancyCheck struct {
	Status                string `json:"status"`
	EvidenceSource        string `json:"evidence_source"`
	ConfiguredLighthouses int    `json:"configured_lighthouses"`
	ActiveLighthouses     int    `json:"active_lighthouses"`
	RequiredLighthouses   int    `json:"required_lighthouses"`
	Summary               string `json:"summary"`
	Action                string `json:"action"`
}

// ReadinessTopologyCheck separates declared placement from Nebula certificate
// groups and proves whether active lighthouses span independent, explicitly
// assigned failure domains. "unassigned" is never counted as diversity.
type ReadinessTopologyCheck struct {
	Status                           string `json:"status"`
	EvidenceSource                   string `json:"evidence_source"`
	ConfiguredSites                  int    `json:"configured_sites"`
	ActiveSites                      int    `json:"active_sites"`
	ActiveNodes                      int    `json:"active_nodes"`
	AssignedActiveNodes              int    `json:"assigned_active_nodes"`
	ActiveLighthouses                int    `json:"active_lighthouses"`
	AssignedActiveLighthouses        int    `json:"assigned_active_lighthouses"`
	DistinctLighthouseFailureDomains int    `json:"distinct_lighthouse_failure_domains"`
	RequiredLighthouseFailureDomains int    `json:"required_lighthouse_failure_domains"`
	Summary                          string `json:"summary"`
	Action                           string `json:"action"`
}

type ReadinessDNSCheck struct {
	Status             string `json:"status"`
	EvidenceSource     string `json:"evidence_source"`
	DNSNames           int    `json:"dns_names"`
	ResolvedDNSNames   int    `json:"resolved_dns_names"`
	UnresolvedDNSNames int    `json:"unresolved_dns_names"`
	Summary            string `json:"summary"`
	Action             string `json:"action"`
}

type ReadinessMemberDNSCheck struct {
	Status                 string     `json:"status"`
	EvidenceSource         string     `json:"evidence_source"`
	ObservedMembers        int        `json:"observed_members"`
	RequiredMembers        int        `json:"required_members"`
	FailingMembers         int        `json:"failing_members"`
	DNSNames               int        `json:"dns_names"`
	FreshnessWindowSeconds int64      `json:"freshness_window_seconds"`
	EvidenceAt             *time.Time `json:"evidence_at"`
	Summary                string     `json:"summary"`
	Action                 string     `json:"action"`
}

type ReadinessUDPCheck struct {
	Status                 string     `json:"status"`
	EvidenceSource         string     `json:"evidence_source"`
	ObservedMembers        int        `json:"observed_members"`
	RequiredMembers        int        `json:"required_members"`
	VerifiedLighthouses    int        `json:"verified_lighthouses"`
	RequiredLighthouses    int        `json:"required_lighthouses"`
	FreshnessWindowSeconds int64      `json:"freshness_window_seconds"`
	EvidenceAt             *time.Time `json:"evidence_at"`
	Summary                string     `json:"summary"`
	Action                 string     `json:"action"`
}

type ReadinessLighthouse struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Site                 string `json:"site"`
	FailureDomain        string `json:"failure_domain"`
	LifecycleStatus      string `json:"lifecycle_status"`
	PublicEndpoint       string `json:"public_endpoint"`
	EndpointHostType     string `json:"endpoint_host_type"`
	DNSResolution        string `json:"dns_resolution"`
	ResolvedAddressCount int    `json:"resolved_address_count"`
}

type ReadinessSite struct {
	Name              string   `json:"name"`
	ConfiguredNodes   int      `json:"configured_nodes"`
	ActiveNodes       int      `json:"active_nodes"`
	ActiveMembers     int      `json:"active_members"`
	ActiveLighthouses int      `json:"active_lighthouses"`
	FailureDomains    []string `json:"failure_domains"`
}

type readinessSnapshot struct {
	network     Network
	networks    []Network
	nodes       []Node
	lighthouses []Node
	health      FleetHealthReport
	generatedAt time.Time
}

type readinessDNSResult struct {
	host     string
	count    int
	resolved bool
}

// NetworkReadiness derives one stable control-inventory snapshot and then
// performs bounded DNS lookups outside the store transaction. It never dials a
// configured endpoint: a UDP Dial would not prove packet delivery, and calling
// it reachability evidence would create a false readiness claim.
func (s *Service) NetworkReadiness(ctx context.Context, networkID string) (NetworkReadinessReport, error) {
	return s.networkReadiness(ctx, networkID, nil)
}

// NetworkReadinessWithRuntime adds separately stored authenticated runtime
// records to the same fail-closed deployment projection. Callers must obtain a
// stable List before this method; a concurrent newer heartbeat can only make
// its sequence comparison fail and return unknown evidence.
func (s *Service) NetworkReadinessWithRuntime(ctx context.Context, networkID string, records []runtimetelemetry.Record) (NetworkReadinessReport, error) {
	return s.networkReadiness(ctx, networkID, records)
}

func (s *Service) networkReadiness(ctx context.Context, networkID string, records []runtimetelemetry.Record) (NetworkReadinessReport, error) {
	if s == nil || s.now == nil || s.endpointResolver == nil {
		return NetworkReadinessReport{}, ErrInvalidStateStore
	}
	if ctx == nil {
		return NetworkReadinessReport{}, fmt.Errorf("%w: readiness requires a request context", ErrInvalid)
	}
	var snapshot readinessSnapshot
	if err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("network readiness requires a valid timestamp")
		}
		snapshot.network = network
		snapshot.networks = append([]Network(nil), state.Networks...)
		snapshot.generatedAt = now
		for _, node := range state.Nodes {
			if node.NetworkID != networkID {
				continue
			}
			snapshot.nodes = append(snapshot.nodes, node)
			if node.Role == "lighthouse" && node.Status != "revoked" {
				snapshot.lighthouses = append(snapshot.lighthouses, node)
			}
		}
		health, err := deriveFleetHealth(state, networkID, now)
		if err != nil {
			return err
		}
		snapshot.health = health
		return nil
	}); err != nil {
		return NetworkReadinessReport{}, err
	}
	return s.deriveNetworkReadiness(ctx, snapshot, records)
}

func (s *Service) deriveNetworkReadiness(ctx context.Context, snapshot readinessSnapshot, records []runtimetelemetry.Record) (NetworkReadinessReport, error) {
	sort.Slice(snapshot.lighthouses, func(i, j int) bool {
		if snapshot.lighthouses[i].Name != snapshot.lighthouses[j].Name {
			return snapshot.lighthouses[i].Name < snapshot.lighthouses[j].Name
		}
		return snapshot.lighthouses[i].ID < snapshot.lighthouses[j].ID
	})
	observed := len(snapshot.lighthouses)
	included := observed
	if included > maxNetworkReadinessLighthouses {
		included = maxNetworkReadinessLighthouses
	}
	projectionComplete := included == observed
	projected := snapshot.lighthouses[:included]

	report := NetworkReadinessReport{
		Schema: NetworkReadinessSchemaV6, GeneratedAt: snapshot.generatedAt,
		Network:     NetworkReadinessNetwork{ID: snapshot.network.ID, Name: snapshot.network.Name, CIDR: snapshot.network.CIDR, ListenPort: snapshot.network.ListenPort},
		Projection:  ReadinessProjection{Complete: projectionComplete, ObservedLighthouses: observed, IncludedLighthouses: included, LighthouseLimit: maxNetworkReadinessLighthouses},
		Lighthouses: make([]ReadinessLighthouse, 0, included),
	}

	overlaps := 0
	for _, candidate := range snapshot.networks {
		if candidate.ID != snapshot.network.ID && cidrsOverlap(snapshot.network.CIDR, candidate.CIDR) {
			overlaps++
		}
	}
	routeStatus, routeSummary, routeAction := NetworkReadinessPass, "No other Mesh-managed network overlaps this CIDR.", "No control-inventory action is required."
	if overlaps != 0 {
		routeStatus = NetworkReadinessBlocked
		routeSummary = "This CIDR overlaps another Mesh-managed network."
		routeAction = "Move this network to an unused CIDR before enrolling nodes."
	}
	report.Checks.ManagedRouteOverlap = ReadinessRouteCheck{Status: routeStatus, EvidenceSource: "control_inventory", OverlappingNetworkCount: overlaps, Summary: routeSummary, Action: routeAction}
	report.Checks.ClientRouteOverlap = deriveReadinessClientRoutes(snapshot, records)

	active := 0
	for _, lighthouse := range snapshot.lighthouses {
		if lighthouse.Status == "active" {
			active++
		}
	}
	redundancyStatus := NetworkReadinessPass
	redundancySummary := fmt.Sprintf("%d active lighthouses meet the redundancy target.", active)
	redundancyAction := "Keep both lighthouses on independent failure domains when possible."
	if active == 0 {
		redundancyStatus = NetworkReadinessBlocked
		redundancySummary = "No active lighthouse is available to bootstrap members."
		redundancyAction = "Create, enroll, and activate a public lighthouse before adding members."
	} else if active < fleetRequiredLighthouses {
		redundancyStatus = NetworkReadinessWarning
		redundancySummary = "Only one active lighthouse is configured."
		redundancyAction = "Add and activate a second lighthouse on an independent failure domain."
	}
	report.Checks.LighthouseRedundancy = ReadinessRedundancyCheck{
		Status: redundancyStatus, EvidenceSource: "control_inventory", ConfiguredLighthouses: observed,
		ActiveLighthouses: active, RequiredLighthouses: fleetRequiredLighthouses,
		Summary: redundancySummary, Action: redundancyAction,
	}
	report.Checks.TopologyDiversity, report.Sites = deriveReadinessTopology(snapshot)

	dnsHosts := make(map[string]string)
	activeDNSHosts := make(map[string]struct{})
	for _, lighthouse := range projected {
		host, _, _ := net.SplitHostPort(lighthouse.PublicEndpoint)
		if net.ParseIP(host) == nil {
			key := strings.ToLower(strings.TrimSuffix(host, "."))
			dnsHosts[key] = host
			if lighthouse.Status == "active" {
				activeDNSHosts[key] = struct{}{}
			}
		}
	}
	dnsResults, err := s.resolveReadinessDNS(ctx, dnsHosts)
	if err != nil {
		return NetworkReadinessReport{}, err
	}
	resolvedNames := 0
	for key := range dnsHosts {
		if dnsResults[key].resolved {
			resolvedNames++
		}
	}
	unresolvedNames := len(dnsHosts) - resolvedNames
	dnsStatus := NetworkReadinessPass
	dnsSummary := "All configured lighthouse endpoints use IP literals; DNS is not required."
	dnsAction := "No DNS action is required."
	if !projectionComplete {
		dnsStatus = NetworkReadinessBlocked
		dnsSummary = "The lighthouse inventory exceeds the bounded readiness projection."
		dnsAction = fmt.Sprintf("Reduce the network to at most %d non-revoked lighthouses before relying on this report.", maxNetworkReadinessLighthouses)
	} else if len(dnsHosts) != 0 && unresolvedNames == 0 {
		dnsSummary = fmt.Sprintf("All %d configured lighthouse DNS names resolve from the control plane.", len(dnsHosts))
		dnsAction = "Confirm the same names resolve from every member network."
	} else if unresolvedNames != 0 {
		dnsStatus = NetworkReadinessBlocked
		dnsSummary = fmt.Sprintf("%d of %d configured lighthouse DNS names do not resolve from the control plane.", unresolvedNames, len(dnsHosts))
		dnsAction = "Publish or correct those DNS records, then run readiness again."
	}
	report.Checks.DNSResolution = ReadinessDNSCheck{
		Status: dnsStatus, EvidenceSource: "control_plane_dns", DNSNames: len(dnsHosts),
		ResolvedDNSNames: resolvedNames, UnresolvedDNSNames: unresolvedNames,
		Summary: dnsSummary, Action: dnsAction,
	}
	report.Checks.MemberDNSResolution = deriveReadinessMemberDNS(snapshot, records, len(activeDNSHosts))

	for _, lighthouse := range projected {
		host, _, _ := net.SplitHostPort(lighthouse.PublicEndpoint)
		hostType, resolution, resolvedCount := "dns", "unresolved", 0
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				hostType = "ipv4"
			} else {
				hostType = "ipv6"
			}
			resolution = "not_applicable"
		} else {
			key := strings.ToLower(strings.TrimSuffix(host, "."))
			result := dnsResults[key]
			if result.resolved {
				resolution = "resolved"
				resolvedCount = result.count
			}
		}
		report.Lighthouses = append(report.Lighthouses, ReadinessLighthouse{
			ID: lighthouse.ID, Name: lighthouse.Name, Site: readinessTopologyLabel(lighthouse.Site), FailureDomain: readinessTopologyLabel(lighthouse.FailureDomain), LifecycleStatus: lighthouse.Status,
			PublicEndpoint: lighthouse.PublicEndpoint, EndpointHostType: hostType,
			DNSResolution: resolution, ResolvedAddressCount: resolvedCount,
		})
	}

	report.Checks.PublicUDPReachability = deriveReadinessUDP(snapshot, records, active)
	report.Overall = readinessOverall(report)
	return report, nil
}

func readinessTopologyLabel(value string) string {
	if validTopologyLabel(value) {
		return value
	}
	return UnassignedTopologyLabel
}

func deriveReadinessTopology(snapshot readinessSnapshot) (ReadinessTopologyCheck, []ReadinessSite) {
	type siteAccumulator struct {
		configuredNodes   int
		activeNodes       int
		activeMembers     int
		activeLighthouses int
		failureDomains    map[string]struct{}
	}
	sites := make(map[string]*siteAccumulator)
	activeNodes, assignedActiveNodes := 0, 0
	activeLighthouses, assignedActiveLighthouses := 0, 0
	lighthouseFailureDomains := make(map[string]struct{})
	for _, node := range snapshot.nodes {
		if node.Status == "revoked" {
			continue
		}
		siteName := readinessTopologyLabel(node.Site)
		failureDomain := readinessTopologyLabel(node.FailureDomain)
		site := sites[siteName]
		if site == nil {
			site = &siteAccumulator{failureDomains: make(map[string]struct{})}
			sites[siteName] = site
		}
		site.configuredNodes++
		site.failureDomains[failureDomain] = struct{}{}
		if node.Status != "active" {
			continue
		}
		activeNodes++
		site.activeNodes++
		assigned := siteName != UnassignedTopologyLabel && failureDomain != UnassignedTopologyLabel
		if assigned {
			assignedActiveNodes++
		}
		if node.Role == "member" {
			site.activeMembers++
			continue
		}
		if node.Role == "lighthouse" {
			activeLighthouses++
			site.activeLighthouses++
			if assigned {
				assignedActiveLighthouses++
				lighthouseFailureDomains[failureDomain] = struct{}{}
			}
		}
	}

	siteNames := make([]string, 0, len(sites))
	for name := range sites {
		siteNames = append(siteNames, name)
	}
	sort.Strings(siteNames)
	resultSites := make([]ReadinessSite, 0, len(siteNames))
	activeSites := 0
	for _, name := range siteNames {
		value := sites[name]
		if value.activeNodes != 0 {
			activeSites++
		}
		failureDomains := make([]string, 0, len(value.failureDomains))
		for failureDomain := range value.failureDomains {
			failureDomains = append(failureDomains, failureDomain)
		}
		sort.Strings(failureDomains)
		resultSites = append(resultSites, ReadinessSite{
			Name: name, ConfiguredNodes: value.configuredNodes, ActiveNodes: value.activeNodes,
			ActiveMembers: value.activeMembers, ActiveLighthouses: value.activeLighthouses,
			FailureDomains: failureDomains,
		})
	}

	check := ReadinessTopologyCheck{
		Status: NetworkReadinessWarning, EvidenceSource: "control_inventory",
		ConfiguredSites: len(resultSites), ActiveSites: activeSites,
		ActiveNodes: activeNodes, AssignedActiveNodes: assignedActiveNodes,
		ActiveLighthouses: activeLighthouses, AssignedActiveLighthouses: assignedActiveLighthouses,
		DistinctLighthouseFailureDomains: len(lighthouseFailureDomains),
		RequiredLighthouseFailureDomains: fleetRequiredLighthouses,
	}
	switch {
	case assignedActiveNodes != activeNodes:
		check.Summary = fmt.Sprintf("%d of %d active nodes have explicit site and failure-domain placement.", assignedActiveNodes, activeNodes)
		check.Action = "Assign a site and failure domain to every active node; migrated nodes remain unassigned until an operator places them."
	case activeLighthouses < fleetRequiredLighthouses:
		check.Summary = "Failure-domain diversity requires at least two active lighthouses."
		check.Action = "Add and activate a second lighthouse, then place it in an independent failure domain."
	case len(lighthouseFailureDomains) < fleetRequiredLighthouses:
		check.Summary = fmt.Sprintf("%d active lighthouses span only %d declared failure domain.", activeLighthouses, len(lighthouseFailureDomains))
		check.Action = "Place active lighthouses in at least two independent failure domains; changing security groups does not change placement."
	default:
		check.Status = NetworkReadinessPass
		check.Summary = fmt.Sprintf("%d active lighthouses span %d explicitly declared failure domains across %d active sites.", activeLighthouses, len(lighthouseFailureDomains), activeSites)
		check.Action = "Keep lighthouse placement independent and update these labels when infrastructure moves."
	}
	return check, resultSites
}

func deriveReadinessUDP(snapshot readinessSnapshot, records []runtimetelemetry.Record, requiredLighthouses int) ReadinessUDPCheck {
	requiredMembers := 0
	for _, node := range snapshot.nodes {
		if node.Role == "member" && node.Status == "active" {
			requiredMembers++
		}
	}
	result := ReadinessUDPCheck{
		Status: NetworkReadinessUnknown, EvidenceSource: "not_observed",
		RequiredMembers:        requiredMembers,
		RequiredLighthouses:    requiredLighthouses,
		FreshnessWindowSeconds: int64(runtimetelemetry.MaxActiveProbeSampleAgeMS / 1000),
		Summary:                "A configured endpoint and successful DNS lookup do not prove that public UDP packets reach Nebula.",
		Action:                 fmt.Sprintf("Allow each public endpoint's UDP port and forward it to Nebula UDP %d, then activate a member from an external network and confirm authenticated overlay traffic.", snapshot.network.ListenPort),
	}
	if requiredMembers == 0 || requiredLighthouses == 0 || requiredLighthouses > int(runtimetelemetry.MaxActiveProbeTargets) {
		return result
	}
	nodes := make(map[string]Node, len(snapshot.nodes))
	for _, node := range snapshot.nodes {
		nodes[node.ID] = node
	}
	health := make(map[string]FleetNodeHealth, len(snapshot.health.Nodes))
	for _, node := range snapshot.health.Nodes {
		health[node.ID] = node
	}
	var oldest time.Time
	observed := 0
	recordCounts := make(map[string]int, len(records))
	for _, record := range records {
		recordCounts[record.NodeID]++
	}
	for _, record := range records {
		// A runtime Store.List result is unique by node. Treat arbitrary or
		// corrupted duplicate input as no evidence for that node rather than
		// choosing one record or inflating the observed-member count.
		if recordCounts[record.NodeID] != 1 {
			continue
		}
		if runtimetelemetry.ValidateRecord(record) != nil {
			continue
		}
		node, found := nodes[record.NodeID]
		projected, healthFound := health[record.NodeID]
		if !found || !healthFound || node.Role != "member" || node.Status != "active" ||
			!projected.Operational || projected.HeartbeatSequence != record.HeartbeatSequence {
			continue
		}
		eligible, total := readinessProbeTargetCounts(snapshot.network.FirewallPolicy, snapshot.lighthouses)
		if total != requiredLighthouses || eligible != total || total > int(runtimetelemetry.MaxActiveProbeTargets) {
			continue
		}
		probe := record.ActiveProbe
		if probe.State != runtimetelemetry.ProbeAttempted || probe.SampleAgeMS == nil ||
			probe.Attempted != uint64(total) || probe.Replied != uint64(total) || record.ReceivedAt.After(snapshot.generatedAt) {
			continue
		}
		sampleAge := time.Duration(*probe.SampleAgeMS) * time.Millisecond
		receiveAge := snapshot.generatedAt.Sub(record.ReceivedAt)
		freshness := time.Duration(runtimetelemetry.MaxActiveProbeSampleAgeMS) * time.Millisecond
		if receiveAge < 0 || sampleAge > freshness || receiveAge > freshness-sampleAge {
			continue
		}
		observedAt := record.ReceivedAt.Add(-sampleAge)
		observed++
		if oldest.IsZero() || observedAt.Before(oldest) {
			oldest = observedAt
		}
	}
	if observed != requiredMembers {
		return result
	}
	result.Status = NetworkReadinessPass
	result.EvidenceSource = "authenticated_member_active_probe"
	result.ObservedMembers = observed
	result.VerifiedLighthouses = requiredLighthouses
	result.EvidenceAt = &oldest
	result.Summary = fmt.Sprintf("Fresh authenticated overlay replies reached all %d active lighthouses from all %d current active member%s.", requiredLighthouses, observed, pluralSuffix(observed))
	result.Action = "Keep every active member reporting current all-lighthouse probe evidence; loss or staleness returns this check to unverified."
	return result
}

func deriveReadinessClientRoutes(snapshot readinessSnapshot, records []runtimetelemetry.Record) ReadinessClientRouteCheck {
	requiredNodes := 0
	for _, node := range snapshot.nodes {
		if node.Status == "active" {
			requiredNodes++
		}
	}
	result := ReadinessClientRouteCheck{
		Status: NetworkReadinessUnknown, EvidenceSource: "not_observed",
		RequiredNodes:          requiredNodes,
		FreshnessWindowSeconds: int64(runtimetelemetry.MaxRouteOverlapSampleAgeMS / 1000),
		Summary:                "Current node route inventories have not all been observed for this configuration.",
		Action:                 fmt.Sprintf("Run every active node's current Mesh agent and confirm that %s does not overlap its non-default LAN, VPN, VPC, or policy routes.", snapshot.network.CIDR),
	}
	if requiredNodes == 0 {
		return result
	}
	nodes := make(map[string]Node, len(snapshot.nodes))
	for _, node := range snapshot.nodes {
		nodes[node.ID] = node
	}
	health := make(map[string]FleetNodeHealth, len(snapshot.health.Nodes))
	for _, node := range snapshot.health.Nodes {
		health[node.ID] = node
	}
	recordCounts := make(map[string]int, len(records))
	for _, record := range records {
		recordCounts[record.NodeID]++
	}
	var oldestObserved, latestOverlap time.Time
	observed, overlapping := 0, 0
	for _, record := range records {
		if recordCounts[record.NodeID] != 1 || runtimetelemetry.ValidateRecord(record) != nil {
			continue
		}
		node, found := nodes[record.NodeID]
		projected, healthFound := health[record.NodeID]
		if !found || !healthFound || node.Status != "active" || !projected.Operational || projected.HeartbeatSequence != record.HeartbeatSequence {
			continue
		}
		route := record.RouteOverlap
		if route.State != runtimetelemetry.RouteOverlapObserved || route.SampleAgeMS == nil || record.ReceivedAt.After(snapshot.generatedAt) {
			continue
		}
		sampleAge := time.Duration(*route.SampleAgeMS) * time.Millisecond
		receiveAge := snapshot.generatedAt.Sub(record.ReceivedAt)
		freshness := time.Duration(runtimetelemetry.MaxRouteOverlapSampleAgeMS) * time.Millisecond
		if receiveAge < 0 || sampleAge > freshness || receiveAge > freshness-sampleAge {
			continue
		}
		observedAt := record.ReceivedAt.Add(-sampleAge)
		observed++
		if oldestObserved.IsZero() || observedAt.Before(oldestObserved) {
			oldestObserved = observedAt
		}
		if route.Overlap {
			overlapping++
			if latestOverlap.IsZero() || observedAt.After(latestOverlap) {
				latestOverlap = observedAt
			}
		}
	}
	if overlapping > 0 {
		result.Status = NetworkReadinessBlocked
		result.EvidenceSource = "authenticated_node_route_inventory"
		result.ObservedNodes = observed
		result.OverlappingNodes = overlapping
		result.EvidenceAt = &latestOverlap
		result.Summary = fmt.Sprintf("%d current active node%s reported a non-default route overlapping %s.", overlapping, pluralSuffix(overlapping), snapshot.network.CIDR)
		result.Action = "Choose an unused Mesh CIDR or remove the conflicting LAN, VPN, VPC, or policy route before relying on the overlay."
		return result
	}
	if observed != requiredNodes {
		return result
	}
	result.Status = NetworkReadinessPass
	result.EvidenceSource = "authenticated_node_route_inventory"
	result.ObservedNodes = observed
	result.EvidenceAt = &oldestObserved
	result.Summary = fmt.Sprintf("All %d active node%s reported no non-default route overlapping %s.", observed, pluralSuffix(observed), snapshot.network.CIDR)
	result.Action = "Re-run readiness after adding a node or changing LAN, VPN, VPC, or policy routes."
	return result
}

func deriveReadinessMemberDNS(snapshot readinessSnapshot, records []runtimetelemetry.Record, requiredNames int) ReadinessMemberDNSCheck {
	requiredMembers := 0
	for _, node := range snapshot.nodes {
		if node.Role == "member" && node.Status == "active" {
			requiredMembers++
		}
	}
	result := ReadinessMemberDNSCheck{
		Status: NetworkReadinessUnknown, EvidenceSource: "not_observed",
		RequiredMembers:        requiredMembers,
		DNSNames:               requiredNames,
		FreshnessWindowSeconds: int64(runtimetelemetry.MaxEndpointDNSSampleAgeMS / 1000),
		Summary:                "Current member-side resolution has not been observed for every active member.",
		Action:                 "Run every active member's current Mesh agent and confirm its resolver can reach every active lighthouse DNS name.",
	}
	if requiredMembers == 0 || requiredNames < 0 || requiredNames > int(runtimetelemetry.MaxEndpointDNSNames) {
		return result
	}
	nodes := make(map[string]Node, len(snapshot.nodes))
	for _, node := range snapshot.nodes {
		nodes[node.ID] = node
	}
	health := make(map[string]FleetNodeHealth, len(snapshot.health.Nodes))
	for _, node := range snapshot.health.Nodes {
		health[node.ID] = node
	}
	recordCounts := make(map[string]int, len(records))
	for _, record := range records {
		recordCounts[record.NodeID]++
	}
	var oldestObserved, latestFailure time.Time
	observed, failing := 0, 0
	for _, record := range records {
		if recordCounts[record.NodeID] != 1 || runtimetelemetry.ValidateRecord(record) != nil {
			continue
		}
		node, found := nodes[record.NodeID]
		projected, healthFound := health[record.NodeID]
		if !found || !healthFound || node.Role != "member" || node.Status != "active" ||
			!projected.Operational || projected.HeartbeatSequence != record.HeartbeatSequence {
			continue
		}
		dns := record.EndpointDNS
		if dns.State != runtimetelemetry.EndpointDNSObserved || dns.SampleAgeMS == nil ||
			dns.DNSNames != uint64(requiredNames) || record.ReceivedAt.After(snapshot.generatedAt) {
			continue
		}
		sampleAge := time.Duration(*dns.SampleAgeMS) * time.Millisecond
		receiveAge := snapshot.generatedAt.Sub(record.ReceivedAt)
		freshness := time.Duration(runtimetelemetry.MaxEndpointDNSSampleAgeMS) * time.Millisecond
		if receiveAge < 0 || sampleAge > freshness || receiveAge > freshness-sampleAge {
			continue
		}
		observedAt := record.ReceivedAt.Add(-sampleAge)
		observed++
		if oldestObserved.IsZero() || observedAt.Before(oldestObserved) {
			oldestObserved = observedAt
		}
		if dns.ResolvedNames != dns.DNSNames {
			failing++
			if latestFailure.IsZero() || observedAt.After(latestFailure) {
				latestFailure = observedAt
			}
		}
	}
	if failing > 0 {
		result.Status = NetworkReadinessBlocked
		result.EvidenceSource = "authenticated_member_dns_resolution"
		result.ObservedMembers = observed
		result.FailingMembers = failing
		result.EvidenceAt = &latestFailure
		result.Summary = fmt.Sprintf("%d current active member%s could not resolve every configured lighthouse DNS name.", result.FailingMembers, pluralSuffix(result.FailingMembers))
		result.Action = "Correct member DNS, split-horizon records, or resolver reachability before relying on this overlay."
		return result
	}
	if observed != requiredMembers {
		return result
	}
	result.Status = NetworkReadinessPass
	result.EvidenceSource = "authenticated_member_dns_resolution"
	result.ObservedMembers = observed
	result.EvidenceAt = &oldestObserved
	if requiredNames == 0 {
		result.Summary = fmt.Sprintf("All %d active member%s confirmed that lighthouse endpoints use IP literals, so member DNS is not required.", observed, pluralSuffix(observed))
	} else {
		result.Summary = fmt.Sprintf("All %d active member%s resolved all %d configured lighthouse DNS name%s.", observed, pluralSuffix(observed), requiredNames, pluralSuffix(requiredNames))
	}
	result.Action = "Re-run readiness after adding a member or changing lighthouse endpoints or member DNS."
	return result
}

func readinessProbeTargetCounts(policy FirewallPolicy, lighthouses []Node) (eligible, total int) {
	for _, lighthouse := range lighthouses {
		if lighthouse.Status != "active" {
			continue
		}
		total++
		target, err := netip.ParseAddr(lighthouse.IP)
		if err == nil && target.Is4() && readinessProbeTargetAllowed(policy.Outbound, target) {
			eligible++
		}
	}
	return eligible, total
}

func readinessProbeTargetAllowed(rules []FirewallRule, target netip.Addr) bool {
	for _, rule := range rules {
		if (rule.Proto != "any" && rule.Proto != "icmp") || rule.Port != "any" {
			continue
		}
		if rule.Group == "all" || rule.Host == "any" {
			return true
		}
		if address, err := netip.ParseAddr(rule.Host); err == nil && address == target {
			return true
		}
		if prefix, err := netip.ParsePrefix(rule.Host); err == nil && prefix.Contains(target) {
			return true
		}
	}
	return false
}

func pluralSuffix(value int) string {
	if value == 1 {
		return ""
	}
	return "s"
}

func (s *Service) resolveReadinessDNS(ctx context.Context, hosts map[string]string) (map[string]readinessDNSResult, error) {
	results := make(map[string]readinessDNSResult, len(hosts))
	if len(hosts) == 0 {
		return results, nil
	}
	lookupContext, cancel := context.WithTimeout(ctx, networkReadinessDNSTimeout)
	defer cancel()
	jobs := make(chan readinessDNSResult)
	completed := make(chan readinessDNSResult)
	workers := maxConcurrentReadinessLookups
	if workers > len(hosts) {
		workers = len(hosts)
	}
	for worker := 0; worker < workers; worker++ {
		go func() {
			for job := range jobs {
				addresses, err := s.endpointResolver.LookupHost(lookupContext, job.host)
				unique := make(map[string]struct{})
				if err == nil {
					for _, value := range addresses {
						if ip := net.ParseIP(value); ip != nil {
							unique[ip.String()] = struct{}{}
						}
					}
				}
				count := len(unique)
				if count > maxReadinessResolvedAddresses {
					count = maxReadinessResolvedAddresses
				}
				job.count, job.resolved = count, count != 0
				select {
				case completed <- job:
				case <-lookupContext.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		keys := make([]string, 0, len(hosts))
		for key := range hosts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			select {
			case jobs <- readinessDNSResult{host: hosts[key]}:
			case <-lookupContext.Done():
				return
			}
		}
	}()
	for len(results) < len(hosts) {
		select {
		case result := <-completed:
			key := strings.ToLower(strings.TrimSuffix(result.host, "."))
			results[key] = result
		case <-lookupContext.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			for key, host := range hosts {
				if _, ok := results[key]; !ok {
					results[key] = readinessDNSResult{host: host}
				}
			}
		}
	}
	return results, nil
}

func readinessOverall(report NetworkReadinessReport) string {
	statuses := []string{
		report.Checks.ManagedRouteOverlap.Status,
		report.Checks.ClientRouteOverlap.Status,
		report.Checks.LighthouseRedundancy.Status,
		report.Checks.TopologyDiversity.Status,
		report.Checks.DNSResolution.Status,
		report.Checks.MemberDNSResolution.Status,
		report.Checks.PublicUDPReachability.Status,
	}
	for _, status := range statuses {
		if status == NetworkReadinessBlocked {
			return NetworkReadinessOverallBlocked
		}
	}
	for _, status := range statuses {
		if status == NetworkReadinessWarning || status == NetworkReadinessUnknown {
			return NetworkReadinessOverallVerificationRequired
		}
	}
	return NetworkReadinessOverallReady
}

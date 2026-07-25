package control

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFleetHealthDerivesDeterministicSecretFreeSnapshotWithoutWrites(t *testing.T) {
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	network := Network{ID: "network-health", Name: "production", ConfigRevision: 7, ConfigUpdatedAt: now.Add(-20 * time.Minute)}
	firstLighthouse := fleetHealthyNode("node-lh-a", "alpha-lighthouse", "lighthouse", network, now)
	secondLighthouse := fleetHealthyNode("node-lh-b", "beta-lighthouse", "lighthouse", network, now)
	offline := fleetHealthyNode("node-member", "zeta-member", "member", network, now)
	offlineSeen := now.Add(-6 * time.Minute)
	offline.LastSeenAt = &offlineSeen
	offline.AgentStatus = "degraded"
	offline.NebulaRunning = false
	offline.LastError = "RAW-HEARTBEAT-ERROR-MUST-NOT-LEAK"
	offline.AppliedConfigRevision = network.ConfigRevision - 1
	offline.AppliedConfigSHA256 = "RAW-CONFIG-DIGEST-MUST-NOT-LEAK"
	offline.CertificateGeneration = 2
	offline.AppliedCertificateGeneration = 1
	offline.CertificateFingerprint = "RAW-DESIRED-FINGERPRINT-MUST-NOT-LEAK"
	offline.ReportedCertificateFingerprint = "RAW-REPORTED-FINGERPRINT-MUST-NOT-LEAK"
	offlineCertificateExpiry := now
	offlineCertificateRenew := now.Add(-time.Hour)
	offlineCredentialExpiry := now.Add(24 * time.Hour)
	offline.CertificateExpiresAt = &offlineCertificateExpiry
	offline.CertificateRenewAfter = &offlineCertificateRenew
	offline.AgentCredentialExpiresAt = &offlineCredentialExpiry
	offline.AgentTokenHash = "RAW-TOKEN-HASH-MUST-NOT-LEAK"

	awaiting := fleetHealthyNode("node-awaiting", "awaiting-member", "member", network, now)
	awaitingEnrolled := now.Add(-time.Minute)
	awaiting.EnrolledAt = &awaitingEnrolled
	awaiting.LastSeenAt = nil
	awaiting.AppliedConfigRevision = 0
	awaiting.AppliedCertificateGeneration = 0
	awaiting.ReportedCertificateFingerprint = ""
	awaiting.NebulaRunning = false
	awaiting.AgentStatus = ""

	pending := Node{ID: "node-pending", NetworkID: network.ID, Name: "pending-member", Role: "member", Status: "pending"}
	revoked := Node{ID: "node-revoked", NetworkID: network.ID, Name: "revoked-member", Role: "member", Status: "revoked"}
	backend := &fakeStateStore{state: State{
		Networks: []Network{network},
		Nodes:    []Node{offline, revoked, secondLighthouse, pending, awaiting, firstLighthouse},
		Audit: []AuditEvent{{
			ID: "audit-sensitive", Action: "diagnostic", Resource: "network", ResourceID: network.ID,
			At: now, Details: map[string]any{"secret": "RAW-AUDIT-DETAIL-MUST-NOT-LEAK"},
		}},
	}}
	fleetFillDesiredDigests(&backend.state, now)
	service, err := NewServiceWithStateStore(backend, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	report, err := service.FleetHealth(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if backend.viewCalls != 1 || backend.updateCalls != 0 || len(backend.state.Audit) != 1 {
		t.Fatalf("health read touched persistence: views=%d updates=%d audit=%#v", backend.viewCalls, backend.updateCalls, backend.state.Audit)
	}
	if !report.GeneratedAt.Equal(now) || report.Network.ID != network.ID || report.Policy.HeartbeatWarningAfterSeconds != 120 || report.Policy.HeartbeatOfflineAfterSeconds != 300 || report.Policy.EvidenceSource != "authenticated_agent_heartbeat" || report.Policy.OverlayReachabilityObserved {
		t.Fatalf("projection metadata = %#v", report)
	}
	wantSummary := FleetHealthSummary{
		Overall: FleetHealthCritical, TotalNodes: 6, PendingNodes: 1, ActiveNodes: 4, RevokedNodes: 1,
		SetupNodes: 2, HealthyNodes: 2, CriticalNodes: 1, ActiveLighthouses: 2, HealthyLighthouses: 2,
	}
	if !reflect.DeepEqual(report.Summary, wantSummary) {
		t.Fatalf("summary = %#v, want %#v", report.Summary, wantSummary)
	}
	wantRollout := FleetRolloutProjection{
		DesiredConfigRevision: 7, EligibleNodes: 4, ConvergedNodes: 2, DriftedNodes: 1, UnreportedNodes: 1, Percent: 50,
	}
	if !reflect.DeepEqual(report.Rollout, wantRollout) {
		t.Fatalf("rollout = %#v, want %#v", report.Rollout, wantRollout)
	}
	wantOrder := []string{"alpha-lighthouse", "awaiting-member", "beta-lighthouse", "pending-member", "revoked-member", "zeta-member"}
	gotOrder := make([]string, len(report.Nodes))
	for i := range report.Nodes {
		gotOrder[i] = report.Nodes[i].Name
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("node order = %v, want %v", gotOrder, wantOrder)
	}
	awaitingHealth := fleetProjectedNode(t, report, awaiting.ID)
	if awaitingHealth.Phase != "setup" || awaitingHealth.Severity != FleetHealthHealthy || len(awaitingHealth.Alerts) != 0 {
		t.Fatalf("fresh enrolled node was not setup grace: %#v", awaitingHealth)
	}
	offlineHealth := fleetProjectedNode(t, report, offline.ID)
	wantCodes := []string{
		"agent_degraded", "certificate_expired", "certificate_fingerprint_drift", "heartbeat_offline", "nebula_stopped",
		"agent_error", "certificate_generation_drift", "config_drift", "credential_expiring",
	}
	if got := fleetAlertCodes(offlineHealth.Alerts); !reflect.DeepEqual(got, wantCodes) {
		t.Fatalf("offline alerts = %v, want %v", got, wantCodes)
	}
	nebulaStopped, ok := fleetFindAlert(offlineHealth.Alerts, "nebula_stopped")
	if !ok || nebulaStopped.Evidence.NebulaRunning == nil || *nebulaStopped.Evidence.NebulaRunning {
		t.Fatalf("nebula stopped evidence did not preserve an explicit false value: %#v", nebulaStopped)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"RAW-HEARTBEAT-ERROR-MUST-NOT-LEAK", "RAW-CONFIG-DIGEST-MUST-NOT-LEAK",
		"RAW-DESIRED-FINGERPRINT-MUST-NOT-LEAK", "RAW-REPORTED-FINGERPRINT-MUST-NOT-LEAK",
		"RAW-TOKEN-HASH-MUST-NOT-LEAK", "RAW-AUDIT-DETAIL-MUST-NOT-LEAK",
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("fleet health response leaked %q: %s", secret, encoded)
		}
	}
	repeated, err := service.FleetHealth(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	repeatedJSON, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(repeatedJSON) || backend.viewCalls != 2 || backend.updateCalls != 0 {
		t.Fatalf("projection was not deterministic/read-only: first=%s second=%s views=%d updates=%d", encoded, repeatedJSON, backend.viewCalls, backend.updateCalls)
	}
}

func TestFleetHealthAllUsesOneSnapshotAndDeterministicAggregation(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	alpha := Network{ID: "network-alpha", Name: "alpha", CIDR: "10.60.0.0/24", ListenPort: 4242, ConfigRevision: 2, ConfigUpdatedAt: now.Add(-time.Hour)}
	bravo := Network{ID: "network-bravo", Name: "bravo", CIDR: "10.61.0.0/24", ListenPort: 4343, ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	charlie := Network{ID: "network-charlie", Name: "charlie", CIDR: "10.62.0.0/24", ListenPort: 4444, ConfigRevision: 3, ConfigUpdatedAt: now.Add(-time.Hour)}

	alphaNodes := []Node{
		fleetHealthyNode("alpha-lh-2", "alpha-lighthouse-2", "lighthouse", alpha, now),
		fleetHealthyNode("alpha-lh-1", "alpha-lighthouse-1", "lighthouse", alpha, now),
	}
	bravoNodes := []Node{
		fleetHealthyNode("bravo-lh-1", "bravo-lighthouse-1", "lighthouse", bravo, now),
		fleetHealthyNode("bravo-lh-2", "bravo-lighthouse-2", "lighthouse", bravo, now),
		fleetHealthyNode("bravo-member", "bravo-member", "member", bravo, now),
	}
	late := now.Add(-fleetHeartbeatWarningAfter)
	bravoNodes[2].LastSeenAt = &late
	bravoNodes[2].LastError = "COLLECTION-RAW-ERROR-MUST-NOT-LEAK"
	bravoNodes[2].AgentTokenHash = "COLLECTION-RAW-TOKEN-MUST-NOT-LEAK"
	bravoNodes[2].Groups = []string{"COLLECTION-GROUP-MUST-NOT-LEAK"}
	bravoNodes[2].PublicEndpoint = "COLLECTION-ENDPOINT-MUST-NOT-LEAK:4242"
	bravoNodes[2].Certificate = "COLLECTION-CERTIFICATE-MUST-NOT-LEAK"

	charlieNodes := []Node{
		fleetHealthyNode("charlie-lh-1", "charlie-lighthouse-1", "lighthouse", charlie, now),
		fleetHealthyNode("charlie-lh-2", "charlie-lighthouse-2", "lighthouse", charlie, now),
		fleetHealthyNode("charlie-offline", "charlie-offline", "member", charlie, now),
		fleetHealthyNode("charlie-awaiting", "charlie-awaiting", "member", charlie, now),
		{ID: "charlie-pending", NetworkID: charlie.ID, Name: "charlie-pending", Role: "member", Status: "pending"},
		{ID: "charlie-revoked", NetworkID: charlie.ID, Name: "charlie-revoked", Role: "member", Status: "revoked"},
	}
	offline := now.Add(-fleetHeartbeatOfflineAfter - time.Second)
	charlieNodes[2].LastSeenAt = &offline
	charlieNodes[2].AppliedConfigRevision = charlie.ConfigRevision - 1
	charlieNodes[2].AppliedConfigSHA256 = "COLLECTION-RAW-DIGEST-MUST-NOT-LEAK"
	charlieNodes[2].AgentStatus = "COLLECTION-RAW-STATUS-MUST-NOT-LEAK"
	awaiting := now.Add(-time.Minute)
	charlieNodes[3].EnrolledAt = &awaiting
	charlieNodes[3].LastSeenAt = nil
	charlieNodes[3].AppliedConfigRevision = 0
	charlieNodes[3].AppliedCertificateGeneration = 0
	charlieNodes[3].ReportedCertificateFingerprint = ""
	charlieNodes[3].NebulaRunning = false
	charlieNodes[3].AgentStatus = ""

	backend := &fakeStateStore{state: State{
		Networks: []Network{charlie, alpha, bravo},
		Nodes:    append(append(charlieNodes, alphaNodes...), bravoNodes...),
		Audit: []AuditEvent{{
			ID: "collection-sensitive", Action: "diagnostic", Resource: "network", ResourceID: alpha.ID,
			At: now, Details: map[string]any{"secret": "COLLECTION-AUDIT-SECRET-MUST-NOT-LEAK"},
		}},
	}}
	fleetFillDesiredDigests(&backend.state, now)
	service, err := NewServiceWithStateStore(backend, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	collection, err := service.FleetHealthAll()
	if err != nil {
		t.Fatal(err)
	}
	if backend.viewCalls != 1 || backend.updateCalls != 0 || !collection.GeneratedAt.Equal(now) {
		t.Fatalf("collection did not use one read/time: views=%d updates=%d generated=%s", backend.viewCalls, backend.updateCalls, collection.GeneratedAt)
	}
	wantNames := []string{"alpha", "bravo", "charlie"}
	gotNames := make([]string, len(collection.Networks))
	for i := range collection.Networks {
		gotNames[i] = collection.Networks[i].Network.Name
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("network order = %v, want %v", gotNames, wantNames)
	}
	if collection.Networks[0].Network.CIDR != alpha.CIDR || collection.Networks[0].Network.ListenPort != alpha.ListenPort {
		t.Fatalf("network dashboard fields = %#v", collection.Networks[0].Network)
	}
	bravoMember := fleetCollectionNode(t, collection, bravo.ID, bravoNodes[2].ID)
	if bravoMember.IP == "" || bravoMember.CertificateRenewAfter == nil {
		t.Fatalf("node dashboard fields are incomplete: %#v", bravoMember)
	}
	charlieOffline := fleetCollectionNode(t, collection, charlie.ID, charlieNodes[2].ID)
	if charlieOffline.AgentStatus != "" {
		t.Fatalf("unknown raw agent status reached collection DTO: %#v", charlieOffline)
	}
	if alert, ok := fleetFindAlert(charlieOffline.Alerts, "telemetry_invalid"); !ok || alert.Severity != FleetHealthCritical || !reflect.DeepEqual(alert.Evidence, FleetHealthEvidence{}) {
		t.Fatalf("unknown agent status did not fail closed generically: %#v", charlieOffline.Alerts)
	}
	wantSummary := FleetHealthCollectionSummary{
		Overall: FleetHealthCritical, TotalNetworks: 3, HealthyNetworks: 1, WarningNetworks: 1, CriticalNetworks: 1,
		TotalNodes: 11, SetupNodes: 2, ActiveNodes: 9, RevokedNodes: 1, HealthyNodes: 6, WarningNodes: 1, CriticalNodes: 1,
	}
	if !reflect.DeepEqual(collection.Summary, wantSummary) {
		t.Fatalf("collection summary = %#v, want %#v", collection.Summary, wantSummary)
	}
	wantRollout := FleetRolloutSummary{EligibleNodes: 9, ConvergedNodes: 7, DriftedNodes: 1, UnreportedNodes: 1, Percent: 77}
	if !reflect.DeepEqual(collection.Rollout, wantRollout) {
		t.Fatalf("collection rollout = %#v, want %#v", collection.Rollout, wantRollout)
	}
	encoded, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"generated_at"`) != 1 || strings.Count(string(encoded), `"policy"`) != 1 {
		t.Fatalf("collection repeated generated_at or policy: %s", encoded)
	}
	for _, forbiddenField := range []string{`"agent_version"`, `"nebula_version"`, `"groups"`, `"public_endpoint"`, `"certificate"`, `"firewall_policy"`} {
		if strings.Contains(string(encoded), forbiddenField) {
			t.Fatalf("collection exposed forbidden field %s: %s", forbiddenField, encoded)
		}
	}
	for _, secret := range []string{
		"COLLECTION-RAW-ERROR-MUST-NOT-LEAK", "COLLECTION-RAW-DIGEST-MUST-NOT-LEAK",
		"COLLECTION-RAW-TOKEN-MUST-NOT-LEAK", "COLLECTION-AUDIT-SECRET-MUST-NOT-LEAK",
		"COLLECTION-GROUP-MUST-NOT-LEAK", "COLLECTION-ENDPOINT-MUST-NOT-LEAK:4242",
		"COLLECTION-CERTIFICATE-MUST-NOT-LEAK",
		"COLLECTION-RAW-STATUS-MUST-NOT-LEAK",
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("collection leaked %q: %s", secret, encoded)
		}
	}
	repeated, err := service.FleetHealthAll()
	if err != nil {
		t.Fatal(err)
	}
	repeatedJSON, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(repeatedJSON) || backend.viewCalls != 2 || backend.updateCalls != 0 {
		t.Fatalf("collection was not deterministic/read-only: first=%s second=%s views=%d updates=%d", encoded, repeatedJSON, backend.viewCalls, backend.updateCalls)
	}
}

func TestFleetHealthAllEmptyAndRolloutPercentNeverRoundsUp(t *testing.T) {
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	backend := &fakeStateStore{}
	service, err := NewServiceWithStateStore(backend, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	collection, err := service.FleetHealthAll()
	if err != nil {
		t.Fatal(err)
	}
	if collection.Networks == nil || len(collection.Networks) != 0 || collection.Summary.Overall != FleetHealthHealthy || collection.Summary.TotalNetworks != 0 || collection.Rollout.Percent != 100 || backend.viewCalls != 1 || backend.updateCalls != 0 {
		t.Fatalf("empty collection = %#v views=%d updates=%d", collection, backend.viewCalls, backend.updateCalls)
	}

	large := FleetHealthCollection{Networks: []FleetNetworkHealthReport{{
		Summary: FleetHealthSummary{Overall: FleetHealthHealthy},
		Rollout: FleetRolloutProjection{EligibleNodes: 200, ConvergedNodes: 199, DriftedNodes: 1},
	}}}
	aggregateFleetHealth(&large)
	if large.Rollout.Percent != 99 {
		t.Fatalf("199/200 aggregate rollout percent = %d, want floor 99", large.Rollout.Percent)
	}
	state := State{
		Networks: []Network{{ID: "large", Name: "large", ConfigRevision: 1, ConfigUpdatedAt: now}},
		Nodes:    make([]Node, 200),
	}
	for i := range state.Nodes {
		state.Nodes[i] = fleetHealthyNode("node-"+strings.Repeat("x", i%8)+string(rune('A'+i%26)), "node-"+string(rune('A'+i%26))+strings.Repeat("x", i/26), "member", state.Networks[0], now)
	}
	fleetFillDesiredDigests(&state, now)
	state.Nodes[199].AppliedConfigRevision = 0
	report, err := deriveFleetHealth(state, "large", now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Rollout.EligibleNodes != 200 || report.Rollout.ConvergedNodes != 199 || report.Rollout.Percent != 99 {
		t.Fatalf("199/200 network rollout = %#v", report.Rollout)
	}
}

func TestFleetHealthHeartbeatGraceAndExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 0, 0, 0, time.UTC)
	network := Network{ID: "network-boundaries", Name: "boundaries", ConfigRevision: 3, ConfigUpdatedAt: now.Add(-time.Hour)}
	tests := []struct {
		name         string
		mutate       func(*Node)
		wantPhase    string
		wantCode     string
		wantSeverity string
	}{
		{name: "awaiting before warning", mutate: func(node *Node) { at := now.Add(-119 * time.Second); node.EnrolledAt, node.LastSeenAt = &at, nil }, wantPhase: "setup"},
		{name: "missing at warning", mutate: func(node *Node) { at := now.Add(-2 * time.Minute); node.EnrolledAt, node.LastSeenAt = &at, nil }, wantPhase: "active", wantCode: "heartbeat_missing", wantSeverity: FleetHealthWarning},
		{name: "missing at offline", mutate: func(node *Node) { at := now.Add(-5 * time.Minute); node.EnrolledAt, node.LastSeenAt = &at, nil }, wantPhase: "active", wantCode: "heartbeat_missing", wantSeverity: FleetHealthCritical},
		{name: "late at warning", mutate: func(node *Node) { at := now.Add(-2 * time.Minute); node.LastSeenAt = &at }, wantPhase: "active", wantCode: "heartbeat_late", wantSeverity: FleetHealthWarning},
		{name: "offline at threshold", mutate: func(node *Node) { at := now.Add(-5 * time.Minute); node.LastSeenAt = &at }, wantPhase: "active", wantCode: "heartbeat_offline", wantSeverity: FleetHealthCritical},
		{name: "missing enrollment time", mutate: func(node *Node) { node.EnrolledAt, node.LastSeenAt = nil, nil }, wantPhase: "active", wantCode: "heartbeat_missing", wantSeverity: FleetHealthCritical},
		{name: "future enrollment time", mutate: func(node *Node) { at := now.Add(time.Second); node.EnrolledAt, node.LastSeenAt = &at, nil }, wantPhase: "active", wantCode: "heartbeat_time_invalid", wantSeverity: FleetHealthCritical},
		{name: "future heartbeat time", mutate: func(node *Node) { at := now.Add(time.Second); node.LastSeenAt = &at }, wantPhase: "active", wantCode: "heartbeat_time_invalid", wantSeverity: FleetHealthCritical},
		{name: "certificate renewal boundary", mutate: func(node *Node) { at := now; node.CertificateRenewAfter = &at }, wantPhase: "active", wantCode: "certificate_renewal_due", wantSeverity: FleetHealthWarning},
		{name: "certificate expiry boundary", mutate: func(node *Node) {
			at, renew := now, now.Add(-time.Hour)
			node.CertificateExpiresAt, node.CertificateRenewAfter = &at, &renew
		}, wantPhase: "active", wantCode: "certificate_expired", wantSeverity: FleetHealthCritical},
		{name: "credential warning boundary", mutate: func(node *Node) { at := now.Add(30 * 24 * time.Hour); node.AgentCredentialExpiresAt = &at }, wantPhase: "active", wantCode: "credential_expiring", wantSeverity: FleetHealthWarning},
		{name: "credential expiry boundary", mutate: func(node *Node) { at := now; node.AgentCredentialExpiresAt = &at }, wantPhase: "active", wantCode: "credential_expired", wantSeverity: FleetHealthCritical},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := fleetHealthyNode("node-boundary", "boundary", "member", network, now)
			node.AppliedConfigSHA256 = "boundary-desired-digest"
			test.mutate(&node)
			projected := projectFleetNode(node, network, now, nil, 0, "boundary-desired-digest")
			if projected.Phase != test.wantPhase {
				t.Fatalf("phase = %q, want %q; alerts=%#v", projected.Phase, test.wantPhase, projected.Alerts)
			}
			if test.wantCode == "" {
				if len(projected.Alerts) != 0 {
					t.Fatalf("fresh setup alerts = %#v", projected.Alerts)
				}
				return
			}
			alert, ok := fleetFindAlert(projected.Alerts, test.wantCode)
			if !ok || alert.Severity != test.wantSeverity {
				t.Fatalf("alerts = %#v, want %s/%s", projected.Alerts, test.wantSeverity, test.wantCode)
			}
		})
	}
}

func TestFleetHealthNeverTreatsIncompleteOrUnallowlistedTelemetryAsCurrent(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC)
	network := Network{ID: "network-fail-closed", Name: "fail-closed", ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	const desiredDigest = "freshly-derived-desired-digest"
	tests := []struct {
		name     string
		mutate   func(*Node)
		digest   string
		wantCode string
	}{
		{name: "valid exact evidence", digest: desiredDigest},
		{name: "missing status after heartbeat", digest: desiredDigest, mutate: func(node *Node) { node.AgentStatus = "" }, wantCode: "telemetry_invalid"},
		{name: "unknown status", digest: desiredDigest, mutate: func(node *Node) { node.AgentStatus = "RAW-STATUS-SECRET" }, wantCode: "telemetry_invalid"},
		{name: "missing desired fingerprint", digest: desiredDigest, mutate: func(node *Node) { node.CertificateFingerprint = "" }, wantCode: "certificate_fingerprint_drift"},
		{name: "missing reported fingerprint", digest: desiredDigest, mutate: func(node *Node) { node.ReportedCertificateFingerprint = "" }, wantCode: "certificate_fingerprint_drift"},
		{name: "wrong reported fingerprint", digest: desiredDigest, mutate: func(node *Node) { node.ReportedCertificateFingerprint = strings.Repeat("e", 64) }, wantCode: "certificate_fingerprint_drift"},
		{name: "missing applied digest", digest: desiredDigest, mutate: func(node *Node) { node.AppliedConfigSHA256 = "" }, wantCode: "config_digest_drift"},
		{name: "wrong applied digest", digest: desiredDigest, mutate: func(node *Node) { node.AppliedConfigSHA256 = "RAW-DIGEST-SECRET" }, wantCode: "config_digest_drift"},
		{name: "missing freshly derived digest", digest: "", wantCode: "config_digest_drift"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := fleetHealthyNode("node-fail-closed", "fail-closed", "member", network, now)
			node.AppliedConfigSHA256 = desiredDigest
			if test.mutate != nil {
				test.mutate(&node)
			}
			projected := projectFleetNode(node, network, now, nil, 0, test.digest)
			if test.wantCode == "" {
				if !projected.RolloutCurrent || !projected.Operational || projected.Severity != FleetHealthHealthy || len(projected.Alerts) != 0 {
					t.Fatalf("exact evidence was not healthy: %#v", projected)
				}
				return
			}
			if projected.RolloutCurrent || projected.Operational {
				t.Fatalf("incomplete telemetry became current/operational: %#v", projected)
			}
			alert, ok := fleetFindAlert(projected.Alerts, test.wantCode)
			if !ok || alert.Severity != FleetHealthCritical {
				t.Fatalf("alerts = %#v, want critical %s", projected.Alerts, test.wantCode)
			}
			encoded, err := json.Marshal(projected)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "RAW-STATUS-SECRET") || strings.Contains(string(encoded), "RAW-DIGEST-SECRET") {
				t.Fatalf("invalid telemetry leaked through DTO: %s", encoded)
			}
		})
	}
}

func TestFleetHealthRolloutRequiresFreshRuntimeProof(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 15, 0, 0, time.UTC)
	network := Network{ID: "network-rollout-proof", Name: "rollout-proof", ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	const desiredDigest = "fresh-rollout-digest"
	tests := []struct {
		name            string
		mutate          func(*Node)
		wantCurrent     bool
		wantOperational bool
		wantCode        string
	}{
		{name: "fresh exact proof", wantCurrent: true, wantOperational: true},
		{name: "late but within offline bound", mutate: func(node *Node) { at := now.Add(-fleetHeartbeatWarningAfter); node.LastSeenAt = &at }, wantCurrent: true, wantOperational: true, wantCode: "heartbeat_late"},
		{name: "offline at bound", mutate: func(node *Node) { at := now.Add(-fleetHeartbeatOfflineAfter); node.LastSeenAt = &at }, wantCode: "heartbeat_offline"},
		{name: "future heartbeat", mutate: func(node *Node) { at := now.Add(time.Second); node.LastSeenAt = &at }, wantCode: "heartbeat_time_invalid"},
		{name: "nebula stopped", mutate: func(node *Node) { node.NebulaRunning = false }, wantCode: "nebula_stopped"},
		{name: "expired certificate", mutate: func(node *Node) {
			expiry, renew := now, now.Add(-time.Hour)
			node.CertificateExpiresAt, node.CertificateRenewAfter = &expiry, &renew
		}, wantCode: "certificate_expired"},
		{name: "expired credential", mutate: func(node *Node) { at := now; node.AgentCredentialExpiresAt = &at }, wantCode: "credential_expired"},
		{name: "degraded but exact rollout", mutate: func(node *Node) { node.AgentStatus = "degraded" }, wantCurrent: true, wantCode: "agent_degraded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := fleetHealthyNode("node-rollout-proof", "rollout-proof", "member", network, now)
			node.AppliedConfigSHA256 = desiredDigest
			if test.mutate != nil {
				test.mutate(&node)
			}
			projected := projectFleetNode(node, network, now, nil, 0, desiredDigest)
			if projected.RolloutCurrent != test.wantCurrent || projected.Operational != test.wantOperational {
				t.Fatalf("rollout_current=%t operational=%t, want %t/%t; alerts=%#v", projected.RolloutCurrent, projected.Operational, test.wantCurrent, test.wantOperational, projected.Alerts)
			}
			if test.wantCode != "" {
				if _, ok := fleetFindAlert(projected.Alerts, test.wantCode); !ok {
					t.Fatalf("alerts=%#v, want %s", projected.Alerts, test.wantCode)
				}
			}
		})
	}
}

func TestFleetHealthImpossibleAppliedRevisionIsSanitizedAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 30, 0, 0, time.UTC)
	network := Network{ID: "network-invalid-revision", Name: "invalid-revision", ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	for _, revision := range []int64{-1, network.ConfigRevision + 1} {
		t.Run(strconv.FormatInt(revision, 10), func(t *testing.T) {
			node := fleetHealthyNode("node-invalid-revision", "invalid-revision", "member", network, now)
			node.AppliedConfigRevision = revision
			node.AppliedConfigSHA256 = "untrusted-digest"
			projected := projectFleetNode(node, network, now, nil, 0, "derived-digest")
			if projected.AppliedConfigRevision != 0 || projected.RolloutCurrent || projected.Operational || projected.Severity != FleetHealthCritical {
				t.Fatalf("impossible revision did not fail closed: %#v", projected)
			}
			if alert, ok := fleetFindAlert(projected.Alerts, "telemetry_invalid"); !ok || alert.Severity != FleetHealthCritical || !reflect.DeepEqual(alert.Evidence, FleetHealthEvidence{}) {
				t.Fatalf("impossible revision alert = %#v", alert)
			}
			if _, ok := fleetFindAlert(projected.Alerts, "config_drift"); ok {
				t.Fatalf("impossible revision was reflected as ordinary drift: %#v", projected.Alerts)
			}
		})
	}
}

func TestFleetHealthOperationalRequiresValidCertificateLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 45, 0, 0, time.UTC)
	network := Network{ID: "network-certificate-metadata", Name: "certificate-metadata", ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	tests := []struct {
		name   string
		mutate func(*Node)
	}{
		{name: "missing renewal time", mutate: func(node *Node) { node.CertificateRenewAfter = nil }},
		{name: "zero renewal time", mutate: func(node *Node) { zero := time.Time{}; node.CertificateRenewAfter = &zero }},
		{name: "renewal equals expiry", mutate: func(node *Node) { at := *node.CertificateExpiresAt; node.CertificateRenewAfter = &at }},
		{name: "renewal follows expiry", mutate: func(node *Node) { at := node.CertificateExpiresAt.Add(time.Second); node.CertificateRenewAfter = &at }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := fleetHealthyNode("lighthouse-invalid", "lighthouse-invalid", "lighthouse", network, now)
			healthy := fleetHealthyNode("lighthouse-healthy", "lighthouse-healthy", "lighthouse", network, now)
			test.mutate(&invalid)
			state := State{Networks: []Network{network}, Nodes: []Node{invalid, healthy}}
			fleetFillDesiredDigests(&state, now)
			report, err := deriveFleetHealth(state, network.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			projected := fleetProjectedNode(t, report, invalid.ID)
			if projected.Operational || projected.Severity != FleetHealthCritical {
				t.Fatalf("invalid certificate lifecycle was operational: %#v", projected)
			}
			if alert, ok := fleetFindAlert(projected.Alerts, "certificate_metadata_missing"); !ok || alert.Severity != FleetHealthCritical {
				t.Fatalf("invalid certificate metadata alert = %#v", alert)
			}
			if report.Summary.HealthyLighthouses != 1 {
				t.Fatalf("healthy lighthouses = %d, want 1", report.Summary.HealthyLighthouses)
			}
			if _, ok := fleetFindAlert(report.Alerts, "lighthouse_single"); !ok {
				t.Fatalf("invalid lighthouse did not reduce redundancy: %#v", report.Alerts)
			}
		})
	}
}

func TestFleetHealthBoundsExactLighthouseConfigProjection(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 50, 0, 0, time.UTC)
	network := Network{ID: "network-projection-limit", Name: "projection-limit", ConfigRevision: 4, ConfigUpdatedAt: now.Add(-time.Hour)}
	state := State{Networks: []Network{network}}
	for i := 0; i < maxFleetHealthLighthousesPerNetwork+1; i++ {
		node := fleetHealthyNode("lighthouse-"+strconv.Itoa(i), "lighthouse", "lighthouse", network, now)
		node.AppliedConfigSHA256 = "untrusted-digest"
		state.Nodes = append(state.Nodes, node)
	}
	index := buildFleetHealthIndex(state, now)
	if got := len(index.DesiredConfigDigestByNode); got != 0 {
		t.Fatalf("projection over the lighthouse limit rendered %d exact configs", got)
	}
	report, err := deriveFleetHealth(state, network.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	alert, ok := fleetFindAlert(report.Alerts, "projection_limit_exceeded")
	if !ok || alert.Severity != FleetHealthCritical || alert.Scope != "network" ||
		alert.Evidence.ObservedLighthouses == nil || *alert.Evidence.ObservedLighthouses != maxFleetHealthLighthousesPerNetwork+1 ||
		alert.Evidence.ProjectionLimit == nil || *alert.Evidence.ProjectionLimit != maxFleetHealthLighthousesPerNetwork {
		t.Fatalf("projection limit did not fail closed: %#v", alert)
	}
	if report.Summary.Overall != FleetHealthCritical || report.Rollout.ConvergedNodes != 0 || report.Rollout.DriftedNodes != len(state.Nodes) || report.Summary.HealthyLighthouses != 0 {
		t.Fatalf("projection limit produced optimistic health: %#v", report)
	}
}

func TestFleetHealthOnlyClaimsStaleRevocationWithConclusiveEvidence(t *testing.T) {
	now := time.Date(2026, 7, 19, 22, 0, 0, 0, time.UTC)
	revokedAt := now.Add(-10 * time.Minute)
	base := func() State {
		network := Network{ID: "network-revocation", Name: "revocations", ConfigRevision: 5, ConfigUpdatedAt: revokedAt}
		peer := fleetHealthyNode("node-peer", "peer", "member", network, now)
		seen := revokedAt.Add(time.Minute)
		peer.LastSeenAt = &seen
		peer.AppliedConfigRevision = 4
		target := Node{ID: "node-revoked", NetworkID: network.ID, Name: "revoked", Role: "member", Status: "revoked"}
		expires := now.Add(time.Hour)
		state := State{
			Networks: []Network{network}, Nodes: []Node{peer, target},
			Revocations: []CertificateRevocation{{Fingerprint: strings.Repeat("a", 64), NodeID: target.ID, NetworkID: network.ID, At: revokedAt, ExpiresAt: &expires}},
			Audit:       []AuditEvent{{ID: "audit-revoke", Action: "node.revoked", Resource: "node", ResourceID: target.ID, At: revokedAt}},
		}
		fleetFillDesiredDigests(&state, now)
		return state
	}
	tests := []struct {
		name   string
		mutate func(*State)
		want   bool
	}{
		{name: "latest revocation and post-revocation stale heartbeat", want: true},
		{name: "heartbeat predates revocation", mutate: func(state *State) { at := revokedAt.Add(-time.Second); state.Nodes[0].LastSeenAt = &at }},
		{name: "later firewall revision makes historical revision unknowable", mutate: func(state *State) {
			updated := revokedAt.Add(time.Minute)
			state.Networks[0].ConfigRevision++
			state.Networks[0].ConfigUpdatedAt = updated
			state.Audit = append(state.Audit, AuditEvent{ID: "audit-firewall", Action: "network.firewall_policy_updated", Resource: "network", ResourceID: state.Networks[0].ID, At: updated})
		}},
		{name: "revocation expired", mutate: func(state *State) { expired := now; state.Revocations[0].ExpiresAt = &expired }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base()
			if test.mutate != nil {
				test.mutate(&state)
			}
			report, err := deriveFleetHealth(state, state.Networks[0].ID, now)
			if err != nil {
				t.Fatal(err)
			}
			peer := fleetProjectedNode(t, report, "node-peer")
			alert, got := fleetFindAlert(peer.Alerts, "stale_revocation")
			if got != test.want {
				t.Fatalf("stale revocation present=%t, want %t; alerts=%#v", got, test.want, peer.Alerts)
			}
			if got && (alert.Severity != FleetHealthCritical || alert.Evidence.ActiveRevocations == nil || *alert.Evidence.ActiveRevocations != 1 || alert.Evidence.RevocationAt == nil || !alert.Evidence.RevocationAt.Equal(revokedAt)) {
				t.Fatalf("stale revocation evidence = %#v", alert)
			}
		})
	}
}

func TestFleetHealthFutureControlTimesFailClosedIncludingRevocation(t *testing.T) {
	now := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC)
	base := func() State {
		network := Network{ID: "network-clock", Name: "clock", ConfigRevision: 2, ConfigUpdatedAt: now.Add(-time.Hour)}
		state := State{
			Networks: []Network{network},
			Nodes: []Node{
				fleetHealthyNode("clock-lh-1", "clock-lighthouse-1", "lighthouse", network, now),
				fleetHealthyNode("clock-lh-2", "clock-lighthouse-2", "lighthouse", network, now),
			},
		}
		return state
	}
	tests := []struct {
		name   string
		mutate func(*State) time.Time
	}{
		{name: "future network config timestamp", mutate: func(state *State) time.Time {
			future := now.Add(time.Minute)
			state.Networks[0].ConfigUpdatedAt = future
			return future
		}},
		{name: "future config audit timestamp", mutate: func(state *State) time.Time {
			future := now.Add(2 * time.Minute)
			state.Audit = append(state.Audit, AuditEvent{ID: "future-firewall", Action: "network.firewall_policy_updated", Resource: "network", ResourceID: state.Networks[0].ID, At: future})
			return future
		}},
		{name: "future revocation timestamp", mutate: func(state *State) time.Time {
			future := now.Add(3 * time.Minute)
			target := Node{ID: "future-revoked", NetworkID: state.Networks[0].ID, Name: "future-revoked", Role: "member", Status: "revoked"}
			state.Nodes = append(state.Nodes, target)
			state.Networks[0].ConfigUpdatedAt = future
			expires := now.Add(time.Hour)
			state.Revocations = append(state.Revocations, CertificateRevocation{Fingerprint: strings.Repeat("a", 64), NodeID: target.ID, NetworkID: target.NetworkID, At: future, ExpiresAt: &expires})
			state.Audit = append(state.Audit, AuditEvent{ID: "future-revoke", Action: "node.revoked", Resource: "node", ResourceID: target.ID, At: future})
			return future
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base()
			wantTime := test.mutate(&state)
			fleetFillDesiredDigests(&state, now)
			report, err := deriveFleetHealth(state, state.Networks[0].ID, now)
			if err != nil {
				t.Fatal(err)
			}
			alert, ok := fleetFindAlert(report.Alerts, "control_time_invalid")
			if !ok || alert.Severity != FleetHealthCritical || alert.Scope != "network" || alert.Evidence.ControlTimeAt == nil || !alert.Evidence.ControlTimeAt.Equal(wantTime) || report.Summary.Overall != FleetHealthCritical {
				t.Fatalf("future control time did not fail closed: report=%#v alert=%#v", report, alert)
			}
			if _, stale := fleetFindAlert(report.Alerts, "stale_revocation"); stale {
				t.Fatalf("future revocation was also claimed as conclusive stale evidence: %#v", report.Alerts)
			}
		})
	}
}

func TestFleetHealthPropagatesReadErrorsAndNotFound(t *testing.T) {
	now := time.Date(2026, 7, 19, 23, 0, 0, 0, time.UTC)
	backend := &fakeStateStore{state: State{Networks: []Network{{ID: "known", Name: "known", ConfigRevision: 1, ConfigUpdatedAt: now}}}}
	service, err := NewServiceWithStateStore(backend, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	if _, err := service.FleetHealth("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing network error = %v", err)
	}
	readErr := errors.New("read failed")
	backend.viewErr = readErr
	if _, err := service.FleetHealth("known"); !errors.Is(err, readErr) {
		t.Fatalf("backend error = %v", err)
	}
	backend.viewErr = nil
	service.now = func() time.Time { return time.Time{} }
	views := backend.viewCalls
	if _, err := service.FleetHealth("known"); err == nil || err.Error() != "fleet health requires a valid timestamp" || backend.viewCalls != views+1 {
		t.Fatalf("zero clock did not fail inside one stable storage read: err=%v views=%d/%d", err, backend.viewCalls, views)
	}
}

func fleetHealthyNode(id, name, role string, network Network, now time.Time) Node {
	enrolled := now.Add(-time.Hour)
	seen := now.Add(-time.Minute)
	certificateExpires := now.Add(90 * 24 * time.Hour)
	certificateRenew := now.Add(31 * 24 * time.Hour)
	credentialExpires := now.Add(60 * 24 * time.Hour)
	fingerprint := strings.Repeat("f", 64)
	return Node{
		ID: id, NetworkID: network.ID, Name: name, Role: role, Status: "active",
		IP: "10.250.0.10", AgentVersion: "mesh-test-agent", NebulaVersion: "1.10.3",
		EnrolledAt: &enrolled, LastSeenAt: &seen, AgentStatus: "healthy", NebulaRunning: true,
		AppliedConfigRevision: network.ConfigRevision,
		CertificateGeneration: 1, AppliedCertificateGeneration: 1,
		CertificateFingerprint: fingerprint, ReportedCertificateFingerprint: fingerprint,
		CertificateExpiresAt: &certificateExpires, CertificateRenewAfter: &certificateRenew,
		AgentCredentialExpiresAt: &credentialExpires,
	}
}

func fleetFillDesiredDigests(state *State, now time.Time) {
	index := buildFleetHealthIndex(*state, now)
	for i := range state.Nodes {
		if state.Nodes[i].Status == "active" && state.Nodes[i].AppliedConfigSHA256 == "" {
			state.Nodes[i].AppliedConfigSHA256 = index.DesiredConfigDigestByNode[state.Nodes[i].ID]
		}
	}
}

func fleetCollectionNode(t *testing.T, collection FleetHealthCollection, networkID, nodeID string) FleetNodeHealth {
	t.Helper()
	for _, report := range collection.Networks {
		if report.Network.ID != networkID {
			continue
		}
		for _, node := range report.Nodes {
			if node.ID == nodeID {
				return node
			}
		}
	}
	t.Fatalf("node %q/%q not found in collection", networkID, nodeID)
	return FleetNodeHealth{}
}

func fleetProjectedNode(t *testing.T, report FleetHealthReport, nodeID string) FleetNodeHealth {
	t.Helper()
	for _, node := range report.Nodes {
		if node.ID == nodeID {
			return node
		}
	}
	t.Fatalf("node %q not found in %#v", nodeID, report.Nodes)
	return FleetNodeHealth{}
}

func fleetAlertCodes(alerts []FleetHealthAlert) []string {
	codes := make([]string, len(alerts))
	for i := range alerts {
		codes[i] = alerts[i].Code
	}
	return codes
}

func fleetFindAlert(alerts []FleetHealthAlert, code string) (FleetHealthAlert, bool) {
	for _, alert := range alerts {
		if alert.Code == code {
			return alert, true
		}
	}
	return FleetHealthAlert{}, false
}

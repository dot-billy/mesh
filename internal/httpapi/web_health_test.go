package httpapi

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestDashboardFleetHealthAssets(t *testing.T) {
	healthScript, err := webFiles.ReadFile("web/health.js")
	if err != nil {
		t.Fatal(err)
	}
	setupGuideScript, err := webFiles.ReadFile("web/setup-guide.js")
	if err != nil {
		t.Fatal(err)
	}
	telemetryScript, err := webFiles.ReadFile("web/runtime-telemetry.js")
	if err != nil {
		t.Fatal(err)
	}
	readinessScript, err := webFiles.ReadFile("web/readiness.js")
	if err != nil {
		t.Fatal(err)
	}
	dnsScript, err := webFiles.ReadFile("web/dns-settings.js")
	if err != nil {
		t.Fatal(err)
	}
	relayScript, err := webFiles.ReadFile("web/relay-settings.js")
	if err != nil {
		t.Fatal(err)
	}
	caRotationScript, err := webFiles.ReadFile("web/ca-rotation.js")
	if err != nil {
		t.Fatal(err)
	}
	routeTransferScript, err := webFiles.ReadFile("web/route-transfer.js")
	if err != nil {
		t.Fatal(err)
	}
	routeProfileScript, err := webFiles.ReadFile("web/route-profile.js")
	if err != nil {
		t.Fatal(err)
	}
	routePoliciesScript, err := webFiles.ReadFile("web/route-policies.js")
	if err != nil {
		t.Fatal(err)
	}
	firewallRolloutScript, err := webFiles.ReadFile("web/firewall-rollout.js")
	if err != nil {
		t.Fatal(err)
	}
	certificateRotationScript, err := webFiles.ReadFile("web/certificate-rotation.js")
	if err != nil {
		t.Fatal(err)
	}
	nodeRevocationScript, err := webFiles.ReadFile("web/node-revocation.js")
	if err != nil {
		t.Fatal(err)
	}
	desktopAuthorizationScript, err := webFiles.ReadFile("web/desktop-authorization.js")
	if err != nil {
		t.Fatal(err)
	}
	appScript, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	enterpriseCSS, err := webFiles.ReadFile("web/enterprise.css")
	if err != nil {
		t.Fatal(err)
	}
	if len(enterpriseCSS) == 0 {
		t.Fatal("dashboard enterprise presentation layer must be embedded")
	}
	fontAwesomeCSS, err := webFiles.ReadFile("web/font-awesome/css/font-awesome.min.css")
	if err != nil {
		t.Fatal(err)
	}
	fontAwesomeWOFF2, err := webFiles.ReadFile("web/font-awesome/fonts/fontawesome-webfont.woff2")
	if err != nil {
		t.Fatal(err)
	}
	if len(fontAwesomeCSS) == 0 || len(fontAwesomeWOFF2) == 0 {
		t.Fatal("dashboard icon library assets must be embedded")
	}

	for _, required := range []string{
		"MAX_SNAPSHOT_AGE_MS", "MAX_FUTURE_SKEW_MS", "validateFleetSnapshot", "createRefreshCoordinator",
		"responseAdjustedNow",
		"authenticated_agent_heartbeat", "certificate_renew_after", "agent_credential_expires_at",
		"agent_degraded", "certificate_fingerprint_drift", "certificate_generation_drift",
		"certificate_metadata_missing", "config_digest_drift", "config_drift", "control_time_invalid",
		"credential_metadata_missing", "heartbeat_time_invalid", "lighthouse_unavailable", "lighthouse_single",
		"projection_limit_exceeded", "stale_revocation", "telemetry_invalid",
		"heartbeat_sequence", "failure_domain", "site", "routed_subnets", "routedSubnet", "compareRoutedSubnets",
	} {
		if !bytes.Contains(healthScript, []byte(required)) {
			t.Fatalf("authoritative fleet health adapter is missing %q", required)
		}
	}
	for _, required := range []string{"Invalid network setup guide input", "requiredLighthouses", "resume_node", "add_redundancy", "Authenticated lifecycle state only"} {
		if !bytes.Contains(setupGuideScript, []byte(required)) {
			t.Fatalf("network setup guide is missing %q", required)
		}
	}
	for _, required := range []string{
		"mesh-network-dns-v1", "network_cidr", "firewall_ready", "resolvers", "config_revision", "sameDesired",
	} {
		if !bytes.Contains(dnsScript, []byte(required)) {
			t.Fatalf("network DNS adapter is missing %q", required)
		}
	}
	for _, required := range []string{
		"mesh-network-relays-v1", "network_cidr", "relay_node_ids", "active_relays", "max_relay_nodes", "sameDesired",
	} {
		if !bytes.Contains(relayScript, []byte(required)) {
			t.Fatalf("network relay adapter is missing %q", required)
		}
	}
	for _, required := range []string{"mesh-network-ca-rotation-v1", "previous_trust_bundle_sha256", "target_ca_certificate_sha256", "available_actions", "converged_nodes"} {
		if !bytes.Contains(caRotationScript, []byte(required)) {
			t.Fatalf("network CA rotation adapter is missing %q", required)
		}
	}
	for _, required := range []string{"mesh-network-route-transfer-v1", "preparing_target", "cleaning_source", "cleaning_target", "desired_certificate_generation", "available_actions"} {
		if !bytes.Contains(routeTransferScript, []byte(required)) {
			t.Fatalf("network route transfer adapter is missing %q", required)
		}
	}
	for _, required := range []string{"mesh-node-route-profile-edit-v1", "preparing_owner", "cleaning_owner", "cleaning_cancelled_owner", "desired_certificate_generation", "available_actions"} {
		if !bytes.Contains(routeProfileScript, []byte(required)) {
			t.Fatalf("node route profile adapter is missing %q", required)
		}
	}
	for _, required := range []string{"mesh-network-route-policies-v1", "gateways", "weight", "mtu", "metric", "last_request_id", "available_actions"} {
		if !bytes.Contains(routePoliciesScript, []byte(required)) {
			t.Fatalf("network route policies adapter is missing %q", required)
		}
	}
	for _, required := range []string{"mesh-network-firewall-rollout-v5", "target_policy_sha256", "canary_nodes", "converged_canaries", "desired_config_sha256", "available_actions", "last_transition", "auto_rolled_back", "paused_at", "resume", "target_runtime_stopped", "automatic_rollback_guards"} {
		if !bytes.Contains(firewallRolloutScript, []byte(required)) {
			t.Fatalf("network firewall rollout adapter is missing %q", required)
		}
	}
	for _, required := range []string{"Invalid certificate rotation evidence", "newRequestID", "restoreExpected", "validateReceipt", "previous_certificate_blocklisted", "agent_recovery_records_invalidated"} {
		if !bytes.Contains(certificateRotationScript, []byte(required)) {
			t.Fatalf("certificate rotation adapter is missing %q", required)
		}
	}
	for _, required := range []string{"Invalid node revocation evidence", "newRequestID", "restoreExpected", "validateReceipt", "credentials_invalidated", "blocklist_entries_added"} {
		if !bytes.Contains(nodeRevocationScript, []byte(required)) {
			t.Fatalf("node revocation adapter is missing %q", required)
		}
	}
	for _, required := range []string{"policy-rollout-guards", "Missing, stale, or generic degraded telemetry never triggers rollback"} {
		if !bytes.Contains(html, []byte(required)) && !bytes.Contains(appScript, []byte(required)) {
			t.Fatalf("network firewall rollout guard UI is missing %q", required)
		}
	}
	for _, required := range []string{
		"mesh-network-readiness-v6", "managed_route_overlap", "client_route_overlap",
		"lighthouse_redundancy", "topology_diversity", "control_plane_dns", "member_dns_resolution", "public_udp_reachability",
		"not_observed", "verification_required", "validate", "statusLabel", "overallLabel",
	} {
		if !bytes.Contains(readinessScript, []byte(required)) {
			t.Fatalf("deployment readiness adapter is missing %q", required)
		}
	}
	for _, required := range []string{
		"api('/api/v1/fleet/health'", "withMetadata: true", "timeoutMS: 10000",
		"headersReceivedAtMS", "bodyParsedAtMS", "performance.now()",
		"responseAdjustedNow", "validateFleetSnapshot(response.payload, responseNowMS)", "loadNetworks(true)",
		"document.addEventListener('visibilitychange'", "window.addEventListener('pageshow'",
		"scheduleFleetExpiry()", "cachedFleetIsStale()", "}, 15000);",
		"api('/api/v1/fleet/runtime-telemetry'", "validateFleetProjection(response.payload, responseNowMS)",
		"runtimeTelemetryModel.presentation", "runtimeObservationPresentation", "return runtimeTelemetryModel.presentation(node, null, 0)",
		"heartbeatEvidence", "Heartbeat #", "Last authenticated heartbeat", "node-heartbeat-detail", "topology-node-heartbeat",
		"node-observation-detail", "node-route-detail", "Routes via this certificate", "form.routed_subnets.value.split",
		"const readinessModel = globalThis.MeshReadiness", "openReadiness(network)",
		"/readiness`, { timeoutMS: 8000", "readinessModel.validate", "No result is inferred",
		"openNode(network.id, true, 'lighthouse')", "Step 2 of 3", "Step 3 of 3", "Configure its first public lighthouse to finish setup",
		"openNode(network.id, true, 'redundancy')", "Readiness remediation", "Place this lighthouse in a different failure domain",
		"READINESS_REFRESH_INTERVAL_MS = 10000", "scheduleReadinessRefresh()", "clearReadinessRefreshTimer()", "dataset.autoRefreshScheduled",
		"state.enrollmentNextNetworkID", "state.enrollmentNextAction", "I saved this — check readiness", "$('#enroll-token').textContent = ''",
		"const dnsSettingsModel = globalThis.MeshDNSSettings", "openDNS(network)", "/dns`,", "Firewall permits UDP", "Save and deploy",
		"const relaySettingsModel = globalThis.MeshRelaySettings", "openRelays(network)", "/relays`,", "Network relays",
		"const caRotationModel = globalThis.MeshCARotation", "openCARotation(network)", "/ca-rotation`,", "Prepare replacement CA",
		"const routeTransferModel = globalThis.MeshRouteTransfer", "openRouteTransfer(network, nodes)", "/route-transfer`", "Start safe transfer",
		"const routeProfileModel = globalThis.MeshRouteProfile", "openRouteProfile(network, node)", "/route-profile`", "Start safe edit",
		"const routePoliciesModel = globalThis.MeshRoutePolicies", "openRoutePolicies(network)", "/route-policies`", "Save and deploy",
		"const firewallRolloutModel = globalThis.MeshFirewallRollout", "/firewall-rollout`", "Start canary rollout", "applyPolicyRolloutAction",
		"const certificateRotationModel = globalThis.MeshCertificateRotation", "certificateRotationModel.newRequestID", "certificateRotationModel.validateReceipt", "sessionStorage", "rememberCertificateRotationRequest", "Verify rotation",
		"const nodeRevocationModel = globalThis.MeshNodeRevocation", "nodeRevocationModel.newRequestID", "nodeRevocationModel.validateReceipt", "rememberNodeRevocationRequest", "Verify revocation", "/revocation`",
		"$('#recovery-node-name').textContent = ''", "$('#recovery-command').textContent = ''",
		"$('#recovery-token').textContent = ''", "$('#recovery-expires-at').textContent = ''",
		"setNetworkWorkspaceChrome", "network-workspace", "Topology", "Back to networks", "Continue enrollment",
		"network-settings-menu", "topology-legend", "workspace-node-management", "setupActionDescription", "network-directory-header",
		"fleet-warning-count", "Awaiting active nodes", "window.scrollTo(0, 0)", "preventScroll: true",
		"topologyNodes", "activity-empty", "check-circle-o",
		"validateSessionAccess", "hasPermission('networks.write')", "hasPermission('networks.security')", "hasPermission('identity.manage')", "Operator access required",
	} {
		if !bytes.Contains(appScript, []byte(required)) {
			t.Fatalf("dashboard authoritative refresh path is missing %q", required)
		}
	}
	if !bytes.Contains(html, []byte(`id="access-role"`)) {
		t.Fatal("dashboard is missing the authenticated role indicator")
	}
	if count := bytes.Count(appScript, []byte("/api/v1/fleet/health")); count != 1 {
		t.Fatalf("dashboard has %d fleet health reads, want one authoritative read path", count)
	}
	if count := bytes.Count(appScript, []byte("/api/v1/fleet/runtime-telemetry")); count != 1 {
		t.Fatalf("dashboard has %d runtime telemetry reads, want one observational read path", count)
	}
	for _, required := range []string{
		"mesh-runtime-telemetry-fleet-v2", "mesh-runtime-telemetry-fleet-v3", "mesh-runtime-telemetry-fleet-v4", "mesh-runtime-telemetry-fleet-v5",
		"observation_version", "process_continuity", "most_recent_authenticated_rx_age_ms", "active_probe", "probe_transition", "sample_age_ms", "duration_ms",
		"not_eligible", "unsupported", "capability_unavailable", "attempted", "unavailable", "Lighthouse ICMP replied",
		"validateFleetProjection", "presentation", "estimatedServerNow",
		"aggregate_only", "end_to_end_reachability_proven", "Not an end-to-end reachability result",
	} {
		if !bytes.Contains(telemetryScript, []byte(required)) {
			t.Fatalf("dashboard runtime telemetry adapter is missing %q", required)
		}
	}
	if bytes.Contains(appScript, []byte("api('/api/v1/networks')")) {
		t.Fatal("dashboard must not restore the legacy networks inventory read")
	}
	if !bytes.Contains(appScript, []byte("api('/api/v1/networks', { method: 'POST'")) ||
		!bytes.Contains(appScript, []byte("/nodes`, { method: 'POST'")) {
		t.Fatal("dashboard inventory mutations must remain available without legacy inventory reads")
	}

	for _, forbidden := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"} {
		if bytes.Contains(appScript, []byte(forbidden)) || bytes.Contains(healthScript, []byte(forbidden)) || bytes.Contains(setupGuideScript, []byte(forbidden)) || bytes.Contains(telemetryScript, []byte(forbidden)) || bytes.Contains(readinessScript, []byte(forbidden)) || bytes.Contains(dnsScript, []byte(forbidden)) || bytes.Contains(relayScript, []byte(forbidden)) || bytes.Contains(routeTransferScript, []byte(forbidden)) || bytes.Contains(routeProfileScript, []byte(forbidden)) || bytes.Contains(routePoliciesScript, []byte(forbidden)) || bytes.Contains(firewallRolloutScript, []byte(forbidden)) || bytes.Contains(certificateRotationScript, []byte(forbidden)) || bytes.Contains(nodeRevocationScript, []byte(forbidden)) {
			t.Fatalf("dashboard health rendering contains unsafe DOM API %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		"'last_error'", "'agent_version'", "'nebula_version'", "'applied_config_sha256'",
		"'reported_certificate_fingerprint'", "'certificate_fingerprint'",
	} {
		if bytes.Contains(appScript, []byte(forbidden)) || bytes.Contains(healthScript, []byte(forbidden)) || bytes.Contains(telemetryScript, []byte(forbidden)) || bytes.Contains(readinessScript, []byte(forbidden)) {
			t.Fatalf("dashboard authoritative health assets expose private telemetry field %q", forbidden)
		}
	}
	for _, forbidden := range []string{"process_instance_id", "private_key", "agent_token", "target_ip", "local_ip", "plan_sha256", "nonce", "socket_error"} {
		if bytes.Contains(appScript, []byte(forbidden)) || bytes.Contains(telemetryScript, []byte(forbidden)) {
			t.Fatalf("dashboard observation assets expose private runtime field %q", forbidden)
		}
	}

	healthIndex := bytes.Index(html, []byte(`<script src="/health.js" defer></script>`))
	telemetryIndex := bytes.Index(html, []byte(`<script src="/runtime-telemetry.js" defer></script>`))
	readinessIndex := bytes.Index(html, []byte(`<script src="/readiness.js" defer></script>`))
	dnsIndex := bytes.Index(html, []byte(`<script src="/dns-settings.js" defer></script>`))
	relayIndex := bytes.Index(html, []byte(`<script src="/relay-settings.js" defer></script>`))
	caRotationIndex := bytes.Index(html, []byte(`<script src="/ca-rotation.js" defer></script>`))
	routeTransferIndex := bytes.Index(html, []byte(`<script src="/route-transfer.js" defer></script>`))
	routeProfileIndex := bytes.Index(html, []byte(`<script src="/route-profile.js" defer></script>`))
	routePoliciesIndex := bytes.Index(html, []byte(`<script src="/route-policies.js" defer></script>`))
	firewallRolloutIndex := bytes.Index(html, []byte(`<script src="/firewall-rollout.js" defer></script>`))
	certificateRotationIndex := bytes.Index(html, []byte(`<script src="/certificate-rotation.js" defer></script>`))
	nodeRevocationIndex := bytes.Index(html, []byte(`<script src="/node-revocation.js" defer></script>`))
	desktopAuthorizationIndex := bytes.Index(html, []byte(`<script src="/desktop-authorization.js" defer></script>`))
	appIndex := bytes.Index(html, []byte(`<script src="/app.js" defer></script>`))
	if healthIndex < 0 || telemetryIndex < 0 || readinessIndex < 0 || dnsIndex < 0 || relayIndex < 0 || caRotationIndex < 0 || routeTransferIndex < 0 || routeProfileIndex < 0 || routePoliciesIndex < 0 || firewallRolloutIndex < 0 || certificateRotationIndex < 0 || nodeRevocationIndex < 0 || desktopAuthorizationIndex < 0 || appIndex < 0 || healthIndex >= telemetryIndex || telemetryIndex >= readinessIndex || readinessIndex >= dnsIndex || dnsIndex >= relayIndex || relayIndex >= caRotationIndex || caRotationIndex >= routeTransferIndex || routeTransferIndex >= routeProfileIndex || routeProfileIndex >= routePoliciesIndex || routePoliciesIndex >= firewallRolloutIndex || firewallRolloutIndex >= certificateRotationIndex || certificateRotationIndex >= nodeRevocationIndex || nodeRevocationIndex >= desktopAuthorizationIndex || desktopAuthorizationIndex >= appIndex {
		t.Fatal("dashboard must load its strict adapters before the application script")
	}
	for _, required := range []string{
		`id="fleet-health"`, `aria-labelledby="fleet-health-title"`,
		`href="/font-awesome/css/font-awesome.min.css"`, `href="/enterprise.css"`, `id="app-page-header"`,
		`id="fleet-health-badge" class="health-badge critical"`, `aria-live="polite">Unavailable`,
		`id="fleet-critical-nodes">—`, `id="fleet-rollout-progress" max="1" value="0"`,
		`id="fleet-generated-at">unavailable`, "No health or inventory is inferred",
		"Authoritative fleet health has not loaded", "Authenticated health telemetry",
		`class="skip-link"`, `id="fleet-warning-count"`, `class="login-assurance"`, `class="brand-copy"`,
		`id="node-dialog-eyebrow"`, `id="node-dialog-title"`, `id="node-dialog-copy"`, `id="node-cancel"`, `id="node-routed-subnets"`, "use the staged route-transfer workflow",
		`id="enroll-next"`, `id="enroll-dialog" class="wide-dialog"`, `id="readiness-dialog" class="wide-dialog"`, "Step 1 of 3", "Checks refresh automatically every 10 seconds", `id="refresh-readiness"`, "Run checks now",
		`id="dns-dialog"`, `id="dns-enabled"`, `id="dns-listen-port"`, `id="dns-native-resolver"`, `id="dns-search-domain"`, `id="dns-resolver-list"`, "Configure Linux split DNS",
		`id="relay-dialog"`, `id="relay-enabled"`, `id="relay-candidate-list"`, `id="relay-active-list"`, "Relay support is experimental upstream",
		`id="ca-rotation-dialog"`, `id="ca-rotation-phase"`, `id="ca-rotation-convergence"`, `id="ca-rotation-primary"`, "overlapping trust",
		`id="route-transfer-dialog"`, `id="route-transfer-source"`, `id="route-transfer-target"`, `id="route-transfer-primary"`, "replacement gateway",
		`id="route-profile-dialog"`, `id="route-profile-subnets"`, `id="route-profile-primary"`, "complete routed-subnet set",
		`id="route-policies-dialog"`, `id="route-policies-prefix"`, `id="route-policies-gateways"`, `id="save-route-policy"`, "relative gateway weights",
		`id="policy-rollout-panel"`, `id="policy-canary-list"`, `id="promote-policy"`, `id="rollback-policy"`, "selected canaries",
		`id="desktop-authorization-dialog"`, `id="desktop-authorization-approve"`, `id="desktop-authorization-deny"`,
		"Approve only if you started sign-in from the native app.",
	} {
		if !bytes.Contains(html, []byte(required)) {
			t.Fatalf("dashboard fail-closed markup is missing %q", required)
		}
	}
	if bytes.Contains(html, []byte("Control plane healthy")) {
		t.Fatal("dashboard static markup must not claim health before authoritative data loads")
	}
	if bytes.Contains(html, []byte("poll_secret")) || bytes.Contains(appScript, []byte("poll_secret")) ||
		!bytes.Contains(desktopAuthorizationScript, []byte("replaceState(null")) ||
		!bytes.Contains(desktopAuthorizationScript, []byte(`^desktop_[A-Za-z0-9_-]{43}$`)) {
		t.Fatal("desktop authorization UI must keep poll secrets out of markup and strictly scrub public request IDs from browser history")
	}
	for _, required := range []string{
		"--surface-raised", "--accent-hover", ".skip-link", ".login-assurance",
		".network-directory-header", ".fleet-warning-panel > summary",
		".workspace-primary-action:disabled", ".activity-empty",
		"@media (max-width: 760px)", "@media (prefers-reduced-motion: reduce)",
	} {
		if !bytes.Contains(enterpriseCSS, []byte(required)) {
			t.Fatalf("dashboard enterprise presentation layer is missing %q", required)
		}
	}

	selectorPattern := regexp.MustCompile(`\$\('#([A-Za-z0-9_-]+)'\)`)
	for _, match := range selectorPattern.FindAllSubmatch(appScript, -1) {
		id := string(match[1])
		if !bytes.Contains(html, []byte(`id="`+id+`"`)) {
			t.Fatalf("dashboard script references missing element id %q", id)
		}
	}
}

func TestDashboardFleetHealthModelWithNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is not installed; asset contract test still applies")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "--test", "webtest/dns-settings.test.js", "webtest/relay-settings.test.js", "webtest/ca-rotation.test.js", "webtest/route-transfer.test.js", "webtest/route-profile.test.js", "webtest/route-policies.test.js", "webtest/firewall-rollout.test.js", "webtest/health.test.js", "webtest/install-guide.test.js", "webtest/runtime-telemetry.test.js", "webtest/readiness.test.js", "webtest/desktop-authorization.test.js")
	output, err := command.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("fleet health JavaScript tests exceeded the 30-second deadline\n%s", output)
	}
	if err != nil {
		t.Fatalf("fleet health JavaScript tests failed: %v\n%s", err, output)
	}
}

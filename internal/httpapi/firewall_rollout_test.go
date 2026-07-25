package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestNetworkFirewallRolloutEndpointsRequireExactAuthenticatedLifecycle(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x72}, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'B'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, migrate := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
	} {
		if err := migrate(); err != nil {
			t.Fatal(err)
		}
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "firewall-rollout-api", CIDR: "10.100.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "canary"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("w", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('W'), control.HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}

	token := strings.Repeat("b", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/firewall-rollout"
	request := func(method, suffix, body, authorization string) (*http.Response, []byte) {
		t.Helper()
		req, requestErr := http.NewRequest(method, endpoint+suffix, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if authorization != "" {
			req.Header.Set("Authorization", "Bearer "+authorization)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		raw, requestErr := io.ReadAll(response.Body)
		response.Body.Close()
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response, raw
	}

	unauthorized, _ := request(http.MethodGet, "", "", "")
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated firewall rollout GET returned %d", unauthorized.StatusCode)
	}
	response, raw := request(http.MethodGet, "", "", token)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stable firewall rollout GET status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), raw)
	}
	var stable control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &stable); err != nil {
		t.Fatal(err)
	}
	if stable.Schema != control.NetworkFirewallRolloutDocumentSchema || stable.Phase != "stable" || stable.ConfigRevision != 1 || stable.ActiveNodes != 1 || len(stable.Nodes) != 1 || len(stable.AvailableActions) != 1 || stable.AvailableActions[0] != "start" || stable.TargetPolicy != nil {
		t.Fatalf("unexpected stable firewall rollout document: %+v", stable)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	gotFields := make([]string, 0, len(fields))
	for field := range fields {
		gotFields = append(gotFields, field)
	}
	sort.Strings(gotFields)
	wantFields := []string{"active_nodes", "automatic_rollback_guards", "available_actions", "canary_nodes", "config_revision", "config_updated_at", "converged_canaries", "current_policy_sha256", "last_transition", "network_id", "nodes", "paused_at", "phase", "schema", "stage_config_revision", "started_at", "target_policy", "target_policy_sha256"}
	if !slicesEqual(gotFields, wantFields) {
		t.Fatalf("firewall rollout fields=%v want=%v", gotFields, wantFields)
	}

	start := `{"action":"start","expected_config_revision":1,"canary_node_ids":["` + created.Node.ID + `"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}`
	response, raw = request(http.MethodPost, "", start, token)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("start firewall rollout status=%d body=%s", response.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("agent_token")) || bytes.Contains(raw, []byte("config_signing")) {
		t.Fatalf("firewall rollout API leaked private material: %s", raw)
	}
	var started control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &started); err != nil {
		t.Fatal(err)
	}
	if started.Phase != control.FirewallRolloutPhaseCanary || started.ConfigRevision != 2 || started.CanaryNodes != 1 || started.TargetPolicy == nil || !slicesEqual(started.AvailableActions, []string{"pause", "rollback"}) {
		t.Fatalf("unexpected started rollout: %+v", started)
	}

	response, _ = request(http.MethodPost, "", strings.TrimSuffix(start, "}")+`,"unexpected":true}`, token)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("firewall rollout endpoint accepted an unknown field: %d", response.StatusCode)
	}
	response, _ = request(http.MethodGet, "?unexpected=1", "", token)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("firewall rollout endpoint accepted a query string: %d", response.StatusCode)
	}
	response, _ = request(http.MethodPost, "", `{"action":"promote","expected_config_revision":2,"canary_node_ids":[]}`, token)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("promote accepted start-only fields: %d", response.StatusCode)
	}
	response, _ = request(http.MethodPost, "", `{"action":"promote","expected_config_revision":1}`, token)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("firewall rollout accepted a stale action: %d", response.StatusCode)
	}
	response, _ = request(http.MethodPost, "", `{"action":"promote","expected_config_revision":2}`, token)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("firewall rollout promoted an unconverged canary: %d", response.StatusCode)
	}
	response, raw = request(http.MethodPost, "", `{"action":"pause","expected_config_revision":2}`, token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("pause firewall rollout status=%d body=%s", response.StatusCode, raw)
	}
	var paused control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &paused); err != nil {
		t.Fatal(err)
	}
	if paused.Phase != control.FirewallRolloutPhasePaused || paused.ConfigRevision != 3 || paused.PausedAt == nil || paused.TargetPolicy == nil || !slicesEqual(paused.AvailableActions, []string{"resume", "rollback"}) || paused.LastTransition == nil || paused.LastTransition.Action != "paused" {
		t.Fatalf("unexpected paused rollout: %+v", paused)
	}
	response, raw = request(http.MethodPost, "", `{"action":"resume","expected_config_revision":3}`, token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("resume firewall rollout status=%d body=%s", response.StatusCode, raw)
	}
	var resumed control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &resumed); err != nil {
		t.Fatal(err)
	}
	if resumed.Phase != control.FirewallRolloutPhaseCanary || resumed.ConfigRevision != 4 || resumed.StageConfigRevision != 4 || resumed.PausedAt != nil || !slicesEqual(resumed.AvailableActions, []string{"pause", "rollback"}) || resumed.LastTransition == nil || resumed.LastTransition.Action != "resumed" {
		t.Fatalf("unexpected resumed rollout: %+v", resumed)
	}

	desired, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	failureEndpoint := server.URL + "/api/v1/agent/config-apply-failure"
	postFailure := func(body, authorization string) (*http.Response, []byte) {
		t.Helper()
		req, requestErr := http.NewRequest(http.MethodPost, failureEndpoint, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			req.Header.Set("Authorization", "Bearer "+authorization)
		}
		failureResponse, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		failureRaw, requestErr := io.ReadAll(failureResponse.Body)
		failureResponse.Body.Close()
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return failureResponse, failureRaw
	}
	failureBody := `{"attempted_config_revision":4,"attempted_config_sha256":"` + desired.SHA256 + `","failure_code":"activation_failed"}`
	response, _ = postFailure(failureBody, "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated activation failure returned %d", response.StatusCode)
	}
	response, _ = postFailure(strings.TrimSuffix(failureBody, "}")+`,"unexpected":true}`, agentToken)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("activation failure accepted an unknown field: %d", response.StatusCode)
	}
	queryRequest, err := http.NewRequest(http.MethodPost, failureEndpoint+"?unexpected=1", strings.NewReader(failureBody))
	if err != nil {
		t.Fatal(err)
	}
	queryRequest.Header.Set("Content-Type", "application/json")
	queryRequest.Header.Set("Authorization", "Bearer "+agentToken)
	queryResponse, err := http.DefaultClient.Do(queryRequest)
	if err != nil {
		t.Fatal(err)
	}
	queryResponse.Body.Close()
	if queryResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("activation failure accepted query parameters: %d", queryResponse.StatusCode)
	}
	forgedBody := `{"attempted_config_revision":4,"attempted_config_sha256":"` + strings.Repeat("f", 64) + `","failure_code":"activation_failed"}`
	response, _ = postFailure(forgedBody, agentToken)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("activation failure accepted a forged digest: %d", response.StatusCode)
	}
	response, raw = postFailure(failureBody, agentToken)
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" || len(raw) != 0 {
		t.Fatalf("exact activation failure status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), raw)
	}
	response, raw = request(http.MethodGet, "", "", token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read automatic rollback status=%d body=%s", response.StatusCode, raw)
	}
	var automatic control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &automatic); err != nil {
		t.Fatal(err)
	}
	if automatic.Phase != "stable" || automatic.ConfigRevision != 5 || automatic.LastTransition == nil || automatic.LastTransition.Action != "auto_rolled_back" || automatic.LastTransition.ReasonCode != "canary_config_activation_failed" || automatic.LastTransition.NodeID != created.Node.ID {
		t.Fatalf("automatic rollback API document is not exact: %+v", automatic)
	}

	restart := `{"action":"start","expected_config_revision":5,"canary_node_ids":["` + created.Node.ID + `"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}`
	response, raw = request(http.MethodPost, "", restart, token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restart for runtime guard status=%d body=%s", response.StatusCode, raw)
	}
	desired, err = service.AgentConfig(agentToken)
	if err != nil || desired.Revision != 6 {
		t.Fatalf("runtime guard desired config=%+v err=%v", desired, err)
	}
	heartbeatBody, err := json.Marshal(control.HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: desired.Revision,
		AppliedConfigSHA256: desired.SHA256, CertificateGeneration: bundle.CertificateGeneration,
		CertificateFingerprint: bundle.CertificateFingerprint, NebulaRunning: false, Status: "degraded",
		LastError: "must not reach the public rollout document", BootID: "http-runtime-guard", Sequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/heartbeat", bytes.NewReader(heartbeatBody))
	if err != nil {
		t.Fatal(err)
	}
	heartbeatRequest.Header.Set("Authorization", "Bearer "+agentToken)
	heartbeatRequest.Header.Set("Content-Type", "application/json")
	heartbeatResponse, err := http.DefaultClient.Do(heartbeatRequest)
	if err != nil {
		t.Fatal(err)
	}
	heartbeatRaw, err := io.ReadAll(heartbeatResponse.Body)
	heartbeatResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if heartbeatResponse.StatusCode != http.StatusNoContent || len(heartbeatRaw) != 0 {
		t.Fatalf("runtime guard heartbeat status=%d body=%s", heartbeatResponse.StatusCode, heartbeatRaw)
	}
	response, raw = request(http.MethodGet, "", "", token)
	if response.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("must not reach")) {
		t.Fatalf("runtime guard readback status=%d body=%s", response.StatusCode, raw)
	}
	var runtimeGuard control.NetworkFirewallRolloutDocument
	if err := json.Unmarshal(raw, &runtimeGuard); err != nil {
		t.Fatal(err)
	}
	if runtimeGuard.Phase != "stable" || runtimeGuard.ConfigRevision != 7 || runtimeGuard.LastTransition == nil || runtimeGuard.LastTransition.Action != "auto_rolled_back" || runtimeGuard.LastTransition.ReasonCode != "canary_target_runtime_stopped" || runtimeGuard.LastTransition.NodeID != created.Node.ID {
		t.Fatalf("runtime health rollback API document is not exact: %+v", runtimeGuard)
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

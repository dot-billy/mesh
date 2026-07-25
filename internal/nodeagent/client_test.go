package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/runtimetelemetry"
)

func TestClientUsesScopedEndpointsAndBearer(t *testing.T) {
	bearer := testBearer(t)
	now := time.Now().UTC().Truncate(time.Second)
	config := control.AgentConfig{NodeID: "node-1", NetworkID: "network-1", Revision: 2, Config: "config", IssuedAt: now, SHA256: strings.Repeat("b", 64), Signature: "signature", CertificateExpiresAt: now.Add(time.Hour)}
	bootstrap := control.EnrollmentBundle{Node: control.Node{ID: "node-1", NetworkID: "network-1"}, Certificate: "certificate", CA: "ca", Config: "config", ConfigRevision: 2}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/v1/agent/recover" && r.Header.Get("Authorization") != "" {
			t.Errorf("recovery authorization header = %q, want empty", r.Header.Get("Authorization"))
		} else if r.URL.Path != "/api/v1/agent/recover" && r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.RecoveryToken != "recovery-token" || input.PublicKey != "public-key" || input.NewAgentTokenHash != "new-hash" {
				t.Errorf("recovery input = %#v", input)
			}
			_ = json.NewEncoder(w).Encode(control.AgentRecoveryBundle{RecoveryReceipt: control.RecoveryReceipt{NodeID: "node-1"}})
		case "/api/v1/agent/config":
			if r.Method != http.MethodGet || r.Header.Get("If-None-Match") != `"1-old"` {
				t.Errorf("unexpected config request: method=%s etag=%q", r.Method, r.Header.Get("If-None-Match"))
			}
			w.Header().Set("ETag", `"2-new"`)
			_ = json.NewEncoder(w).Encode(config)
		case "/api/v1/agent/bootstrap":
			_ = json.NewEncoder(w).Encode(bootstrap)
		case "/api/v1/agent/heartbeat":
			var input control.HeartbeatInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.Sequence != 7 {
				t.Errorf("heartbeat sequence = %d", input.Sequence)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/config-apply-failure":
			var input control.ConfigApplyFailureInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if r.Method != http.MethodPost || input.AttemptedConfigRevision != 8 || input.AttemptedConfigSHA256 != strings.Repeat("c", 64) || input.FailureCode != control.ConfigApplyFailureCodeActivation {
				t.Errorf("config activation failure input = %#v method=%s", input, r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/runtime-telemetry":
			var input runtimetelemetry.ReportInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if r.Method != http.MethodPost || input.HeartbeatSequence != 7 || input.Observation.Version != runtimetelemetry.VersionV1 || input.Observation.State != runtimetelemetry.StateUnknown ||
				input.ActiveProbe == nil || input.ActiveProbe.State != runtimetelemetry.ProbeNotEligible {
				t.Errorf("runtime telemetry input = %#v method=%s", input, r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/certificate/renew":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["public_key"] != "public-key" {
				t.Errorf("renew public key = %q", input["public_key"])
			}
			_ = json.NewEncoder(w).Encode(control.RenewalBundle{Certificate: "new-certificate", ConfigRevision: 2})
		case "/api/v1/agent/credentials/rotate":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["new_token_hash"] != "new-hash" {
				t.Errorf("rotation hash = %q", input["new_token_hash"])
			}
			_ = json.NewEncoder(w).Encode(control.CredentialRotation{Generation: 3, ExpiresAt: now.Add(90 * 24 * time.Hour)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, bearer, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	response, err := client.GetConfig(ctx, `"1-old"`)
	if err != nil || response.Config.Revision != 2 || response.ETag != `"2-new"` {
		t.Fatalf("GetConfig response=%#v err=%v", response, err)
	}
	if recovered, err := client.Bootstrap(ctx); err != nil || recovered.Certificate != "certificate" {
		t.Fatalf("Bootstrap response=%#v err=%v", recovered, err)
	}
	if recovered, err := client.RecoverAgent(ctx, control.RecoverAgentInput{RecoveryToken: "recovery-token", PublicKey: "public-key", NewAgentTokenHash: "new-hash"}); err != nil || recovered.RecoveryReceipt.NodeID != "node-1" {
		t.Fatalf("RecoverAgent response=%#v err=%v", recovered, err)
	}
	if err := client.Heartbeat(ctx, control.HeartbeatInput{Sequence: 7}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportConfigApplyFailure(ctx, control.ConfigApplyFailureInput{AttemptedConfigRevision: 8, AttemptedConfigSHA256: strings.Repeat("c", 64), FailureCode: control.ConfigApplyFailureCodeActivation}); err != nil {
		t.Fatal(err)
	}
	probe := runtimetelemetry.NotEligibleActiveProbe()
	if err := client.ReportRuntimeTelemetry(ctx, runtimetelemetry.ReportInput{
		HeartbeatSequence: 7,
		Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV1, State: runtimetelemetry.StateUnknown},
		ActiveProbe:       &probe,
	}); err != nil {
		t.Fatal(err)
	}
	if renewed, err := client.RenewCertificate(ctx, "public-key"); err != nil || renewed.Certificate != "new-certificate" {
		t.Fatalf("RenewCertificate response=%#v err=%v", renewed, err)
	}
	if rotated, err := client.RotateCredential(ctx, "new-hash"); err != nil || rotated.Generation != 3 {
		t.Fatalf("RotateCredential response=%#v err=%v", rotated, err)
	}
	if calls.Load() != 8 {
		t.Fatalf("API calls = %d, want 8", calls.Load())
	}
}

func TestClientTreatsMissingRuntimeTelemetryEndpointAsMixedVersion(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			client, err := NewClient(server.URL, testBearer(t), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			err = client.ReportRuntimeTelemetry(context.Background(), runtimetelemetry.ReportInput{
				HeartbeatSequence: 1,
				Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV1, State: runtimetelemetry.StateUnknown},
			})
			if !errors.Is(err, ErrRuntimeTelemetryUnsupported) {
				t.Fatalf("missing endpoint error = %v", err)
			}
		})
	}
}

func TestClientRejectsRedirectWithoutLeakingBearer(t *testing.T) {
	var received atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	client, err := NewClient(source.URL, testBearer(t), source.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetConfig(context.Background(), ""); err == nil {
		t.Fatal("redirected config request unexpectedly succeeded")
	}
	if received.Load() != 0 {
		t.Fatal("agent client followed a redirect and leaked request scope")
	}
}

func TestClientHonorsNotModified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testBearer(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.GetConfig(context.Background(), `"1-digest"`)
	if err != nil || !response.NotModified {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

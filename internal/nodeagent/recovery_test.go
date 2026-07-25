package nodeagent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestAgentRecoverCredentialVerifiesAndCommitsProvenBearer(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	recoveryToken := testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	var requestHash, pendingBearer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/recover":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("recovery endpoint received bearer authorization: %q", r.Header.Get("Authorization"))
			}
			var input control.RecoverAgentInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				return
			}
			if input.RecoveryToken != recoveryToken || input.PublicKey != bundle.PublicKey {
				t.Errorf("recovery input = %#v", input)
			}
			requestHash = input.NewAgentTokenHash
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, requestHash, 2, expiresAt))
		case "/api/v1/agent/bootstrap":
			pendingBearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !control.TokenHashEqual(requestHash, control.HashToken(pendingBearer)) {
				t.Errorf("bootstrap did not authenticate with proposed recovery bearer")
			}
			confirmed := testAgentRecoveryBundle(t, signer, bundle, requestHash, 2, expiresAt).EnrollmentBundle
			// Node is not signed and must not be used for recovery trust decisions.
			confirmed.Node = control.Node{ID: "unsigned-attacker-node", NetworkID: "unsigned-attacker-network"}
			_ = json.NewEncoder(w).Encode(confirmed)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	before.HeartbeatSequence = 41
	if err := store.Save(before); err != nil {
		t.Fatal(err)
	}
	result, err := agent.RecoverCredential(context.Background(), recoveryToken)
	if err != nil {
		t.Fatalf("recover credential: %v", err)
	}
	if !result.Changed || result.Revision != bundle.Revision {
		t.Fatalf("recovery result = %#v", result)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Bearer != pendingBearer || after.PendingBearer != "" || after.PendingRecoveryToken != "" {
		t.Fatalf("recovered bearer journal was not committed exactly: %#v", after)
	}
	if after.AgentCredentialGeneration != 2 || !after.AgentCredentialExpiresAt.Equal(expiresAt) || after.HeartbeatSequence != 41 {
		t.Fatalf("credential metadata or counters changed incorrectly: %#v", after)
	}
	if after.NodeID != before.NodeID || after.NetworkID != before.NetworkID || after.ConfigSigningPublicKey != before.ConfigSigningPublicKey || after.CACertificateSHA256 != before.CACertificateSHA256 || after.PublicKeyHash != before.PublicKeyHash {
		t.Fatal("recovery overwrote enrolled trust pins")
	}
}

func TestAgentRecoverCredentialRejectsAdversarialReceiptsAndBootstrap(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, testConfigSigner, *control.AgentRecoveryBundle)
	}{
		{name: "wrong signer", mutate: func(t *testing.T, _ testConfigSigner, response *control.AgentRecoveryBundle) {
			attacker := newTestSigner(t)
			resignTestRecoveryReceipt(t, attacker, response)
		}},
		{name: "pending bearer hash", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.NewAgentTokenHash = control.HashToken(testBearer(t))
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "node identity", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.NodeID = "node-2"
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "credential generation", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.AgentCredentialGeneration++
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "credential expiry", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.AgentCredentialExpiresAt = response.RecoveryReceipt.AgentCredentialExpiresAt.Add(time.Hour)
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "config digest", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.ConfigSHA256 = strings.Repeat("c", 64)
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "config signature link", mutate: func(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
			other := signer.bundle(t, 2, testNebulaConfig("other"), "certificate-one")
			response.RecoveryReceipt.ConfigSignature = other.Signature
			resignTestRecoveryReceipt(t, signer, response)
		}},
		{name: "receipt signature", mutate: func(_ *testing.T, _ testConfigSigner, response *control.AgentRecoveryBundle) {
			response.RecoveryReceipt.Signature = "invalid"
		}},
		{name: "bootstrap signing key", mutate: func(t *testing.T, _ testConfigSigner, response *control.AgentRecoveryBundle) {
			response.ConfigSigningPublicKey = newTestSigner(t).publicKey
		}},
		{name: "bootstrap CA bytes", mutate: func(_ *testing.T, _ testConfigSigner, response *control.AgentRecoveryBundle) {
			response.CA = "attacker-ca"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
			token := testBearer(t)
			now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
			var bootstrapCalls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/agent/bootstrap" {
					bootstrapCalls++
					http.Error(w, "unexpected proof request", http.StatusInternalServerError)
					return
				}
				if r.URL.Path != "/api/v1/agent/recover" {
					http.NotFound(w, r)
					return
				}
				var input control.RecoverAgentInput
				_ = json.NewDecoder(r.Body).Decode(&input)
				response := testAgentRecoveryBundle(t, signer, bundle, input.NewAgentTokenHash, 2, now.Add(90*24*time.Hour))
				test.mutate(t, signer, &response)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
			defer agent.Close()
			agent.Now = func() time.Time { return now }
			before, _ := store.Load()
			if _, err := agent.RecoverCredential(context.Background(), token); err == nil {
				t.Fatal("adversarial recovery unexpectedly succeeded")
			}
			after, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Bearer != before.Bearer || after.AgentCredentialGeneration != before.AgentCredentialGeneration || !after.AgentCredentialExpiresAt.Equal(before.AgentCredentialExpiresAt) {
				t.Fatalf("unverified recovery changed committed credential state: before=%#v after=%#v", before, after)
			}
			if after.PendingRecoveryToken != token || after.PendingBearer == "" {
				t.Fatalf("unverified recovery did not preserve its exact crash journal: %#v", after)
			}
			if bootstrapCalls != 0 {
				t.Fatalf("invalid recovery reached bearer proof %d times", bootstrapCalls)
			}
		})
	}
}

func TestAgentRecoverCredentialRejectsUnprovenOrMismatchedBearer(t *testing.T) {
	tests := []struct {
		name          string
		unauthorized  bool
		mutateBoth    func(*control.EnrollmentBundle)
		mutateConfirm func(*control.EnrollmentBundle)
	}{
		{name: "pending bearer unauthorized", unauthorized: true},
		{name: "credential metadata mismatch", mutateConfirm: func(bundle *control.EnrollmentBundle) {
			bundle.AgentCredentialGeneration++
		}},
		{name: "certificate bytes mismatch signed fingerprint", mutateBoth: func(bundle *control.EnrollmentBundle) {
			bundle.Certificate = "certificate-new"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
			token := testBearer(t)
			now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
			expiresAt := now.Add(90 * 24 * time.Hour)
			var requestHash string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/agent/recover":
					var input control.RecoverAgentInput
					_ = json.NewDecoder(r.Body).Decode(&input)
					requestHash = input.NewAgentTokenHash
					response := testAgentRecoveryBundle(t, signer, bundle, requestHash, 2, expiresAt)
					if test.mutateBoth != nil {
						test.mutateBoth(&response.EnrollmentBundle)
					}
					_ = json.NewEncoder(w).Encode(response)
				case "/api/v1/agent/bootstrap":
					if !control.TokenHashEqual(requestHash, control.HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))) {
						t.Error("proof request did not use pending bearer")
					}
					if test.unauthorized {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					confirmed := testAgentRecoveryBundle(t, signer, bundle, requestHash, 2, expiresAt).EnrollmentBundle
					if test.mutateBoth != nil {
						test.mutateBoth(&confirmed)
					}
					if test.mutateConfirm != nil {
						test.mutateConfirm(&confirmed)
					}
					_ = json.NewEncoder(w).Encode(confirmed)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
			defer agent.Close()
			agent.Now = func() time.Time { return now }
			before, _ := store.Load()
			if _, err := agent.RecoverCredential(context.Background(), token); err == nil {
				t.Fatal("unproven or mismatched recovery unexpectedly succeeded")
			}
			after, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Bearer != before.Bearer || after.AgentCredentialGeneration != before.AgentCredentialGeneration || after.PendingRecoveryToken != token || after.PendingBearer == "" {
				t.Fatalf("failed bearer proof changed committed state or lost journal: %#v", after)
			}
		})
	}
}

func TestAgentRecoverCredentialConcurrentResponseLossRetriesExactRequest(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	token := testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var requests []control.RecoverAgentInput
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			mu.Lock()
			requests = append(requests, input)
			attempt := len(requests)
			mu.Unlock()
			if attempt == 1 {
				close(firstStarted)
				<-releaseFirst
				_, _ = w.Write([]byte(`{"node_id":`))
				return
			}
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, input.NewAgentTokenHash, 2, expiresAt))
		case "/api/v1/agent/bootstrap":
			mu.Lock()
			input := requests[len(requests)-1]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, input.NewAgentTokenHash, 2, expiresAt).EnrollmentBundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }

	type outcome struct {
		result SyncResult
		err    error
	}
	firstDone := make(chan outcome, 1)
	secondDone := make(chan outcome, 1)
	go func() {
		result, err := agent.RecoverCredential(context.Background(), token)
		firstDone <- outcome{result: result, err: err}
	}()
	<-firstStarted
	go func() {
		result, err := agent.RecoverCredential(context.Background(), token)
		secondDone <- outcome{result: result, err: err}
	}()
	close(releaseFirst)
	if first := <-firstDone; first.err == nil {
		t.Fatal("truncated first response unexpectedly succeeded")
	}
	if second := <-secondDone; second.err != nil || !second.result.Changed {
		t.Fatalf("exact concurrent retry result=%#v err=%v", second.result, second.err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0] != requests[1] {
		t.Fatalf("response-loss retry changed its request: %#v", requests)
	}
	state, err := store.Load()
	if err != nil || state.PendingRecoveryToken != "" || state.PendingBearer != "" || state.AgentCredentialGeneration != 2 {
		t.Fatalf("exact retry state=%#v err=%v", state, err)
	}
}

func TestAgentRecoverCredentialSupersedesRotationOnlyPendingBearer(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	token := testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	rotationBearer := testBearer(t)
	var recoveredHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			recoveredHash = input.NewAgentTokenHash
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, recoveredHash, 2, expiresAt))
		case "/api/v1/agent/bootstrap":
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, recoveredHash, 2, expiresAt).EnrollmentBundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	state, _ := store.Load()
	state.PendingBearer = rotationBearer
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.RecoverCredential(context.Background(), token); err != nil {
		t.Fatalf("recover over interrupted rotation: %v", err)
	}
	if control.TokenHashEqual(recoveredHash, control.HashToken(rotationBearer)) {
		t.Fatal("administrative recovery reused the rotation-only pending bearer")
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.Bearer == rotationBearer || !control.TokenHashEqual(recoveredHash, control.HashToken(committed.Bearer)) {
		t.Fatalf("wrong bearer committed after superseding rotation: %#v", committed)
	}
}

func TestAgentRecoverCredentialAcceptsMonotonicBootstrapAdvance(t *testing.T) {
	signer := newTestSigner(t)
	initial := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	advanced := useTestRecoveryIdentity(t, signer, signer.bundle(t, 2, testNebulaConfig("advanced"), "certificate-one"), initial)
	token := testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	var requestHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			requestHash = input.NewAgentTokenHash
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, initial, requestHash, 2, expiresAt))
		case "/api/v1/agent/bootstrap":
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, advanced, requestHash, 2, expiresAt).EnrollmentBundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, initial)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	result, err := agent.RecoverCredential(context.Background(), token)
	if err != nil || result.Revision != 2 {
		t.Fatalf("monotonic recovery result=%#v err=%v", result, err)
	}
	state, _ := store.Load()
	if state.AppliedConfigRevision != 2 || state.AppliedConfigSHA256 != advanced.Digest {
		t.Fatalf("advanced signed bootstrap was not applied: %#v", state)
	}
}

func TestAgentRecoverCredentialRenewsExpiredCertificateBeforeActivation(t *testing.T) {
	for _, renewalFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "renewal failure"}[renewalFails], func(t *testing.T) {
			signer := newTestSigner(t)
			expired := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
			renewed := useTestRecoveryIdentity(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-new"), expired)
			token := testBearer(t)
			now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
			expiresAt := now.Add(90 * 24 * time.Hour)
			var requestHash string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/agent/recover":
					var input control.RecoverAgentInput
					_ = json.NewDecoder(r.Body).Decode(&input)
					requestHash = input.NewAgentTokenHash
					_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, expired, requestHash, 2, expiresAt))
				case "/api/v1/agent/bootstrap":
					_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, expired, requestHash, 2, expiresAt).EnrollmentBundle)
				case "/api/v1/agent/certificate/renew":
					if renewalFails {
						http.Error(w, "renewal unavailable", http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(renewalBundleForTest(renewed))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			agent, store, _ := installedTestAgent(t, server.URL, signer, expired)
			defer agent.Close()
			agent.Now = func() time.Time { return now }
			result, err := agent.RecoverCredential(context.Background(), token)
			state, loadErr := store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if state.AgentCredentialGeneration != 2 || state.PendingBearer != "" || state.PendingRecoveryToken != "" {
				t.Fatalf("recovered credential was not durably committed before renewal: %#v", state)
			}
			if renewalFails {
				if err == nil {
					t.Fatal("failed expired-certificate renewal unexpectedly succeeded")
				}
				if state.CertificateGeneration != expired.CertificateGeneration || agent.Reloader.(*fakeReloader).Calls() != 1 {
					t.Fatalf("expired certificate was activated before failed renewal: state=%#v reloads=%d", state, agent.Reloader.(*fakeReloader).Calls())
				}
				return
			}
			if err != nil || !result.Changed || state.CertificateGeneration != renewed.CertificateGeneration {
				t.Fatalf("post-recovery renewal result=%#v state=%#v err=%v", result, state, err)
			}
			if agent.Reloader.(*fakeReloader).Calls() != 2 {
				t.Fatalf("reloads=%d, want install plus renewed activation", agent.Reloader.(*fakeReloader).Calls())
			}
		})
	}
}

func testAgentRecoveryBundle(t *testing.T, signer testConfigSigner, bundle Bundle, newHash string, generation int64, expiresAt time.Time) control.AgentRecoveryBundle {
	t.Helper()
	bootstrap := enrollmentBundleFor(bundle, signer, bundle.Certificate)
	bootstrap.AgentCredentialGeneration = generation
	bootstrap.AgentCredentialExpiresAt = expiresAt
	receipt := control.RecoveryReceipt{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID, NewAgentTokenHash: newHash,
		AgentCredentialGeneration: generation, AgentCredentialExpiresAt: expiresAt,
		ConfigSHA256: bundle.Digest, ConfigSignature: bundle.Signature,
	}
	signature, err := control.SignRecoveryReceipt(signer.privateKey, receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = signature
	return control.AgentRecoveryBundle{EnrollmentBundle: bootstrap, RecoveryReceipt: receipt}
}

func resignTestRecoveryReceipt(t *testing.T, signer testConfigSigner, response *control.AgentRecoveryBundle) {
	t.Helper()
	signature, err := control.SignRecoveryReceipt(signer.privateKey, response.RecoveryReceipt)
	if err != nil {
		t.Fatal(err)
	}
	response.RecoveryReceipt.Signature = signature
}

func renewalBundleForTest(bundle Bundle) control.RenewalBundle {
	return control.RenewalBundle{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID,
		CA: bundle.CACertificate, Certificate: bundle.Certificate,
		CertificateExpiresAt: bundle.CertificateExpiresAt, CertificateRenewAfter: bundle.CertificateRenewAfter,
		Config: bundle.SignedConfig, ConfigRevision: bundle.Revision, ConfigIssuedAt: bundle.IssuedAt,
		ConfigSHA256: bundle.Digest, CACertificateSHA256: bundle.CACertificateSHA256,
		CertificateFingerprint: bundle.CertificateFingerprint, CertificateGeneration: bundle.CertificateGeneration,
		PublicKeyHash: bundle.PublicKeyHash, ConfigSignature: bundle.Signature,
	}
}

func TestAgentRecoverCredentialRejectsDifferentTokenOnResume(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	first := testBearer(t)
	if _, err := agent.RecoverCredential(context.Background(), first); err == nil {
		t.Fatal("failed recovery unexpectedly succeeded")
	}
	before, _ := store.Load()
	if _, err := agent.RecoverCredential(context.Background(), testBearer(t)); err == nil || !strings.Contains(err.Error(), "probe pending recovery bearer") {
		t.Fatalf("replacement probe error = %v", err)
	}
	after, _ := store.Load()
	if before.PendingRecoveryToken != first || after.PendingRecoveryToken != first || before.PendingBearer != after.PendingBearer || after.PendingRecoveryAllowsGenerationAdvance {
		t.Fatal("different token changed pending recovery journal")
	}
}

func TestPendingRecoveryBlocksOrdinaryAgentLifecycle(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	agent, _, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	if _, err := agent.RecoverCredential(context.Background(), testBearer(t)); err == nil {
		t.Fatal("failed recovery unexpectedly succeeded")
	}
	requestsAfterRecovery := requestCount
	operations := []struct {
		name string
		run  func() error
	}{
		{name: "sync", run: func() error { _, err := agent.Sync(context.Background()); return err }},
		{name: "renew", run: func() error { _, err := agent.RenewCertificate(context.Background()); return err }},
		{name: "rotate", run: func() error { _, err := agent.RotateCredential(context.Background()); return err }},
		{name: "heartbeat", run: func() error {
			_, err := agent.Heartbeat(context.Background(), Health{NebulaVersion: "1.10.3"})
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !errors.Is(err, ErrAgentRecoveryPending) {
				t.Fatalf("pending recovery error = %v", err)
			}
		})
	}
	if requestCount != requestsAfterRecovery {
		t.Fatalf("ordinary lifecycle made %d requests while recovery was pending", requestCount-requestsAfterRecovery)
	}
}

func testRecoveryIdentityBundle(t *testing.T, signer testConfigSigner, bundle Bundle) Bundle {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle.PrivateKey = nebulaX25519PrivateHeader + "\n" + base64.StdEncoding.EncodeToString(privateKey.Bytes()) + "\n" + nebulaX25519PrivateFooter + "\n" // gitleaks:allow -- generated only at test runtime
	bundle.PublicKey = nebulaX25519PublicHeader + "\n" + base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()) + "\n" + nebulaX25519PublicFooter + "\n"
	bundle.PublicKeyHash = canonicalPublicKeyHash(bundle.PublicKey)
	return signer.resignBundle(t, bundle, func(*Bundle) {})
}

func useTestRecoveryIdentity(t *testing.T, signer testConfigSigner, bundle, identity Bundle) Bundle {
	t.Helper()
	bundle.PrivateKey = identity.PrivateKey
	bundle.PublicKey = identity.PublicKey
	bundle.PublicKeyHash = identity.PublicKeyHash
	return signer.resignBundle(t, bundle, func(*Bundle) {})
}

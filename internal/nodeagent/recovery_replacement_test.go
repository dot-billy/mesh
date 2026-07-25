package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestRecoveryTokenReplacementAfterPendingBearerUnauthorized(t *testing.T) {
	for _, reason := range []string{"wrong pending token", "expired pending token"} {
		t.Run(reason, func(t *testing.T) {
			signer := newTestSigner(t)
			bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
			oldToken, oldBearer, replacementToken := testBearer(t), testBearer(t), testBearer(t)
			now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
			expiresAt := now.Add(90 * 24 * time.Hour)
			var replacementHash string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/agent/bootstrap":
					bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if bearer == oldBearer {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					if !control.TokenHashEqual(replacementHash, control.HashToken(bearer)) {
						http.Error(w, "unexpected bearer", http.StatusUnauthorized)
						return
					}
					_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, replacementHash, 2, expiresAt).EnrollmentBundle)
				case "/api/v1/agent/recover":
					var input control.RecoverAgentInput
					_ = json.NewDecoder(r.Body).Decode(&input)
					if input.RecoveryToken != replacementToken {
						t.Errorf("recovery token = %q, want replacement", input.RecoveryToken)
					}
					replacementHash = input.NewAgentTokenHash
					if control.TokenHashEqual(replacementHash, control.HashToken(oldBearer)) {
						t.Error("replacement reused unauthorized pending bearer")
					}
					_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, replacementHash, 2, expiresAt))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
			defer agent.Close()
			agent.Now = func() time.Time { return now }
			setPendingRecoveryJournal(t, store, oldToken, oldBearer, false)

			if _, err := agent.RecoverCredential(context.Background(), replacementToken); err != nil {
				t.Fatalf("replace %s: %v", reason, err)
			}
			state, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if state.AgentCredentialGeneration != 2 || state.PendingRecoveryToken != "" || state.PendingBearer != "" || state.PendingRecoveryAllowsGenerationAdvance {
				t.Fatalf("replacement did not commit and clear its journal: %#v", state)
			}
		})
	}
}

func TestActivePendingRecoveryBearerForcesOldTokenResume(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	oldToken, oldBearer, replacementToken := testBearer(t), testBearer(t), testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	oldHash := control.HashToken(oldBearer)
	var recoveryPosts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/bootstrap":
			if r.Header.Get("Authorization") != "Bearer "+oldBearer {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, oldHash, 2, expiresAt).EnrollmentBundle)
		case "/api/v1/agent/recover":
			recoveryPosts++
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.RecoveryToken != oldToken || input.NewAgentTokenHash != oldHash {
				t.Errorf("resume changed committed request: %#v", input)
			}
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, oldHash, 2, expiresAt))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	before := setPendingRecoveryJournal(t, store, oldToken, oldBearer, false)

	if _, err := agent.RecoverCredential(context.Background(), replacementToken); !errors.Is(err, ErrAgentRecoveryResumeRequired) {
		t.Fatalf("active pending bearer replacement error = %v", err)
	}
	afterProbe, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	assertSamePendingRecoveryJournal(t, before, afterProbe)
	if recoveryPosts != 0 {
		t.Fatalf("replacement recovery POST count = %d, want zero", recoveryPosts)
	}

	if _, err := agent.RecoverCredential(context.Background(), ""); err != nil {
		t.Fatalf("resume retained committed recovery: %v", err)
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if recoveryPosts != 1 || committed.Bearer != oldBearer || committed.AgentCredentialGeneration != 2 || committed.PendingRecoveryToken != "" {
		t.Fatalf("old exact recovery was not resumed: posts=%d state=%#v", recoveryPosts, committed)
	}
}

func TestExpiredCommittedPendingRecoveryReplacementAcceptsGenerationJump(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	oldToken, oldBearer, replacementToken := testBearer(t), testBearer(t), testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	var replacementHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/bootstrap":
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if bearer == oldBearer {
				// The generation-2 reset committed, but its 90-day credential has
				// expired before the local agent received or committed the receipt.
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, replacementHash, 3, expiresAt).EnrollmentBundle)
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.RecoveryToken != replacementToken {
				t.Errorf("replacement token = %q", input.RecoveryToken)
			}
			replacementHash = input.NewAgentTokenHash
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, replacementHash, 3, expiresAt))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	setPendingRecoveryJournal(t, store, oldToken, oldBearer, false)

	if _, err := agent.RecoverCredential(context.Background(), replacementToken); err != nil {
		t.Fatalf("replace expired committed recovery: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.AgentCredentialGeneration != 3 || state.PendingRecoveryAllowsGenerationAdvance || state.PendingRecoveryToken != "" {
		t.Fatalf("signed generation jump was not committed exactly: %#v", state)
	}
}

func TestReplacementProbeErrorsPreserveExactPendingJournal(t *testing.T) {
	tests := []struct {
		name    string
		respond func(*testing.T, testConfigSigner, Bundle, http.ResponseWriter)
	}{
		{name: "transient failure", respond: func(_ *testing.T, _ testConfigSigner, _ Bundle, w http.ResponseWriter) {
			http.Error(w, "try later", http.StatusServiceUnavailable)
		}},
		{name: "transport failure", respond: func(_ *testing.T, _ testConfigSigner, _ Bundle, _ http.ResponseWriter) {
			panic(http.ErrAbortHandler)
		}},
		{name: "wrong node signed bootstrap", respond: func(t *testing.T, signer testConfigSigner, bundle Bundle, w http.ResponseWriter) {
			wrong := bundle
			wrong.NodeID = "node-2"
			wrong = signer.resignBundle(t, wrong, func(*Bundle) {})
			bootstrap := enrollmentBundleFor(wrong, signer, wrong.Certificate)
			bootstrap.NodeID = wrong.NodeID
			_ = json.NewEncoder(w).Encode(bootstrap)
		}},
		{name: "tampered signature", respond: func(t *testing.T, signer testConfigSigner, bundle Bundle, w http.ResponseWriter) {
			bootstrap := enrollmentBundleFor(bundle, signer, bundle.Certificate)
			bootstrap.ConfigSignature = "invalid"
			_ = json.NewEncoder(w).Encode(bootstrap)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
			oldToken, oldBearer, replacementToken := testBearer(t), testBearer(t), testBearer(t)
			var recoveryPosts int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/agent/recover" {
					recoveryPosts++
					http.Error(w, "must not replace", http.StatusInternalServerError)
					return
				}
				if r.URL.Path != "/api/v1/agent/bootstrap" {
					http.NotFound(w, r)
					return
				}
				test.respond(t, signer, bundle, w)
			}))
			defer server.Close()
			agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
			defer agent.Close()
			before := setPendingRecoveryJournal(t, store, oldToken, oldBearer, false)

			if _, err := agent.RecoverCredential(context.Background(), replacementToken); err == nil {
				t.Fatal("unsafe replacement probe unexpectedly succeeded")
			}
			after, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			assertSamePendingRecoveryJournal(t, before, after)
			if recoveryPosts != 0 {
				t.Fatalf("replacement POST count = %d, want zero", recoveryPosts)
			}
		})
	}
}

func TestReplacementRecoveryCrashReusesExactPersistedPair(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	oldToken, oldBearer, replacementToken := testBearer(t), testBearer(t), testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	var recoveryRequests []control.RecoverAgentInput
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/bootstrap":
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if bearer == oldBearer {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			last := recoveryRequests[len(recoveryRequests)-1]
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, last.NewAgentTokenHash, 3, expiresAt).EnrollmentBundle)
		case "/api/v1/agent/recover":
			var input control.RecoverAgentInput
			_ = json.NewDecoder(r.Body).Decode(&input)
			recoveryRequests = append(recoveryRequests, input)
			if len(recoveryRequests) == 1 {
				_, _ = w.Write([]byte(`{"node_id":`))
				return
			}
			_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, input.NewAgentTokenHash, 3, expiresAt))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	setPendingRecoveryJournal(t, store, oldToken, oldBearer, false)

	if _, err := agent.RecoverCredential(context.Background(), replacementToken); err == nil {
		t.Fatal("truncated replacement response unexpectedly succeeded")
	}
	afterLoss, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if afterLoss.PendingRecoveryToken != replacementToken || afterLoss.PendingBearer == oldBearer || !afterLoss.PendingRecoveryAllowsGenerationAdvance {
		t.Fatalf("replacement journal was not durable after response loss: %#v", afterLoss)
	}
	if _, err := agent.RecoverCredential(context.Background(), ""); err != nil {
		t.Fatalf("resume replacement recovery: %v", err)
	}
	if len(recoveryRequests) != 2 || recoveryRequests[0] != recoveryRequests[1] {
		t.Fatalf("replacement retry changed exact request: %#v", recoveryRequests)
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.AgentCredentialGeneration != 3 || committed.PendingRecoveryToken != "" || committed.PendingBearer != "" || committed.PendingRecoveryAllowsGenerationAdvance {
		t.Fatalf("replacement retry did not commit cleanly: %#v", committed)
	}
}

func TestReplacementGenerationAdvanceStillRejectsEqualGeneration(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testRecoveryIdentityBundle(t, signer, signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one"))
	token, bearer := testBearer(t), testBearer(t)
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	expiresAt := now.Add(90 * 24 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/recover" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(testAgentRecoveryBundle(t, signer, bundle, control.HashToken(bearer), 1, expiresAt))
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	agent.Now = func() time.Time { return now }
	before := setPendingRecoveryJournal(t, store, token, bearer, true)
	if _, err := agent.RecoverCredential(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "non-monotonic") {
		t.Fatalf("equal replacement generation error = %v", err)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	assertSamePendingRecoveryJournal(t, before, after)
}

func setPendingRecoveryJournal(t *testing.T, store *StateStore, token, bearer string, allowsAdvance bool) State {
	t.Helper()
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.PendingRecoveryToken = token
	state.PendingBearer = bearer
	state.PendingRecoveryAllowsGenerationAdvance = allowsAdvance
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	return state
}

func assertSamePendingRecoveryJournal(t *testing.T, before, after State) {
	t.Helper()
	if before != after {
		t.Fatalf("pending recovery journal changed: before=%#v after=%#v", before, after)
	}
}

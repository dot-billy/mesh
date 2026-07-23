package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestVerifySignedConfigRejectsIdentitySignatureRollbackAndEquivocation(t *testing.T) {
	signer := newTestSigner(t)
	current := signer.bundle(t, 2, testNebulaConfig("current"), "certificate-one")
	state := State{
		NodeID: signer.nodeID, NetworkID: signer.networkID,
		ConfigSigningPublicKey: signer.publicKey,
		CACertificateSHA256:    current.CACertificateSHA256, PublicKeyHash: current.PublicKeyHash,
		AppliedConfigRevision: 2, AppliedConfigSHA256: current.Digest,
		CertificateFingerprint: current.CertificateFingerprint, CertificateExpiresAt: current.CertificateExpiresAt,
		CertificateRenewAfter: current.CertificateRenewAfter,
		CertificateGeneration: current.CertificateGeneration,
	}

	rollback := signer.bundle(t, 1, testNebulaConfig("old"), "certificate-one")
	if err := VerifySignedConfig(state, agentConfig(rollback)); !errors.Is(err, ErrConfigRollback) {
		t.Fatalf("rollback error = %v", err)
	}

	equivocation := signer.bundle(t, 2, testNebulaConfig("different"), "certificate-one")
	if err := VerifySignedConfig(state, agentConfig(equivocation)); !errors.Is(err, ErrConfigEquivocation) {
		t.Fatalf("equivocation error = %v", err)
	}

	wrongIdentity := agentConfig(current)
	wrongIdentity.NodeID = "node-2"
	if err := VerifySignedConfig(state, wrongIdentity); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("wrong identity error = %v", err)
	}

	badSignature := agentConfig(current)
	badSignature.Signature = strings.Repeat("x", len(badSignature.Signature))
	if err := VerifySignedConfig(state, badSignature); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature error = %v", err)
	}

	higherRevisionLowerCertificateGeneration := signer.bundle(t, 3, testNebulaConfig("new-config-old-cert"), "certificate-one")
	state.CertificateGeneration = 2
	if err := VerifySignedConfig(state, agentConfig(higherRevisionLowerCertificateGeneration)); !errors.Is(err, ErrConfigRollback) {
		t.Fatalf("certificate-generation rollback error = %v", err)
	}

	state.CertificateGeneration = current.CertificateGeneration
	wrongCA := signer.resignBundle(t, current, func(bundle *Bundle) {
		bundle.CACertificateSHA256 = control.ConfigDigest("attacker-ca")
	})
	if err := VerifySignedConfig(state, agentConfig(wrongCA)); err == nil || !strings.Contains(err.Error(), "CA or public key") {
		t.Fatalf("signed CA substitution error = %v", err)
	}

	wrongPublicKey := signer.resignBundle(t, current, func(bundle *Bundle) {
		bundle.PublicKeyHash = canonicalPublicKeyHash("attacker-public-key")
	})
	if err := VerifySignedConfig(state, agentConfig(wrongPublicKey)); err == nil || !strings.Contains(err.Error(), "CA or public key") {
		t.Fatalf("signed public-key substitution error = %v", err)
	}

	changedCertificateMetadata := signer.resignBundle(t, current, func(bundle *Bundle) {
		bundle.CertificateExpiresAt = bundle.CertificateExpiresAt.Add(time.Hour)
	})
	if err := VerifySignedConfig(state, agentConfig(changedCertificateMetadata)); !errors.Is(err, ErrConfigEquivocation) {
		t.Fatalf("same-generation certificate equivocation error = %v", err)
	}

	changedRenewAfter := signer.resignBundle(t, current, func(bundle *Bundle) {
		bundle.CertificateRenewAfter = bundle.CertificateRenewAfter.Add(time.Minute)
	})
	if err := VerifySignedConfig(state, agentConfig(changedRenewAfter)); !errors.Is(err, ErrConfigEquivocation) {
		t.Fatalf("same-generation renewal schedule equivocation error = %v", err)
	}
}

func TestVerifySignedConfigAuthenticatesForwardAndAbortCATrustTransitions(t *testing.T) {
	signer := newTestSigner(t)
	current := signer.bundle(t, 2, testNebulaConfig("current-ca"), "certificate-one")
	state := State{
		NodeID: signer.nodeID, NetworkID: signer.networkID, ConfigSigningPublicKey: signer.publicKey,
		CACertificateSHA256: current.CACertificateSHA256, PublicKeyHash: current.PublicKeyHash,
		AppliedConfigRevision: current.Revision, AppliedConfigSHA256: current.Digest,
		CertificateFingerprint: current.CertificateFingerprint, CertificateGeneration: current.CertificateGeneration,
		CertificateExpiresAt: current.CertificateExpiresAt, CertificateRenewAfter: current.CertificateRenewAfter,
	}
	dualCA := current.CACertificate + "\nreplacement-ca"
	prepared := signer.resignBundle(t, current, func(bundle *Bundle) {
		bundle.Revision++
		bundle.IssuedAt = bundle.IssuedAt.Add(time.Minute)
		bundle.CACertificate = dualCA
		bundle.PreviousCACertificateSHA256 = current.CACertificateSHA256
		bundle.CACertificateSHA256 = control.ConfigDigest(dualCA)
		bundle.CARotationRequired = true
	})
	if err := VerifySignedConfig(state, agentConfig(prepared)); err != nil {
		t.Fatalf("authenticated CA trust transition was rejected: %v", err)
	}
	wrongAncestor := signer.resignBundle(t, prepared, func(bundle *Bundle) {
		bundle.PreviousCACertificateSHA256 = control.ConfigDigest("unrelated-ca")
	})
	if err := VerifySignedConfig(state, agentConfig(wrongAncestor)); err == nil || !strings.Contains(err.Error(), "does not descend") {
		t.Fatalf("signed transition from an unrelated trust pin was accepted: %v", err)
	}
	tamperedAncestor := agentConfig(prepared)
	tamperedAncestor.PreviousCACertificateSHA256 = control.ConfigDigest("tampered-ca")
	if err := VerifySignedConfig(state, tamperedAncestor); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("unsigned previous-CA mutation was accepted: %v", err)
	}

	state.CACertificateSHA256 = prepared.CACertificateSHA256
	state.AppliedConfigRevision = prepared.Revision
	state.AppliedConfigSHA256 = prepared.Digest
	aborted := signer.resignBundle(t, prepared, func(bundle *Bundle) {
		bundle.Revision++
		bundle.IssuedAt = bundle.IssuedAt.Add(time.Minute)
		bundle.CACertificate = current.CACertificate
		bundle.CACertificateSHA256 = current.CACertificateSHA256
		bundle.PreviousCACertificateSHA256 = prepared.CACertificateSHA256
		bundle.CARotationRequired = false
	})
	if err := VerifySignedConfig(state, agentConfig(aborted)); err != nil {
		t.Fatalf("authenticated prepared-rotation abort was rejected: %v", err)
	}
}

func TestAgentSyncPerformsRotationRequiredEarlyCertificateRenewal(t *testing.T) {
	signer := newTestSigner(t)
	initial := signer.bundle(t, 1, testNebulaConfig("old-ca"), "certificate-one")
	dualCA := initial.CACertificate + "\nreplacement-ca"
	desired := signer.resignBundle(t, initial, func(bundle *Bundle) {
		bundle.Revision = 2
		bundle.IssuedAt = bundle.IssuedAt.Add(time.Minute)
		bundle.CACertificate = dualCA
		bundle.CACertificateSHA256 = control.ConfigDigest(dualCA)
		bundle.PreviousCACertificateSHA256 = initial.CACertificateSHA256
		bundle.CARotationRequired = true
	})
	replacement := signer.bundle(t, 2, desired.SignedConfig, "certificate-new")
	replacement = signer.resignBundle(t, replacement, func(bundle *Bundle) {
		bundle.CACertificate = dualCA
		bundle.CACertificateSHA256 = desired.CACertificateSHA256
		bundle.PreviousCACertificateSHA256 = initial.CACertificateSHA256
	})
	renewal := control.RenewalBundle{
		NodeID: replacement.NodeID, NetworkID: replacement.NetworkID, CA: replacement.CACertificate, Certificate: replacement.Certificate,
		CertificateExpiresAt: replacement.CertificateExpiresAt, CertificateRenewAfter: replacement.CertificateRenewAfter,
		Config: replacement.SignedConfig, ConfigRevision: replacement.Revision, ConfigIssuedAt: replacement.IssuedAt,
		ConfigSHA256: replacement.Digest, CACertificateSHA256: replacement.CACertificateSHA256,
		PreviousCACertificateSHA256: replacement.PreviousCACertificateSHA256, CARotationRequired: replacement.CARotationRequired,
		CertificateFingerprint: replacement.CertificateFingerprint, CertificateGeneration: replacement.CertificateGeneration,
		PublicKeyHash: replacement.PublicKeyHash, ConfigSignature: replacement.Signature,
	}
	bootstrap := enrollmentBundleFor(desired, signer, initial.Certificate)
	var configRequests, bootstrapRequests, renewalRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/config":
			configRequests++
			_ = json.NewEncoder(w).Encode(agentConfig(desired))
		case "/api/v1/agent/bootstrap":
			bootstrapRequests++
			_ = json.NewEncoder(w).Encode(bootstrap)
		case "/api/v1/agent/certificate/renew":
			renewalRequests++
			_ = json.NewEncoder(w).Encode(renewal)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, initial)
	defer agent.Close()
	result, err := agent.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync rotation-required trust transition: %v", err)
	}
	if !result.Changed || configRequests != 1 || bootstrapRequests != 1 || renewalRequests != 0 {
		t.Fatalf("trust sync=%+v config_requests=%d bootstrap_requests=%d renewal_requests=%d", result, configRequests, bootstrapRequests, renewalRequests)
	}
	result, err = agent.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync rotation-required renewal: %v", err)
	}
	if !result.Changed || configRequests != 2 || bootstrapRequests != 1 || renewalRequests != 1 {
		t.Fatalf("renewal sync=%+v config_requests=%d bootstrap_requests=%d renewal_requests=%d", result, configRequests, bootstrapRequests, renewalRequests)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.CACertificateSHA256 != control.ConfigDigest(dualCA) || state.CertificateGeneration != replacement.CertificateGeneration || state.CertificateFingerprint != replacement.CertificateFingerprint {
		t.Fatalf("agent did not persist replacement trust/certificate state: %+v", state)
	}
}

func TestAgentSyncPerformsSignedCertificateProfileRenewal(t *testing.T) {
	signer := newTestSigner(t)
	initial := signer.bundle(t, 1, testNebulaConfig("route-source"), "certificate-one")
	desired := signer.resignBundle(t, initial, func(bundle *Bundle) {
		bundle.Revision = 2
		bundle.IssuedAt = bundle.IssuedAt.Add(time.Minute)
		bundle.SignedConfig = testNebulaConfig("route-target-staged")
		bundle.CertificateProfileRenewalRequired = true
	})
	replacement := signer.bundle(t, 2, desired.SignedConfig, "certificate-new")
	renewal := control.RenewalBundle{
		NodeID: replacement.NodeID, NetworkID: replacement.NetworkID, CA: replacement.CACertificate, Certificate: replacement.Certificate,
		CertificateExpiresAt: replacement.CertificateExpiresAt, CertificateRenewAfter: replacement.CertificateRenewAfter,
		Config: replacement.SignedConfig, ConfigRevision: replacement.Revision, ConfigIssuedAt: replacement.IssuedAt,
		ConfigSHA256: replacement.Digest, CACertificateSHA256: replacement.CACertificateSHA256,
		CertificateProfileRenewalRequired: false,
		CertificateFingerprint:            replacement.CertificateFingerprint, CertificateGeneration: replacement.CertificateGeneration,
		PublicKeyHash: replacement.PublicKeyHash, ConfigSignature: replacement.Signature,
	}
	var configRequests, renewalRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/config":
			configRequests++
			_ = json.NewEncoder(w).Encode(agentConfig(desired))
		case "/api/v1/agent/certificate/renew":
			renewalRequests++
			_ = json.NewEncoder(w).Encode(renewal)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, initial)
	defer agent.Close()
	result, err := agent.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync certificate-profile renewal: %v", err)
	}
	if !result.Changed || configRequests != 1 || renewalRequests != 1 {
		t.Fatalf("profile sync=%+v config_requests=%d renewal_requests=%d", result, configRequests, renewalRequests)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.CertificateGeneration != replacement.CertificateGeneration || state.CertificateFingerprint != replacement.CertificateFingerprint || state.AppliedConfigRevision != replacement.Revision {
		t.Fatalf("agent did not persist profile-renewed state: %+v", state)
	}
}

func TestAgentSyncBootstrapsHigherCertificateGenerationWithSameFingerprint(t *testing.T) {
	signer := newTestSigner(t)
	initial := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	advanced := signer.resignBundle(t, initial, func(bundle *Bundle) {
		bundle.CertificateGeneration++
	})
	bootstrap := enrollmentBundleFor(advanced, signer, advanced.Certificate)
	var configRequests, bootstrapRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/config":
			configRequests++
			_ = json.NewEncoder(w).Encode(agentConfig(advanced))
		case "/api/v1/agent/bootstrap":
			bootstrapRequests++
			_ = json.NewEncoder(w).Encode(bootstrap)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	agent, store, _ := installedTestAgent(t, server.URL, signer, initial)
	defer agent.Close()
	result, err := agent.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync higher certificate generation: %v", err)
	}
	if !result.Changed || configRequests != 1 || bootstrapRequests != 1 {
		t.Fatalf("sync result=%#v config requests=%d bootstrap requests=%d", result, configRequests, bootstrapRequests)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.CertificateGeneration != advanced.CertificateGeneration || state.CertificateFingerprint != advanced.CertificateFingerprint || !state.CertificateExpiresAt.Equal(advanced.CertificateExpiresAt) {
		t.Fatalf("certificate artifact state was not advanced: %#v", state)
	}
}

func TestAgentReconcilesCrashAfterLiveSwapBeforeStateCommit(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	var observedETag string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/config" {
			http.NotFound(w, r)
			return
		}
		observedETag = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	agent, store, initial := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()

	// Simulate loss of the final state rename after the live symlink and reload
	// committed. The on-disk state is back at its pre-activation revision.
	initial.AppliedConfigRevision = 0
	initial.AppliedConfigSHA256 = ""
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	result, err := agent.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync after interrupted state commit: %v", err)
	}
	if result.Revision != 1 || result.Digest != bundle.Digest {
		t.Fatalf("sync result = %#v", result)
	}
	if observedETag != `"`+bundle.Signature+`"` {
		t.Fatalf("config request used stale ETag %q", observedETag)
	}
	reconciled, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.AppliedConfigRevision != 1 || reconciled.AppliedConfigSHA256 != bundle.Digest || !reconciled.CertificateExpiresAt.Equal(agent.Validator.Runner.(*fakeCommandRunner).expiryFor("certificate-one")) {
		t.Fatalf("state was not reconciled from live bundle: %#v", reconciled)
	}
}

func TestAgentActivationFailureCarriesExactSignedTargetAndRetainsPreviousBundle(t *testing.T) {
	signer := newTestSigner(t)
	initial := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	desired := signer.resignBundle(t, initial, func(bundle *Bundle) {
		bundle.Revision = 2
		bundle.IssuedAt = bundle.IssuedAt.Add(time.Minute)
		bundle.SignedConfig = testNebulaConfig("target")
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/config" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(agentConfig(desired))
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, initial)
	defer agent.Close()
	agent.Reloader.(*fakeReloader).failAt = map[int]error{2: errors.New("target runtime rejected")}

	_, err := agent.Sync(context.Background())
	var activationError *ConfigActivationError
	if !errors.As(err, &activationError) || activationError.Revision != desired.Revision || activationError.Digest != desired.Digest || !strings.Contains(err.Error(), "target runtime rejected") {
		t.Fatalf("activation error=%#v raw=%v", activationError, err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.AppliedConfigRevision != initial.Revision || state.AppliedConfigSHA256 != initial.Digest {
		t.Fatalf("failed activation advanced local state: %#v", state)
	}
	current, err := agent.activator(state).CurrentBundle(context.Background())
	if err != nil || current.Revision != initial.Revision || current.Digest != initial.Digest {
		t.Fatalf("failed activation did not restore previous bundle: current=%#v err=%v", current, err)
	}
}

func TestAgentRecoversMissingLiveBundleFromAuthenticatedBootstrap(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	bootstrap := enrollmentBundleFor(bundle, signer, "certificate-one")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/bootstrap":
			_ = json.NewEncoder(w).Encode(bootstrap)
		case "/api/v1/agent/config":
			w.WriteHeader(http.StatusNotModified)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	state, _ := store.Load()
	if err := os.Remove(filepath.Join(state.OutputDir, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Sync(context.Background()); err != nil {
		t.Fatalf("recover missing live bundle: %v", err)
	}
	current, err := agent.activator(state).CurrentBundle(context.Background())
	if err != nil || current.Certificate != "certificate-one" || current.Digest != bundle.Digest {
		t.Fatalf("recovered bundle = %#v err=%v", current, err)
	}
	if agent.Reloader.(*fakeReloader).Calls() != 2 {
		t.Fatalf("reload calls = %d, want install plus recovery", agent.Reloader.(*fakeReloader).Calls())
	}
}

func TestSuccessfulConfigContactRefreshesFreshnessCoarsely(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/config" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()

	enrolled, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.LastSuccessfulConfigAt.IsZero() {
		t.Fatal("enrollment did not initialize config freshness")
	}
	fixed := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	enrolled.LastSuccessfulConfigAt = fixed.Add(-2 * time.Minute)
	if err := store.Save(enrolled); err != nil {
		t.Fatal(err)
	}
	agent.Now = func() time.Time { return fixed }
	if _, err := agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !first.LastSuccessfulConfigAt.Equal(fixed) {
		t.Fatalf("first refreshed timestamp = %s, want %s", first.LastSuccessfulConfigAt, fixed)
	}

	agent.Now = func() time.Time { return fixed.Add(30 * time.Second) }
	if _, err := agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	coalesced, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !coalesced.LastSuccessfulConfigAt.Equal(fixed) {
		t.Fatalf("coalesced timestamp changed to %s", coalesced.LastSuccessfulConfigAt)
	}

	agent.ConfigSuccessPersistInterval = 5 * time.Second
	agent.Now = func() time.Time { return fixed.Add(35 * time.Second) }
	if _, err := agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	tightPolicy, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !tightPolicy.LastSuccessfulConfigAt.Equal(fixed.Add(35 * time.Second)) {
		t.Fatalf("tight-policy timestamp = %s", tightPolicy.LastSuccessfulConfigAt)
	}
}

func TestAgentRecoversAmbiguousCommittedRenewal(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	renewedBundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-new")
	recovered := enrollmentBundleFor(renewedBundle, signer, "certificate-new")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/certificate/renew":
			// Model a committed server renewal whose response is truncated in
			// transit. The subsequent bootstrap exposes the committed certificate.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"certificate":`))
		case "/api/v1/agent/bootstrap":
			_ = json.NewEncoder(w).Encode(recovered)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	result, err := agent.RenewCertificate(context.Background())
	if err != nil {
		t.Fatalf("recover ambiguous renewal: %v", err)
	}
	if !result.Changed || result.Revision != 1 {
		t.Fatalf("renewal result = %#v", result)
	}
	state, _ := store.Load()
	current, err := agent.activator(state).CurrentBundle(context.Background())
	if err != nil || current.Certificate != "certificate-new" {
		t.Fatalf("renewed bundle = %#v err=%v", current, err)
	}
	wantExpiry := agent.Validator.Runner.(*fakeCommandRunner).expiryFor("certificate-new")
	if !state.CertificateExpiresAt.Equal(wantExpiry) {
		t.Fatalf("certificate expiry = %s, want %s", state.CertificateExpiresAt, wantExpiry)
	}
}

func TestAgentRenewsWithRecoveryKeysWhenLiveCertificateIsExpired(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	renewedBundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-new")
	renewal := control.RenewalBundle{
		NodeID: renewedBundle.NodeID, NetworkID: renewedBundle.NetworkID,
		CA: renewedBundle.CACertificate, Certificate: renewedBundle.Certificate,
		CertificateExpiresAt: renewedBundle.CertificateExpiresAt, CertificateFingerprint: renewedBundle.CertificateFingerprint,
		CertificateRenewAfter: renewedBundle.CertificateRenewAfter,
		CertificateGeneration: renewedBundle.CertificateGeneration, CACertificateSHA256: renewedBundle.CACertificateSHA256,
		PublicKeyHash: renewedBundle.PublicKeyHash,
		Config:        renewedBundle.SignedConfig, ConfigRevision: renewedBundle.Revision, ConfigIssuedAt: renewedBundle.IssuedAt,
		ConfigSHA256: renewedBundle.Digest, ConfigSignature: renewedBundle.Signature,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/certificate/renew" {
			http.NotFound(w, r)
			return
		}
		var input map[string]string
		_ = json.NewDecoder(r.Body).Decode(&input)
		if input["public_key"] != bundle.PublicKey {
			t.Errorf("renewal did not use persisted recovery public key: %q", input["public_key"])
		}
		_ = json.NewEncoder(w).Encode(renewal)
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	runner := agent.Validator.Runner.(*fakeCommandRunner)
	runner.failCertificates["certificate-one"] = errors.New("certificate is expired")
	state, _ := store.Load()
	result, err := agent.RenewCertificate(context.Background())
	if err != nil {
		t.Fatalf("renew expired live certificate: %v", err)
	}
	if !result.Changed {
		t.Fatal("expired certificate renewal did not activate a new bundle")
	}
	state, _ = store.Load()
	current, err := agent.activator(state).CurrentBundle(context.Background())
	if err != nil || current.Certificate != "certificate-new" {
		t.Fatalf("current renewed bundle = %#v err=%v", current, err)
	}
}

func TestAgentExactRenewalReplayDoesNotReloadOrCreateVersion(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	renewal := control.RenewalBundle{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID,
		CA: bundle.CACertificate, Certificate: bundle.Certificate,
		CertificateExpiresAt: bundle.CertificateExpiresAt, CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateRenewAfter: bundle.CertificateRenewAfter,
		CertificateGeneration: bundle.CertificateGeneration, CACertificateSHA256: bundle.CACertificateSHA256,
		PublicKeyHash: bundle.PublicKeyHash,
		Config:        bundle.SignedConfig, ConfigRevision: bundle.Revision, ConfigIssuedAt: bundle.IssuedAt,
		ConfigSHA256: bundle.Digest, ConfigSignature: bundle.Signature,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/certificate/renew" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(renewal)
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()

	for attempt := 0; attempt < 3; attempt++ {
		result, err := agent.RenewCertificate(context.Background())
		if err != nil {
			t.Fatalf("renewal replay %d: %v", attempt, err)
		}
		if result.Changed {
			t.Fatalf("renewal replay %d reported a change: %#v", attempt, result)
		}
	}
	if calls := agent.Reloader.(*fakeReloader).Calls(); calls != 1 {
		t.Fatalf("reload calls = %d, want only initial activation", calls)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(state.OutputDir, "versions"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("immutable version count = %d, want 1", len(entries))
	}
}

func TestAgentCredentialRotationRejectsInvalidCommitMetadata(t *testing.T) {
	tests := []struct {
		name     string
		rotation control.CredentialRotation
	}{
		{name: "generation rollback", rotation: control.CredentialRotation{Generation: 1, ExpiresAt: time.Now().UTC().Add(90 * 24 * time.Hour)}},
		{name: "expired credential", rotation: control.CredentialRotation{Generation: 2, ExpiresAt: time.Now().UTC().Add(-time.Minute)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/agent/credentials/rotate" {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(test.rotation)
			}))
			defer server.Close()
			agent, store, before := installedTestAgent(t, server.URL, signer, bundle)
			defer agent.Close()

			if _, err := agent.RotateCredential(context.Background()); err == nil {
				t.Fatal("invalid credential rotation response was committed")
			}
			after, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Bearer != before.Bearer || after.PendingBearer == "" || after.AgentCredentialGeneration != before.AgentCredentialGeneration || !after.AgentCredentialExpiresAt.Equal(before.AgentCredentialExpiresAt) {
				t.Fatalf("invalid rotation changed committed credential state: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestAgentCredentialRotationRecoversUsingPendingBearer(t *testing.T) {
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, testNebulaConfig("initial"), "certificate-one")
	var oldBearer, pendingBearer string
	expiresAt := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/credentials/rotate" {
			http.NotFound(w, r)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + oldBearer:
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer " + pendingBearer:
			_ = json.NewEncoder(w).Encode(control.CredentialRotation{Generation: 2, ExpiresAt: expiresAt})
		default:
			http.Error(w, "unexpected bearer", http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	agent, store, _ := installedTestAgent(t, server.URL, signer, bundle)
	defer agent.Close()
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldBearer = state.Bearer
	pendingBearer, err = GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	state.PendingBearer = pendingBearer
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}

	rotation, err := agent.RotateCredential(context.Background())
	if err != nil {
		t.Fatalf("recover pending credential rotation: %v", err)
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Generation != 2 || committed.Bearer != pendingBearer || committed.PendingBearer != "" || committed.AgentCredentialGeneration != 2 || !committed.AgentCredentialExpiresAt.Equal(expiresAt) {
		t.Fatalf("pending credential was not committed exactly: rotation=%#v state=%#v", rotation, committed)
	}
}

func installedTestAgent(t *testing.T, serverURL string, signer testConfigSigner, bundle Bundle) (*Agent, *StateStore, State) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := enrollmentBundleFor(bundle, signer, bundle.Certificate)
	state, err := NewEnrollmentState(serverURL, bearer, filepath.Join(dir, "nebula"), bundle.PublicKey, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	runner := newFakeCommandRunner()
	agent := &Agent{
		Store: store, HTTPClient: http.DefaultClient, Validator: BundleValidator{Runner: runner},
		Reloader: &fakeReloader{}, AgentVersion: "0.1.0",
	}
	if err := agent.InstallEnrollment(context.Background(), state, enrollment, bundle.PrivateKey, bundle.PublicKey); err != nil {
		_ = agent.Close()
		t.Fatalf("install enrollment: %v", err)
	}
	return agent, store, state
}

func enrollmentBundleFor(bundle Bundle, signer testConfigSigner, certificate string) control.EnrollmentBundle {
	return control.EnrollmentBundle{
		NodeID: signer.nodeID, NetworkID: signer.networkID,
		Node:        control.Node{ID: signer.nodeID, NetworkID: signer.networkID, Status: "active"},
		Certificate: certificate, CA: bundle.CACertificate, Config: bundle.SignedConfig,
		ConfigRevision: bundle.Revision, CertificateExpiresAt: bundle.CertificateExpiresAt,
		CertificateRenewAfter:    bundle.CertificateRenewAfter,
		AgentCredentialExpiresAt: time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC), AgentCredentialGeneration: 1,
		ConfigIssuedAt: bundle.IssuedAt, ConfigSHA256: bundle.Digest,
		CACertificateSHA256: bundle.CACertificateSHA256, PreviousCACertificateSHA256: bundle.PreviousCACertificateSHA256,
		CARotationRequired: bundle.CARotationRequired, CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired, CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateGeneration: bundle.CertificateGeneration, PublicKeyHash: bundle.PublicKeyHash,
		ConfigSignature: bundle.Signature, ConfigSigningPublicKey: signer.publicKey,
	}
}

func agentConfig(bundle Bundle) control.AgentConfig {
	return control.AgentConfig{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID, Revision: bundle.Revision,
		Config: bundle.SignedConfig, IssuedAt: bundle.IssuedAt, SHA256: bundle.Digest,
		Signature: bundle.Signature, CACertificateSHA256: bundle.CACertificateSHA256,
		PreviousCACertificateSHA256: bundle.PreviousCACertificateSHA256, CARotationRequired: bundle.CARotationRequired, CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired,
		CertificateFingerprint: bundle.CertificateFingerprint, CertificateExpiresAt: bundle.CertificateExpiresAt,
		CertificateRenewAfter: bundle.CertificateRenewAfter,
		CertificateGeneration: bundle.CertificateGeneration, PublicKeyHash: bundle.PublicKeyHash,
	}
}

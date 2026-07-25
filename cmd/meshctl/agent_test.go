package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

func TestRequestEnrollmentRecoversAmbiguousCommitWithoutSendingBearer(t *testing.T) {
	t.Parallel()
	bearer := testBearer(1)
	payload := enrollmentRequest{
		Token:          strings.Repeat("enrollment-secret-", 3),
		PublicKey:      "-----BEGIN NEBULA X25519 PUBLIC KEY-----\npublic\n-----END NEBULA X25519 PUBLIC KEY-----\n",
		AgentTokenHash: control.HashToken(bearer),
	}
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/enroll":
			postCount++
			var received enrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
				t.Errorf("decode enrollment request: %v", err)
			}
			if !reflect.DeepEqual(received, payload) {
				t.Errorf("enrollment request changed across retry: %#v", received)
			}
			if received.AgentTokenHash == bearer {
				t.Error("raw local bearer was sent in enrollment body")
			}
			response.WriteHeader(http.StatusBadGateway)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/agent/bootstrap":
			if request.Header.Get("Authorization") != "Bearer "+bearer {
				t.Errorf("bootstrap authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(control.EnrollmentBundle{Certificate: "recovered-certificate"})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	httpClient := secureHTTPClient()
	agentClient, err := nodeagent.NewClient(server.URL, bearer, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := requestEnrollment(context.Background(), httpClient, agentClient, server.URL, payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Certificate != "recovered-certificate" {
		t.Fatalf("recovered certificate = %q", recovered.Certificate)
	}
	if postCount != 2 {
		t.Fatalf("POST count = %d, want 2", postCount)
	}
}

func TestRequestEnrollmentDoesNotRetryDeterministicRejection(t *testing.T) {
	t.Parallel()
	bearer := testBearer(2)
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		postCount++
		response.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	httpClient := secureHTTPClient()
	agentClient, err := nodeagent.NewClient(server.URL, bearer, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestEnrollment(context.Background(), httpClient, agentClient, server.URL, enrollmentRequest{}, false)
	if err == nil {
		t.Fatal("expected deterministic enrollment rejection")
	}
	if postCount != 1 {
		t.Fatalf("request count = %d, want 1", postCount)
	}
}

func TestPendingEnrollmentCanResumeWithoutEnvironmentToken(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("e", 42) + "A"
	pending := &nodeagent.ProvisionalEnrollment{EnrollmentToken: token}
	if got, err := effectiveEnrollmentToken("", pending); err != nil || got != token {
		t.Fatalf("resume token = %q, err = %v", got, err)
	}
	if _, err := effectiveEnrollmentToken(strings.Repeat("x", 42)+"A", pending); err == nil {
		t.Fatal("conflicting resume token was accepted")
	}
	if _, err := effectiveEnrollmentToken("", nil); err == nil {
		t.Fatal("new enrollment without a token was accepted")
	}
}

func TestLoadEnrollmentTokenSources(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("e", 42) + "A"
	for name, test := range map[string]struct {
		explicit, file, environment string
		input                       io.Reader
	}{
		"explicit":    {explicit: token},
		"environment": {environment: token},
		"stdin":       {file: "-", input: strings.NewReader(token + "\n")},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := loadEnrollmentToken(test.explicit, test.file, test.input, test.environment)
			if err != nil || got != token {
				t.Fatalf("token=%q err=%v", got, err)
			}
		})
	}
	if value, err := loadEnrollmentToken("", "", nil, ""); err != nil || value != "" {
		t.Fatalf("empty resumable token=%q err=%v", value, err)
	}
	if _, err := loadEnrollmentToken(token, "-", strings.NewReader(token), ""); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("mixed enrollment token sources accepted: %v", err)
	}
	if _, err := loadEnrollmentToken("bad", "", nil, ""); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid enrollment token accepted: %v", err)
	}
}

func TestLoadEnrollmentTokenPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private file permission validation is fail-closed on Windows")
	}
	token := strings.Repeat("p", 42) + "A"
	path := filepath.Join(t.TempDir(), "enrollment-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadEnrollmentToken("", path, nil, "")
	if err != nil || loaded != token {
		t.Fatalf("private enrollment token=%q err=%v", loaded, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEnrollmentToken("", path, nil, ""); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("insecure enrollment-token file accepted: %v", err)
	}
}

func TestResumedEnrollmentBootstrapsCommittedBundleBeforeExpiredTokenPOST(t *testing.T) {
	t.Parallel()
	bearer := testBearer(4)
	postCount := 0
	bootstrapCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			bootstrapCount++
			if request.Header.Get("Authorization") != "Bearer "+bearer {
				t.Errorf("bootstrap authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(control.EnrollmentBundle{Certificate: "committed-before-token-expired"})
		case http.MethodPost:
			postCount++
			response.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	httpClient := secureHTTPClient()
	agentClient, err := nodeagent.NewClient(server.URL, bearer, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := requestEnrollment(context.Background(), httpClient, agentClient, server.URL, enrollmentRequest{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Certificate != "committed-before-token-expired" {
		t.Fatalf("certificate = %q", bundle.Certificate)
	}
	if bootstrapCount != 1 || postCount != 0 {
		t.Fatalf("bootstrap count = %d, POST count = %d", bootstrapCount, postCount)
	}
}

func TestLifecycleDue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{name: "unknown", want: false},
		{name: "boundary", expiry: now.Add(lifecycleWindow), want: true},
		{name: "inside", expiry: now.Add(lifecycleWindow - time.Second), want: true},
		{name: "outside", expiry: now.Add(lifecycleWindow + time.Second), want: false},
		{name: "expired", expiry: now.Add(-time.Second), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := lifecycleDue(test.expiry, now); got != test.want {
				t.Fatalf("lifecycleDue() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRuntimeTelemetryReportingIsBestEffortAfterHeartbeat(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		err    error
		status string
	}{
		{name: "reported", status: "reported"},
		{name: "mixed-version server", err: nodeagent.ErrRuntimeTelemetryUnsupported, status: "unsupported"},
		{name: "transient failure", err: errors.New("telemetry transport failed"), status: "error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := &recordingRuntimeTelemetryAgent{reportErr: test.err}
			if got := reportRuntimeTelemetry(context.Background(), agent, 17); got != test.status {
				t.Fatalf("status = %q, want %q", got, test.status)
			}
			if agent.reportSequence != 17 || agent.reportCalls != 1 {
				t.Fatalf("report sequence=%d calls=%d", agent.reportSequence, agent.reportCalls)
			}
		})
	}
	if got := reportRuntimeTelemetry(context.Background(), &recordingLifecycleAgent{}, 17); got != "" {
		t.Fatalf("agent without telemetry capability returned status %q", got)
	}
}

func TestSignedActivationFailureReportsOnlyExactArtifactIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 22, 30, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now)
	digest := strings.Repeat("a", 64)
	agent := &recordingConfigFailureAgent{recordingLifecycleAgent: recordingLifecycleAgent{syncErr: &nodeagent.ConfigActivationError{
		Revision: 8, Digest: digest, Cause: errors.New("local reload failed"),
	}}}
	runner := &agentRunner{agent: agent, store: store, now: func() time.Time { return now }, failOpen: true}
	if _, err := runner.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "local reload failed") {
		t.Fatalf("activation failure cycle error = %v", err)
	}
	if agent.reportCalls != 1 || agent.reportInput.AttemptedConfigRevision != 8 || agent.reportInput.AttemptedConfigSHA256 != digest || agent.reportInput.FailureCode != control.ConfigApplyFailureCodeActivation {
		t.Fatalf("activation failure report=%+v calls=%d", agent.reportInput, agent.reportCalls)
	}

	agent.syncErr = errors.New("control plane unavailable")
	if _, err := runner.cycle(context.Background()); err == nil {
		t.Fatal("generic sync failure was accepted")
	}
	if agent.reportCalls != 1 {
		t.Fatalf("generic sync failure emitted an activation report: calls=%d", agent.reportCalls)
	}
}

func TestCertificateRenewalUsesSignedServerSchedule(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	// A 24-hour certificate is server-eligible only in its final 8 hours. The
	// old fixed 30-day client window incorrectly treated it as due at issuance.
	renewAfter := now.Add(16 * time.Hour)
	if certificateRenewalDue(renewAfter, now) || certificateRenewalDue(renewAfter, renewAfter.Add(-time.Nanosecond)) {
		t.Fatal("short-lived certificate was renewed before its signed server schedule")
	}
	if !certificateRenewalDue(renewAfter, renewAfter) || !certificateRenewalDue(renewAfter, renewAfter.Add(time.Minute)) {
		t.Fatal("certificate was not renewed at or after its signed server schedule")
	}
}

func TestExpiredCertificateRenewsBeforeStrictSync(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store, err := nodeagent.NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(nodeagent.State{
		ServerURL:                 "http://127.0.0.1:8080",
		Bearer:                    testBearer(3),
		NodeID:                    "node-1",
		NetworkID:                 "network-1",
		ConfigSigningPublicKey:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CACertificateSHA256:       strings.Repeat("c", 64),
		PublicKeyHash:             base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CertificateFingerprint:    strings.Repeat("f", 64),
		CertificateGeneration:     1,
		CertificateRenewAfter:     now.Add(-2 * time.Hour),
		CertificateExpiresAt:      now.Add(-time.Minute),
		AgentCredentialExpiresAt:  now.Add(60 * 24 * time.Hour),
		AgentCredentialGeneration: 1,
		BootID:                    "boot-1",
		OutputDir:                 t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("strict sync should run after recovery")
	agent := &recordingLifecycleAgent{syncErr: syncFailure}
	runner := &agentRunner{agent: agent, store: store, now: func() time.Time { return now }, failOpen: true}
	_, err = runner.cycle(context.Background())
	if !errors.Is(err, syncFailure) {
		t.Fatalf("cycle error = %v", err)
	}
	if want := []string{"renew", "sync"}; !reflect.DeepEqual(agent.calls, want) {
		t.Fatalf("lifecycle order = %#v, want %#v", agent.calls, want)
	}
}

func TestFreshTransientSyncFailureDoesNotQuarantine(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now.Add(-time.Minute))
	runtime := &freshnessRuntime{}
	agent := &recordingLifecycleAgent{syncErr: errors.New("temporary control-plane outage")}
	runner := &agentRunner{
		agent: agent, store: store, runtime: runtime, now: func() time.Time { return now },
		startup: false, maxConfigStaleness: 5 * time.Minute,
	}
	if _, err := runner.cycle(context.Background()); err == nil {
		t.Fatal("expected sync failure")
	}
	if runtime.quarantineCalls != 0 || runner.quarantined {
		t.Fatalf("fresh transient failure quarantined runtime: calls=%d state=%v", runtime.quarantineCalls, runner.quarantined)
	}
}

func TestStartupSyncFailureQuarantinesImmediately(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now)
	events := []string{}
	runtime := &freshnessRuntime{events: &events}
	runner := &agentRunner{
		agent: &recordingLifecycleAgent{syncErr: errors.New("control plane unavailable"), events: &events},
		store: store, runtime: runtime, now: func() time.Time { return now },
		startup: true, maxConfigStaleness: 5 * time.Minute,
	}
	if _, err := runner.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("startup failure error = %v", err)
	}
	if runtime.quarantineCalls != 1 || !runner.quarantined {
		t.Fatalf("startup quarantine calls=%d state=%v", runtime.quarantineCalls, runner.quarantined)
	}
	if want := []string{"quarantine", "sync"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("startup order = %#v, want %#v", events, want)
	}
}

func TestQuarantinedAgentReconfirmsStopOnEveryFailedCycle(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now)
	runtime := &freshnessRuntime{}
	runner := &agentRunner{
		agent: &recordingLifecycleAgent{syncErr: errors.New("control plane unavailable")},
		store: store, runtime: runtime, now: func() time.Time { return now },
		startup: true, maxConfigStaleness: 5 * time.Minute,
	}
	for range 2 {
		if _, err := runner.cycle(context.Background()); err == nil {
			t.Fatal("expected sync failure")
		}
	}
	if runtime.quarantineCalls != 2 {
		t.Fatalf("quarantine confirmations = %d, want one per failed cycle", runtime.quarantineCalls)
	}
}

func TestOneShotNoReloadWithExplicitFailOpenRemainsValidationOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, time.Time{})
	runtime := &freshnessRuntime{}
	runner := &agentRunner{
		agent: &recordingLifecycleAgent{syncErr: errors.New("validation request failed")},
		store: store, runtime: runtime, now: func() time.Time { return now },
		startup: true, maxConfigStaleness: 5 * time.Minute, failOpen: true,
	}
	if _, err := runner.cycle(context.Background()); err == nil {
		t.Fatal("expected validation sync failure")
	}
	if runtime.quarantineCalls != 0 || runner.quarantined {
		t.Fatal("one-shot no-reload validation claimed runtime quarantine")
	}
}

func TestStaleSyncFailureQuarantinesBeforeRetry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now.Add(-5*time.Minute))
	runtime := &freshnessRuntime{}
	runner := &agentRunner{
		agent: &recordingLifecycleAgent{syncErr: errors.New("control plane unavailable")},
		store: store, runtime: runtime, now: func() time.Time { return now },
		startup: false, maxConfigStaleness: 5 * time.Minute,
	}
	if _, err := runner.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "remains quarantined") {
		t.Fatalf("stale failure error = %v", err)
	}
	if runtime.quarantineCalls != 1 || !runner.quarantined {
		t.Fatalf("stale quarantine calls=%d state=%v", runtime.quarantineCalls, runner.quarantined)
	}
}

func TestSuccessfulSyncRestartsQuarantinedRuntime(t *testing.T) {
	t.Parallel()
	runtime := &freshnessRuntime{}
	runner := &agentRunner{runtime: runtime, startup: false, quarantined: true, maxConfigStaleness: 5 * time.Minute}
	if err := runner.ensureRuntimeAfterSync(context.Background(), nodeagent.SyncResult{Revision: 3}, false); err != nil {
		t.Fatal(err)
	}
	if runtime.reloadCalls != 1 || runner.quarantined || runner.startup {
		t.Fatalf("recovery reload calls=%d quarantined=%v startup=%v", runtime.reloadCalls, runner.quarantined, runner.startup)
	}
}

func TestAgentReconcilesExactCurrentSignedNativeDNSConfig(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	store := saveLifecycleState(t, now, now)
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(state.OutputDir, "current")
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "# signed native DNS policy\npki:\n"
	if err := os.WriteFile(filepath.Join(current, "config.signed.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &recordingNativeDNS{}
	runner := &agentRunner{store: store, nativeDNS: resolver}
	if err := runner.reconcileNativeDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resolver.reconcileCalls != 1 || resolver.config != config {
		t.Fatalf("native DNS reconciliation calls=%d config=%q", resolver.reconcileCalls, resolver.config)
	}
	if err := os.WriteFile(filepath.Join(current, "config.signed.yml"), make([]byte, control.MaxManagedConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.reconcileNativeDNS(context.Background()); err == nil {
		t.Fatal("oversized signed native DNS config was accepted")
	}
}

func TestAgentDisablesNativeDNSBeforeRuntimeQuarantine(t *testing.T) {
	events := []string{}
	resolver := &recordingNativeDNS{events: &events}
	runtime := &freshnessRuntime{events: &events}
	runner := &agentRunner{nativeDNS: resolver, runtime: runtime}
	if err := runner.stopRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"native-dns-disable", "quarantine"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("quarantine order=%#v want=%#v", events, want)
	}
	if !runner.quarantined {
		t.Fatal("successful combined quarantine did not update runner state")
	}
}

func TestAgentTimingRequiresRetryHeadroom(t *testing.T) {
	t.Parallel()
	if err := validateAgentTiming(false, time.Minute, 5*time.Minute, false); err != nil {
		t.Fatalf("default timing rejected: %v", err)
	}
	if err := validateAgentTiming(false, 4*time.Second, 5*time.Minute, false); err == nil {
		t.Fatal("too-fast interval was accepted")
	}
	if err := validateAgentTiming(false, 3*time.Minute, 5*time.Minute, false); err == nil {
		t.Fatal("interval without retry headroom was accepted")
	}
	if err := validateAgentTiming(false, 10*time.Minute, 5*time.Minute, true); err != nil {
		t.Fatalf("explicit fail-open timing was rejected: %v", err)
	}
	if err := validateAgentTiming(true, 0, 0, false); err != nil {
		t.Fatalf("one-shot validation timing was rejected: %v", err)
	}
	if got := configSuccessPersistence(10 * time.Second); got != 5*time.Second {
		t.Fatalf("tight-policy persistence = %s, want 5s", got)
	}
	if got := configSuccessPersistence(5 * time.Minute); got != time.Minute {
		t.Fatalf("default-policy persistence = %s, want 1m", got)
	}
	for range 100 {
		delay := jitteredInterval(time.Minute)
		if delay < 48*time.Second || delay > time.Minute {
			t.Fatalf("jittered delay %s exceeded safe cadence bounds", delay)
		}
	}
}

func TestReportedNebulaVersion(t *testing.T) {
	t.Parallel()
	version, err := reportedNebulaVersion("Version: 1.10.3\n")
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.10.3" {
		t.Fatalf("version = %q", version)
	}
	if _, err := reportedNebulaVersion("Version: 1.10.2"); err == nil {
		t.Fatal("expected old Nebula version to fail")
	}
}

func TestRuntimeSelectionIsExplicit(t *testing.T) {
	t.Parallel()
	if _, err := selectRuntimeController(runtimeOptions{}); err == nil {
		t.Fatal("expected missing runtime policy to fail")
	}
	if _, err := selectRuntimeController(runtimeOptions{restartService: "nebula", noReload: true}); err == nil {
		t.Fatal("expected multiple runtime policies to fail")
	}
	controller, err := selectRuntimeController(runtimeOptions{reloadService: "nebula.service", configPath: "/etc/mesh/current/config.yml", runner: &recordingCommandRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.(*serviceRuntime); !ok {
		t.Fatalf("controller type = %T", controller)
	}
	observation, err := (noReloadRuntime{}).Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observation.HeartbeatAllowed {
		t.Fatal("no-reload runtime must not permit heartbeat")
	}
}

func TestRuntimeObservationRecoversBeforeAcknowledgment(t *testing.T) {
	t.Parallel()
	runtime := &recoveringRuntime{observeErr: errors.New("service stopped")}
	observation, recovered, err := observeRuntimeWithRecovery(context.Background(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("successful runtime recovery was not reported to resolver reconciliation")
	}
	if !observation.HeartbeatAllowed || !observation.NebulaRunning {
		t.Fatalf("recovered observation = %#v", observation)
	}
	if want := []string{"observe", "reload", "observe"}; !reflect.DeepEqual(runtime.calls, want) {
		t.Fatalf("runtime calls = %#v, want %#v", runtime.calls, want)
	}
}

func TestServiceRuntimeRestartsAndChecksActiveWithoutShell(t *testing.T) {
	t.Parallel()
	recorder := &recordingCommandRunner{outputs: [][]byte{
		[]byte("{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }\n"),
		[]byte("SubState=running\nMainPID=4132\nActiveState=active\n"),
	}}
	runtime := &serviceRuntime{service: "nebula.service", runner: recorder, expectedConfig: "/etc/mesh/current/config.yml", expectedBinary: "/usr/local/bin/nebula"}
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "show", "--property=ExecStart", "--value", "--", "nebula.service"},
		{"systemctl", "restart", "--", "nebula.service"},
		{"systemctl", "show", "--property=ActiveState,SubState,MainPID", "--", "nebula.service"},
	}
	if !reflect.DeepEqual(recorder.commands, want) {
		t.Fatalf("commands = %#v, want %#v", recorder.commands, want)
	}
}

func TestPackagedServiceRuntimeOpensReadinessOnlyAfterValidation(t *testing.T) {
	t.Parallel()
	events := []string{}
	marker := &recordingReadinessMarker{events: &events}
	runner := &orderedServiceCommandRunner{events: &events}
	runtime := &serviceRuntime{
		service: "mesh-nebula.service", runner: runner,
		expectedConfig: "/etc/mesh/current/config.yml", expectedBinary: "/usr/local/bin/nebula",
		readinessMarker: marker,
	}
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"validate-exec-start", "marker-open", "restart", "inspect-runtime"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("runtime authorization order = %#v, want %#v", events, want)
	}
	if !marker.open {
		t.Fatal("successful controlled start did not leave readiness open")
	}
}

func TestPackagedServiceRuntimeClosesBeforeEveryStop(t *testing.T) {
	t.Parallel()
	events := []string{}
	marker := &recordingReadinessMarker{events: &events, open: true}
	runner := &orderedServiceCommandRunner{events: &events}
	runtime := &serviceRuntime{service: "mesh-nebula.service", runner: runner, readinessMarker: marker}
	if err := runtime.Quarantine(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"marker-close", "stop", "inspect-runtime"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("quarantine order = %#v, want %#v", events, want)
	}
	if marker.open {
		t.Fatal("quarantine left readiness open")
	}
}

func TestPackagedServiceRuntimeRestartCancellationStillFailsClosed(t *testing.T) {
	t.Parallel()
	events := []string{}
	ctx, cancel := context.WithCancel(context.Background())
	marker := &recordingReadinessMarker{events: &events}
	runner := &orderedServiceCommandRunner{
		events: &events,
		restart: func(ctx context.Context) error {
			cancel()
			return ctx.Err()
		},
	}
	runtime := &serviceRuntime{
		service: "mesh-nebula.service", runner: runner,
		expectedConfig: "/etc/mesh/current/config.yml", expectedBinary: "/usr/local/bin/nebula",
		readinessMarker: marker,
	}
	err := runtime.Reload(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reload error = %v", err)
	}
	want := []string{"validate-exec-start", "marker-open", "restart", "marker-close", "stop", "inspect-runtime"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("canceled restart cleanup order = %#v, want %#v", events, want)
	}
	if runner.stopContextErr != nil || runner.inspectContextErr != nil {
		t.Fatalf("fail-closed cleanup inherited canceled context: stop=%v inspect=%v", runner.stopContextErr, runner.inspectContextErr)
	}
	if marker.open {
		t.Fatal("canceled restart left readiness open")
	}
}

func TestPackagedServiceRuntimeMarkerOpenFailureStopsWithoutRestart(t *testing.T) {
	t.Parallel()
	events := []string{}
	markerErr := errors.New("marker publication failed")
	marker := &recordingReadinessMarker{events: &events, openErr: markerErr}
	runner := &orderedServiceCommandRunner{events: &events}
	runtime := &serviceRuntime{
		service: "mesh-nebula.service", runner: runner,
		expectedConfig: "/etc/mesh/current/config.yml", expectedBinary: "/usr/local/bin/nebula",
		readinessMarker: marker,
	}
	err := runtime.Reload(context.Background())
	if !errors.Is(err, markerErr) {
		t.Fatalf("reload error = %v", err)
	}
	want := []string{"validate-exec-start", "marker-open", "marker-close", "stop", "inspect-runtime"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("publication-failure cleanup order = %#v, want %#v", events, want)
	}
}

func TestPackagedServiceRuntimeCloseFailureStillStopsButCannotClaimQuarantine(t *testing.T) {
	t.Parallel()
	events := []string{}
	closeErr := errors.New("marker removal failed")
	marker := &recordingReadinessMarker{events: &events, open: true, closeErr: closeErr}
	runner := &orderedServiceCommandRunner{events: &events}
	runtime := &serviceRuntime{service: "mesh-nebula.service", runner: runner, readinessMarker: marker}
	err := runtime.Quarantine(context.Background())
	if !errors.Is(err, closeErr) {
		t.Fatalf("quarantine error = %v", err)
	}
	want := []string{"marker-close", "stop", "inspect-runtime"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("failed-close stop order = %#v, want %#v", events, want)
	}
}

func TestServiceRuntimeTeardownRevokesReadiness(t *testing.T) {
	t.Parallel()
	events := []string{}
	marker := &recordingReadinessMarker{events: &events, open: true}
	runtime := &serviceRuntime{readinessMarker: marker}
	if err := runtime.CloseReadinessMarker(); err != nil {
		t.Fatal(err)
	}
	if marker.open || !reflect.DeepEqual(events, []string{"marker-close"}) {
		t.Fatalf("teardown marker state=%v events=%#v", marker.open, events)
	}
}

func TestServiceRuntimeObserveRequiresRunningMainProcess(t *testing.T) {
	t.Parallel()
	recorder := &recordingCommandRunner{outputs: [][]byte{
		[]byte("{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }\n"),
		[]byte("MainPID=72\nActiveState=active\nSubState=running\n"),
	}}
	runtime := &serviceRuntime{service: "nebula.service", runner: recorder, expectedConfig: "/etc/mesh/current/config.yml", expectedBinary: "/usr/local/bin/nebula"}
	observation, err := runtime.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !observation.HeartbeatAllowed || !observation.NebulaRunning {
		t.Fatalf("observation = %#v", observation)
	}
}

func TestServiceRuntimeStopsAndConfirmsInactiveDespiteConfigDrift(t *testing.T) {
	t.Parallel()
	recorder := &recordingCommandRunner{outputs: [][]byte{[]byte("MainPID=0\nSubState=dead\nActiveState=inactive\n")}}
	runtime := &serviceRuntime{service: "nebula.service", runner: recorder, expectedConfig: "/drifted/config.yml", expectedBinary: "/drifted/nebula"}
	if err := runtime.Quarantine(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "stop", "--", "nebula.service"},
		{"systemctl", "show", "--property=ActiveState,SubState,MainPID", "--", "nebula.service"},
	}
	if !reflect.DeepEqual(recorder.commands, want) {
		t.Fatalf("commands = %#v, want %#v", recorder.commands, want)
	}
	if err := (noReloadRuntime{}).Quarantine(context.Background()); !errors.Is(err, errQuarantineUnsupported) {
		t.Fatalf("no-reload quarantine error = %v", err)
	}
}

func TestServiceRuntimeRejectsUnprovenActiveStates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		output string
	}{
		{name: "active but exited", output: "ActiveState=active\nSubState=exited\nMainPID=92\n"},
		{name: "zero pid", output: "ActiveState=active\nSubState=running\nMainPID=0\n"},
		{name: "pid one", output: "ActiveState=active\nSubState=running\nMainPID=1\n"},
		{name: "missing property", output: "ActiveState=active\nMainPID=92\n"},
		{name: "duplicate property", output: "ActiveState=active\nSubState=running\nMainPID=92\nMainPID=93\n"},
		{name: "malformed pid", output: "ActiveState=active\nSubState=running\nMainPID=9x\n"},
		{name: "unexpected property", output: "ActiveState=active\nSubState=running\nMainPID=92\nUnitFileState=enabled\n"},
		{name: "blank line", output: "ActiveState=active\n\nSubState=running\nMainPID=92\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &serviceRuntime{service: "nebula.service", runner: &recordingCommandRunner{output: []byte(test.output)}}
			if err := runtime.active(context.Background()); err == nil {
				t.Fatal("unproven systemd runtime was accepted")
			}
		})
	}
	t.Run("oversized output", func(t *testing.T) {
		runtime := &serviceRuntime{service: "nebula.service", runner: &recordingCommandRunner{output: []byte(strings.Repeat("x", maxSystemdStateOutput+1))}}
		if err := runtime.active(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized output error = %v", err)
		}
	})
}

func TestServiceRuntimeQuarantineRejectsResidualProcess(t *testing.T) {
	t.Parallel()
	for name, output := range map[string]string{
		"residual pid":       "ActiveState=inactive\nSubState=dead\nMainPID=92\n",
		"deactivating":       "ActiveState=deactivating\nSubState=stop-sigterm\nMainPID=92\n",
		"failed not dead":    "ActiveState=failed\nSubState=failed\nMainPID=0\n",
		"active without pid": "ActiveState=active\nSubState=running\nMainPID=0\n",
	} {
		t.Run(name, func(t *testing.T) {
			runtime := &serviceRuntime{service: "nebula.service", runner: &recordingCommandRunner{output: []byte(output)}}
			if err := runtime.Quarantine(context.Background()); err == nil {
				t.Fatal("unproven quarantine was accepted")
			}
		})
	}
}

func TestServiceRuntimeRejectsAmbiguousOrWrongExecStart(t *testing.T) {
	t.Parallel()
	for name, command := range map[string]string{
		"missing path":       `{ argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }`,
		"duplicate path":     `{ path=/usr/local/bin/nebula ; path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }`,
		"at argv spoof":      `{ path=/usr/local/bin/evil ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }`,
		"path argv mismatch": `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/wrapper -config /etc/mesh/current/config.yml ; }`,
		"duplicate config":   `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml -config /tmp/hostile.yml ; }`,
		"extra argument":     `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml -test ; }`,
		"wrong config":       `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /tmp/hostile.yml ; }`,
		"multiple commands":  `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }`,
		"embedded nul":       "{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }\x00",
		"oversized output":   strings.Repeat("x", (64<<10)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if execStartUsesManagedNebula(command, "/usr/local/bin/nebula", "/etc/mesh/current/config.yml") {
				t.Fatal("unsafe ExecStart was accepted")
			}
		})
	}
}

func TestServiceRuntimeAcceptsExactPathArgvAndManagedConfig(t *testing.T) {
	t.Parallel()
	command := `{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; ignore_errors=no ; }`
	if !execStartUsesManagedNebula(command, "/usr/local/bin/nebula", "/etc/mesh/current/config.yml") {
		t.Fatal("exact managed ExecStart was rejected")
	}
}

func TestProcessLockIsExclusiveAndStable(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "state.json")
	first, err := acquireProcessLock(target, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireProcessLock(target, "test"); err == nil {
		t.Fatal("expected second process lock to fail")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireProcessLock(target, "test")
	if err != nil {
		t.Fatalf("reacquire process lock: %v", err)
	}
	defer third.Close()
}

type recordingCommandRunner struct {
	commands [][]string
	err      error
	output   []byte
	outputs  [][]byte
}

type recordingReadinessMarker struct {
	events     *[]string
	open       bool
	openErr    error
	closeErr   error
	inspectErr error
}

func (m *recordingReadinessMarker) Inspect() (bool, error) {
	if m.events != nil {
		*m.events = append(*m.events, "marker-inspect")
	}
	return m.open, m.inspectErr
}

func (m *recordingReadinessMarker) Open() error {
	if m.events != nil {
		*m.events = append(*m.events, "marker-open")
	}
	if m.openErr == nil {
		m.open = true
	}
	return m.openErr
}

func (m *recordingReadinessMarker) Close() error {
	if m.events != nil {
		*m.events = append(*m.events, "marker-close")
	}
	if m.closeErr == nil {
		m.open = false
	}
	return m.closeErr
}

type orderedServiceCommandRunner struct {
	events            *[]string
	restart           func(context.Context) error
	stopErr           error
	stopContextErr    error
	inspectContextErr error
}

func (r *orderedServiceCommandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "systemctl" {
		return nil, errors.New("unexpected command")
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--property=ExecStart") {
		*r.events = append(*r.events, "validate-exec-start")
		return []byte("{ path=/usr/local/bin/nebula ; argv[]=/usr/local/bin/nebula -config /etc/mesh/current/config.yml ; }\n"), nil
	}
	if strings.Contains(joined, "--property=ActiveState,SubState,MainPID") {
		*r.events = append(*r.events, "inspect-runtime")
		r.inspectContextErr = ctx.Err()
		if len(*r.events) >= 2 && (*r.events)[len(*r.events)-2] == "stop" {
			return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
		}
		return []byte("ActiveState=active\nSubState=running\nMainPID=4132\n"), nil
	}
	return nil, errors.New("unexpected systemctl output request")
}

func (r *orderedServiceCommandRunner) RunQuiet(ctx context.Context, name string, args ...string) error {
	if name != "systemctl" || len(args) == 0 {
		return errors.New("unexpected command")
	}
	switch args[0] {
	case "restart":
		*r.events = append(*r.events, "restart")
		if r.restart != nil {
			return r.restart(ctx)
		}
		return nil
	case "stop":
		*r.events = append(*r.events, "stop")
		r.stopContextErr = ctx.Err()
		return r.stopErr
	default:
		return errors.New("unexpected systemctl operation")
	}
}

type recoveringRuntime struct {
	calls      []string
	observeErr error
}

type freshnessRuntime struct {
	quarantineCalls int
	reloadCalls     int
	quarantineErr   error
	reloadErr       error
	events          *[]string
}

type recordingNativeDNS struct {
	reconcileCalls int
	disableCalls   int
	config         string
	reconcileErr   error
	disableErr     error
	events         *[]string
}

func (r *recordingNativeDNS) Reconcile(_ context.Context, config string) error {
	r.reconcileCalls++
	r.config = config
	return r.reconcileErr
}

func (r *recordingNativeDNS) Disable(context.Context) error {
	r.disableCalls++
	if r.events != nil {
		*r.events = append(*r.events, "native-dns-disable")
	}
	return r.disableErr
}

func (r *freshnessRuntime) Reload(context.Context) error {
	r.reloadCalls++
	return r.reloadErr
}

func (r *freshnessRuntime) Quarantine(context.Context) error {
	r.quarantineCalls++
	if r.events != nil {
		*r.events = append(*r.events, "quarantine")
	}
	return r.quarantineErr
}

func (r *freshnessRuntime) Observe(context.Context) (runtimeObservation, error) {
	return runtimeObservation{HeartbeatAllowed: true, NebulaRunning: true, Status: "healthy"}, nil
}

func (r *recoveringRuntime) Quarantine(context.Context) error {
	r.calls = append(r.calls, "quarantine")
	return nil
}

func (r *recoveringRuntime) Reload(context.Context) error {
	r.calls = append(r.calls, "reload")
	r.observeErr = nil
	return nil
}

func (r *recoveringRuntime) Observe(context.Context) (runtimeObservation, error) {
	r.calls = append(r.calls, "observe")
	if r.observeErr != nil {
		return runtimeObservation{}, r.observeErr
	}
	return runtimeObservation{HeartbeatAllowed: true, NebulaRunning: true, Status: "healthy"}, nil
}

func testBearer(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

type recordingLifecycleAgent struct {
	calls   []string
	syncErr error
	events  *[]string
}

type recordingRuntimeTelemetryAgent struct {
	recordingLifecycleAgent
	reportErr      error
	reportSequence int64
	reportCalls    int
}

type recordingConfigFailureAgent struct {
	recordingLifecycleAgent
	reportInput control.ConfigApplyFailureInput
	reportCalls int
}

func (a *recordingConfigFailureAgent) ReportConfigApplyFailure(_ context.Context, input control.ConfigApplyFailureInput) error {
	a.reportCalls++
	a.reportInput = input
	return nil
}

func (a *recordingRuntimeTelemetryAgent) ReportRuntimeTelemetry(_ context.Context, heartbeatSequence int64) error {
	a.reportCalls++
	a.reportSequence = heartbeatSequence
	return a.reportErr
}

func (a *recordingLifecycleAgent) Sync(context.Context) (nodeagent.SyncResult, error) {
	a.calls = append(a.calls, "sync")
	if a.events != nil {
		*a.events = append(*a.events, "sync")
	}
	return nodeagent.SyncResult{}, a.syncErr
}

func (a *recordingLifecycleAgent) RenewCertificate(context.Context) (nodeagent.SyncResult, error) {
	a.calls = append(a.calls, "renew")
	return nodeagent.SyncResult{Changed: true, Revision: 1}, nil
}

func (a *recordingLifecycleAgent) RotateCredential(context.Context) (control.CredentialRotation, error) {
	a.calls = append(a.calls, "rotate")
	return control.CredentialRotation{}, nil
}

func (a *recordingLifecycleAgent) Heartbeat(context.Context, nodeagent.Health) (int64, error) {
	a.calls = append(a.calls, "heartbeat")
	return 1, nil
}

func (r *recordingCommandRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	command := append([]string{name}, args...)
	r.commands = append(r.commands, command)
	if len(r.outputs) > 0 {
		output := r.outputs[0]
		r.outputs = r.outputs[1:]
		return output, r.err
	}
	return r.output, r.err
}

func (r *recordingCommandRunner) RunQuiet(_ context.Context, name string, args ...string) error {
	command := append([]string{name}, args...)
	r.commands = append(r.commands, command)
	return r.err
}

func saveLifecycleState(t *testing.T, now, lastConfigSuccess time.Time) *nodeagent.StateStore {
	t.Helper()
	dir := t.TempDir()
	store, err := nodeagent.NewStateStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := nodeagent.State{
		ServerURL:                 "http://127.0.0.1:8080",
		Bearer:                    testBearer(9),
		NodeID:                    "node-1",
		NetworkID:                 "network-1",
		ConfigSigningPublicKey:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CACertificateSHA256:       strings.Repeat("c", 64),
		PublicKeyHash:             base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		LastSuccessfulConfigAt:    lastConfigSuccess,
		CertificateFingerprint:    strings.Repeat("f", 64),
		CertificateGeneration:     1,
		CertificateRenewAfter:     now.Add(16 * time.Hour),
		CertificateExpiresAt:      now.Add(24 * time.Hour),
		AgentCredentialExpiresAt:  now.Add(60 * 24 * time.Hour),
		AgentCredentialGeneration: 1,
		BootID:                    "boot-1",
		OutputDir:                 filepath.Join(dir, "nebula"),
	}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	return store
}

package iosmobile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"mesh/internal/configsignature"
	"mesh/internal/mobileruntime"
)

func TestLifecycleRefreshReturnsOnlyVerifiedCurrentIdentityConfiguration(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_lifecycle",
		netip.MustParseAddr("10.88.0.12"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.12:4242"),
	)
	agentSecret := bytes.Repeat([]byte{0x81}, 32)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	bundle := enrollmentBundleFromFixture(fixture, now)
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet ||
				request.URL.Path != "/api/v1/agent/bootstrap" ||
				request.Header.Get("Authorization") != "Bearer "+agentBearer {
				t.Error("lifecycle refresh authority changed")
			}
			response.Header().Set("Cache-Control", "no-store")
			writeEnrollmentTestJSON(t, response, bundle)
		},
	))
	defer server.Close()
	fixture.document.ControlPlaneOrigin = server.URL
	fixture.raw = marshalEngineTestDocument(t, fixture.document)

	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return append([]byte(nil), agentSecret...), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			t.Fatal("literal signed endpoint unexpectedly used DNS")
			return nil, nil
		},
		func() time.Time { return now },
	)
	raw, err := session.Refresh(server.URL, fixture.raw, 10)
	if err != nil {
		t.Fatal(err)
	}
	var outcome lifecycleRefreshOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.Schema != lifecycleRefreshSchema ||
		outcome.Status != lifecycleRefreshReady ||
		outcome.Configuration == "" ||
		strings.Contains(raw, agentBearer) {
		t.Fatalf("unexpected lifecycle refresh outcome: %#v", outcome)
	}
	document, err := decodeEngineConfiguration(outcome.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if document.NodeID != fixture.document.NodeID ||
		document.NetworkID != fixture.document.NetworkID ||
		document.ControlPlaneOrigin != server.URL ||
		document.MonotonicCounter != 10 {
		t.Fatalf("unexpected lifecycle configuration: %#v", document)
	}
	if _, err := verifyEngineConfiguration(
		outcome.Configuration,
		fixture.privateKey,
	); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleRefreshSeparatesAuthorizationAndOfflineDeferral(
	t *testing.T,
) {
	for _, test := range []struct {
		name       string
		statusCode int
		want       lifecycleRefreshStatus
	}{
		{
			name:       "authorization rejected",
			statusCode: http.StatusUnauthorized,
			want:       lifecycleRefreshUnauthorized,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			want:       lifecycleRefreshDeferred,
		},
		{
			name:       "server unavailable",
			statusCode: http.StatusServiceUnavailable,
			want:       lifecycleRefreshDeferred,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Round(time.Second)
			fixture := newEngineTestFixture(
				t,
				newEngineTestAuthority(t, now),
				now,
				"node_lifecycle_status",
				netip.MustParseAddr("10.88.0.13"),
				4242,
				false,
				netip.MustParseAddrPort("192.0.2.13:4242"),
			)
			server := httptest.NewTLSServer(http.HandlerFunc(
				func(response http.ResponseWriter, _ *http.Request) {
					http.Error(response, "bounded failure", test.statusCode)
				},
			))
			defer server.Close()
			fixture.document.ControlPlaneOrigin = server.URL
			fixture.raw = marshalEngineTestDocument(t, fixture.document)
			session := newLifecycleSession(
				func() ([]byte, error) {
					return append([]byte(nil), fixture.privateKey...), nil
				},
				func() ([]byte, error) {
					return bytes.Repeat([]byte{0x82}, 32), nil
				},
				server.Client(),
				func(_ context.Context, _ string) ([]netip.Addr, error) {
					return nil, nil
				},
				func() time.Time { return now },
			)
			raw, err := session.Refresh(server.URL, fixture.raw, 10)
			if err != nil {
				t.Fatal(err)
			}
			var outcome lifecycleRefreshOutcome
			if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
				t.Fatal(err)
			}
			if outcome.Schema != lifecycleRefreshSchema ||
				outcome.Status != test.want ||
				outcome.Configuration != "" {
				t.Fatalf("unexpected lifecycle status: %#v", outcome)
			}
		})
	}
}

func TestLifecycleRefreshRenewsDueCertificateWithExistingIdentity(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_lifecycle_renewal",
		netip.MustParseAddr("10.88.0.17"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.17:4242"),
	)
	agentSecret := bytes.Repeat([]byte{0x86}, 32)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	bootstrap := enrollmentBundleFromFixture(fixture, now)
	lifecycleNow := now.Add(25 * time.Minute)
	renewal := renewalBundleFromFixture(t, fixture, now)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			requests++
			if request.Header.Get("Authorization") != "Bearer "+agentBearer {
				t.Error("certificate renewal bearer changed")
			}
			response.Header().Set("Cache-Control", "no-store")
			switch {
			case request.Method == http.MethodGet &&
				request.URL.Path == "/api/v1/agent/bootstrap":
				writeEnrollmentTestJSON(t, response, bootstrap)
			case request.Method == http.MethodPost &&
				request.URL.Path == "/api/v1/agent/certificate/renew":
				var input struct {
					PublicKey string `json:"public_key"`
				}
				if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				publicKey, err := publicKeyPEM(fixture.privateKey)
				if err != nil || input.PublicKey != publicKey {
					t.Errorf("renewal public key changed: err=%v", err)
				}
				writeEnrollmentTestJSON(t, response, renewal)
			default:
				http.Error(response, "unexpected request", http.StatusNotFound)
			}
		},
	))
	defer server.Close()
	fixture.document.ControlPlaneOrigin = server.URL
	fixture.raw = marshalEngineTestDocument(t, fixture.document)
	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return append([]byte(nil), agentSecret...), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return lifecycleNow },
	)
	raw, err := session.Refresh(server.URL, fixture.raw, 11)
	if err != nil {
		t.Fatal(err)
	}
	var outcome lifecycleRefreshOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		t.Fatal(err)
	}
	if requests != 2 ||
		outcome.Status != lifecycleRefreshReady ||
		outcome.Configuration == "" {
		t.Fatalf("unexpected renewal outcome: requests=%d %#v", requests, outcome)
	}
	document, err := decodeEngineConfiguration(outcome.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if document.CertificateGeneration !=
		uint64(renewal.CertificateGeneration) ||
		document.CertificateFingerprint != renewal.CertificateFingerprint ||
		document.MonotonicCounter != 11 ||
		document.Nebula.ConfigSigningPublicKey !=
			bootstrap.ConfigSigningPublicKey {
		t.Fatalf("renewed document lost authenticated bindings: %#v", document)
	}
	if _, err := verifyEngineConfiguration(
		outcome.Configuration,
		fixture.privateKey,
	); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleRefreshRotatesCredentialAndRecoversAmbiguousCommit(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_lifecycle_credential",
		netip.MustParseAddr("10.88.0.19"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.19:4242"),
	)
	currentSecret := bytes.Repeat([]byte{0x88}, 32)
	currentBearer := base64.RawURLEncoding.EncodeToString(currentSecret)
	pendingSecret := bytes.Repeat([]byte{0x89}, 32)
	pendingBearer := base64.RawURLEncoding.EncodeToString(pendingSecret)
	bootstrap := enrollmentBundleFromFixture(fixture, now)
	bootstrap.AgentCredentialExpiresAt = now.Add(time.Hour)
	bootstrap.Node.AgentCredentialExpiresAt = pointerToTime(
		bootstrap.AgentCredentialExpiresAt,
	)
	rotatedExpiry := now.Add(90 * 24 * time.Hour)
	postCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodGet &&
				request.URL.Path == "/api/v1/agent/bootstrap":
				if request.Header.Get("Authorization") !=
					"Bearer "+currentBearer {
					t.Error("bootstrap did not use current credential")
				}
				response.Header().Set("Cache-Control", "no-store")
				writeEnrollmentTestJSON(t, response, bootstrap)
			case request.Method == http.MethodPost &&
				request.URL.Path == "/api/v1/agent/credentials/rotate":
				postCount++
				var input struct {
					NewTokenHash string `json:"new_token_hash"`
				}
				if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				if input.NewTokenHash != enrollmentTokenHash(pendingBearer) {
					t.Error("credential rotation hash changed")
				}
				if postCount == 1 {
					if request.Header.Get("Authorization") !=
						"Bearer "+currentBearer {
						t.Error("initial rotation did not use current credential")
					}
					http.Error(
						response,
						"ambiguous commit",
						http.StatusServiceUnavailable,
					)
					return
				}
				if request.Header.Get("Authorization") !=
					"Bearer "+pendingBearer {
					t.Error("rotation recovery did not use pending credential")
				}
				response.Header().Set("Cache-Control", "no-store")
				writeEnrollmentTestJSON(t, response, credentialRotation{
					Generation: 2,
					ExpiresAt:  rotatedExpiry,
				})
			default:
				http.Error(response, "unexpected request", http.StatusNotFound)
			}
		},
	))
	defer server.Close()
	fixture.document.ControlPlaneOrigin = server.URL
	fixture.raw = marshalEngineTestDocument(t, fixture.document)
	committed := []byte(nil)
	pendingDeleted := false
	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return append([]byte(nil), currentSecret...), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return now },
	)
	session.loadPendingAgentSecret = func() ([]byte, error) {
		return nil, nil
	}
	session.loadOrCreatePendingAgentSecret = func() ([]byte, error) {
		return append([]byte(nil), pendingSecret...), nil
	}
	session.replaceAgentSecret = func(value []byte) error {
		committed = append([]byte(nil), value...)
		return nil
	}
	session.deletePendingAgentSecret = func() error {
		pendingDeleted = true
		return nil
	}
	raw, err := session.Refresh(server.URL, fixture.raw, 13)
	if err != nil {
		t.Fatal(err)
	}
	var outcome lifecycleRefreshOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		t.Fatal(err)
	}
	document, err := decodeEngineConfiguration(outcome.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != lifecycleRefreshReady ||
		postCount != 2 ||
		!bytes.Equal(committed, pendingSecret) ||
		!pendingDeleted ||
		document.AgentCredentialGeneration != 2 ||
		document.AgentCredentialExpiresAt != canonicalTime(rotatedExpiry) ||
		strings.Contains(raw, currentBearer) ||
		strings.Contains(raw, pendingBearer) {
		t.Fatalf(
			"credential rotation lost crash-safe state: posts=%d committed=%t deleted=%t outcome=%#v document=%#v",
			postCount,
			bytes.Equal(committed, pendingSecret),
			pendingDeleted,
			outcome,
			document,
		)
	}
}

func TestLifecycleRefreshDoesNotDeferMandatoryRenewal(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_lifecycle_mandatory",
		netip.MustParseAddr("10.88.0.18"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.18:4242"),
	)
	bootstrap := enrollmentBundleFromFixture(fixture, now)
	bootstrap.CertificateProfileRenewalRequired = true
	resignEnrollmentBundleForTest(t, fixture, &bootstrap)
	postCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			if request.Method == http.MethodGet {
				writeEnrollmentTestJSON(t, response, bootstrap)
				return
			}
			postCount++
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
		},
	))
	defer server.Close()
	fixture.document.ControlPlaneOrigin = server.URL
	fixture.raw = marshalEngineTestDocument(t, fixture.document)
	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return bytes.Repeat([]byte{0x87}, 32), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return now },
	)
	if _, err := session.Refresh(server.URL, fixture.raw, 12); err == nil ||
		!strings.Contains(err.Error(), "certificate renewal failed") {
		t.Fatalf("mandatory renewal error=%v", err)
	}
	if postCount != 2 {
		t.Fatalf("mandatory renewal retries=%d, want 2", postCount)
	}
}

func TestLifecycleRefreshRejectsOriginSubstitutionBeforeBearerRequest(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_lifecycle_origin",
		netip.MustParseAddr("10.88.0.14"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.14:4242"),
	)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, _ *http.Request) {
			requests++
			http.Error(response, "must not receive bearer", http.StatusUnauthorized)
		},
	))
	defer server.Close()
	agentLoads := 0
	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			agentLoads++
			return bytes.Repeat([]byte{0x83}, 32), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return now },
	)
	if _, err := session.Refresh(server.URL, fixture.raw, 10); err == nil ||
		!strings.Contains(err.Error(), "current lifecycle configuration") {
		t.Fatalf("origin substitution error=%v", err)
	}
	if requests != 0 || agentLoads != 0 {
		t.Fatalf(
			"origin substitution crossed bearer boundary: requests=%d agent=%d",
			requests,
			agentLoads,
		)
	}
}

func renewalBundleFromFixture(
	t *testing.T,
	fixture engineTestFixture,
	now time.Time,
) renewalBundle {
	t.Helper()
	certificate, err := (&cert.TBSCertificate{
		Version:   fixture.authority.ca.Version(),
		Name:      fixture.certificate.Name(),
		Networks:  fixture.certificate.Networks(),
		Groups:    fixture.certificate.Groups(),
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(55 * time.Minute),
		PublicKey: fixture.certificate.PublicKey(),
		Curve:     fixture.certificate.Curve(),
	}).Sign(
		fixture.authority.ca,
		fixture.authority.ca.Curve(),
		fixture.authority.caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := certificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	document := fixture.document
	metadata := configsignature.Metadata{
		NodeID:                 document.NodeID,
		NetworkID:              document.NetworkID,
		Revision:               int64(document.ConfigRevision),
		IssuedAt:               mustParseEngineTestTime(t, document.Nebula.ConfigIssuedAt),
		CACertificateSHA256:    document.Nebula.CACertificateSHA256,
		CertificateFingerprint: fingerprint,
		CertificateExpiresAt:   certificate.NotAfter(),
		CertificateRenewAfter:  now.Add(45 * time.Minute),
		CertificateGeneration:  int64(document.CertificateGeneration) + 1,
		PublicKeyHash:          document.Nebula.PublicKeyHash,
	}
	digest, signature, err := configsignature.Sign(
		fixture.authority.configSigningKey,
		metadata,
		document.Nebula.Config,
	)
	if err != nil {
		t.Fatal(err)
	}
	return renewalBundle{
		NodeID:                 document.NodeID,
		NetworkID:              document.NetworkID,
		CA:                     document.Nebula.CA,
		Certificate:            string(certificatePEM),
		CertificateExpiresAt:   certificate.NotAfter(),
		CertificateRenewAfter:  metadata.CertificateRenewAfter,
		Config:                 document.Nebula.Config,
		ConfigRevision:         int64(document.ConfigRevision),
		ConfigIssuedAt:         metadata.IssuedAt,
		ConfigSHA256:           digest,
		CACertificateSHA256:    metadata.CACertificateSHA256,
		CertificateFingerprint: metadata.CertificateFingerprint,
		CertificateGeneration:  metadata.CertificateGeneration,
		PublicKeyHash:          metadata.PublicKeyHash,
		ConfigSignature:        signature,
	}
}

func resignEnrollmentBundleForTest(
	t *testing.T,
	fixture engineTestFixture,
	bundle *enrollmentBundle,
) {
	t.Helper()
	digest, signature, err := configsignature.Sign(
		fixture.authority.configSigningKey,
		bundle.signatureMetadata(),
		bundle.Config,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ConfigSHA256 = digest
	bundle.ConfigSignature = signature
}

func TestLifecycleRuntimeReportBindsVerifiedConfigurationAndCredential(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_mobile_runtime",
		netip.MustParseAddr("10.88.0.15"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.15:4242"),
	)
	agentSecret := bytes.Repeat([]byte{0x84}, 32)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	var received mobileruntime.ReportInput
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost ||
				request.URL.Path != "/api/v1/agent/mobile-runtime" ||
				request.Header.Get("Authorization") != "Bearer "+agentBearer {
				t.Error("mobile runtime report authority changed")
			}
			if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
				t.Error(err)
			}
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusNoContent)
		},
	))
	defer server.Close()
	fixture.document.ControlPlaneOrigin = server.URL
	fixture.raw = marshalEngineTestDocument(t, fixture.document)
	session := newLifecycleSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return append([]byte(nil), agentSecret...), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return now },
	)
	raw, err := session.ReportRuntime(
		server.URL,
		fixture.raw,
		12,
		3,
		mobileruntime.StateTunnelRunning,
		15_000,
		7,
		5,
		true,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	var outcome mobileRuntimeReportOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.Schema != mobileRuntimeReportSchema ||
		outcome.Status != mobileRuntimeReportAccepted ||
		strings.Contains(raw, agentBearer) {
		t.Fatalf("unexpected runtime outcome: %#v", outcome)
	}
	if received.Version != mobileruntime.VersionV1 ||
		received.InstanceGeneration != 12 ||
		received.Sequence != 3 ||
		received.ConfigRevision != int64(fixture.document.ConfigRevision) ||
		received.ConfigSHA256 != fixture.document.ConfigDigest ||
		received.CertificateFingerprint !=
			fixture.document.CertificateFingerprint ||
		received.CertificateGeneration !=
			int64(fixture.document.CertificateGeneration) ||
		received.EngineIdentity != fixture.document.EngineIdentity ||
		received.PacketsRead == nil ||
		*received.PacketsRead != 7 ||
		received.PacketsWritten == nil ||
		*received.PacketsWritten != 5 {
		t.Fatalf("unexpected mobile runtime report: %#v", received)
	}
}

func TestLifecycleRuntimeReportSeparatesServerOutcomes(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusCode int
		want       mobileRuntimeReportStatus
	}{
		{
			name:       "authorization rejected",
			statusCode: http.StatusUnauthorized,
			want:       mobileRuntimeReportUnauthorized,
		},
		{
			name:       "desired state changed",
			statusCode: http.StatusConflict,
			want:       mobileRuntimeReportRefreshRequired,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			want:       mobileRuntimeReportDeferred,
		},
		{
			name:       "older server",
			statusCode: http.StatusMethodNotAllowed,
			want:       mobileRuntimeReportUnsupported,
		},
		{
			name:       "server unavailable",
			statusCode: http.StatusServiceUnavailable,
			want:       mobileRuntimeReportDeferred,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Round(time.Second)
			fixture := newEngineTestFixture(
				t,
				newEngineTestAuthority(t, now),
				now,
				"node_mobile_status",
				netip.MustParseAddr("10.88.0.16"),
				4242,
				false,
				netip.MustParseAddrPort("192.0.2.16:4242"),
			)
			server := httptest.NewTLSServer(http.HandlerFunc(
				func(response http.ResponseWriter, _ *http.Request) {
					http.Error(response, "bounded failure", test.statusCode)
				},
			))
			defer server.Close()
			fixture.document.ControlPlaneOrigin = server.URL
			fixture.raw = marshalEngineTestDocument(t, fixture.document)
			session := newLifecycleSession(
				func() ([]byte, error) {
					return append([]byte(nil), fixture.privateKey...), nil
				},
				func() ([]byte, error) {
					return bytes.Repeat([]byte{0x85}, 32), nil
				},
				server.Client(),
				func(_ context.Context, _ string) ([]netip.Addr, error) {
					return nil, nil
				},
				func() time.Time { return now },
			)
			raw, err := session.ReportRuntime(
				server.URL,
				fixture.raw,
				1,
				1,
				mobileruntime.StateTunnelStarting,
				0,
				0,
				0,
				false,
				"",
			)
			if err != nil {
				t.Fatal(err)
			}
			var outcome mobileRuntimeReportOutcome
			if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
				t.Fatal(err)
			}
			if outcome.Schema != mobileRuntimeReportSchema ||
				outcome.Status != test.want {
				t.Fatalf("unexpected mobile runtime status: %#v", outcome)
			}
		})
	}
}

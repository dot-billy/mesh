package iosmobile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExtensionEnrollmentExchangesOnlyPublicIdentityAndReturnsVerifiedConfig(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_1",
		netip.MustParseAddr("10.88.0.7"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.9:4242"),
	)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	agentSecret := bytes.Repeat([]byte{0x72}, 32)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	bundle := enrollmentBundleFromFixture(fixture, now)

	var mu sync.Mutex
	var enrollmentBodies [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			switch request.URL.Path {
			case "/api/v1/enroll/preflight":
				if request.Method != http.MethodPost ||
					request.Header.Get("Authorization") != "" {
					t.Error("preflight request authority changed")
				}
				writeEnrollmentTestJSON(t, response, enrollmentPreflight{
					Schema:              enrollmentPreflightV1,
					TargetRole:          "member",
					NetworkCIDR:         "10.88.0.0/24",
					LighthouseEndpoints: []string{"192.0.2.9:4242"},
					TokenExpiresAt:      now.Add(10 * time.Minute),
				})
			case "/api/v1/enroll":
				if request.Method != http.MethodPost ||
					request.Header.Get("Authorization") != "" {
					t.Error("enrollment request authority changed")
				}
				raw := readEnrollmentTestBody(t, request)
				mu.Lock()
				enrollmentBodies = append(enrollmentBodies, raw)
				mu.Unlock()
				var received enrollmentExchangeRequest
				if err := json.Unmarshal(raw, &received); err != nil {
					t.Error(err)
				}
				publicKey, err := publicKeyPEM(fixture.privateKey)
				if err != nil {
					t.Error(err)
				}
				if received.Token != token ||
					received.PublicKey != publicKey ||
					received.AgentTokenHash != enrollmentTokenHash(agentBearer) ||
					strings.Contains(string(raw), agentBearer) {
					t.Error("enrollment request crossed a secret boundary")
				}
				writeEnrollmentTestJSON(t, response, bundle)
			default:
				http.NotFound(response, request)
			}
		},
	))
	defer server.Close()

	privateLoads := 0
	agentLoads := 0
	session := newEnrollmentSession(
		func() ([]byte, error) {
			privateLoads++
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			agentLoads++
			return append([]byte(nil), agentSecret...), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			t.Fatal("literal signed endpoint unexpectedly used DNS")
			return nil, nil
		},
		func() time.Time { return now },
	)
	raw, err := session.Enroll(server.URL, token, 1)
	if err != nil {
		t.Fatal(err)
	}
	if privateLoads != 1 || agentLoads != 1 {
		t.Fatalf(
			"identity loads private=%d agent=%d, want one each",
			privateLoads,
			agentLoads,
		)
	}
	if strings.Contains(raw, token) || strings.Contains(raw, agentBearer) {
		t.Fatal("verified configuration returned enrollment or agent secret")
	}
	document, err := decodeEngineConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if document.NodeID != bundle.NodeID ||
		document.NetworkID != bundle.NetworkID ||
		document.MonotonicCounter != 1 ||
		document.TunnelRemoteAddress != "192.0.2.9" ||
		document.EngineIdentity != FrameworkIdentitySHA256() {
		t.Fatalf("unexpected enrolled document: %#v", document)
	}
	if _, err := verifyEngineConfiguration(raw, fixture.privateKey); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(enrollmentBodies) != 1 {
		t.Fatalf("enrollment exchanged %d request bodies", len(enrollmentBodies))
	}
}

func TestInterruptedEnrollmentRecoversWithExistingAgentAuthority(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_recovered",
		netip.MustParseAddr("10.88.0.31"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.31:4242"),
	)
	agentSecret := bytes.Repeat([]byte{0x93}, 32)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	bundle := enrollmentBundleFromFixture(fixture, now)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			requests++
			if request.Method != http.MethodGet ||
				request.URL.Path != "/api/v1/agent/bootstrap" ||
				request.Header.Get("Authorization") != "Bearer "+agentBearer ||
				request.Body == nil {
				t.Error("enrollment recovery authority changed")
			}
			response.Header().Set("Cache-Control", "no-store")
			writeEnrollmentTestJSON(t, response, bundle)
		},
	))
	defer server.Close()

	session := newEnrollmentSession(
		func() ([]byte, error) {
			t.Fatal("recovery created or loaded enrollment private authority")
			return nil, nil
		},
		func() ([]byte, error) {
			t.Fatal("recovery created or loaded enrollment agent authority")
			return nil, nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			t.Fatal("literal signed endpoint unexpectedly used DNS")
			return nil, nil
		},
		func() time.Time { return now },
	)
	session.loadExistingPrivateKey = func() ([]byte, error) {
		return append([]byte(nil), fixture.privateKey...), nil
	}
	session.loadExistingAgentSecret = func() ([]byte, error) {
		return append([]byte(nil), agentSecret...), nil
	}
	raw, err := session.Recover(server.URL, 3)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || strings.Contains(raw, agentBearer) {
		t.Fatalf(
			"unexpected enrollment recovery requests=%d document=%q",
			requests,
			raw,
		)
	}
	var outcome enrollmentRecoveryOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.Schema != enrollmentRecoveryV1 ||
		outcome.Status != enrollmentRecoveryReady ||
		outcome.Configuration == "" {
		t.Fatalf("unexpected enrollment recovery outcome: %#v", outcome)
	}
	document, err := decodeEngineConfiguration(outcome.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if document.NodeID != fixture.document.NodeID ||
		document.NetworkID != fixture.document.NetworkID ||
		document.ControlPlaneOrigin != server.URL ||
		document.MonotonicCounter != 3 {
		t.Fatalf("unexpected recovered configuration: %#v", document)
	}
	if _, err := verifyEngineConfiguration(
		outcome.Configuration,
		fixture.privateKey,
	); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedEnrollmentRecoveryClassifiesRetryBoundary(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_recovery_boundary",
		netip.MustParseAddr("10.88.0.32"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.32:4242"),
	)
	agentSecret := bytes.Repeat([]byte{0x94}, 32)
	for _, test := range []struct {
		name       string
		statusCode int
		want       enrollmentRecoveryStatus
	}{
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       enrollmentRecoveryUnauthorized,
		},
		{
			name:       "server unavailable",
			statusCode: http.StatusServiceUnavailable,
			want:       enrollmentRecoveryDeferred,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			want:       enrollmentRecoveryDeferred,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(
				func(response http.ResponseWriter, request *http.Request) {
					response.WriteHeader(test.statusCode)
				},
			))
			defer server.Close()
			session := newEnrollmentSession(
				func() ([]byte, error) {
					t.Fatal("recovery created private authority")
					return nil, nil
				},
				func() ([]byte, error) {
					t.Fatal("recovery created agent authority")
					return nil, nil
				},
				server.Client(),
				func(_ context.Context, _ string) ([]netip.Addr, error) {
					return nil, nil
				},
				func() time.Time { return now },
			)
			session.loadExistingPrivateKey = func() ([]byte, error) {
				return append([]byte(nil), fixture.privateKey...), nil
			}
			session.loadExistingAgentSecret = func() ([]byte, error) {
				return append([]byte(nil), agentSecret...), nil
			}
			raw, err := session.Recover(server.URL, 4)
			if err != nil {
				t.Fatal(err)
			}
			var outcome enrollmentRecoveryOutcome
			if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
				t.Fatal(err)
			}
			if outcome.Schema != enrollmentRecoveryV1 ||
				outcome.Status != test.want ||
				outcome.Configuration != "" {
				t.Fatalf("unexpected recovery boundary: %#v", outcome)
			}
		})
	}
}

func TestExtensionEnrollmentRetriesOnlyAmbiguousIdenticalRequest(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_2",
		netip.MustParseAddr("10.88.0.8"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.10:4242"),
	)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))
	agentSecret := bytes.Repeat([]byte{0x74}, 32)
	bundle := enrollmentBundleFromFixture(fixture, now)
	var bodies [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			switch request.URL.Path {
			case "/api/v1/enroll/preflight":
				writeEnrollmentTestJSON(t, response, enrollmentPreflight{
					Schema:              enrollmentPreflightV1,
					TargetRole:          "member",
					NetworkCIDR:         "10.88.0.0/24",
					LighthouseEndpoints: []string{"192.0.2.10:4242"},
					TokenExpiresAt:      now.Add(10 * time.Minute),
				})
			case "/api/v1/enroll":
				bodies = append(bodies, readEnrollmentTestBody(t, request))
				if len(bodies) == 1 {
					http.Error(response, "ambiguous", http.StatusBadGateway)
					return
				}
				writeEnrollmentTestJSON(t, response, bundle)
			default:
				http.NotFound(response, request)
			}
		},
	))
	defer server.Close()
	session := newEnrollmentSession(
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
	if _, err := session.Enroll(server.URL, token, 2); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("ambiguous enrollment did not replay the identical request")
	}
}

func TestExtensionEnrollmentRejectsUnsafeOriginsAndTamperedBundle(
	t *testing.T,
) {
	for _, origin := range []string{
		"http://mesh.example",
		"https://user@mesh.example",
		"https://mesh.example/path",
		"https://MESH.example",
	} {
		if _, err := normalizeEnrollmentOrigin(origin); err == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}

	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_3",
		netip.MustParseAddr("10.88.0.9"),
		4242,
		false,
		netip.MustParseAddrPort("192.0.2.11:4242"),
	)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x75}, 32))
	bundle := enrollmentBundleFromFixture(fixture, now)
	bundle.Config += "# tampered\n"
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			if request.URL.Path == "/api/v1/enroll/preflight" {
				writeEnrollmentTestJSON(t, response, enrollmentPreflight{
					Schema:              enrollmentPreflightV1,
					TargetRole:          "member",
					NetworkCIDR:         "10.88.0.0/24",
					LighthouseEndpoints: []string{"192.0.2.11:4242"},
					TokenExpiresAt:      now.Add(10 * time.Minute),
				})
				return
			}
			writeEnrollmentTestJSON(t, response, bundle)
		},
	))
	defer server.Close()
	session := newEnrollmentSession(
		func() ([]byte, error) {
			return append([]byte(nil), fixture.privateKey...), nil
		},
		func() ([]byte, error) {
			return bytes.Repeat([]byte{0x76}, 32), nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
		func() time.Time { return now },
	)
	if _, err := session.Enroll(server.URL, token, 1); err == nil {
		t.Fatal("accepted a tampered enrollment bundle")
	}
}

func TestExtensionEnrollmentResolvesPreflightBeforeCreatingOrConsumingIdentity(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	enrollmentRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			switch request.URL.Path {
			case "/api/v1/enroll/preflight":
				writeEnrollmentTestJSON(t, response, enrollmentPreflight{
					Schema:              enrollmentPreflightV1,
					TargetRole:          "member",
					NetworkCIDR:         "10.88.0.0/24",
					LighthouseEndpoints: []string{"lh.example:4242"},
					TokenExpiresAt:      now.Add(10 * time.Minute),
				})
			case "/api/v1/enroll":
				enrollmentRequests++
				http.Error(response, "must not consume", http.StatusInternalServerError)
			default:
				http.NotFound(response, request)
			}
		},
	))
	defer server.Close()

	privateLoads := 0
	agentLoads := 0
	session := newEnrollmentSession(
		func() ([]byte, error) {
			privateLoads++
			return nil, nil
		},
		func() ([]byte, error) {
			agentLoads++
			return nil, nil
		},
		server.Client(),
		func(_ context.Context, host string) ([]netip.Addr, error) {
			if host != "lh.example" {
				t.Fatalf("unexpected preflight DNS host %q", host)
			}
			return nil, context.DeadlineExceeded
		},
		func() time.Time { return now },
	)
	if _, err := session.Enroll(server.URL, token, 1); err == nil ||
		!strings.Contains(err.Error(), "preflight lighthouse DNS") {
		t.Fatalf("preflight DNS error=%v", err)
	}
	if privateLoads != 0 || agentLoads != 0 || enrollmentRequests != 0 {
		t.Fatalf(
			"failed preflight crossed identity/consume boundary: private=%d agent=%d enroll=%d",
			privateLoads,
			agentLoads,
			enrollmentRequests,
		)
	}
}

func TestExtensionEnrollmentContainsUnexpectedNativeBoundaryPanic(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x78}, 32))
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Cache-Control", "no-store")
			if request.URL.Path != "/api/v1/enroll/preflight" {
				t.Errorf("unexpected request path %q", request.URL.Path)
				http.NotFound(response, request)
				return
			}
			writeEnrollmentTestJSON(t, response, enrollmentPreflight{
				Schema:              enrollmentPreflightV1,
				TargetRole:          "member",
				NetworkCIDR:         "10.88.0.0/24",
				LighthouseEndpoints: []string{"panic.example:4242"},
				TokenExpiresAt:      now.Add(10 * time.Minute),
			})
		},
	))
	defer server.Close()

	session := newEnrollmentSession(
		func() ([]byte, error) {
			t.Fatal("panic containment crossed the identity boundary")
			return nil, nil
		},
		func() ([]byte, error) {
			t.Fatal("panic containment crossed the agent boundary")
			return nil, nil
		},
		server.Client(),
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			panic("untrusted resolver panic must not terminate the app")
		},
		func() time.Time { return now },
	)
	document, err := session.Enroll(server.URL, token, 1)
	if document != "" ||
		err == nil ||
		err.Error() != "iOS enrollment processing failed safely" {
		t.Fatalf("panic result document=%q error=%v", document, err)
	}
}

func TestInterruptedEnrollmentContainsUnexpectedNativeBoundaryPanic(
	t *testing.T,
) {
	session := &EnrollmentSession{
		loadExistingPrivateKey: func() ([]byte, error) {
			panic("existing Keychain boundary panic must not terminate the app")
		},
		loadExistingAgentSecret: func() ([]byte, error) {
			t.Fatal("panic containment crossed the agent boundary")
			return nil, nil
		},
		httpClient: &http.Client{},
		resolve: func(
			_ context.Context,
			_ string,
		) ([]netip.Addr, error) {
			return nil, nil
		},
		now: time.Now,
	}
	document, err := session.Recover("https://mesh.example", 1)
	if document != "" ||
		err == nil ||
		err.Error() != "iOS enrollment processing failed safely" {
		t.Fatalf("panic result document=%q error=%v", document, err)
	}
}

func TestSignedNativeDNSPolicyBindsCertificateAndRejectsAmbiguity(
	t *testing.T,
) {
	policy := signedNativeDNSPolicy{
		Schema:       nativeDNSPolicyV1,
		LocalIP:      "10.88.0.7",
		NetworkCIDR:  "10.88.0.0/24",
		SearchDomain: "mesh.example",
		Resolvers: []signedNativeDNSResolver{
			{IP: "10.88.0.2", Port: 53},
			{IP: "10.88.0.3", Port: 53},
		},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	line := nativeDNSPolicyPrefix +
		base64.RawURLEncoding.EncodeToString(raw) +
		"\n"
	servers, err := signedDNSServers(
		line,
		netip.MustParsePrefix("10.88.0.7/24"),
	)
	if err != nil ||
		len(servers) != 2 ||
		servers[0] != "10.88.0.2" ||
		servers[1] != "10.88.0.3" {
		t.Fatalf("signed DNS servers=%v err=%v", servers, err)
	}
	if _, err := signedDNSServers(
		line,
		netip.MustParsePrefix("10.88.0.8/24"),
	); err == nil {
		t.Fatal("accepted native DNS policy for another certificate address")
	}
	if _, _, err := parseSignedNativeDNSPolicy(line + line); err == nil {
		t.Fatal("accepted duplicate native DNS policy")
	}
	policy.SearchDomain = "mesh.local"
	raw, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseSignedNativeDNSPolicy(
		nativeDNSPolicyPrefix +
			base64.RawURLEncoding.EncodeToString(raw) +
			"\n",
	); err == nil {
		t.Fatal("accepted reserved native DNS search domain")
	}
}

func enrollmentBundleFromFixture(
	fixture engineTestFixture,
	now time.Time,
) enrollmentBundle {
	document := fixture.document
	return enrollmentBundle{
		NodeID:    document.NodeID,
		NetworkID: document.NetworkID,
		Node: enrollmentNode{
			ID:                        document.NodeID,
			NetworkID:                 document.NetworkID,
			Name:                      document.NodeID,
			IP:                        document.NetworkSettings.Addresses[0].Address,
			Groups:                    []string{},
			Role:                      "member",
			Status:                    "active",
			CertificateGeneration:     int64(document.CertificateGeneration),
			AgentCredentialGeneration: 1,
			CreatedAt:                 now.Add(-time.Minute),
			EnrolledAt:                pointerToTime(now),
		},
		Certificate:               document.Nebula.Certificate,
		CA:                        document.Nebula.CA,
		Config:                    document.Nebula.Config,
		ConfigRevision:            int64(document.ConfigRevision),
		CertificateExpiresAt:      mustParseEngineTestTimeValue(document.Nebula.CertificateExpiresAt),
		CertificateRenewAfter:     mustParseEngineTestTimeValue(document.Nebula.CertificateRenewAfter),
		AgentCredentialExpiresAt:  now.Add(30 * 24 * time.Hour),
		AgentCredentialGeneration: 1,
		ConfigIssuedAt:            mustParseEngineTestTimeValue(document.Nebula.ConfigIssuedAt),
		ConfigSHA256:              document.ConfigDigest,
		CACertificateSHA256:       document.Nebula.CACertificateSHA256,
		CertificateFingerprint:    document.CertificateFingerprint,
		CertificateGeneration:     int64(document.CertificateGeneration),
		PublicKeyHash:             document.Nebula.PublicKeyHash,
		ConfigSignature:           document.Nebula.ConfigSignature,
		ConfigSigningPublicKey:    document.Nebula.ConfigSigningPublicKey,
	}
}

func pointerToTime(value time.Time) *time.Time {
	return &value
}

func mustParseEngineTestTimeValue(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func writeEnrollmentTestJSON(
	t *testing.T,
	response http.ResponseWriter,
	value any,
) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Error(err)
	}
}

func readEnrollmentTestBody(
	t *testing.T,
	request *http.Request,
) []byte {
	t.Helper()
	defer request.Body.Close()
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

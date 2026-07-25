package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestOIDCMemberCanCreateOnlyFixedPolicySelfEnrollment(t *testing.T) {
	fixture := newSelfEnrollmentFixture(t)
	session, csrf := createRBACSession(
		t, fixture.store, fixture.config, fixture.fingerprint,
		fixture.now, "mobile-member", "mesh-members",
	)
	response := rbacRequest(
		t, fixture.server.Client(), http.MethodPost, fixture.endpoint,
		bytes.NewBufferString(`{"name":"ios-7f3a9c2d"}`),
		session, csrf, fixture.publicURL, "",
	)
	var created control.CreatedNode
	decodeRBACResponse(t, response, http.StatusCreated, &created)
	if created.Node.Name != "ios-7f3a9c2d" || created.Node.Role != "member" ||
		created.Node.Site != "mobile" || created.Node.FailureDomain != "unassigned" ||
		strings.Join(created.Node.Groups, ",") != "all,members" ||
		created.Node.Status != "pending" || !control.ValidBearerToken(created.EnrollmentToken) ||
		created.ExpiresAt.Sub(created.Node.CreatedAt) < 29*time.Minute ||
		created.ExpiresAt.Sub(created.Node.CreatedAt) > 31*time.Minute {
		t.Fatalf("self enrollment escaped fixed policy: %#v", created)
	}
	preflight := postSelfEnrollmentPreflight(
		t, fixture.server.Client(), fixture.publicURL, created.EnrollmentToken,
	)
	if preflight.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(preflight.Body)
		_ = preflight.Body.Close()
		t.Fatalf("returned enrollment token failed preflight: status=%d body=%s", preflight.StatusCode, raw)
	}
	_ = preflight.Body.Close()

	retry := rbacRequest(
		t, fixture.server.Client(), http.MethodPost, fixture.endpoint,
		bytes.NewBufferString(`{"name":"ios-7f3a9c2d"}`),
		session, csrf, fixture.publicURL, "",
	)
	var reissued control.CreatedNode
	decodeRBACResponse(t, retry, http.StatusCreated, &reissued)
	if reissued.Node.ID != created.Node.ID ||
		reissued.EnrollmentToken == created.EnrollmentToken ||
		!control.ValidBearerToken(reissued.EnrollmentToken) {
		t.Fatalf("same-principal retry did not safely reissue: first=%#v retry=%#v", created, reissued)
	}
	oldPreflight := postSelfEnrollmentPreflight(
		t, fixture.server.Client(), fixture.publicURL, created.EnrollmentToken,
	)
	if oldPreflight.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(oldPreflight.Body)
		_ = oldPreflight.Body.Close()
		t.Fatalf("retry left first token usable: status=%d body=%s", oldPreflight.StatusCode, raw)
	}
	_ = oldPreflight.Body.Close()

	otherSession, otherCSRF := createRBACSession(
		t, fixture.store, fixture.config, fixture.fingerprint,
		fixture.now, "other-mobile-member", "mesh-members",
	)
	otherRetry := rbacRequest(
		t, fixture.server.Client(), http.MethodPost, fixture.endpoint,
		bytes.NewBufferString(`{"name":"ios-7f3a9c2d"}`),
		otherSession, otherCSRF, fixture.publicURL, "",
	)
	decodeRBACResponse(t, otherRetry, http.StatusConflict, nil)
	reissuedPreflight := postSelfEnrollmentPreflight(
		t, fixture.server.Client(), fixture.publicURL,
		reissued.EnrollmentToken,
	)
	if reissuedPreflight.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(reissuedPreflight.Body)
		_ = reissuedPreflight.Body.Close()
		t.Fatalf("different-principal retry changed owner token: status=%d body=%s", reissuedPreflight.StatusCode, raw)
	}
	_ = reissuedPreflight.Body.Close()

	var decoded map[string]any
	raw, err := json.Marshal(reissued)
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded["enrollment_token"] == "" {
		t.Fatalf("one-time response omitted enrollment token: %s error=%v", raw, err)
	}
}

func TestSelfEnrollmentRejectsViewerLegacyAndPrivilegeFields(t *testing.T) {
	fixture := newSelfEnrollmentFixture(t)
	memberSession, memberCSRF := createRBACSession(
		t, fixture.store, fixture.config, fixture.fingerprint,
		fixture.now, "member-reject", "mesh-members",
	)
	viewerSession, viewerCSRF := createRBACSession(
		t, fixture.store, fixture.config, fixture.fingerprint,
		fixture.now, "viewer-reject", "mesh-viewers",
	)

	tests := []struct {
		name    string
		body    string
		session string
		csrf    string
		bearer  string
		query   string
		want    int
	}{
		{name: "viewer lacks permission", body: `{"name":"viewer-ios"}`, session: viewerSession, csrf: viewerCSRF, want: http.StatusForbidden},
		{name: "legacy bearer is not personal OIDC", body: `{"name":"legacy-ios"}`, bearer: fixture.adminToken, want: http.StatusForbidden},
		{name: "privilege fields rejected", body: `{"name":"member-ios","role":"lighthouse"}`, session: memberSession, csrf: memberCSRF, want: http.StatusBadRequest},
		{name: "query rejected", body: `{"name":"member-ios"}`, session: memberSession, csrf: memberCSRF, query: "?role=lighthouse", want: http.StatusBadRequest},
		{name: "invalid name rejected", body: `{"name":"Billy's iPhone"}`, session: memberSession, csrf: memberCSRF, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := rbacRequest(
				t, fixture.server.Client(), http.MethodPost,
				fixture.endpoint+test.query, bytes.NewBufferString(test.body),
				test.session, test.csrf, fixture.publicURL, test.bearer,
			)
			decodeRBACResponse(t, response, test.want, nil)
		})
	}
	nodes, err := fixture.service.Nodes(fixture.network.ID)
	if err != nil || len(nodes) != 0 {
		t.Fatalf("rejected self enrollments changed inventory: nodes=%#v error=%v", nodes, err)
	}
}

type selfEnrollmentFixture struct {
	now         time.Time
	publicURL   string
	adminToken  string
	config      identity.IdentityConfig
	fingerprint string
	store       identity.SessionStore
	service     *control.Service
	network     control.Network
	server      *httptest.Server
	endpoint    string
}

func newSelfEnrollmentFixture(t *testing.T) selfEnrollmentFixture {
	t.Helper()
	now := time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC)
	server := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + server.Listener.Addr().String()
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeHybrid, PublicURL: publicURL, LegacyBearer: true,
		OIDC: &identity.OIDCConfig{
			Issuer: "https://id.example.test/tenant", ClientID: "mesh-test",
			ClientSecretFile: "/run/secrets/mesh-test", Scopes: []string{"openid"},
			GroupsClaim: "groups", AllowedSigningAlgs: []string{"RS256"},
			Admins: []identity.AdminSelector{{Kind: "group", Value: "mesh-admins"}},
			RoleBindings: []identity.RoleBinding{
				{Role: identity.RoleMember, Selector: identity.AdminSelector{Kind: "group", Value: "mesh-members"}},
				{Role: identity.RoleViewer, Selector: identity.AdminSelector{Kind: "group", Value: "mesh-viewers"}},
			},
			RequiredAMRAll: []string{"otp"}, MaxAuthenticationAge: 15 * time.Minute,
		},
	}).Normalized(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := config.PolicyFingerprint(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("B", 43)
	service := testSessionControlService(t, t.TempDir())
	ensureSecurityGroupSchemaForHTTPTest(t, service, adminToken)
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{
		Name: "mobile-test", CIDR: "10.242.0.0/24", CertificateTTL: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.OpenFileStore(filepath.Join(t.TempDir(), "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	api, err := New(service, Options{
		IdentityConfig: config, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: true},
		PolicyFingerprint: fingerprint, SessionStore: store, OIDCAuthenticator: rbacOIDCStub{},
		AdminToken: adminToken, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = api.Handler()
	server.Start()
	t.Cleanup(server.Close)
	return selfEnrollmentFixture{
		now: now, publicURL: publicURL, adminToken: adminToken,
		config: config, fingerprint: fingerprint, store: store,
		service: service, network: network, server: server,
		endpoint: publicURL + "/api/v1/networks/" + network.ID + "/self-enrollment",
	}
}

func postSelfEnrollmentPreflight(
	t *testing.T,
	client *http.Client,
	origin string,
	token string,
) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost, origin+"/api/v1/enroll/preflight", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

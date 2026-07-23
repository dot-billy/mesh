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

type rbacOIDCStub struct{}

func (rbacOIDCStub) Start(context.Context, string) (identity.OIDCStartResult, error) {
	return identity.OIDCStartResult{}, identity.ErrOIDCUnavailable
}

func (rbacOIDCStub) Complete(context.Context, string, string, string) (identity.OIDCCompleteResult, error) {
	return identity.OIDCCompleteResult{}, identity.ErrOIDCUnavailable
}

func (rbacOIDCStub) ConsumeAuthorizationError(context.Context, string, string) (string, error) {
	return "", identity.ErrOIDCUnavailable
}

func TestHTTPRBACEnforcesViewerOperatorAndAdminBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	testServer := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + testServer.Listener.Addr().String()
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeHybrid, PublicURL: publicURL, LegacyBearer: true,
		OIDC: &identity.OIDCConfig{
			Issuer: "https://id.example.test/tenant", ClientID: "mesh-test", ClientSecretFile: "/run/secrets/mesh-test",
			Scopes: []string{"openid"}, GroupsClaim: "groups", AllowedSigningAlgs: []string{"RS256"},
			Admins: []identity.AdminSelector{{Kind: "group", Value: "mesh-admins"}},
			RoleBindings: []identity.RoleBinding{
				{Role: identity.RoleViewer, Selector: identity.AdminSelector{Kind: "group", Value: "mesh-viewers"}},
				{Role: identity.RoleOperator, Selector: identity.AdminSelector{Kind: "group", Value: "mesh-operators"}},
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
	service := testSessionControlService(t, t.TempDir())
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.OpenFileStore(filepath.Join(t.TempDir(), "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	adminToken := strings.Repeat("A", 43)
	api, err := New(service, Options{
		IdentityConfig: config, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: true},
		PolicyFingerprint: fingerprint, SessionStore: store, OIDCAuthenticator: rbacOIDCStub{},
		AdminToken: adminToken, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	testServer.Config.Handler = api.Handler()
	testServer.Start()
	defer testServer.Close()

	viewerSession, viewerCSRF := createRBACSession(t, store, config, fingerprint, now, "viewer", "mesh-viewers")
	operatorSession, operatorCSRF := createRBACSession(t, store, config, fingerprint, now, "operator", "mesh-operators")

	response := rbacRequest(t, testServer.Client(), http.MethodGet, publicURL+"/api/v1/session", nil, viewerSession, "", publicURL, "")
	var current sessionResponse
	decodeRBACResponse(t, response, http.StatusOK, &current)
	if current.Role != identity.RoleViewer || !identity.RoleAllows(current.Role, identity.PermissionNetworksRead) || len(current.Permissions) != 2 {
		t.Fatalf("viewer session access=%#v", current)
	}

	response = rbacRequest(t, testServer.Client(), http.MethodGet, publicURL+"/api/v1/networks", nil, viewerSession, "", publicURL, "")
	decodeRBACResponse(t, response, http.StatusOK, nil)
	response = rbacRequest(t, testServer.Client(), http.MethodPost, publicURL+"/api/v1/networks", bytes.NewBufferString(`{"name":"viewer-denied","cidr":"10.90.0.0/24"}`), viewerSession, viewerCSRF, publicURL, "")
	decodeRBACResponse(t, response, http.StatusForbidden, nil)

	response = rbacRequest(t, testServer.Client(), http.MethodPost, publicURL+"/api/v1/networks", bytes.NewBufferString(`{"name":"operator-network","cidr":"10.91.0.0/24","certificate_ttl_hours":24}`), operatorSession, operatorCSRF, publicURL, "")
	var network control.Network
	decodeRBACResponse(t, response, http.StatusCreated, &network)
	if network.ID == "" {
		t.Fatal("operator network creation omitted an ID")
	}
	response = rbacRequest(t, testServer.Client(), http.MethodPost, publicURL+"/api/v1/networks/"+network.ID+"/retire", bytes.NewBufferString(`{}`), operatorSession, operatorCSRF, publicURL, "")
	decodeRBACResponse(t, response, http.StatusForbidden, nil)
	response = rbacRequest(t, testServer.Client(), http.MethodGet, publicURL+"/api/v1/sessions", nil, operatorSession, "", publicURL, "")
	decodeRBACResponse(t, response, http.StatusForbidden, nil)

	response = rbacRequest(t, testServer.Client(), http.MethodGet, publicURL+"/api/v1/sessions", nil, "", "", publicURL, adminToken)
	decodeRBACResponse(t, response, http.StatusOK, nil)
	response = rbacRequest(t, testServer.Client(), http.MethodGet, publicURL+"/api/v1/session", nil, "", "", publicURL, adminToken)
	current = sessionResponse{}
	decodeRBACResponse(t, response, http.StatusOK, &current)
	if current.Role != identity.RoleAdmin || !identity.RoleAllows(current.Role, identity.PermissionNetworksSecurity) || !identity.RoleAllows(current.Role, identity.PermissionIdentityManage) {
		t.Fatalf("legacy bearer access=%#v", current)
	}

	networks, err := service.Networks()
	if err != nil || len(networks) != 1 || networks[0].ID != network.ID {
		t.Fatalf("denied writes changed network inventory: networks=%#v error=%v", networks, err)
	}
}

func createRBACSession(t *testing.T, store identity.SessionStore, config identity.IdentityConfig, fingerprint string, now time.Time, label, group string) (string, string) {
	t.Helper()
	principal, err := identity.NewOIDCPrincipal(config.OIDC.Issuer, label+"-subject", label, "", []string{group}, "mfa", []string{"otp"}, now)
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, err := identity.NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfToken, err := identity.NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateSession(context.Background(), identity.CreateSessionInput{
		ID: "session_" + label, Token: sessionToken, CSRFToken: csrfToken, Principal: principal,
		PolicyFingerprint: fingerprint, AuthMethod: "oidc", CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return sessionToken, csrfToken
}

func rbacRequest(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, sessionToken, csrfToken, origin, bearer string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if sessionToken != "" {
		request.AddCookie(&http.Cookie{Name: "mesh_session", Value: sessionToken})
	}
	if csrfToken != "" {
		request.AddCookie(&http.Cookie{Name: "mesh_csrf", Value: csrfToken})
		request.Header.Set("X-Mesh-CSRF", csrfToken)
		request.Header.Set("Origin", origin)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeRBACResponse(t *testing.T, response *http.Response, wantStatus int, target any) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("response status=%d, want %d: %s", response.StatusCode, wantStatus, raw)
	}
	if target != nil {
		if err := json.NewDecoder(response.Body).Decode(target); err != nil {
			t.Fatal(err)
		}
	}
}

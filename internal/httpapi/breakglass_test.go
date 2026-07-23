package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mesh/internal/identity"
)

func TestBreakGlassHTTPProvisionCutoverUseAndInventoryFloor(t *testing.T) {
	fakeOIDC := newFakeOIDCAuthenticator()
	service, store, baseConfig, hybridOptions := newOIDCHTTPOptions(t, fakeOIDC, false, nil)
	now := hybridOptions.Now()
	hybridConfig := baseConfig
	hybridConfig.BreakGlass.Enabled = true
	var err error
	hybridConfig, err = hybridConfig.Normalized(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hybridOptions.IdentityConfig = hybridConfig
	hybridOptions.PolicyFingerprint, err = hybridConfig.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hybridAPI, err := New(service, hybridOptions)
	if err != nil {
		t.Fatal(err)
	}

	first, firstCombined, err := identity.NewBreakGlassCredential()
	if err != nil {
		t.Fatal(err)
	}
	_, secondCombined, err := identity.NewBreakGlassCredential()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := now.Add(30 * 24 * time.Hour)
	register := func(code string, want int) []byte {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"code": code, "expires_at": expiresAt})
		request := httptest.NewRequest(http.MethodPost, hybridConfig.PublicURL+"/api/v1/break-glass-codes", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+hybridOptions.AdminToken)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		hybridAPI.Handler().ServeHTTP(response, request)
		if response.Code != want || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("register status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
		}
		return append([]byte(nil), response.Body.Bytes()...)
	}
	firstRegistration := register(firstCombined, http.StatusCreated)
	if bytes.Contains(firstRegistration, []byte(firstCombined)) || bytes.Contains(firstRegistration, []byte(first.Token)) || bytes.Contains(firstRegistration, []byte("token_hash")) {
		t.Fatalf("registration exposed recovery credential: %s", firstRegistration)
	}
	_ = register(firstCombined, http.StatusOK)
	_ = register(secondCombined, http.StatusCreated)

	listRequest := httptest.NewRequest(http.MethodGet, hybridConfig.PublicURL+"/api/v1/break-glass-codes", nil)
	listRequest.Header.Set("Authorization", "Bearer "+hybridOptions.AdminToken)
	listResponse := httptest.NewRecorder()
	hybridAPI.Handler().ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || bytes.Contains(listResponse.Body.Bytes(), []byte(firstCombined)) || bytes.Contains(listResponse.Body.Bytes(), []byte(first.Token)) || bytes.Contains(listResponse.Body.Bytes(), []byte("token_hash")) {
		t.Fatalf("unsafe recovery inventory status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var inventory breakGlassInventoryResponse
	if err := json.Unmarshal(listResponse.Body.Bytes(), &inventory); err != nil || inventory.MinimumUsableCodes != 2 || inventory.UsableCodes != 2 || len(inventory.Codes) != 2 {
		t.Fatalf("recovery inventory=%#v error=%v", inventory, err)
	}

	oidcOnly := hybridConfig
	oidcOnly.Mode, oidcOnly.LegacyBearer, oidcOnly.LegacyBrowserLogin = identity.ModeOIDC, false, false
	oidcOnly, err = oidcOnly.Normalized(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oidcOptions := hybridOptions
	oidcOptions.IdentityConfig = oidcOnly
	oidcOptions.AdminToken = ""
	oidcOptions.PolicyFingerprint, err = oidcOnly.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oidcAPI, err := New(service, oidcOptions)
	if err != nil {
		t.Fatalf("OIDC-only startup with two usable recovery codes: %v", err)
	}

	methodsResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(methodsResponse, httptest.NewRequest(http.MethodGet, oidcOnly.PublicURL+"/api/v1/auth/methods", nil))
	if methodsResponse.Code != http.StatusOK || !strings.Contains(methodsResponse.Body.String(), `"break_glass":true`) || !strings.Contains(methodsResponse.Body.String(), `"legacy_browser_login":false`) {
		t.Fatalf("auth methods status=%d body=%s", methodsResponse.Code, methodsResponse.Body.String())
	}
	bearerRequest := httptest.NewRequest(http.MethodGet, oidcOnly.PublicURL+"/api/v1/networks", nil)
	bearerRequest.Header.Set("Authorization", "Bearer "+hybridOptions.AdminToken)
	bearerResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(bearerResponse, bearerRequest)
	if bearerResponse.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC-only mode accepted legacy bearer: %d", bearerResponse.Code)
	}

	loginBody, _ := json.Marshal(map[string]string{"code": firstCombined})
	loginRequest := httptest.NewRequest(http.MethodPost, oidcOnly.PublicURL+"/api/v1/auth/break-glass", bytes.NewReader(loginBody))
	loginRequest.Header.Set("Origin", oidcOnly.PublicURL)
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	loginResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("recovery login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	var session sessionResponse
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Principal.Kind != identity.PrincipalBreakGlass || session.AuthMethod != "break_glass" || session.IdleExpiresAt == nil || session.AbsoluteExpiresAt == nil || session.IdleExpiresAt.Sub(now) != breakGlassIdleTTL || session.AbsoluteExpiresAt.Sub(now) != breakGlassAbsoluteTTL {
		t.Fatalf("recovery session=%#v", session)
	}
	cookies := map[string]*http.Cookie{}
	for _, cookie := range loginResponse.Result().Cookies() {
		cookies[cookie.Name] = cookie
	}
	if cookies["__Host-mesh_session"] == nil || cookies["__Host-mesh_csrf"] == nil {
		t.Fatalf("recovery session cookies=%#v", cookies)
	}

	readRequest := httptest.NewRequest(http.MethodGet, oidcOnly.PublicURL+"/api/v1/networks", nil)
	readRequest.AddCookie(cookies["__Host-mesh_session"])
	readResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(readResponse, readRequest)
	if readResponse.Code != http.StatusOK {
		t.Fatalf("recovery session could not administer the control plane: %d %s", readResponse.Code, readResponse.Body.String())
	}
	mutationRequest := httptest.NewRequest(http.MethodPost, oidcOnly.PublicURL+"/api/v1/networks", strings.NewReader(`{"name":"recovery-administered","cidr":"10.92.0.0/24"}`))
	mutationRequest.AddCookie(cookies["__Host-mesh_session"])
	mutationRequest.AddCookie(cookies["__Host-mesh_csrf"])
	mutationRequest.Header.Set("Content-Type", "application/json")
	addCookieCSRF(mutationRequest, oidcOnly.PublicURL, cookies["__Host-mesh_csrf"].Value)
	mutationResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(mutationResponse, mutationRequest)
	if mutationResponse.Code != http.StatusCreated {
		t.Fatalf("recovery session could not mutate the control plane: %d %s", mutationResponse.Code, mutationResponse.Body.String())
	}

	forbiddenCode, forbiddenCombined, err := identity.NewBreakGlassCredential()
	if err != nil || forbiddenCode.ID == "" {
		t.Fatal(err)
	}
	forbiddenBody, _ := json.Marshal(map[string]any{"code": forbiddenCombined, "expires_at": expiresAt})
	forbiddenRequest := httptest.NewRequest(http.MethodPost, oidcOnly.PublicURL+"/api/v1/break-glass-codes", bytes.NewReader(forbiddenBody))
	forbiddenRequest.AddCookie(cookies["__Host-mesh_session"])
	forbiddenRequest.AddCookie(cookies["__Host-mesh_csrf"])
	forbiddenRequest.Header.Set("Content-Type", "application/json")
	addCookieCSRF(forbiddenRequest, oidcOnly.PublicURL, cookies["__Host-mesh_csrf"].Value)
	forbiddenResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(forbiddenResponse, forbiddenRequest)
	if forbiddenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("recovery session minted a replacement code: %d %s", forbiddenResponse.Code, forbiddenResponse.Body.String())
	}

	replayResponse := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, oidcOnly.PublicURL+"/api/v1/auth/break-glass", bytes.NewReader(loginBody))
	replayRequest.Header.Set("Origin", oidcOnly.PublicURL)
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	oidcAPI.Handler().ServeHTTP(replayResponse, replayRequest)
	malformedBody, _ := json.Marshal(map[string]string{"code": "not-a-code"})
	malformedRequest := httptest.NewRequest(http.MethodPost, oidcOnly.PublicURL+"/api/v1/auth/break-glass", bytes.NewReader(malformedBody))
	malformedRequest.Header.Set("Origin", oidcOnly.PublicURL)
	malformedRequest.Header.Set("Content-Type", "application/json")
	malformedRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	malformedResponse := httptest.NewRecorder()
	oidcAPI.Handler().ServeHTTP(malformedResponse, malformedRequest)
	if replayResponse.Code != http.StatusUnauthorized || malformedResponse.Code != http.StatusUnauthorized || replayResponse.Body.String() != malformedResponse.Body.String() {
		t.Fatalf("non-uniform recovery failures replay=%d %q malformed=%d %q", replayResponse.Code, replayResponse.Body.String(), malformedResponse.Code, malformedResponse.Body.String())
	}

	breakGlassStore := store.(identity.BreakGlassStore)
	usable, err := breakGlassStore.CountUsableBreakGlassCodes(loginRequest.Context(), now)
	if err != nil || usable != 1 {
		t.Fatalf("usable recovery codes after one use=%d error=%v", usable, err)
	}
	postUseInventoryRequest := httptest.NewRequest(http.MethodGet, oidcOnly.PublicURL+"/api/v1/break-glass-codes", nil)
	postUseInventoryRequest.Header.Set("Authorization", "Bearer "+hybridOptions.AdminToken)
	postUseInventoryResponse := httptest.NewRecorder()
	hybridAPI.Handler().ServeHTTP(postUseInventoryResponse, postUseInventoryRequest)
	if postUseInventoryResponse.Code != http.StatusOK {
		t.Fatalf("hybrid recovery posture status=%d body=%s", postUseInventoryResponse.Code, postUseInventoryResponse.Body.String())
	}
	inventory = breakGlassInventoryResponse{}
	if err := json.Unmarshal(postUseInventoryResponse.Body.Bytes(), &inventory); err != nil || inventory.MinimumUsableCodes != 2 || inventory.UsableCodes != 1 {
		t.Fatalf("below-floor recovery posture=%#v error=%v", inventory, err)
	}
	if _, err := New(service, oidcOptions); err == nil || !strings.Contains(err.Error(), "at least 2 usable") {
		t.Fatalf("OIDC-only startup below inventory floor returned %v", err)
	}
}

func TestBreakGlassDashboardGeneratesAndScrubsBrowserCustody(t *testing.T) {
	script, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"globalThis.crypto.getRandomValues", "new Uint8Array(32)", "mesh-bg-v1.${id}",
		"/api/v1/auth/break-glass", "/api/v1/break-glass-codes", "state.recoveryDraft = null",
		"scrubRecoveryDraft();", "Registration confirmation was not received", "approved secure location",
	} {
		if !bytes.Contains(script, []byte(required)) && !bytes.Contains(html, []byte(required)) {
			t.Fatalf("recovery dashboard is missing %q", required)
		}
	}
	for _, required := range []string{
		`id="break-glass-login-form" class="hidden"`, `autocomplete="one-time-code"`,
		`id="recovery-codes-panel"`, `id="recovery-code-dialog"`, `id="recovery-code-plaintext"`,
		`id="recovery-code-stored"`, `id="retry-recovery-registration"`,
	} {
		if !bytes.Contains(html, []byte(required)) {
			t.Fatalf("recovery dashboard HTML is missing %q", required)
		}
	}
	if bytes.Contains(script, []byte("localStorage")) {
		t.Fatal("dashboard must not persist recovery plaintext in local storage")
	}
}

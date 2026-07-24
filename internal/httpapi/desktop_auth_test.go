package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestDesktopAuthorizationHTTPFlowCreatesOneNormalSession(t *testing.T) {
	current := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	adminToken := strings.Repeat("D", 43)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	server, _, _ := newTestHTTPServer(t, testSessionControlService(t, t.TempDir()), adminToken, false, logger, func() time.Time {
		return current
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	desktopClient := &http.Client{Transport: server.Client().Transport, Jar: jar}
	start := startDesktopAuthorization(t, desktopClient, server.URL)
	if !strings.HasPrefix(start.RequestID, "desktop_") || !identity.ValidOpaqueToken(start.PollSecret) ||
		start.IntervalSeconds != 5 || !start.ExpiresAt.Equal(current.Add(5*time.Minute)) {
		t.Fatalf("invalid start response: %#v", start)
	}
	verification, err := url.Parse(start.VerificationURL)
	if err != nil || verification.Scheme+"://"+verification.Host != server.URL ||
		verification.Path != "/" ||
		verification.Query().Get("mesh_desktop_request") != start.RequestID ||
		strings.Contains(start.VerificationURL, start.PollSecret) {
		t.Fatalf("unsafe verification URL %q error=%v", start.VerificationURL, err)
	}

	pendingResponse := completeDesktopAuthorization(t, desktopClient, server.URL, start.RequestID, start.PollSecret)
	var pending desktopAuthorizationCompletionResponse
	decodeDesktopHTTPResponse(t, pendingResponse, http.StatusOK, &pending)
	if pending.State != string(identity.DesktopAuthorizationPending) || pending.Session != nil {
		t.Fatalf("pending response=%#v", pending)
	}
	tooSoon := completeDesktopAuthorization(t, desktopClient, server.URL, start.RequestID, start.PollSecret)
	if tooSoon.Header.Get("Retry-After") != "5" {
		t.Fatalf("early poll retry-after=%q", tooSoon.Header.Get("Retry-After"))
	}
	decodeDesktopHTTPResponse(t, tooSoon, http.StatusTooManyRequests, nil)

	browserClient, _, browserCookies := loginHTTPClient(t, server, adminToken)
	unauthenticatedDecision := desktopDecisionRequest(t, server.URL, start.RequestID, "approve")
	unauthenticatedDecision.Header.Set("Origin", server.URL)
	unauthenticatedDecision.Header.Set("Sec-Fetch-Site", "same-origin")
	unauthenticatedResponse, err := server.Client().Do(unauthenticatedDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, unauthenticatedResponse, http.StatusUnauthorized, nil)

	bearerDecision := desktopDecisionRequest(t, server.URL, start.RequestID, "approve")
	bearerDecision.Header.Set("Authorization", "Bearer "+adminToken)
	bearerDecision.Header.Set("Origin", server.URL)
	bearerDecision.Header.Set("Sec-Fetch-Site", "same-origin")
	bearerResponse, err := server.Client().Do(bearerDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, bearerResponse, http.StatusForbidden, nil)

	duplicateDecision := desktopDecisionRequest(t, server.URL, start.RequestID, "approve")
	duplicateBody := `{"decision":"approve","decision":"approve"}`
	duplicateDecision.Body = io.NopCloser(strings.NewReader(duplicateBody))
	duplicateDecision.ContentLength = int64(len(duplicateBody))
	addDesktopBrowserProof(duplicateDecision, browserCookies["mesh_csrf"].Value)
	duplicateResponse, err := browserClient.Do(duplicateDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, duplicateResponse, http.StatusBadRequest, nil)

	current = current.Add(time.Second)
	decision := desktopDecisionRequest(t, server.URL, start.RequestID, "approve")
	addDesktopBrowserProof(decision, browserCookies["mesh_csrf"].Value)
	decisionResponse, err := browserClient.Do(decision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, decisionResponse, http.StatusNoContent, nil)
	idempotentDecision := desktopDecisionRequest(t, server.URL, start.RequestID, "approve")
	addDesktopBrowserProof(idempotentDecision, browserCookies["mesh_csrf"].Value)
	idempotentResponse, err := browserClient.Do(idempotentDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, idempotentResponse, http.StatusNoContent, nil)
	conflictingDecision := desktopDecisionRequest(t, server.URL, start.RequestID, "deny")
	addDesktopBrowserProof(conflictingDecision, browserCookies["mesh_csrf"].Value)
	conflictingResponse, err := browserClient.Do(conflictingDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, conflictingResponse, http.StatusConflict, nil)

	current = current.Add(4 * time.Second)
	authorizedResponse := completeDesktopAuthorization(t, desktopClient, server.URL, start.RequestID, start.PollSecret)
	var authorized desktopAuthorizationCompletionResponse
	raw := decodeDesktopHTTPResponse(t, authorizedResponse, http.StatusOK, &authorized)
	if authorized.State != "authorized" || authorized.Session == nil ||
		authorized.Session.Role != identity.RoleAdmin || authorized.Session.AuthMethod != "legacy_token" ||
		bytes.Contains(raw, []byte(start.PollSecret)) {
		t.Fatalf("authorized response=%#v body=%s", authorized, raw)
	}
	cookies := map[string]*http.Cookie{}
	for _, cookie := range authorizedResponse.Cookies() {
		cookies[cookie.Name] = cookie
	}
	assertCookieContract(t, cookies, *authorized.Session, false)

	replayed := completeDesktopAuthorization(t, desktopClient, server.URL, start.RequestID, start.PollSecret)
	decodeDesktopHTTPResponse(t, replayed, http.StatusUnauthorized, nil)

	sessionHTTPResponse, err := desktopClient.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	var currentSession sessionResponse
	decodeDesktopHTTPResponse(t, sessionHTTPResponse, http.StatusOK, &currentSession)
	if currentSession.SessionID != authorized.Session.SessionID {
		t.Fatalf("desktop session ID=%q want %q", currentSession.SessionID, authorized.Session.SessionID)
	}
	if strings.Contains(logs.String(), start.PollSecret) {
		t.Fatal("request logging exposed the desktop poll secret")
	}
}

func TestDesktopAuthorizationHTTPFlowCrossesServerInstancesThroughSharedStore(t *testing.T) {
	current := time.Date(2026, 7, 23, 13, 0, 0, 0, time.UTC)
	adminToken := strings.Repeat("S", 43)
	masterKey := make([]byte, 32)
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.OpenFileStore(filepath.Join(t.TempDir(), "identity.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service := testSessionControlService(t, t.TempDir())
	startServer := newSharedDesktopHTTPInstance(t, service, store, adminToken, masterKey, func() time.Time { return current })
	decisionServer := newSharedDesktopHTTPInstance(t, service, store, adminToken, masterKey, func() time.Time { return current })
	completionServer := newSharedDesktopHTTPInstance(t, service, store, adminToken, masterKey, func() time.Time { return current })

	start := startDesktopAuthorization(t, startServer.Client(), startServer.URL)
	browserClient, _, browserCookies := loginHTTPClient(t, decisionServer, adminToken)
	current = current.Add(time.Second)
	decision := desktopDecisionRequest(t, decisionServer.URL, start.RequestID, "approve")
	addDesktopBrowserProof(decision, browserCookies["mesh_csrf"].Value)
	response, err := browserClient.Do(decision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, response, http.StatusNoContent, nil)

	current = current.Add(4 * time.Second)
	response = completeDesktopAuthorization(t, completionServer.Client(), completionServer.URL, start.RequestID, start.PollSecret)
	var completed desktopAuthorizationCompletionResponse
	decodeDesktopHTTPResponse(t, response, http.StatusOK, &completed)
	if completed.State != "authorized" || completed.Session == nil {
		t.Fatalf("cross-server completion=%#v", completed)
	}
	replay := completeDesktopAuthorization(t, startServer.Client(), startServer.URL, start.RequestID, start.PollSecret)
	decodeDesktopHTTPResponse(t, replay, http.StatusUnauthorized, nil)
}

func TestDesktopAuthorizationHTTPRejectsUnsafeRequestsAndReportsTerminalStates(t *testing.T) {
	current := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	adminToken := strings.Repeat("E", 43)
	server, api, _ := newTestHTTPServer(
		t, testSessionControlService(t, t.TempDir()), adminToken, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return current },
	)
	plainClient := server.Client()

	for _, test := range []struct {
		name        string
		origin      string
		contentType string
		body        string
		want        int
	}{
		{name: "missing origin", contentType: "application/json", body: `{}`, want: http.StatusForbidden},
		{name: "wrong origin", origin: "https://attacker.example", contentType: "application/json", body: `{}`, want: http.StatusForbidden},
		{name: "content type parameters", origin: server.URL, contentType: "application/json; charset=utf-8", body: `{}`, want: http.StatusForbidden},
		{name: "nonempty object", origin: server.URL, contentType: "application/json", body: `{"extra":true}`, want: http.StatusBadRequest},
		{name: "duplicate object", origin: server.URL, contentType: "application/json", body: `{} {}`, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/desktop/start", strings.NewReader(test.body))
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()
			api.desktopAuthorizationStart(recorder, request)
			if recorder.Code != test.want || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d want=%d cache=%q body=%s", recorder.Code, test.want, recorder.Header().Get("Cache-Control"), recorder.Body.String())
			}
		})
	}

	browserClient, _, browserCookies := loginHTTPClient(t, server, adminToken)
	malformedDecision := desktopDecisionRequest(t, server.URL, "desktop_short", "approve")
	addDesktopBrowserProof(malformedDecision, browserCookies["mesh_csrf"].Value)
	malformedResponse, err := browserClient.Do(malformedDecision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, malformedResponse, http.StatusBadRequest, nil)

	denied := startDesktopAuthorization(t, plainClient, server.URL)
	current = current.Add(time.Second)
	decision := desktopDecisionRequest(t, server.URL, denied.RequestID, "deny")
	addDesktopBrowserProof(decision, browserCookies["mesh_csrf"].Value)
	response, err := browserClient.Do(decision)
	if err != nil {
		t.Fatal(err)
	}
	decodeDesktopHTTPResponse(t, response, http.StatusNoContent, nil)
	current = current.Add(4 * time.Second)
	response = completeDesktopAuthorization(t, plainClient, server.URL, denied.RequestID, denied.PollSecret)
	var terminal desktopAuthorizationCompletionResponse
	decodeDesktopHTTPResponse(t, response, http.StatusOK, &terminal)
	if terminal.State != string(identity.DesktopAuthorizationDenied) || terminal.Session != nil || len(response.Cookies()) != 0 {
		t.Fatalf("denied completion=%#v cookies=%#v", terminal, response.Cookies())
	}

	expired := startDesktopAuthorization(t, plainClient, server.URL)
	wrongSecret, _ := identity.NewOpaqueToken()
	response = completeDesktopAuthorization(t, plainClient, server.URL, expired.RequestID, wrongSecret)
	decodeDesktopHTTPResponse(t, response, http.StatusUnauthorized, nil)
	current = current.Add(6 * time.Minute)
	response = completeDesktopAuthorization(t, plainClient, server.URL, expired.RequestID, expired.PollSecret)
	terminal = desktopAuthorizationCompletionResponse{}
	decodeDesktopHTTPResponse(t, response, http.StatusOK, &terminal)
	if terminal.State != string(identity.DesktopAuthorizationExpired) || terminal.Session != nil || len(response.Cookies()) != 0 {
		t.Fatalf("expired completion=%#v cookies=%#v", terminal, response.Cookies())
	}
}

func newSharedDesktopHTTPInstance(t *testing.T, service *control.Service, store identity.SessionStore, adminToken string, masterKey []byte, now func() time.Time) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: "http://" + server.Listener.Addr().String(),
		LegacyBrowserLogin: true, LegacyBearer: true,
	}).Normalized(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	fingerprint, err := config.PolicyFingerprint(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	binding, err := DeriveLegacyCredentialBinding(masterKey, adminToken)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	api, err := New(service, Options{
		IdentityConfig: config, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: true},
		PolicyFingerprint: fingerprint, LegacyCredentialBinding: binding, SessionStore: store,
		AdminToken: adminToken, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = api.Handler()
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func startDesktopAuthorization(t *testing.T, client *http.Client, origin string) desktopAuthorizationStartResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, origin+"/api/v1/auth/desktop/start", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var result desktopAuthorizationStartResponse
	decodeDesktopHTTPResponse(t, response, http.StatusCreated, &result)
	return result
}

func completeDesktopAuthorization(t *testing.T, client *http.Client, origin, requestID, pollSecret string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"request_id": requestID, "poll_secret": pollSecret})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/api/v1/auth/desktop/complete", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func desktopDecisionRequest(t *testing.T, origin, requestID, decision string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, origin+"/api/v1/auth/desktop/"+requestID+"/decision",
		strings.NewReader(`{"decision":"`+decision+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func addDesktopBrowserProof(request *http.Request, csrf string) {
	request.Header.Set("Origin", request.URL.Scheme+"://"+request.URL.Host)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-Mesh-CSRF", csrf)
}

func decodeDesktopHTTPResponse(t *testing.T, response *http.Response, want int, target any) []byte {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d want=%d cache=%q body=%s", response.StatusCode, want, response.Header.Get("Cache-Control"), raw)
	}
	if target != nil {
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

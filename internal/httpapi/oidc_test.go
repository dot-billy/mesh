package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

const (
	oidcTestTransaction = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	oidcTestState       = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ"
	oidcTestCode        = "confidential-authorization-code"
)

type fakeOIDCAuthenticator struct {
	mu sync.Mutex

	startPaths []string
	completes  []struct{ transaction, state, code string }
	consumes   []struct{ transaction, state string }

	startResult    identity.OIDCStartResult
	startErr       error
	completeResult identity.OIDCCompleteResult
	completeErr    error
	consumePath    string
	consumeErr     error
	startFunc      func(context.Context, string) (identity.OIDCStartResult, error)
	completeFunc   func(context.Context, string, string, string) (identity.OIDCCompleteResult, error)
}

func newFakeOIDCAuthenticator() *fakeOIDCAuthenticator {
	return &fakeOIDCAuthenticator{
		startResult: identity.OIDCStartResult{
			AuthorizationURL: "https://id.example.test/authorize?state=" + oidcTestState,
			TransactionToken: oidcTestTransaction,
		},
		completeErr: identity.ErrUnauthorized,
		consumePath: "/",
	}
}

func (f *fakeOIDCAuthenticator) Start(ctx context.Context, returnPath string) (identity.OIDCStartResult, error) {
	f.mu.Lock()
	f.startPaths = append(f.startPaths, returnPath)
	function, result, err := f.startFunc, f.startResult, f.startErr
	f.mu.Unlock()
	if function != nil {
		return function(ctx, returnPath)
	}
	return result, err
}

func (f *fakeOIDCAuthenticator) Complete(ctx context.Context, transaction, state, code string) (identity.OIDCCompleteResult, error) {
	f.mu.Lock()
	f.completes = append(f.completes, struct{ transaction, state, code string }{transaction, state, code})
	function, result, err := f.completeFunc, f.completeResult, f.completeErr
	f.mu.Unlock()
	if function != nil {
		return function(ctx, transaction, state, code)
	}
	return result, err
}

func (f *fakeOIDCAuthenticator) ConsumeAuthorizationError(_ context.Context, transaction, state string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumes = append(f.consumes, struct{ transaction, state string }{transaction, state})
	return f.consumePath, f.consumeErr
}

func (f *fakeOIDCAuthenticator) counts() (starts, completes, consumes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.startPaths), len(f.completes), len(f.consumes)
}

type oidcHTTPFixture struct {
	server      *Server
	handler     http.Handler
	service     *control.Service
	store       identity.SessionStore
	config      identity.IdentityConfig
	fingerprint string
	now         time.Time
	adminToken  string
}

func newOIDCHTTPOptions(t *testing.T, authenticator OIDCAuthenticator, legacyBrowser bool, logger *slog.Logger) (*control.Service, identity.SessionStore, identity.IdentityConfig, Options) {
	t.Helper()
	now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	service := testSessionControlService(t, t.TempDir())
	masterKey := bytes.Repeat([]byte{0x5c}, 32)
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.OpenFileStore(filepath.Join(t.TempDir(), "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw := identity.IdentityConfig{
		Mode: identity.ModeHybrid, PublicURL: "https://mesh.example.test",
		LegacyBearer: true, LegacyBrowserLogin: legacyBrowser,
		OIDC: &identity.OIDCConfig{
			Issuer: "https://id.example.test/tenant", ClientID: "mesh-control-plane",
			ClientSecretFile: filepath.Join(t.TempDir(), "oidc-client-secret"),
			Scopes:           []string{"openid", "email", "profile"}, AllowedSigningAlgs: []string{"RS256"},
			Admins:         []identity.AdminSelector{{Kind: "subject", Value: "admin-subject"}},
			RequiredAMRAll: []string{"otp"}, MaxAuthenticationAge: 15 * time.Minute,
		},
	}
	config, err := raw.Normalized(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := config.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("L", 43)
	binding := ""
	if legacyBrowser {
		binding, err = DeriveLegacyCredentialBinding(masterKey, adminToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	options := Options{
		IdentityConfig: config, PolicyFingerprint: fingerprint, LegacyCredentialBinding: binding,
		SessionStore: store, OIDCAuthenticator: authenticator, AdminToken: adminToken,
		SecureCookies: true, Logger: logger, Now: func() time.Time { return now },
	}
	return service, store, config, options
}

func newOIDCHTTPFixture(t *testing.T, authenticator *fakeOIDCAuthenticator, logger *slog.Logger) oidcHTTPFixture {
	t.Helper()
	service, store, config, options := newOIDCHTTPOptions(t, authenticator, false, logger)
	server, err := New(service, options)
	if err != nil {
		t.Fatal(err)
	}
	return oidcHTTPFixture{
		server: server, handler: server.Handler(), service: service, store: store, config: config,
		fingerprint: options.PolicyFingerprint, now: options.Now(), adminToken: options.AdminToken,
	}
}

func TestOIDCConstructorRequiresExactHybridComposition(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	service, _, _, options := newOIDCHTTPOptions(t, fake, false, nil)
	if _, err := New(service, options); err != nil {
		t.Fatalf("hybrid composition was rejected: %v", err)
	}

	missing := options
	missing.OIDCAuthenticator = nil
	if _, err := New(service, missing); err == nil {
		t.Fatal("hybrid configuration was accepted without an OIDC authenticator")
	}
	var typedNil *fakeOIDCAuthenticator
	missing.OIDCAuthenticator = typedNil
	if _, err := New(service, missing); err == nil {
		t.Fatal("hybrid configuration was accepted with a typed-nil OIDC authenticator")
	}

	legacy, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: "https://mesh.example.test", LegacyBearer: true,
	}).Normalized(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unexpected := options
	unexpected.IdentityConfig = legacy
	unexpected.PolicyFingerprint, err = legacy.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(service, unexpected); err == nil {
		t.Fatal("legacy-only configuration accepted an OIDC authenticator")
	}
}

func TestOIDCAuthMethodsAndStartCookieContract(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	fixture := newOIDCHTTPFixture(t, fake, nil)

	methods := httptest.NewRequest(http.MethodGet, fixture.config.PublicURL+"/api/v1/auth/methods", nil)
	methodsResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(methodsResponse, methods)
	if methodsResponse.Code != http.StatusOK || methodsResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("methods status=%d headers=%v body=%s", methodsResponse.Code, methodsResponse.Header(), methodsResponse.Body.String())
	}
	var advertised map[string]bool
	if err := json.Unmarshal(methodsResponse.Body.Bytes(), &advertised); err != nil {
		t.Fatal(err)
	}
	if !advertised["oidc"] || advertised["legacy_browser_login"] {
		t.Fatalf("unexpected auth methods: %#v", advertised)
	}
	service, _, _, bothOptions := newOIDCHTTPOptions(t, newFakeOIDCAuthenticator(), true, nil)
	bothServer, err := New(service, bothOptions)
	if err != nil {
		t.Fatal(err)
	}
	bothResponse := httptest.NewRecorder()
	bothServer.Handler().ServeHTTP(bothResponse, httptest.NewRequest(http.MethodGet, bothOptions.IdentityConfig.PublicURL+"/api/v1/auth/methods", nil))
	var both map[string]bool
	if bothResponse.Code != http.StatusOK || json.Unmarshal(bothResponse.Body.Bytes(), &both) != nil || !both["oidc"] || !both["legacy_browser_login"] {
		t.Fatalf("hybrid browser methods status=%d body=%s", bothResponse.Code, bothResponse.Body.String())
	}
	legacyConfig, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: bothOptions.IdentityConfig.PublicURL,
		LegacyBearer: true, LegacyBrowserLogin: true,
	}).Normalized(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	legacyOptions := bothOptions
	legacyOptions.IdentityConfig = legacyConfig
	legacyOptions.PolicyFingerprint, err = legacyConfig.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the credential-bound session policy for legacy browser login,
	// but remove the authenticator when OIDC is absent.
	legacyOptions.OIDCAuthenticator = nil
	legacyServer, err := New(service, legacyOptions)
	if err != nil {
		t.Fatal(err)
	}
	legacyResponse := httptest.NewRecorder()
	legacyServer.Handler().ServeHTTP(legacyResponse, httptest.NewRequest(http.MethodGet, legacyConfig.PublicURL+"/api/v1/auth/methods", nil))
	var legacyMethods map[string]bool
	if legacyResponse.Code != http.StatusOK || json.Unmarshal(legacyResponse.Body.Bytes(), &legacyMethods) != nil || legacyMethods["oidc"] || !legacyMethods["legacy_browser_login"] {
		t.Fatalf("legacy browser methods status=%d body=%s", legacyResponse.Code, legacyResponse.Body.String())
	}

	request := newOIDCStartRequest(fixture.config.PublicURL, `{"return_path":"/networks?view=active"}`)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("start status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	cookie := responseCookie(response, "__Host-mesh_oidc")
	if cookie == nil || cookie.Value != oidcTestTransaction || !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge < 60 || cookie.MaxAge > 300 {
		t.Fatalf("invalid OIDC transaction cookie: %#v", cookie)
	}
	if bytes.Contains(response.Body.Bytes(), []byte(oidcTestTransaction)) {
		t.Fatal("transaction bearer leaked into the start response body")
	}
	starts, completes, consumes := fake.counts()
	if starts != 1 || completes != 0 || consumes != 0 || fake.startPaths[0] != "/networks?view=active" {
		t.Fatalf("unexpected authenticator calls: starts=%d completes=%d consumes=%d paths=%v", starts, completes, consumes, fake.startPaths)
	}
}

func TestOIDCStartRejectsAmbiguousOrCrossOriginRequests(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		mutate func(*http.Request)
		status int
	}{
		{name: "missing origin", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header.Del("Origin") }, status: http.StatusForbidden},
		{name: "wrong origin", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, status: http.StatusForbidden},
		{name: "duplicate origin", body: `{"return_path":"/"}`, mutate: func(r *http.Request) {
			r.Header["Origin"] = []string{"https://mesh.example.test", "https://mesh.example.test"}
		}, status: http.StatusForbidden},
		{name: "non exact JSON", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, status: http.StatusForbidden},
		{name: "duplicate content type", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header["Content-Type"] = []string{"application/json", "application/json"} }, status: http.StatusForbidden},
		{name: "cross site fetch", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, status: http.StatusForbidden},
		{name: "duplicate fetch", body: `{"return_path":"/"}`, mutate: func(r *http.Request) { r.Header["Sec-Fetch-Site"] = []string{"same-origin", "same-origin"} }, status: http.StatusForbidden},
		{name: "unknown JSON field", body: `{"return_path":"/","state":"attacker"}`, status: http.StatusBadRequest},
		{name: "duplicate return path", body: `{"return_path":"/","return_path":"/other"}`, status: http.StatusBadRequest},
		{name: "multiple JSON values", body: `{"return_path":"/"} {}`, status: http.StatusBadRequest},
		{name: "scheme relative return", body: `{"return_path":"//attacker.example"}`, status: http.StatusBadRequest},
		{name: "encoded scheme relative return", body: `{"return_path":"/%2fattacker.example"}`, status: http.StatusBadRequest},
		{name: "backslash return", body: `{"return_path":"/safe\\attacker"}`, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeOIDCAuthenticator()
			fixture := newOIDCHTTPFixture(t, fake, nil)
			request := newOIDCStartRequest(fixture.config.PublicURL, test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			starts, _, _ := fake.counts()
			if response.Code != test.status || starts != 0 || response.Header().Get("Cache-Control") != "no-store" || responseCookie(response, "__Host-mesh_oidc") != nil {
				t.Fatalf("status=%d starts=%d headers=%v body=%s", response.Code, starts, response.Header(), response.Body.String())
			}
		})
	}
}

func TestOIDCStartAdmissionLimitsGlobalClientAndConcurrency(t *testing.T) {
	t.Run("per client", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		fixture := newOIDCHTTPFixture(t, fake, nil)
		for index := 0; index < 5; index++ {
			request := newOIDCStartRequest(fixture.config.PublicURL, `{"return_path":"/"}`)
			request.RemoteAddr = "198.51.100.10:1234"
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			want := http.StatusOK
			if index == 4 {
				want = http.StatusTooManyRequests
			}
			if response.Code != want || (want == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "1") {
				t.Fatalf("request %d status=%d headers=%v body=%s", index, response.Code, response.Header(), response.Body.String())
			}
		}
		starts, _, _ := fake.counts()
		if starts != 4 {
			t.Fatalf("per-client limiter admitted %d starts, want 4", starts)
		}
	})

	t.Run("global", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		fixture := newOIDCHTTPFixture(t, fake, nil)
		for index := 0; index < 9; index++ {
			request := newOIDCStartRequest(fixture.config.PublicURL, `{"return_path":"/"}`)
			request.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", index+1)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			want := http.StatusOK
			if index == 8 {
				want = http.StatusTooManyRequests
			}
			if response.Code != want {
				t.Fatalf("request %d status=%d body=%s", index, response.Code, response.Body.String())
			}
		}
		starts, _, _ := fake.counts()
		if starts != 8 {
			t.Fatalf("global limiter admitted %d starts, want 8", starts)
		}
	})

	t.Run("slots", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		entered := make(chan struct{}, 4)
		release := make(chan struct{})
		fake.startFunc = func(context.Context, string) (identity.OIDCStartResult, error) {
			entered <- struct{}{}
			<-release
			return fake.startResult, nil
		}
		fixture := newOIDCHTTPFixture(t, fake, nil)
		responses := make(chan *httptest.ResponseRecorder, 4)
		for index := 0; index < 4; index++ {
			index := index
			go func() {
				request := newOIDCStartRequest(fixture.config.PublicURL, `{"return_path":"/"}`)
				request.RemoteAddr = "192.0.2." + []string{"1", "2", "3", "4"}[index] + ":1234"
				response := httptest.NewRecorder()
				fixture.handler.ServeHTTP(response, request)
				responses <- response
			}()
		}
		for index := 0; index < 4; index++ {
			<-entered
		}
		fifth := newOIDCStartRequest(fixture.config.PublicURL, `{"return_path":"/"}`)
		fifth.RemoteAddr = "192.0.2.5:1234"
		fifthResponse := httptest.NewRecorder()
		fixture.handler.ServeHTTP(fifthResponse, fifth)
		if fifthResponse.Code != http.StatusTooManyRequests || fifthResponse.Header().Get("Retry-After") != "1" {
			t.Fatalf("fifth concurrent start status=%d headers=%v", fifthResponse.Code, fifthResponse.Header())
		}
		close(release)
		for index := 0; index < 4; index++ {
			if response := <-responses; response.Code != http.StatusOK {
				t.Fatalf("admitted concurrent start status=%d body=%s", response.Code, response.Body.String())
			}
		}
		starts, _, _ := fake.counts()
		if starts != 4 {
			t.Fatalf("slot limiter invoked authenticator %d times, want 4", starts)
		}
	})
}

func TestOIDCCallbackRejectsAmbiguousQueriesBeforeAuthenticator(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		duplicateCookie bool
		wantComplete    int
	}{
		{name: "duplicate state", query: "state=" + oidcTestState + "&state=" + oidcTestState + "&code=" + oidcTestCode},
		{name: "missing state", query: "code=" + oidcTestCode},
		{name: "code and error", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&error=access_denied"},
		{name: "no result", query: "state=" + oidcTestState},
		{name: "unknown parameter", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&extra=1"},
		{name: "malformed percent", query: "state=%ZZ&code=" + oidcTestCode},
		{name: "oversized", query: "state=" + oidcTestState + "&code=" + strings.Repeat("x", maxOIDCCallbackQueryBytes)},
		{name: "issuer mismatch", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&iss=" + url.QueryEscape("https://other.example/tenant")},
		{name: "duplicate issuer", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&iss=x&iss=x"},
		{name: "error metadata with code", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&error_description=no"},
		{name: "invalid session state", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&session_state=%0A"},
		{name: "duplicate transaction cookie", query: "state=" + oidcTestState + "&code=" + oidcTestCode, duplicateCookie: true},
		{name: "exact optional issuer", query: "state=" + oidcTestState + "&code=" + oidcTestCode + "&iss=" + url.QueryEscape("https://id.example.test/tenant") + "&session_state=provider-session", wantComplete: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeOIDCAuthenticator()
			fixture := newOIDCHTTPFixture(t, fake, nil)
			request := newOIDCCallbackRequest(fixture, test.query)
			if test.duplicateCookie {
				request.AddCookie(&http.Cookie{Name: "__Host-mesh_oidc", Value: oidcTestTransaction})
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			_, completes, consumes := fake.counts()
			if completes != test.wantComplete || consumes != 0 {
				t.Fatalf("authenticator calls completes=%d consumes=%d", completes, consumes)
			}
			wantStatus := http.StatusBadRequest
			if test.duplicateCookie || test.wantComplete == 1 {
				wantStatus = http.StatusUnauthorized
			}
			if response.Code != wantStatus || clearingCookie(response, "__Host-mesh_oidc") != nil {
				t.Fatalf("status=%d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
			}
		})
	}
}

func TestOIDCCallbackAdmissionLimitsGlobalClientAndConcurrency(t *testing.T) {
	query := "state=" + oidcTestState + "&code=" + oidcTestCode
	t.Run("per client", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		fixture := newOIDCHTTPFixture(t, fake, nil)
		for index := 0; index < 21; index++ {
			request := newOIDCCallbackRequest(fixture, query)
			request.RemoteAddr = "198.51.100.10:1234"
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			want := http.StatusUnauthorized
			if index == 20 {
				want = http.StatusTooManyRequests
			}
			if response.Code != want || (want == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "1") {
				t.Fatalf("request %d status=%d headers=%v body=%s", index, response.Code, response.Header(), response.Body.String())
			}
		}
		_, completes, _ := fake.counts()
		if completes != 20 {
			t.Fatalf("per-client callback limiter admitted %d completions, want 20", completes)
		}
	})

	t.Run("global", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		fixture := newOIDCHTTPFixture(t, fake, nil)
		for index := 0; index < 41; index++ {
			request := newOIDCCallbackRequest(fixture, query)
			request.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", index+1)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			want := http.StatusUnauthorized
			if index == 40 {
				want = http.StatusTooManyRequests
			}
			if response.Code != want {
				t.Fatalf("request %d status=%d body=%s", index, response.Code, response.Body.String())
			}
		}
		_, completes, _ := fake.counts()
		if completes != 40 {
			t.Fatalf("global callback limiter admitted %d completions, want 40", completes)
		}
	})

	t.Run("slots", func(t *testing.T) {
		fake := newFakeOIDCAuthenticator()
		entered := make(chan struct{}, 8)
		release := make(chan struct{})
		fake.completeFunc = func(context.Context, string, string, string) (identity.OIDCCompleteResult, error) {
			entered <- struct{}{}
			<-release
			return identity.OIDCCompleteResult{}, identity.ErrUnauthorized
		}
		fixture := newOIDCHTTPFixture(t, fake, nil)
		responses := make(chan *httptest.ResponseRecorder, 8)
		for index := 0; index < 8; index++ {
			index := index
			go func() {
				request := newOIDCCallbackRequest(fixture, query)
				request.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", index+1)
				response := httptest.NewRecorder()
				fixture.handler.ServeHTTP(response, request)
				responses <- response
			}()
		}
		for index := 0; index < 8; index++ {
			<-entered
		}
		ninth := newOIDCCallbackRequest(fixture, query)
		ninth.RemoteAddr = "192.0.2.9:1234"
		ninthResponse := httptest.NewRecorder()
		fixture.handler.ServeHTTP(ninthResponse, ninth)
		if ninthResponse.Code != http.StatusTooManyRequests || ninthResponse.Header().Get("Retry-After") != "1" {
			t.Fatalf("ninth concurrent callback status=%d headers=%v", ninthResponse.Code, ninthResponse.Header())
		}
		close(release)
		for index := 0; index < 8; index++ {
			if response := <-responses; response.Code != http.StatusUnauthorized {
				t.Fatalf("admitted callback status=%d body=%s", response.Code, response.Body.String())
			}
		}
		_, completes, _ := fake.counts()
		if completes != 8 {
			t.Fatalf("callback slot limiter invoked authenticator %d times, want 8", completes)
		}
	})
}

func TestOIDCCallbackWrongStateDoesNotClearTransaction(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	fake.completeErr = identity.ErrUnauthorized
	fake.completeResult = identity.OIDCCompleteResult{AttemptConsumed: false}
	fixture := newOIDCHTTPFixture(t, fake, nil)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, newOIDCCallbackRequest(fixture, "state="+oidcTestState+"&code="+oidcTestCode))
	if response.Code != http.StatusUnauthorized || clearingCookie(response, "__Host-mesh_oidc") != nil {
		t.Fatalf("wrong-state status=%d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
	}
	_, completes, _ := fake.counts()
	if completes != 1 {
		t.Fatalf("complete calls=%d, want 1", completes)
	}
}

func TestOIDCCallbackConsumedFailureClearsAndReturnsGenericError(t *testing.T) {
	secret := "provider-token-secret-must-not-leak"
	var logs bytes.Buffer
	fake := newFakeOIDCAuthenticator()
	fake.completeResult = identity.OIDCCompleteResult{AttemptConsumed: true, ReturnPath: "/dashboard?view=networks"}
	fake.completeErr = errors.New(secret)
	fixture := newOIDCHTTPFixture(t, fake, slog.New(slog.NewTextHandler(&logs, nil)))
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, newOIDCCallbackRequest(fixture, "state="+oidcTestState+"&code="+secret))
	location := response.Header().Get("Location")
	cleared := clearingCookie(response, "__Host-mesh_oidc")
	if response.Code != http.StatusSeeOther || cleared == nil || cleared.SameSite != http.SameSiteLaxMode || !strings.Contains(location, "mesh_auth_error=oidc") || !strings.Contains(location, "view=networks") {
		t.Fatalf("status=%d location=%q cookies=%v body=%s", response.Code, location, response.Result().Cookies(), response.Body.String())
	}
	combined := response.Body.String() + location + logs.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("callback secret leaked in response or logs: %q", combined)
	}
}

func TestOIDCProviderErrorConsumesClearsAndReturnsGenericError(t *testing.T) {
	secret := "provider-description-must-not-leak"
	var logs bytes.Buffer
	fake := newFakeOIDCAuthenticator()
	fake.consumePath = "/return?from=login"
	fixture := newOIDCHTTPFixture(t, fake, slog.New(slog.NewTextHandler(&logs, nil)))
	query := "state=" + oidcTestState + "&error=access_denied&error_description=" + url.QueryEscape(secret) + "&error_uri=" + url.QueryEscape("https://id.example.test/help")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, newOIDCCallbackRequest(fixture, query))
	location := response.Header().Get("Location")
	if response.Code != http.StatusSeeOther || clearingCookie(response, "__Host-mesh_oidc") == nil || !strings.Contains(location, "mesh_auth_error=oidc") || !strings.Contains(location, "from=login") {
		t.Fatalf("status=%d location=%q cookies=%v body=%s", response.Code, location, response.Result().Cookies(), response.Body.String())
	}
	_, completes, consumes := fake.counts()
	if completes != 0 || consumes != 1 {
		t.Fatalf("complete=%d consume=%d, want 0/1", completes, consumes)
	}
	if combined := response.Body.String() + location + logs.String(); strings.Contains(combined, secret) || strings.Contains(combined, "access_denied") {
		t.Fatalf("provider error details leaked in response or logs: %q", combined)
	}
}

func TestOIDCProviderErrorWrongStateDoesNotClearTransaction(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	fake.consumeErr = identity.ErrUnauthorized
	fixture := newOIDCHTTPFixture(t, fake, nil)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, newOIDCCallbackRequest(fixture, "state="+oidcTestState+"&error=access_denied"))
	if response.Code != http.StatusUnauthorized || clearingCookie(response, "__Host-mesh_oidc") != nil {
		t.Fatalf("wrong-state provider error status=%d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
	}
	_, completes, consumes := fake.counts()
	if completes != 0 || consumes != 1 {
		t.Fatalf("complete=%d consume=%d, want 0/1", completes, consumes)
	}
}

func TestOIDCCallbackSuccessCreatesStrictSessionAndOIDCActor(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	fixture := newOIDCHTTPFixture(t, fake, nil)
	principal, err := identity.NewOIDCPrincipal(
		fixture.config.OIDC.Issuer, "admin-subject", "Mesh Admin", "admin@example.test",
		[]string{"mesh-admins"}, "", []string{"otp"}, fixture.now.Add(-time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	fake.completeResult = identity.OIDCCompleteResult{Principal: principal, ReturnPath: "/networks", AttemptConsumed: true}
	fake.completeErr = nil

	callback := httptest.NewRecorder()
	fixture.handler.ServeHTTP(callback, newOIDCCallbackRequest(fixture, "state="+oidcTestState+"&code="+oidcTestCode))
	if callback.Code != http.StatusSeeOther || callback.Header().Get("Location") != "/networks" {
		t.Fatalf("callback status=%d location=%q body=%s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	sessionCookie := responseCookie(callback, "__Host-mesh_session")
	csrfCookie := responseCookie(callback, "__Host-mesh_csrf")
	transactionCookie := clearingCookie(callback, "__Host-mesh_oidc")
	if sessionCookie == nil || csrfCookie == nil || transactionCookie == nil || !sessionCookie.HttpOnly || csrfCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || csrfCookie.SameSite != http.SameSiteStrictMode || transactionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("invalid success cookies: session=%#v csrf=%#v transaction=%#v", sessionCookie, csrfCookie, transactionCookie)
	}
	session, err := fixture.store.AuthenticateSession(context.Background(), sessionCookie.Value, fixture.server.policyFingerprint, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if session.AuthMethod != "oidc" || session.Principal.ID != principal.ID || session.Principal.Kind != identity.PrincipalOIDCAdmin {
		t.Fatalf("unexpected OIDC session: %#v", session)
	}

	body := strings.NewReader(`{"name":"oidc-audit","cidr":"10.115.0.0/24","listen_port":4242,"certificate_ttl_hours":24}`)
	mutation := httptest.NewRequest(http.MethodPost, fixture.config.PublicURL+"/api/v1/networks", body)
	mutation.Header.Set("Content-Type", "application/json")
	mutation.Header.Set("Origin", fixture.config.PublicURL)
	mutation.Header.Set("Sec-Fetch-Site", "same-origin")
	mutation.Header.Set("X-Mesh-CSRF", csrfCookie.Value)
	mutation.AddCookie(sessionCookie)
	mutation.AddCookie(csrfCookie)
	mutationResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(mutationResponse, mutation)
	if mutationResponse.Code != http.StatusCreated {
		t.Fatalf("OIDC mutation status=%d body=%s", mutationResponse.Code, mutationResponse.Body.String())
	}
	events, err := fixture.service.Audit(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action != "network.created" {
			continue
		}
		found = true
		if event.Details["actor_id"] != principal.ID || event.Details["actor_kind"] != control.ActorKindOIDCAdmin || event.Details["actor_session_id"] != session.ID {
			t.Fatalf("wrong OIDC mutation actor: %#v", event.Details)
		}
	}
	if !found {
		t.Fatal("network creation did not append an audit event")
	}
}

func TestOIDCDashboardWiringIsMethodGatedAndGeneric(t *testing.T) {
	script, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"/api/v1/auth/methods", "/api/v1/auth/oidc/start", "legacy_browser_login",
		"mesh_auth_error", "history.replaceState", "Single sign-on could not be completed. Please try again.",
		"['__Host-mesh_csrf=', 'mesh_csrf=']",
	} {
		if !bytes.Contains(script, []byte(required)) {
			t.Fatalf("dashboard script is missing %q", required)
		}
	}
	for _, required := range []string{"id=\"oidc-login-panel\" class=\"login-method hidden\"", "id=\"login-form\" class=\"hidden\"", "id=\"login-error\""} {
		if !bytes.Contains(html, []byte(required)) {
			t.Fatalf("dashboard HTML is missing %q", required)
		}
	}
}

func newOIDCStartRequest(publicURL, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, publicURL+"/api/v1/auth/oidc/start", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", publicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func newOIDCCallbackRequest(fixture oidcHTTPFixture, query string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, fixture.config.PublicURL+"/api/v1/auth/oidc/callback?"+query, nil)
	request.AddCookie(&http.Cookie{Name: "__Host-mesh_oidc", Value: oidcTestTransaction})
	return request
}

func responseCookie(response *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	return nil
}

func clearingCookie(response *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return cookie
		}
	}
	return nil
}

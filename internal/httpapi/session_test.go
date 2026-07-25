package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestOpaqueLegacySessionPersistsWithoutRawCredentialsAndRejectsRotatedPolicy(t *testing.T) {
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "identity-state.json")
	masterKey := bytes.Repeat([]byte{0x45}, 32)
	adminToken := strings.Repeat("A", 43)
	now := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	config := testLegacyIdentityConfig(t, "https://mesh.example.test", identity.SessionConfig{})
	service := testSessionControlService(t, directory)

	store := openSessionStore(t, identityPath, masterKey)
	api := testSessionAPI(t, service, store, config, adminToken, masterKey, func() time.Time { return now })
	loggedIn, cookies, responseBody := loginThroughHandler(t, api.Handler(), config.PublicURL, adminToken)
	sessionCookie := cookies["__Host-mesh_session"]
	csrfCookie := cookies["__Host-mesh_csrf"]
	if sessionCookie == nil || csrfCookie == nil || sessionCookie.Value == adminToken || !identity.ValidOpaqueToken(sessionCookie.Value) || !identity.ValidOpaqueToken(csrfCookie.Value) {
		t.Fatalf("login did not issue independent opaque credentials: session=%#v csrf=%#v", sessionCookie, csrfCookie)
	}
	if bytes.Contains(responseBody, []byte(adminToken)) || bytes.Contains(responseBody, []byte(sessionCookie.Value)) || bytes.Contains(responseBody, []byte(csrfCookie.Value)) {
		t.Fatal("login JSON exposed an administrator, session, or CSRF credential")
	}
	rawState, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	for label, secret := range map[string]string{"administrator": adminToken, "session": sessionCookie.Value, "csrf": csrfCookie.Value} {
		if bytes.Contains(rawState, []byte(secret)) {
			t.Fatalf("identity state contains raw %s credential", label)
		}
	}
	if !bytes.Contains(rawState, []byte(`"token_hash"`)) || !bytes.Contains(rawState, []byte(`"csrf_hash"`)) {
		t.Fatal("identity state omitted hashed browser credentials")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openSessionStore(t, identityPath, masterKey)
	api = testSessionAPI(t, service, store, config, adminToken, masterKey, func() time.Time { return now.Add(time.Minute) })
	response := authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", sessionCookie, nil, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("persisted session returned %d after restart: %s", response.Code, response.Body.String())
	}
	var current sessionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if current.SessionID != loggedIn.SessionID || current.AuthMethod != "legacy_token" || current.Principal.ID != "legacy_admin" {
		t.Fatalf("unsafe or incorrect current session response: %#v", current)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	rotatedAdminToken := strings.Repeat("B", 43)
	store = openSessionStore(t, identityPath, masterKey)
	api = testSessionAPI(t, service, store, config, rotatedAdminToken, masterKey, func() time.Time { return now.Add(2 * time.Minute) })
	response = authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", sessionCookie, nil, "", "")
	if response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("old session survived administrator-token rotation: status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	rotatedMasterKey := bytes.Repeat([]byte{0x46}, 32)
	store = openSessionStore(t, identityPath, rotatedMasterKey)
	api = testSessionAPI(t, service, store, config, adminToken, rotatedMasterKey, func() time.Time { return now.Add(2 * time.Minute) })
	response = authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", sessionCookie, nil, "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived master-key rotation: status=%d", response.Code)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	changedConfig := testLegacyIdentityConfig(t, config.PublicURL, identity.SessionConfig{AbsoluteTTL: 2 * time.Hour})
	store = openSessionStore(t, identityPath, masterKey)
	defer store.Close()
	api = testSessionAPI(t, service, store, changedConfig, adminToken, masterKey, func() time.Time { return now.Add(2 * time.Minute) })
	response = authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", sessionCookie, nil, "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived identity-policy change: status=%d", response.Code)
	}
}

func TestSessionCookieContractsListingRevocationAndLogout(t *testing.T) {
	service := testSessionControlService(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	adminToken := strings.Repeat("C", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)

	firstClient, firstLogin, firstCookies := loginHTTPClient(t, server, adminToken)
	_, secondLogin, _ := loginHTTPClient(t, server, adminToken)
	assertCookieContract(t, firstCookies, firstLogin, false)
	if firstCookies["mesh_session"].Value == adminToken || firstLogin.SessionID == secondLogin.SessionID {
		t.Fatal("browser sessions reused the shared credential or record identity")
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	rawList, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || bytes.Contains(rawList, []byte("token_hash")) || bytes.Contains(rawList, []byte("csrf_hash")) || bytes.Contains(rawList, []byte(firstCookies["mesh_session"].Value)) || bytes.Contains(rawList, []byte(firstCookies["mesh_csrf"].Value)) {
		t.Fatalf("session listing leaked credential material or failed: status=%d body=%s", response.StatusCode, rawList)
	}
	var active []identity.SessionSummary
	if err := json.Unmarshal(rawList, &active); err != nil || len(active) != 2 {
		t.Fatalf("active session list=%#v error=%v", active, err)
	}

	revokeURL := server.URL + "/api/v1/sessions/" + secondLogin.SessionID
	for attempt := 0; attempt < 2; attempt++ {
		request, _ = http.NewRequest(http.MethodDelete, revokeURL, nil)
		request.Header.Set("Authorization", "Bearer "+adminToken)
		response, err = server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("idempotent session revocation attempt %d returned %d", attempt+1, response.StatusCode)
		}
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	active = nil
	if err := json.NewDecoder(response.Body).Decode(&active); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(active) != 1 || active[0].ID != firstLogin.SessionID {
		t.Fatalf("default session list included revoked records: %#v", active)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions?include_revoked=true&limit=10", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var all []identity.SessionSummary
	if err := json.NewDecoder(response.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(all) != 2 || all[0].ID == "" || all[1].ID == "" {
		t.Fatalf("revoked-inclusive session list=%#v", all)
	}

	logout, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/session", nil)
	addCookieCSRF(logout, server.URL, firstCookies["mesh_csrf"].Value)
	response, err = firstClient.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("logout returned %d", response.StatusCode)
	}
	assertClearedCookies(t, response.Cookies(), false)
	oldSession := authenticatedHandlerRequest(server.Config.Handler, http.MethodGet, server.URL+"/api/v1/session", firstCookies["mesh_session"], nil, "", "")
	if oldSession.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out cookie remained valid: %d", oldSession.Code)
	}

	thirdClient, thirdLogin, thirdCookies := loginHTTPClient(t, server, adminToken)
	deleteCurrent, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sessions/"+thirdLogin.SessionID, nil)
	addCookieCSRF(deleteCurrent, server.URL, thirdCookies["mesh_csrf"].Value)
	response, err = thirdClient.Do(deleteCurrent)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("current-session revocation returned %d", response.StatusCode)
	}
	assertClearedCookies(t, response.Cookies(), false)

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions?limit=999", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unbounded session list returned %d", response.StatusCode)
	}
}

func TestSecureSessionCookieContract(t *testing.T) {
	service := testSessionControlService(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _, _ := newTestHTTPServer(t, service, strings.Repeat("D", 43), true, logger, nil)
	_, loggedIn, cookies := loginHTTPClient(t, server, strings.Repeat("D", 43))
	assertCookieContract(t, cookies, loggedIn, true)
}

func TestLoginRequiresExactSameOriginJSONRequest(t *testing.T) {
	service := testSessionControlService(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	adminToken := strings.Repeat("J", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	body, _ := json.Marshal(map[string]string{"token": adminToken})
	tests := []struct {
		name        string
		origin      string
		contentType string
		fetchSite   string
		duplicate   string
		want        int
	}{
		{name: "missing origin", contentType: "application/json", want: http.StatusForbidden},
		{name: "wrong origin", origin: "https://attacker.example", contentType: "application/json", want: http.StatusForbidden},
		{name: "duplicate origin", origin: server.URL, contentType: "application/json", duplicate: "origin", want: http.StatusForbidden},
		{name: "simple text content", origin: server.URL, contentType: "text/plain", want: http.StatusForbidden},
		{name: "missing content type", origin: server.URL, want: http.StatusForbidden},
		{name: "duplicate content type", origin: server.URL, contentType: "application/json", duplicate: "content", want: http.StatusForbidden},
		{name: "cross site fetch metadata", origin: server.URL, contentType: "application/json", fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "exact same origin JSON", origin: server.URL, contentType: "application/json", fetchSite: "same-origin", want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/session", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			switch test.duplicate {
			case "origin":
				request.Header.Add("Origin", test.origin)
			case "content":
				request.Header.Add("Content-Type", test.contentType)
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.want || response.Header.Get("Cache-Control") != "no-store" {
				raw, _ := io.ReadAll(response.Body)
				t.Fatalf("status=%d cache=%q want=%d body=%s", response.StatusCode, response.Header.Get("Cache-Control"), test.want, raw)
			}
		})
	}
}

func TestLegacyCredentialBindingIsStableDomainSeparatedAndRotationSensitive(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x71}, 32)
	originalKey := append([]byte(nil), masterKey...)
	token := strings.Repeat("K", 43)
	first, err := DeriveLegacyCredentialBinding(masterKey, token)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveLegacyCredentialBinding(masterKey, token)
	if err != nil {
		t.Fatal(err)
	}
	rotatedToken, err := DeriveLegacyCredentialBinding(masterKey, strings.Repeat("L", 43))
	if err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := DeriveLegacyCredentialBinding(bytes.Repeat([]byte{0x72}, 32), token)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !validCredentialBinding(first) || first == rotatedToken || first == rotatedKey || !bytes.Equal(masterKey, originalKey) {
		t.Fatalf("binding stability/rotation failure: first=%q second=%q token=%q key=%q", first, second, rotatedToken, rotatedKey)
	}
	if _, err := DeriveLegacyCredentialBinding(masterKey[:31], token); err == nil {
		t.Fatal("short master key was accepted")
	}
	if _, err := DeriveLegacyCredentialBinding(masterKey, "short"); err == nil {
		t.Fatal("weak administrator token was accepted")
	}
}

func TestCookieCSRFOriginFetchMetadataAndBearerSeparation(t *testing.T) {
	service := testSessionControlService(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	adminToken := strings.Repeat("E", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	_, _, cookies := loginHTTPClient(t, server, adminToken)
	sessionCookie, csrfCookie := cookies["mesh_session"], cookies["mesh_csrf"]
	alternateCSRF, err := identity.NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		want       int
		cookieCSRF string
		headerCSRF string
		origin     string
		fetchSite  string
		bearer     string
		duplicate  string
		cookies    bool
	}{
		{name: "missing csrf", want: http.StatusForbidden, origin: server.URL, fetchSite: "same-origin", cookies: true},
		{name: "stored csrf mismatch", want: http.StatusForbidden, cookieCSRF: alternateCSRF, headerCSRF: alternateCSRF, origin: server.URL, fetchSite: "same-origin", cookies: true},
		{name: "missing origin", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, fetchSite: "same-origin", cookies: true},
		{name: "wrong origin", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: "https://attacker.example", fetchSite: "same-origin", cookies: true},
		{name: "cross site fetch", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "cross-site", cookies: true},
		{name: "duplicate origin", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", duplicate: "origin", cookies: true},
		{name: "comma folded origin", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL + ", " + server.URL, fetchSite: "same-origin", cookies: true},
		{name: "duplicate csrf", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", duplicate: "csrf", cookies: true},
		{name: "comma folded csrf", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value + ", " + csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", cookies: true},
		{name: "duplicate fetch", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", duplicate: "fetch", cookies: true},
		{name: "comma folded fetch", want: http.StatusForbidden, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin, same-origin", cookies: true},
		{name: "duplicate session cookie", want: http.StatusUnauthorized, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", duplicate: "cookie", cookies: true},
		{name: "invalid bearer cannot fall through", want: http.StatusUnauthorized, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", bearer: strings.Repeat("X", 43), cookies: true},
		{name: "comma folded bearer", want: http.StatusUnauthorized, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", bearer: adminToken + ", Bearer " + adminToken, cookies: true},
		{name: "duplicate authorization fields", want: http.StatusUnauthorized, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", bearer: adminToken, duplicate: "authorization", cookies: true},
		{name: "exact cookie proof", want: http.StatusCreated, cookieCSRF: csrfCookie.Value, headerCSRF: csrfCookie.Value, origin: server.URL, fetchSite: "same-origin", cookies: true},
		{name: "valid bearer bypass", want: http.StatusCreated, bearer: adminToken},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := strings.NewReader(fmt.Sprintf(`{"name":"csrf-%d","cidr":"10.25.%d.0/24"}`, index, index))
			request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/networks", body)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			if test.cookies {
				request.AddCookie(sessionCookie)
				request.AddCookie(&http.Cookie{Name: "mesh_csrf", Value: test.cookieCSRF})
			}
			if test.headerCSRF != "" {
				request.Header.Set("X-Mesh-CSRF", test.headerCSRF)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			switch test.duplicate {
			case "origin":
				request.Header.Add("Origin", test.origin)
			case "csrf":
				request.Header.Add("X-Mesh-CSRF", test.headerCSRF)
			case "fetch":
				request.Header.Add("Sec-Fetch-Site", test.fetchSite)
			case "cookie":
				request.AddCookie(sessionCookie)
			case "authorization":
				request.Header.Add("Authorization", "Bearer "+test.bearer)
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.want || response.Header.Get("Cache-Control") != "no-store" {
				raw, _ := io.ReadAll(response.Body)
				t.Fatalf("status=%d cache=%q want=%d body=%s", response.StatusCode, response.Header.Get("Cache-Control"), test.want, raw)
			}
		})
	}
}

func TestSessionIdleAbsoluteExpiryAndConcurrentTouch(t *testing.T) {
	t.Run("idle and concurrent touch", func(t *testing.T) {
		directory := t.TempDir()
		masterKey := bytes.Repeat([]byte{0x51}, 32)
		t0 := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
		clock := &sessionTestClock{value: t0}
		config := testLegacyIdentityConfig(t, "https://mesh.example.test", identity.SessionConfig{IdleTTL: 5 * time.Minute, AbsoluteTTL: 15 * time.Minute, TouchInterval: 30 * time.Second})
		service := testSessionControlService(t, directory)
		store := openSessionStore(t, filepath.Join(directory, "identity.json"), masterKey)
		defer store.Close()
		api := testSessionAPI(t, service, store, config, strings.Repeat("F", 43), masterKey, clock.Now)
		_, cookies, _ := loginThroughHandler(t, api.Handler(), config.PublicURL, strings.Repeat("F", 43))
		clock.Set(t0.Add(31 * time.Second))
		statuses := make(chan int, 32)
		var wait sync.WaitGroup
		for index := 0; index < 32; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				response := authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", cookies["__Host-mesh_session"], nil, "", "")
				statuses <- response.Code
			}()
		}
		wait.Wait()
		close(statuses)
		for status := range statuses {
			if status != http.StatusOK {
				t.Fatalf("concurrent touch returned %d", status)
			}
		}
		summaries, err := store.ListSessions(context.Background(), identity.SessionListFilter{Limit: 10})
		if err != nil || len(summaries) != 1 || summaries[0].Version != 2 || !summaries[0].LastSeenAt.Equal(t0.Add(31*time.Second)) {
			t.Fatalf("concurrent CAS touch summary=%#v error=%v", summaries, err)
		}
		clock.Set(t0.Add(31*time.Second + 5*time.Minute))
		expired := authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", cookies["__Host-mesh_session"], nil, "", "")
		if expired.Code != http.StatusUnauthorized {
			t.Fatalf("session valid at exact idle expiry: %d", expired.Code)
		}
	})

	t.Run("absolute", func(t *testing.T) {
		directory := t.TempDir()
		masterKey := bytes.Repeat([]byte{0x52}, 32)
		t0 := time.Date(2026, 7, 19, 19, 0, 0, 0, time.UTC)
		clock := &sessionTestClock{value: t0}
		config := testLegacyIdentityConfig(t, "https://mesh.example.test", identity.SessionConfig{IdleTTL: 5 * time.Minute, AbsoluteTTL: 15 * time.Minute, TouchInterval: 30 * time.Second})
		service := testSessionControlService(t, directory)
		store := openSessionStore(t, filepath.Join(directory, "identity.json"), masterKey)
		defer store.Close()
		api := testSessionAPI(t, service, store, config, strings.Repeat("G", 43), masterKey, clock.Now)
		_, cookies, _ := loginThroughHandler(t, api.Handler(), config.PublicURL, strings.Repeat("G", 43))
		for _, elapsed := range []time.Duration{4 * time.Minute, 8 * time.Minute, 12 * time.Minute} {
			clock.Set(t0.Add(elapsed))
			response := authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", cookies["__Host-mesh_session"], nil, "", "")
			if response.Code != http.StatusOK {
				t.Fatalf("session expired before absolute lifetime at %s: %d", elapsed, response.Code)
			}
		}
		clock.Set(t0.Add(15 * time.Minute))
		expired := authenticatedHandlerRequest(api.Handler(), http.MethodGet, config.PublicURL+"/api/v1/session", cookies["__Host-mesh_session"], nil, "", "")
		if expired.Code != http.StatusUnauthorized {
			t.Fatalf("session valid at exact absolute expiry: %d", expired.Code)
		}
	})
}

func TestNewRequiresExactNormalizedIdentityContract(t *testing.T) {
	directory := t.TempDir()
	service := testSessionControlService(t, directory)
	masterKey := bytes.Repeat([]byte{0x63}, 32)
	store := openSessionStore(t, filepath.Join(directory, "identity.json"), masterKey)
	defer store.Close()
	token := strings.Repeat("H", 43)
	binding, err := DeriveLegacyCredentialBinding(masterKey, token)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	unnormalized := identity.IdentityConfig{Mode: identity.ModeLegacyToken, PublicURL: "http://127.0.0.1:8080", LegacyBrowserLogin: true, LegacyBearer: true}
	if _, err := New(service, Options{IdentityConfig: unnormalized, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: true}, PolicyFingerprint: strings.Repeat("0", 64), LegacyCredentialBinding: binding, SessionStore: store, AdminToken: token, Logger: logger}); err == nil {
		t.Fatal("unnormalized identity configuration was accepted")
	}
	normalized, err := unnormalized.Normalized(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := normalized.PolicyFingerprint(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	base := Options{IdentityConfig: normalized, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: true}, PolicyFingerprint: fingerprint, LegacyCredentialBinding: binding, SessionStore: store, AdminToken: token, Logger: logger}
	wrongValidation := base
	wrongValidation.ValidationOptions.AllowInsecureLoopback = false
	if _, err := New(service, wrongValidation); err == nil {
		t.Fatal("HTTP loopback identity was accepted without the caller's insecure-loopback decision")
	}
	wrongSecurity := base
	wrongSecurity.SecureCookies = true
	if _, err := New(service, wrongSecurity); err == nil {
		t.Fatal("cookie security did not match public URL scheme")
	}
	wrongBinding := base
	wrongBinding.LegacyCredentialBinding = ""
	if _, err := New(service, wrongBinding); err == nil {
		t.Fatal("legacy browser login was accepted without credential binding")
	}
}

type sessionTestClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (c *sessionTestClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.value
}

func (c *sessionTestClock) Set(value time.Time) {
	c.mu.Lock()
	c.value = value
	c.mu.Unlock()
}

func testLegacyIdentityConfig(t *testing.T, publicURL string, sessions identity.SessionConfig) identity.IdentityConfig {
	t.Helper()
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: publicURL, Sessions: sessions,
		LegacyBrowserLogin: true, LegacyBearer: true,
	}).Normalized(identity.ValidationOptions{AllowInsecureLoopback: strings.HasPrefix(publicURL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testSessionControlService(t *testing.T, directory string) *control.Service {
	t.Helper()
	store, err := control.OpenStore(filepath.Join(directory, "control-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return control.NewService(store, box, &httpTestIssuer{})
}

func openSessionStore(t *testing.T, path string, masterKey []byte) *identity.FileStore {
	t.Helper()
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.OpenFileStore(path, box)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testSessionAPI(t *testing.T, service *control.Service, store identity.SessionStore, config identity.IdentityConfig, adminToken string, masterKey []byte, now func() time.Time) *Server {
	t.Helper()
	validation := identity.ValidationOptions{AllowInsecureLoopback: strings.HasPrefix(config.PublicURL, "http://")}
	fingerprint, err := config.PolicyFingerprint(validation)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := DeriveLegacyCredentialBinding(masterKey, adminToken)
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(service, Options{
		IdentityConfig: config, ValidationOptions: validation, PolicyFingerprint: fingerprint,
		LegacyCredentialBinding: binding, SessionStore: store, AdminToken: adminToken,
		SecureCookies: strings.HasPrefix(config.PublicURL, "https://"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func loginThroughHandler(t *testing.T, handler http.Handler, publicURL, adminToken string) (sessionResponse, map[string]*http.Cookie, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": adminToken})
	request := httptest.NewRequest(http.MethodPost, publicURL+"/api/v1/session", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", publicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	raw := append([]byte(nil), response.Body.Bytes()...)
	var loggedIn sessionResponse
	if err := json.Unmarshal(raw, &loggedIn); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]*http.Cookie{}
	for _, cookie := range response.Result().Cookies() {
		cookies[cookie.Name] = cookie
	}
	return loggedIn, cookies, raw
}

func authenticatedHandlerRequest(handler http.Handler, method, endpoint string, sessionCookie, csrfCookie *http.Cookie, origin, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, endpoint, nil)
	if sessionCookie != nil {
		request.AddCookie(sessionCookie)
	}
	if csrfCookie != nil {
		request.AddCookie(csrfCookie)
	}
	if csrf != "" {
		request.Header.Set("X-Mesh-CSRF", csrf)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func loginHTTPClient(t *testing.T, server *httptest.Server, adminToken string) (*http.Client, sessionResponse, map[string]*http.Cookie) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	baseClient := server.Client()
	client := &http.Client{Transport: baseClient.Transport, Jar: jar, Timeout: baseClient.Timeout, CheckRedirect: baseClient.CheckRedirect}
	body, _ := json.Marshal(map[string]string{"token": adminToken})
	response, err := postTestLogin(client, server.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var loggedIn sessionResponse
	if err := json.NewDecoder(response.Body).Decode(&loggedIn); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", response.StatusCode)
	}
	cookies := map[string]*http.Cookie{}
	for _, cookie := range response.Cookies() {
		cookies[cookie.Name] = cookie
	}
	return client, loggedIn, cookies
}

func assertCookieContract(t *testing.T, cookies map[string]*http.Cookie, session sessionResponse, secure bool) {
	t.Helper()
	sessionName, csrfName := "mesh_session", "mesh_csrf"
	if secure {
		sessionName, csrfName = "__Host-mesh_session", "__Host-mesh_csrf"
	}
	sessionCookie, csrfCookie := cookies[sessionName], cookies[csrfName]
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("cookies=%#v, want %q and %q", cookies, sessionName, csrfName)
	}
	if !sessionCookie.HttpOnly || csrfCookie.HttpOnly || sessionCookie.Secure != secure || csrfCookie.Secure != secure || sessionCookie.Path != "/" || csrfCookie.Path != "/" || sessionCookie.Domain != "" || csrfCookie.Domain != "" || sessionCookie.SameSite != http.SameSiteStrictMode || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("invalid cookie contract: session=%#v csrf=%#v", sessionCookie, csrfCookie)
	}
	if session.AbsoluteExpiresAt == nil || !sessionCookie.Expires.Equal(session.AbsoluteExpiresAt.Truncate(time.Second)) || !csrfCookie.Expires.Equal(session.AbsoluteExpiresAt.Truncate(time.Second)) || sessionCookie.MaxAge < 1 || sessionCookie.MaxAge > 8*60*60 || csrfCookie.MaxAge != sessionCookie.MaxAge {
		t.Fatalf("cookie lifetime mismatch: response=%#v session=%#v csrf=%#v", session, sessionCookie, csrfCookie)
	}
}

func assertClearedCookies(t *testing.T, cookies []*http.Cookie, secure bool) {
	t.Helper()
	want := map[string]bool{"mesh_session": false, "mesh_csrf": false}
	if secure {
		want = map[string]bool{"__Host-mesh_session": false, "__Host-mesh_csrf": false}
	}
	for _, cookie := range cookies {
		if _, ok := want[cookie.Name]; !ok {
			continue
		}
		if cookie.MaxAge >= 0 || cookie.Path != "/" || cookie.Secure != secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("invalid clearing cookie: %#v", cookie)
		}
		want[cookie.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("clearing response omitted %q", name)
		}
	}
}

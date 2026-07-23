package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestAuditIncludesDurableSessionCreationAndRequiresAuthentication(t *testing.T) {
	adminToken := strings.Repeat("q", 43)
	server := testServer(t, adminToken)
	client, loggedIn, _ := loginAuditClient(t, server.URL, adminToken)

	unauthenticated, err := server.Client().Get(server.URL + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated audit returned %d", unauthenticated.StatusCode)
	}

	response, err := client.Get(server.URL + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("audit returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	events := decodeAuditResponse(t, response)
	if len(events) != 1 {
		t.Fatalf("audit returned %d events, want the login creation event: %#v", len(events), events)
	}
	event := events[0]
	if event.Action != string(identity.IdentityAuditSessionCreated) || event.Resource != "session" || event.ResourceID != loggedIn.SessionID || event.TargetSessionID != loggedIn.SessionID || event.TargetPrincipalID != loggedIn.Principal.ID {
		t.Fatalf("unexpected session creation event: %#v", event)
	}
	if event.Actor == nil || event.Actor.ID != loggedIn.Principal.ID || event.Actor.Kind != string(loggedIn.Principal.Kind) || event.Actor.SessionID != loggedIn.SessionID {
		t.Fatalf("session creation actor was not structural: %#v", event.Actor)
	}
	if _, flattened := event.Details["actor_id"]; flattened {
		t.Fatalf("session creation actor was flattened into details: %#v", event.Details)
	}
	if event.Details["auth_method"] != "legacy_token" || event.Details["session_version"] != "1" {
		t.Fatalf("session creation details changed: %#v", event.Details)
	}
}

func TestAdminSessionRevocationAuditAttributesCookieAndBearerActors(t *testing.T) {
	adminToken := strings.Repeat("r", 43)
	server := testServer(t, adminToken)
	cookieAdmin, cookieActor, csrf := loginAuditClient(t, server.URL, adminToken)
	_, cookieTarget, _ := loginAuditClient(t, server.URL, adminToken)
	_, bearerTarget, _ := loginAuditClient(t, server.URL, adminToken)

	request, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sessions/"+cookieTarget.SessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	addCookieCSRF(request, server.URL, csrf)
	response, err := cookieAdmin.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("cookie administrator revocation returned %d", response.StatusCode)
	}

	request, err = http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sessions/"+bearerTarget.SessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("bearer administrator revocation returned %d", response.StatusCode)
	}

	request, err = http.NewRequest(http.MethodGet, server.URL+"/api/v1/audit", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bearer audit read returned %d", response.StatusCode)
	}
	events := decodeAuditResponse(t, response)

	cookieRevocation := findAuditEvent(t, events, string(identity.IdentityAuditSessionRevoked), cookieTarget.SessionID)
	if cookieRevocation.Actor == nil || cookieRevocation.Actor.ID != cookieActor.Principal.ID || cookieRevocation.Actor.Kind != string(cookieActor.Principal.Kind) || cookieRevocation.Actor.SessionID != cookieActor.SessionID {
		t.Fatalf("cookie revocation actor mismatch: %#v", cookieRevocation.Actor)
	}
	if cookieRevocation.TargetPrincipalID != cookieTarget.Principal.ID || cookieRevocation.TargetSessionID != cookieTarget.SessionID || cookieRevocation.Details["reason"] != "administrator revocation" {
		t.Fatalf("cookie revocation target mismatch: %#v", cookieRevocation)
	}

	bearerRevocation := findAuditEvent(t, events, string(identity.IdentityAuditSessionRevoked), bearerTarget.SessionID)
	if bearerRevocation.Actor == nil || bearerRevocation.Actor.ID != bearerTarget.Principal.ID || bearerRevocation.Actor.Kind != string(bearerTarget.Principal.Kind) || bearerRevocation.Actor.SessionID != "" {
		t.Fatalf("bearer revocation actor mismatch: %#v", bearerRevocation.Actor)
	}
	if _, flattened := bearerRevocation.Details["actor_session_id"]; flattened {
		t.Fatalf("bearer actor was flattened into details: %#v", bearerRevocation.Details)
	}
}

func TestAuditMergesSortsAndCapsControlAndIdentityEvents(t *testing.T) {
	directory := t.TempDir()
	service := testSessionControlService(t, directory)
	beforeControl := time.Now().UTC()
	created, err := service.CreateNetworkAs(context.Background(), control.LegacyAdminActor(), control.CreateNetworkInput{Name: "audit-cap", CIDR: "10.123.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	afterControl := time.Now().UTC()

	masterKey := []byte(strings.Repeat("m", 32))
	baseStore := openSessionStore(t, filepath.Join(directory, "identity.json"), masterKey)
	defer baseStore.Close()
	staticEvents := make([]identity.IdentityAuditSummary, 0, maxAuditResponseEvents)
	for index := 0; index < maxAuditResponseEvents-1; index++ {
		sessionID := fmt.Sprintf("session_static_%03d", index)
		staticEvents = append(staticEvents, identity.IdentityAuditSummary{
			ID: fmt.Sprintf("audit_static_%03d", index), Type: identity.IdentityAuditSessionCreated,
			At:                afterControl.Add(time.Duration(index+1) * time.Second),
			Actor:             identity.Actor{ID: "legacy_admin", Kind: identity.PrincipalLegacyAdmin, SessionID: sessionID},
			TargetPrincipalID: "legacy_admin", TargetSessionID: sessionID,
			Details: map[string]string{"auth_method": "legacy_token", "session_version": "1"},
		})
	}
	staticEvents = append(staticEvents, identity.IdentityAuditSummary{
		ID: "audit_static_old", Type: identity.IdentityAuditSessionCreated, At: beforeControl.Add(-time.Second),
		Actor:             identity.Actor{ID: "legacy_admin", Kind: identity.PrincipalLegacyAdmin, SessionID: "session_static_old"},
		TargetPrincipalID: "legacy_admin", TargetSessionID: "session_static_old",
		Details: map[string]string{"auth_method": "legacy_token", "session_version": "1"},
	})
	store := &staticIdentityAuditStore{SessionStore: baseStore, delegate: baseStore, events: staticEvents}
	config := testLegacyIdentityConfig(t, "https://mesh.example.test", identity.SessionConfig{})
	adminToken := strings.Repeat("s", 43)
	api := testSessionAPI(t, service, store, config, adminToken, masterKey, nil)

	request := httptest.NewRequest(http.MethodGet, config.PublicURL+"/api/v1/audit", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("merged audit returned %d: %s", response.Code, response.Body.String())
	}
	events := decodeAuditRecorder(t, response)
	if len(events) != maxAuditResponseEvents {
		t.Fatalf("merged audit returned %d events, want cap %d", len(events), maxAuditResponseEvents)
	}
	for index := 1; index < len(events); index++ {
		if events[index].At.After(events[index-1].At) {
			t.Fatalf("events are not descending at %d: %s before %s", index, events[index-1].At, events[index].At)
		}
	}
	if events[0].ID != "audit_static_098" {
		t.Fatalf("newest identity event was not first: %#v", events[0])
	}
	for _, event := range events {
		if event.ID == "audit_static_old" {
			t.Fatal("oldest event survived the total response cap")
		}
		if event.Action != "network.created" || event.ResourceID != created.ID {
			continue
		}
		if event.Actor == nil || event.Actor.ID != "legacy_admin" || event.Actor.Kind != control.ActorKindLegacyAdmin || event.Actor.SessionID != "" {
			t.Fatalf("control actor was not promoted structurally: %#v", event.Actor)
		}
		for _, key := range []string{"actor_id", "actor_kind", "actor_session_id"} {
			if _, flattened := event.Details[key]; flattened {
				t.Fatalf("control actor key %q remained flattened: %#v", key, event.Details)
			}
		}
		return
	}
	t.Fatal("control audit event was dropped despite being among the newest 100 events")
}

func TestNewRejectsSessionStoreWithoutDurableIdentityAudit(t *testing.T) {
	fake := newFakeOIDCAuthenticator()
	service, store, _, options := newOIDCHTTPOptions(t, fake, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	options.SessionStore = &sessionStoreWithoutIdentityAudit{SessionStore: store}
	if _, err := New(service, options); err == nil || !strings.Contains(err.Error(), "durable identity audit") {
		t.Fatalf("session-only store returned %v", err)
	}
}

type sessionStoreWithoutIdentityAudit struct {
	identity.SessionStore
}

type staticIdentityAuditStore struct {
	identity.SessionStore
	delegate identity.IdentityAuditStore
	events   []identity.IdentityAuditSummary
}

func (s *staticIdentityAuditStore) ListIdentityAudit(ctx context.Context, filter identity.IdentityAuditListFilter) ([]identity.IdentityAuditSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := append([]identity.IdentityAuditSummary(nil), s.events...)
	if len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	return result, nil
}

func (s *staticIdentityAuditStore) RevokeSessionAs(ctx context.Context, actor identity.Actor, sessionID string, at time.Time, reason string) (identity.Session, error) {
	return s.delegate.RevokeSessionAs(ctx, actor, sessionID, at, reason)
}

func (s *staticIdentityAuditStore) RevokePrincipalAs(ctx context.Context, actor identity.Actor, principalID string, at time.Time, reason string) (int, error) {
	return s.delegate.RevokePrincipalAs(ctx, actor, principalID, at, reason)
}

func loginAuditClient(t *testing.T, serverURL, adminToken string) (*http.Client, sessionResponse, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	body := []byte(fmt.Sprintf(`{"token":%q}`, adminToken))
	response, err := postTestLogin(client, serverURL, body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", response.StatusCode)
	}
	var loggedIn sessionResponse
	if err := json.NewDecoder(response.Body).Decode(&loggedIn); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	csrf := ""
	for _, cookie := range jar.Cookies(request.URL) {
		if cookie.Name == "mesh_csrf" || cookie.Name == "__Host-mesh_csrf" {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("login did not set a CSRF cookie")
	}
	return client, loggedIn, csrf
}

func decodeAuditResponse(t *testing.T, response *http.Response) []auditResponseEvent {
	t.Helper()
	var events []auditResponseEvent
	if err := json.NewDecoder(response.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	return events
}

func decodeAuditRecorder(t *testing.T, response *httptest.ResponseRecorder) []auditResponseEvent {
	t.Helper()
	var events []auditResponseEvent
	if err := json.NewDecoder(response.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	return events
}

func findAuditEvent(t *testing.T, events []auditResponseEvent, action, resourceID string) auditResponseEvent {
	t.Helper()
	for _, event := range events {
		if event.Action == action && event.ResourceID == resourceID {
			return event
		}
	}
	t.Fatalf("audit event %s for %s was not found in %#v", action, resourceID, events)
	return auditResponseEvent{}
}

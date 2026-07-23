package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileStoreIdentityAuditLifecycleActorsIdempotencyAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	targetInput := testCreateSessionInput(t, "session_target", now)
	target, err := store.CreateSession(context.Background(), targetInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSession(context.Background(), targetInput); err != nil {
		t.Fatalf("idempotent create: %v", err)
	}

	servicePrincipal, err := NewServicePrincipal("auditor", "Audit automation", now)
	if err != nil {
		t.Fatal(err)
	}
	callerInput := testCreateSessionInput(t, "session_caller", now)
	callerInput.Token, callerInput.CSRFToken = mustToken(t), mustToken(t)
	callerInput.Principal, callerInput.AuthMethod = servicePrincipal, "service_account"
	caller, err := store.CreateSession(context.Background(), callerInput)
	if err != nil {
		t.Fatal(err)
	}
	callerActor, err := caller.Actor()
	if err != nil {
		t.Fatal(err)
	}

	before, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{SessionID: target.ID, Limit: 10})
	if err != nil || len(before) != 1 || before[0].Type != IdentityAuditSessionCreated {
		t.Fatalf("created audit = %#v, %v", before, err)
	}
	created := before[0]
	if created.Actor.ID != target.Principal.ID || created.Actor.Kind != target.Principal.Kind || created.Actor.SessionID != target.ID || created.Details["auth_method"] != "oidc" || created.Details["session_version"] != "1" {
		t.Fatalf("created attribution = %#v", created)
	}

	forged := callerActor
	forged.ID = "service_forged"
	if _, err := store.RevokeSessionAs(context.Background(), forged, target.ID, now.Add(time.Minute), "forged caller"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged session actor = %v, want unauthorized", err)
	}
	if _, err := store.RevokeSessionAs(context.Background(), callerActor, target.ID, caller.IdleExpiresAt, "expired caller"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("caller at exact idle expiry = %v, want unauthorized", err)
	}
	oidcWithoutSession, err := target.Principal.Actor("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeSessionAs(context.Background(), oidcWithoutSession, target.ID, now.Add(time.Minute), "sessionless OIDC caller"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("sessionless OIDC actor = %v, want unauthorized", err)
	}
	if events, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{SessionID: target.ID, Limit: 10}); err != nil || len(events) != 1 {
		t.Fatalf("forged caller changed audit = %#v, %v", events, err)
	}

	newToken, newCSRF := mustToken(t), mustToken(t)
	rotated, err := store.RotateSession(context.Background(), target.ID, target.Version, newToken, newCSRF, now.Add(2*time.Minute), now.Add(17*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateSession(context.Background(), target.ID, target.Version, newToken, newCSRF, now.Add(2*time.Minute), now.Add(17*time.Minute)); err != nil {
		t.Fatalf("idempotent rotation: %v", err)
	}
	revoked, err := store.RevokeSessionAs(context.Background(), callerActor, target.ID, now.Add(3*time.Minute), "operator logout")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeSessionAs(context.Background(), callerActor, target.ID, now.Add(3*time.Minute), "operator logout"); err != nil {
		t.Fatalf("idempotent revocation: %v", err)
	}
	if revoked.Version != rotated.Version+1 {
		t.Fatalf("revoked version = %d, want %d", revoked.Version, rotated.Version+1)
	}

	events, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{PrincipalID: target.Principal.ID, SessionID: target.ID, Limit: 10})
	if err != nil || len(events) != 3 {
		t.Fatalf("session audit = %#v, %v", events, err)
	}
	if events[0].Type != IdentityAuditSessionRevoked || events[0].Actor != callerActor || events[0].Details["reason"] != "operator logout" {
		t.Fatalf("revocation audit = %#v", events[0])
	}
	if events[1].Type != IdentityAuditSessionRotated || events[1].Actor.ID != target.Principal.ID || events[1].Actor.SessionID != target.ID || events[1].Details["session_version"] != "2" {
		t.Fatalf("rotation audit = %#v", events[1])
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token_hash", "csrf_hash", targetInput.Token, targetInput.CSRFToken, newToken, newCSRF} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("audit summary exposed credential material %q", forbidden)
		}
	}
	events[0].Details["reason"] = "mutated"
	again, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{SessionID: target.ID, Type: IdentityAuditSessionRevoked, Limit: 1})
	if err != nil || len(again) != 1 || again[0].Details["reason"] != "operator logout" {
		t.Fatalf("audit summary was not deeply cloned: %#v, %v", again, err)
	}
	if _, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: 0}); err == nil {
		t.Fatal("unbounded identity audit listing was accepted")
	}
	if _, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Type: "session.unknown", Limit: 1}); err == nil {
		t.Fatal("unknown identity audit type was accepted")
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	restarted, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{SessionID: target.ID, Limit: 10})
	if err != nil || len(restarted) != 3 || restarted[0].Type != IdentityAuditSessionRevoked {
		t.Fatalf("restarted audit = %#v, %v", restarted, err)
	}
}

func TestFileStoreIdentityAuditPrincipalRevocationActorsAndIdempotency(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	firstInput := testCreateSessionInput(t, "session_first", now)
	first, err := store.CreateSession(context.Background(), firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := testCreateSessionInput(t, "session_second", now)
	secondInput.Token, secondInput.CSRFToken, secondInput.Principal = mustToken(t), mustToken(t), first.Principal
	if _, err := store.CreateSession(context.Background(), secondInput); err != nil {
		t.Fatal(err)
	}
	servicePrincipal, err := NewServicePrincipal("revoker", "Revoker", now)
	if err != nil {
		t.Fatal(err)
	}
	callerInput := testCreateSessionInput(t, "session_revoker", now)
	callerInput.Token, callerInput.CSRFToken, callerInput.Principal, callerInput.AuthMethod = mustToken(t), mustToken(t), servicePrincipal, "service_account"
	caller, err := store.CreateSession(context.Background(), callerInput)
	if err != nil {
		t.Fatal(err)
	}
	callerActor, _ := caller.Actor()
	count, err := store.RevokePrincipalAs(context.Background(), callerActor, first.Principal.ID, now.Add(time.Minute), "identity disabled")
	if err != nil || count != 2 {
		t.Fatalf("principal revocation count=%d err=%v", count, err)
	}
	if count, err := store.RevokePrincipalAs(context.Background(), callerActor, first.Principal.ID, now.Add(time.Minute), "identity disabled"); err != nil || count != 0 {
		t.Fatalf("principal revocation retry count=%d err=%v", count, err)
	}

	thirdInput := testCreateSessionInput(t, "session_third", now.Add(2*time.Minute))
	thirdInput.Token, thirdInput.CSRFToken = mustToken(t), mustToken(t)
	thirdInput.Principal = first.Principal
	thirdInput.Principal.AuthTime = now
	thirdInput.AuthMethod = "oidc"
	if _, err := store.CreateSession(context.Background(), thirdInput); err != nil {
		t.Fatal(err)
	}
	if count, err := store.RevokePrincipal(context.Background(), first.Principal.ID, now.Add(3*time.Minute), "self sign out everywhere"); err != nil || count != 1 {
		t.Fatalf("legacy principal self-revocation count=%d err=%v", count, err)
	}

	events, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{PrincipalID: first.Principal.ID, Type: IdentityAuditPrincipalRevoked, Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("principal audit = %#v, %v", events, err)
	}
	if events[0].Actor.ID != first.Principal.ID || events[0].Actor.Kind != first.Principal.Kind || events[0].Actor.SessionID != "" || events[0].Details["revoked_sessions"] != "1" {
		t.Fatalf("legacy principal actor = %#v", events[0])
	}
	if events[1].Actor != callerActor || events[1].Details["revoked_sessions"] != "2" {
		t.Fatalf("explicit principal actor = %#v", events[1])
	}
}

func TestFileStoreMigratesStrictV1IdentityStateToV2Once(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_migrated", now)
	if _, err := store.CreateSession(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current := dumpIdentityState(t, path)
	legacy := legacyIdentityStateV1{
		Schema: legacyIdentityStateSchema, LoginAttempts: current.LoginAttempts,
		Sessions: current.Sessions, BreakGlassCodes: current.BreakGlassCodes,
	}
	writePrivateJSON(t, path, legacy)

	store = openTestStore(t, path)
	if store.state.Schema != identityStateSchema || store.state.Audit == nil || len(store.state.Audit) != 0 || len(store.state.Sessions) != 1 {
		t.Fatalf("migrated state = %s", debugState(store.state))
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(time.Minute)); err != nil {
		t.Fatalf("migrated session is unusable: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	firstMigration, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(firstMigration, []byte(`"schema": "identity-state-v2"`)) || !bytes.Contains(firstMigration, []byte(`"audit": []`)) {
		t.Fatalf("migration did not persist required v2 audit array: %s", firstMigration)
	}
	store = openTestStore(t, path)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	secondOpen, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstMigration, secondOpen) {
		t.Fatal("opening v2 state rewrote the already-completed migration")
	}
}

func TestFileStoreRejectsAuditlessDowngradedAndTamperedState(t *testing.T) {
	minimalV1 := `{"schema":"identity-state-v1","login_attempts":[],"sessions":[],"break_glass_codes":[]`
	minimalV2 := `{"schema":"identity-state-v2","login_attempts":[],"sessions":[],"break_glass_codes":[]`
	tests := []struct {
		name string
		raw  string
	}{
		{name: "v1 smuggled audit", raw: minimalV1 + `,"audit":[]}`},
		{name: "v2 missing audit", raw: minimalV2 + `}`},
		{name: "v2 null audit", raw: minimalV2 + `,"audit":null}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.json")
			if err := os.WriteFile(path, []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
				t.Fatalf("accepted malformed schema state: %s", test.raw)
			}
		})
	}

	t.Run("semantic actor tamper", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		if _, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_tamper", identityTestTime())); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		state := dumpIdentityState(t, path)
		state.Audit[0].Actor = Actor{ID: "service_forged", Kind: PrincipalService}
		writePrivateJSON(t, path, state)
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("accepted semantically forged audit actor")
		}
	})

	t.Run("reserved actor detail", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		if _, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_reserved", identityTestTime())); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		state := dumpIdentityState(t, path)
		state.Audit[0].Details["actor_id"] = "legacy_admin"
		writePrivateJSON(t, path, state)
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("accepted actor attribution in scalar details")
		}
	})

	t.Run("duplicate audit ID", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		if _, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_duplicate", identityTestTime())); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		state := dumpIdentityState(t, path)
		state.Audit = append(state.Audit, cloneIdentityAuditEvent(state.Audit[0]))
		writePrivateJSON(t, path, state)
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("accepted duplicate audit event ID")
		}
	})

	t.Run("non-string detail", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		if _, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_scalar", identityTestTime())); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte(`"session_version": "1"`), []byte(`"session_version": 1`), 1)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("accepted non-string audit detail")
		}
	})
}

func TestFileStoreAuditLimitRollsBackSessionMutation(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_limit", now)
	created, err := store.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.Audit = make([]IdentityAuditEvent, maxIdentityAuditEvents)
	store.mu.Unlock()
	newToken, newCSRF := mustToken(t), mustToken(t)
	if _, err := store.RotateSession(context.Background(), created.ID, created.Version, newToken, newCSRF, now.Add(time.Minute), now.Add(16*time.Minute)); !errors.Is(err, ErrLimit) {
		t.Fatalf("audit-limit rotation = %v, want limit", err)
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("audit-limit failure partially rotated old credential: %v", err)
	}
	if _, err := store.AuthenticateSession(context.Background(), newToken, input.PolicyFingerprint, now.Add(2*time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("audit-limit failure committed new credential: %v", err)
	}
	store.mu.Lock()
	version, auditCount := store.state.Sessions[0].Version, len(store.state.Audit)
	store.mu.Unlock()
	if version != created.Version || auditCount != maxIdentityAuditEvents {
		t.Fatalf("audit-limit rollback version=%d audit=%d", version, auditCount)
	}
}

func TestFileStoreConcurrentIdentityAuditWritesAndReads(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	const sessions = 12
	ids := make([]string, sessions)
	for index := range ids {
		ids[index] = "session_race_" + string(rune('a'+index))
		input := testCreateSessionInput(t, ids[index], now)
		if _, err := store.CreateSession(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for _, id := range ids {
		id := id
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, err := store.RevokeSession(context.Background(), id, now.Add(time.Minute), "concurrent logout"); err != nil {
				t.Errorf("revoke %s: %v", id, err)
			}
		}()
	}
	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 20; iteration++ {
				if _, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: MaxIdentityAuditListLimit}); err != nil {
					t.Errorf("concurrent audit list: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	events, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: MaxIdentityAuditListLimit})
	if err != nil || len(events) != sessions*2 {
		t.Fatalf("concurrent audit count=%d err=%v", len(events), err)
	}
}

func TestIdentityAuditModelRejectsOversizedAndReservedDetails(t *testing.T) {
	now := identityTestTime()
	principal, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := principal.Actor("session_model")
	if err != nil {
		t.Fatal(err)
	}
	event, err := newIdentityAuditEvent(IdentityAuditSessionRevoked, now, actor, principal.ID, "session_model", map[string]string{"reason": "logout", "session_version": "2"})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxIdentityAuditDetails; index++ {
		event.Details["extra_"+strings.Repeat("x", index)] = "value"
	}
	if err := validateIdentityAuditEvent(event); err == nil {
		t.Fatal("accepted oversized identity audit details")
	}
}

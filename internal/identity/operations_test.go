package identity

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeIdentityStateBackend struct {
	mu sync.Mutex

	state     identityState
	closed    bool
	viewErr   error
	updateErr error

	viewCalls       int
	viewCallbacks   int
	updateCalls     int
	updateCallbacks int
	commits         int
}

func newFakeIdentityStateBackend() *fakeIdentityStateBackend {
	return &fakeIdentityStateBackend{state: identityState{
		Schema: identityStateSchema, LoginAttempts: []persistedLoginAttempt{}, Sessions: []Session{},
		BreakGlassCodes: []BreakGlassCode{}, Audit: []IdentityAuditEvent{},
	}}
}

func (b *fakeIdentityStateBackend) viewIdentityState(ctx context.Context, inspect func(identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.viewCalls++
	if b.closed {
		return ErrClosed
	}
	if b.viewErr != nil {
		return b.viewErr
	}
	snapshot := cloneIdentityState(b.state)
	b.viewCallbacks++
	err := inspect(snapshot)
	if contextErr := identityContextError(ctx); contextErr != nil {
		return contextErr
	}
	return err
}

func (b *fakeIdentityStateBackend) updateIdentityState(ctx context.Context, mutate func(*identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateCalls++
	if b.closed {
		return ErrClosed
	}
	if b.updateErr != nil {
		return b.updateErr
	}
	next := cloneIdentityState(b.state)
	b.updateCallbacks++
	if err := mutate(&next); err != nil {
		return err
	}
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if reflect.DeepEqual(next, b.state) {
		return nil
	}
	b.state = cloneIdentityState(next)
	b.commits++
	return nil
}

func (b *fakeIdentityStateBackend) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

func (b *fakeIdentityStateBackend) setViewError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.viewErr = err
}

func (b *fakeIdentityStateBackend) setUpdateError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateErr = err
}

func (b *fakeIdentityStateBackend) counters() (viewCallbacks, updateCallbacks, commits int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.viewCallbacks, b.updateCallbacks, b.commits
}

func TestIdentityOperationsShareWholeDocumentBackend(t *testing.T) {
	backend := newFakeIdentityStateBackend()
	sealer := newTestSealer(t)
	firstCore := newIdentityOperations(backend, sealer)
	secondCore := newIdentityOperations(backend, sealer)
	now := identityTestTime()

	firstInput := testCreateSessionInput(t, "session_shared_first", now)
	first, err := firstCore.CreateSession(context.Background(), firstInput)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := secondCore.AuthenticateSession(context.Background(), firstInput.Token, firstInput.PolicyFingerprint, now.Add(1))
	if err != nil || authenticated.ID != first.ID {
		t.Fatalf("second core did not observe first commit: session=%#v err=%v", authenticated, err)
	}

	secondInput := testCreateSessionInput(t, "session_shared_second", now)
	if _, err := secondCore.CreateSession(context.Background(), secondInput); err != nil {
		t.Fatal(err)
	}
	listed, err := firstCore.ListSessions(context.Background(), SessionListFilter{IncludeRevoked: true, Limit: 10})
	if err != nil || len(listed) != 2 {
		t.Fatalf("first core lost sequential backend state: sessions=%#v err=%v", listed, err)
	}

	// Generic backend views are detached even if a callback violates the
	// read-only operations convention.
	if err := backend.viewIdentityState(context.Background(), func(state identityState) error {
		state.Sessions[0].Principal.Groups[0] = "mutated"
		state.Sessions = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	again, err := secondCore.ListSessions(context.Background(), SessionListFilter{IncludeRevoked: true, Limit: 10})
	if err != nil || len(again) != 2 || again[0].Principal.Groups[0] != "admins" {
		t.Fatalf("backend view leaked mutable state: sessions=%#v err=%v", again, err)
	}

	_, callbacksBefore, commitsBefore := backend.counters()
	if _, err := firstCore.CreateSession(context.Background(), firstInput); err != nil {
		t.Fatalf("exact session retry: %v", err)
	}
	_, callbacksAfter, commitsAfter := backend.counters()
	if callbacksAfter != callbacksBefore+1 || commitsAfter != commitsBefore {
		t.Fatalf("no-op callback/commit counts = %d/%d, want %d/%d", callbacksAfter, commitsAfter, callbacksBefore+1, commitsBefore)
	}
}

func TestBreakGlassLifecycleIsAuditedCredentialFreeAndIdempotent(t *testing.T) {
	backend := newFakeIdentityStateBackend()
	core := newIdentityOperations(backend, newTestSealer(t))
	now := identityTestTime()

	sessionInput := testCreateSessionInput(t, "session_break_glass_admin", now)
	session, err := core.CreateSession(context.Background(), sessionInput)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := session.Actor()
	if err != nil {
		t.Fatal(err)
	}
	firstToken := mustToken(t)
	firstInput := BreakGlassCodeInput{
		ID: "bg_first", Token: firstToken, CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Second).Add(MinBreakGlassCodeLifetime),
	}
	first, created, err := core.RegisterBreakGlassCodeAs(context.Background(), actor, firstInput)
	if err != nil || !created || first.ID != firstInput.ID || first.State != BreakGlassCodeUsable {
		t.Fatalf("register first = %#v, %t, %v", first, created, err)
	}
	retryInput := firstInput
	retryInput.CreatedAt = retryInput.CreatedAt.Add(time.Second)
	retried, created, err := core.RegisterBreakGlassCodeAs(context.Background(), actor, retryInput)
	if err != nil || created || retried != first {
		t.Fatalf("registration retry = %#v, %t, %v", retried, created, err)
	}
	conflict := firstInput
	conflict.Token = mustToken(t)
	if _, _, err := core.RegisterBreakGlassCodeAs(context.Background(), actor, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("registration collision = %v", err)
	}

	listed, err := core.ListBreakGlassCodes(context.Background(), now.Add(2*time.Second))
	if err != nil || len(listed) != 1 || listed[0] != first {
		t.Fatalf("list = %#v, %v", listed, err)
	}
	usable, err := core.CountUsableBreakGlassCodes(context.Background(), now.Add(2*time.Second))
	if err != nil || usable != 1 {
		t.Fatalf("usable before consumption = %d, %v", usable, err)
	}
	if _, err := core.ConsumeBreakGlassCodeAs(context.Background(), first.ID, mustToken(t), now.Add(3*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong recovery code = %v", err)
	}
	consumed, err := core.ConsumeBreakGlassCodeAs(context.Background(), first.ID, firstToken, now.Add(3*time.Second))
	if err != nil || consumed.UsedAt == nil || !consumed.UsedAt.Equal(now.Add(3*time.Second)) {
		t.Fatalf("consume = %#v, %v", consumed, err)
	}
	if _, err := core.ConsumeBreakGlassCodeAs(context.Background(), first.ID, firstToken, now.Add(4*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay = %v", err)
	}
	if _, err := core.RevokeBreakGlassCodeAs(context.Background(), actor, first.ID, now.Add(4*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoke used code = %v", err)
	}

	secondInput := BreakGlassCodeInput{
		ID: "bg_second", Token: mustToken(t), CreatedAt: now.Add(5 * time.Second), ExpiresAt: now.Add(48 * time.Hour),
	}
	if _, created, err := core.RegisterBreakGlassCodeAs(context.Background(), actor, secondInput); err != nil || !created {
		t.Fatalf("register second = %t, %v", created, err)
	}
	revoked, err := core.RevokeBreakGlassCodeAs(context.Background(), actor, secondInput.ID, now.Add(6*time.Second))
	if err != nil || revoked.State != BreakGlassCodeRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoke second = %#v, %v", revoked, err)
	}
	repeated, err := core.RevokeBreakGlassCodeAs(context.Background(), actor, secondInput.ID, now.Add(7*time.Second))
	if err != nil || repeated.ID != revoked.ID || repeated.State != BreakGlassCodeRevoked {
		t.Fatalf("repeat revoke = %#v, %v", repeated, err)
	}

	breakGlassPrincipal, err := NewBreakGlassPrincipal(first.ID, now.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	breakGlassActor, err := breakGlassPrincipal.Actor("")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.RegisterBreakGlassCodeAs(context.Background(), breakGlassActor, BreakGlassCodeInput{
		ID: "bg_forbidden", Token: mustToken(t), CreatedAt: now.Add(8 * time.Second), ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("break-glass principal registered replacement code: %v", err)
	}

	usable, err = core.CountUsableBreakGlassCodes(context.Background(), now.Add(9*time.Second))
	if err != nil || usable != 0 {
		t.Fatalf("usable after consumption and revocation = %d, %v", usable, err)
	}
	audit, err := core.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[IdentityAuditEventType]int{}
	for _, event := range audit {
		counts[event.Type]++
		if event.Type == IdentityAuditBreakGlassRegistered || event.Type == IdentityAuditBreakGlassConsumed || event.Type == IdentityAuditBreakGlassRevoked {
			if event.TargetPrincipalID == "" || len(event.Details) != 1 {
				t.Fatalf("unsafe break-glass audit: %#v", event)
			}
		}
	}
	if counts[IdentityAuditBreakGlassRegistered] != 2 || counts[IdentityAuditBreakGlassConsumed] != 1 || counts[IdentityAuditBreakGlassRevoked] != 1 {
		t.Fatalf("break-glass audit counts = %#v", counts)
	}
}

func TestIdentityOperationsBackendErrorsCallbacksAndCloseFailClosed(t *testing.T) {
	backend := newFakeIdentityStateBackend()
	core := newIdentityOperations(backend, newTestSealer(t))
	sentinel := errors.New("injected backend failure")

	mutations := 0
	_, callbacksBefore, commitsBefore := backend.counters()
	if err := core.update(context.Background(), func(state *identityState) error {
		mutations++
		state.Schema = "invalid"
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("mutation error = %v, want sentinel", err)
	}
	_, callbacksAfter, commitsAfter := backend.counters()
	if mutations != 1 || callbacksAfter != callbacksBefore+1 || commitsAfter != commitsBefore {
		t.Fatalf("error callback counts mutations=%d callbacks=%d commits=%d", mutations, callbacksAfter-callbacksBefore, commitsAfter-commitsBefore)
	}

	backend.setUpdateError(sentinel)
	mutations = 0
	if err := core.update(context.Background(), func(*identityState) error { mutations++; return nil }); !errors.Is(err, sentinel) || mutations != 0 {
		t.Fatalf("backend update failure = %v mutations=%d", err, mutations)
	}
	backend.setUpdateError(nil)

	backend.setViewError(sentinel)
	viewCallbacksBefore, _, _ := backend.counters()
	if _, err := core.ListSessions(context.Background(), SessionListFilter{Limit: 1}); !errors.Is(err, sentinel) {
		t.Fatalf("backend view failure = %v, want sentinel", err)
	}
	viewCallbacksAfter, _, _ := backend.counters()
	if viewCallbacksAfter != viewCallbacksBefore {
		t.Fatal("backend view failure invoked the read callback")
	}
	backend.setViewError(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	viewCallbacksBefore, callbacksBefore, _ = backend.counters()
	if _, err := core.ListSessions(ctx, SessionListFilter{Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled view = %v", err)
	}
	if err := core.update(ctx, func(*identityState) error { mutations++; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled update = %v", err)
	}
	viewCallbacksAfter, callbacksAfter, _ = backend.counters()
	if viewCallbacksAfter != viewCallbacksBefore || callbacksAfter != callbacksBefore {
		t.Fatal("pre-canceled context reached a backend callback")
	}

	viewCtx, cancelView := context.WithCancel(context.Background())
	readCallbacks := 0
	if err := core.view(viewCtx, func(identityState) error {
		readCallbacks++
		cancelView()
		return nil
	}); !errors.Is(err, context.Canceled) || readCallbacks != 1 {
		t.Fatalf("context canceled during view = %v callbacks=%d", err, readCallbacks)
	}
	updateCtx, cancelUpdate := context.WithCancel(context.Background())
	_, callbacksBefore, commitsBefore = backend.counters()
	mutations = 0
	if err := core.update(updateCtx, func(*identityState) error {
		mutations++
		cancelUpdate()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("context canceled during update = %v", err)
	}
	_, callbacksAfter, commitsAfter = backend.counters()
	if mutations != 1 || callbacksAfter != callbacksBefore+1 || commitsAfter != commitsBefore {
		t.Fatalf("mid-update cancellation mutations=%d callbacks=%d commits=%d", mutations, callbacksAfter-callbacksBefore, commitsAfter-commitsBefore)
	}

	backend.close()
	if _, err := core.ListSessions(context.Background(), SessionListFilter{Limit: 1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed backend read = %v", err)
	}
	if _, err := core.CleanupExpired(context.Background(), identityTestTime()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed backend update = %v", err)
	}
}

func TestFileStoreAuthenticationDoesNotCloneWholeState(t *testing.T) {
	store := openTestStore(t, t.TempDir()+"/identity.json")
	defer store.Close()
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_auth_clone_regression", now)
	if _, err := store.CreateSession(context.Background(), input); err != nil {
		t.Fatal(err)
	}

	before := store.cloneCount.Load()
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(context.Background(), mustToken(t), input.PolicyFingerprint, now.Add(1)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown credential = %v, want unauthorized", err)
	}
	if _, err := store.ListSessions(context.Background(), SessionListFilter{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if after := store.cloneCount.Load(); after != before {
		t.Fatalf("identity read hot paths cloned whole state: before=%d after=%d", before, after)
	}
}

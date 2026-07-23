package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"mesh/internal/postgresstore"
)

type fakePostgresIdentityRepository struct {
	mu sync.Mutex

	body          []byte
	readErr       error
	updateErr     error
	readinessErr  error
	blockRead     bool
	updateReady   chan struct{}
	releaseUpdate <-chan struct{}

	readCalls      int
	updateCalls    int
	readinessCalls int
	mutateCalls    int
	lastDomain     postgresstore.Domain
	lastOperation  string
}

func (r *fakePostgresIdentityRepository) Read(ctx context.Context, domain postgresstore.Domain) (postgresstore.Document, error) {
	r.mu.Lock()
	r.readCalls++
	r.lastDomain = domain
	block, readErr, body := r.blockRead, r.readErr, append([]byte(nil), r.body...)
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return postgresstore.Document{}, ctx.Err()
	}
	if readErr != nil {
		return postgresstore.Document{}, readErr
	}
	return postgresstore.Document{Domain: domain, Bytes: body}, nil
}

func (r *fakePostgresIdentityRepository) Update(ctx context.Context, domain postgresstore.Domain, operation string, mutate func([]byte) ([]byte, error)) (postgresstore.WriteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateCalls++
	r.lastDomain = domain
	r.lastOperation = operation
	if r.updateErr != nil {
		return postgresstore.WriteResult{}, r.updateErr
	}
	if err := ctx.Err(); err != nil {
		return postgresstore.WriteResult{}, err
	}
	r.mutateCalls++
	next, err := mutate(append([]byte(nil), r.body...))
	if err != nil {
		return postgresstore.WriteResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return postgresstore.WriteResult{}, err
	}
	if r.updateReady != nil {
		close(r.updateReady)
		r.updateReady = nil
		<-r.releaseUpdate
		if err := ctx.Err(); err != nil {
			return postgresstore.WriteResult{}, err
		}
	}
	changed := !bytes.Equal(next, r.body)
	if changed {
		r.body = append([]byte(nil), next...)
	}
	return postgresstore.WriteResult{
		Changed:  changed,
		Document: postgresstore.Document{Domain: domain, Bytes: append([]byte(nil), r.body...)},
	}, nil
}

func (r *fakePostgresIdentityRepository) CheckReadiness(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readinessCalls++
	return r.readinessErr
}

func (r *fakePostgresIdentityRepository) bodyCopy() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.body...)
}

func (r *fakePostgresIdentityRepository) setBody(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = append([]byte(nil), body...)
}

func (r *fakePostgresIdentityRepository) setUpdateError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateErr = err
}

func (r *fakePostgresIdentityRepository) setReadinessError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readinessErr = err
}

func nonCanonicalValidIdentityRaw() []byte {
	return []byte("{\n  \"sessions\" : [ ],\n  \"schema\" : \"identity-state-v2\",\n  \"audit\" : [ ],\n  \"break_glass_codes\" : [ ],\n  \"login_attempts\" : [ ]\n}\n")
}

func newTestPostgresIdentityStore(t *testing.T, repository postgresIdentityRepository, sealer Sealer, options PostgresStoreOptions) *PostgresStore {
	t.Helper()
	store, err := newPostgresStore(repository, sealer, options)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func invalidSealedIdentityRaw(t *testing.T) []byte {
	t.Helper()
	now := identityTestTime()
	transactionHash, err := HashOpaqueToken(mustToken(t))
	if err != nil {
		t.Fatal(err)
	}
	stateHash, err := HashOpaqueToken(mustToken(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeIdentityStateDocument(identityState{
		Schema: identityStateSchema,
		LoginAttempts: []persistedLoginAttempt{{
			ID: "login_invalid_sealed", TransactionHash: transactionHash, StateHash: stateHash,
			SealedOIDCPayload: "not-a-valid-sealed-payload", ReturnPath: "/networks",
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		}},
		Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{}, Audit: []IdentityAuditEvent{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPostgresStoreConstructorRejectsNilAndInvalidOptions(t *testing.T) {
	sealer := newTestSealer(t)
	if store, err := NewPostgresStore(nil, sealer, PostgresStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidPostgresStore) {
		t.Fatalf("public nil constructor = (%#v, %v), want invalid store", store, err)
	}
	var typedNilRepository *fakePostgresIdentityRepository
	if store, err := newPostgresStore(typedNilRepository, sealer, PostgresStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidPostgresStore) {
		t.Fatalf("typed-nil repository = (%#v, %v), want invalid store", store, err)
	}
	repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw()}
	if store, err := newPostgresStore(repository, nil, PostgresStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidPostgresStore) {
		t.Fatalf("nil sealer = (%#v, %v), want invalid store", store, err)
	}
	var typedNilSealer *testSealer
	if store, err := newPostgresStore(repository, typedNilSealer, PostgresStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidPostgresStore) {
		t.Fatalf("typed-nil sealer = (%#v, %v), want invalid store", store, err)
	}
	if store, err := newPostgresStore(repository, sealer, PostgresStoreOptions{OperationTimeout: -time.Second}); store != nil || !errors.Is(err, ErrInvalidPostgresStore) {
		t.Fatalf("negative timeout = (%#v, %v), want invalid store", store, err)
	}
}

func TestPostgresStoreRejectsInvalidCurrentDocumentBeforeCallbacks(t *testing.T) {
	legacy, err := json.MarshalIndent(legacyIdentityStateV1{
		Schema: legacyIdentityStateSchema, LoginAttempts: []persistedLoginAttempt{}, Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "malformed", raw: []byte(`{"schema":`)},
		{name: "duplicate", raw: []byte(`{"schema":"identity-state-v2","schema":"identity-state-v2","login_attempts":[],"sessions":[],"break_glass_codes":[],"audit":[]}`)},
		{name: "unknown", raw: []byte(`{"schema":"identity-state-v2","login_attempts":[],"sessions":[],"break_glass_codes":[],"audit":[],"unknown":true}`)},
		{name: "trailing", raw: append(nonCanonicalValidIdentityRaw(), []byte(` {}`)...)},
		{name: "legacy", raw: legacy},
		{name: "invalid sealed value", raw: invalidSealedIdentityRaw(t)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakePostgresIdentityRepository{body: append([]byte(nil), test.raw...)}
			store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
			viewCalled := false
			if err := store.viewIdentityState(context.Background(), func(identityState) error { viewCalled = true; return nil }); !errors.Is(err, postgresstore.ErrCorruptDocument) {
				t.Fatalf("view error = %v, want corrupt document", err)
			}
			updateCalled := false
			if err := store.updateIdentityState(context.Background(), func(*identityState) error { updateCalled = true; return nil }); !errors.Is(err, postgresstore.ErrCorruptDocument) {
				t.Fatalf("update error = %v, want corrupt document", err)
			}
			if viewCalled || updateCalled {
				t.Fatalf("invalid document reached callback: view=%t update=%t", viewCalled, updateCalled)
			}
		})
	}
}

func TestPostgresStoreNoOpPreservesExactRawBytes(t *testing.T) {
	raw := nonCanonicalValidIdentityRaw()
	repository := &fakePostgresIdentityRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	result, err := store.CleanupExpired(context.Background(), identityTestTime())
	if err != nil {
		t.Fatal(err)
	}
	if result != (CleanupResult{}) || repository.mutateCalls != 1 || repository.updateCalls != 1 {
		t.Fatalf("no-op result/calls = %#v, mutate %d update %d", result, repository.mutateCalls, repository.updateCalls)
	}
	if repository.lastDomain != postgresstore.DomainIdentity || repository.lastOperation != postgresIdentityUpdateOperation {
		t.Fatalf("write route = %q/%q", repository.lastDomain, repository.lastOperation)
	}
	if got := repository.bodyCopy(); !bytes.Equal(got, raw) {
		t.Fatalf("no-op rewrote exact bytes:\n got %q\nwant %q", got, raw)
	}
}

func TestPostgresStoreChangedStateUsesCanonicalEncoding(t *testing.T) {
	raw := nonCanonicalValidIdentityRaw()
	repository := &fakePostgresIdentityRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	now := identityTestTime()
	if err := store.CreateBreakGlassCode(context.Background(), BreakGlassCodeInput{
		ID: "bg_postgres", Token: mustToken(t), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	changed := repository.bodyCopy()
	if bytes.Equal(changed, raw) {
		t.Fatal("changed identity document retained source bytes")
	}
	state, err := decodeIdentityStateDocument(changed, false)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := encodeIdentityStateDocument(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(changed, canonical) || len(state.BreakGlassCodes) != 1 || state.BreakGlassCodes[0].ID != "bg_postgres" {
		t.Fatalf("changed document is not canonical or complete: %s", changed)
	}
}

func TestPostgresStoreCallbackErrorAndInvalidMutationRollBackOnce(t *testing.T) {
	raw := nonCanonicalValidIdentityRaw()
	repository := &fakePostgresIdentityRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	sentinel := errors.New("mutation rejected")
	calls := 0
	err := store.update(context.Background(), func(state *identityState) error {
		calls++
		state.Schema = "invalid"
		return sentinel
	})
	if !errors.Is(err, sentinel) || calls != 1 || repository.mutateCalls != 1 || !bytes.Equal(repository.bodyCopy(), raw) {
		t.Fatalf("callback rollback err=%v calls=%d repository=%d body=%q", err, calls, repository.mutateCalls, repository.bodyCopy())
	}
	calls = 0
	err = store.update(context.Background(), func(state *identityState) error {
		calls++
		state.Schema = "invalid"
		return nil
	})
	if err == nil || calls != 1 || repository.mutateCalls != 2 || !bytes.Equal(repository.bodyCopy(), raw) {
		t.Fatalf("invalid mutation rollback err=%v calls=%d repository=%d body=%q", err, calls, repository.mutateCalls, repository.bodyCopy())
	}
}

func TestPostgresStoreBoundsOperationsMapsErrorsAndClosesLogically(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw(), blockRead: true}
		store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{OperationTimeout: 10 * time.Millisecond})
		started := time.Now()
		_, err := store.ListSessions(context.Background(), SessionListFilter{Limit: 1})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bounded read = %v, want deadline", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("bounded read took %s", elapsed)
		}
	})

	tests := []struct {
		name           string
		source         error
		identityTarget error
	}{
		{name: "closed", source: &wrappedIdentityTestError{postgresstore.ErrClosed}, identityTarget: ErrClosed},
		{name: "uncertain", source: &wrappedIdentityTestError{postgresstore.ErrUncertainCommit}, identityTarget: ErrUncertainCommit},
		{name: "not committed", source: &wrappedIdentityTestError{postgresstore.ErrNotCommitted}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw(), updateErr: test.source}
			store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
			_, err := store.CleanupExpired(context.Background(), identityTestTime())
			if !errors.Is(err, test.source) {
				t.Fatalf("mapped error = %v, want source %v", err, test.source)
			}
			if test.identityTarget != nil && !errors.Is(err, test.identityTarget) {
				t.Fatalf("mapped error = %v, want identity target %v", err, test.identityTarget)
			}
			if test.identityTarget == nil && errors.Is(err, ErrUncertainCommit) {
				t.Fatalf("definite failure became uncertain: %v", err)
			}
		})
	}

	repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw()}
	first := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	second := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ListSessions(context.Background(), SessionListFilter{Limit: 1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed logical adapter read = %v", err)
	}
	if _, err := second.ListSessions(context.Background(), SessionListFilter{Limit: 1}); err != nil {
		t.Fatalf("closing first adapter closed shared repository: %v", err)
	}
}

func TestPostgresStoreCloseWaitsForAdmittedUpdate(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	repository := &fakePostgresIdentityRepository{
		body: nonCanonicalValidIdentityRaw(), updateReady: ready, releaseUpdate: release,
	}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	now := identityTestTime()
	token := mustToken(t)
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- store.CreateBreakGlassCode(context.Background(), BreakGlassCodeInput{
			ID: "bg_close_gate", Token: token, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("update did not reach the deterministic commit gate")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		store.lifecycleMu.Lock()
		closing := store.lifecycleClosed
		store.lifecycleMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not mark the adapter closed")
		}
		runtime.Gosched()
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before admitted update completed: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("admitted update failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted update did not finish")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after update drained")
	}
	state, err := decodeIdentityStateDocument(repository.bodyCopy(), false)
	if err != nil || len(state.BreakGlassCodes) != 1 || state.BreakGlassCodes[0].ID != "bg_close_gate" {
		t.Fatalf("admitted update did not commit before Close returned: state=%#v err=%v", state, err)
	}
	if _, err := store.CleanupExpired(context.Background(), now); !errors.Is(err, ErrClosed) {
		t.Fatalf("operation admitted after Close returned: %v", err)
	}
}

type wrappedIdentityTestError struct{ cause error }

func (e *wrappedIdentityTestError) Error() string { return "wrapped: " + e.cause.Error() }
func (e *wrappedIdentityTestError) Unwrap() error { return e.cause }

func TestPostgresStoreReadinessUsesLowLevelCheckAndFreshValidation(t *testing.T) {
	repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw()}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	if err := store.CheckReadiness(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.readinessCalls != 1 || repository.readCalls != 1 {
		t.Fatalf("readiness/read calls = %d/%d, want 1/1", repository.readinessCalls, repository.readCalls)
	}
	repository.setBody([]byte(`{"schema":"identity-state-v2"}`))
	if err := store.CheckReadiness(context.Background()); !errors.Is(err, postgresstore.ErrCorruptDocument) {
		t.Fatalf("invalid fresh identity readiness = %v, want corrupt", err)
	}
	readsBefore := repository.readCalls
	repository.setReadinessError(postgresstore.ErrUnwritablePrimary)
	if err := store.CheckReadiness(context.Background()); !errors.Is(err, postgresstore.ErrUnwritablePrimary) {
		t.Fatalf("low-level readiness failure = %v", err)
	}
	if repository.readCalls != readsBefore {
		t.Fatal("adapter read identity document after low-level readiness failed")
	}
}

func TestPostgresStoreAdaptersObserveSessionAndRevocationImmediately(t *testing.T) {
	repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw()}
	sealer := newTestSealer(t)
	first := newTestPostgresIdentityStore(t, repository, sealer, PostgresStoreOptions{})
	second := newTestPostgresIdentityStore(t, repository, sealer, PostgresStoreOptions{})
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_postgres_shared", now)
	created, err := first.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := second.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(time.Second))
	if err != nil || observed.ID != created.ID {
		t.Fatalf("second adapter missed session: %#v err=%v", observed, err)
	}
	revokedAt := now.Add(time.Minute)
	if _, err := second.RevokeSession(context.Background(), created.ID, revokedAt, "administrator revocation"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(2*time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("first adapter retained stale pre-revocation state: %v", err)
	}
	sessions, err := first.ListSessions(context.Background(), SessionListFilter{IncludeRevoked: true, Limit: 10})
	if err != nil || len(sessions) != 1 || sessions[0].RevokedAt == nil || !sessions[0].RevokedAt.Equal(revokedAt) {
		t.Fatalf("revocation not authoritative: sessions=%#v err=%v", sessions, err)
	}
	audit, err := first.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: 10})
	if err != nil || len(audit) != 2 {
		t.Fatalf("shared audit state = %#v err=%v", audit, err)
	}
}

func TestPostgresStoreAdapterExecutesAuditedBreakGlassLifecycle(t *testing.T) {
	repository := &fakePostgresIdentityRepository{body: nonCanonicalValidIdentityRaw()}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	now := identityTestTime()
	session, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_postgres_breakglass", now))
	if err != nil {
		t.Fatal(err)
	}
	actor, err := session.Actor()
	if err != nil {
		t.Fatal(err)
	}
	firstToken, secondToken := mustToken(t), mustToken(t)
	for _, input := range []BreakGlassCodeInput{
		{ID: "bg_postgres_first", Token: firstToken, CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(24 * time.Hour)},
		{ID: "bg_postgres_second", Token: secondToken, CreatedAt: now.Add(2 * time.Second), ExpiresAt: now.Add(48 * time.Hour)},
	} {
		if _, created, err := store.RegisterBreakGlassCodeAs(context.Background(), actor, input); err != nil || !created {
			t.Fatalf("register %s = %t, %v", input.ID, created, err)
		}
	}
	if _, err := store.ConsumeBreakGlassCodeAs(context.Background(), "bg_postgres_first", firstToken, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeBreakGlassCodeAs(context.Background(), actor, "bg_postgres_second", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if usable, err := store.CountUsableBreakGlassCodes(context.Background(), now.Add(5*time.Second)); err != nil || usable != 0 {
		t.Fatalf("usable codes = %d, %v", usable, err)
	}
	codes, err := store.ListBreakGlassCodes(context.Background(), now.Add(5*time.Second))
	if err != nil || len(codes) != 2 || codes[0].State == BreakGlassCodeUsable || codes[1].State == BreakGlassCodeUsable {
		t.Fatalf("credential-free inventory = %#v, %v", codes, err)
	}
	audit, err := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Limit: 20})
	if err != nil || len(audit) != 5 {
		t.Fatalf("audited PostgreSQL lifecycle = %#v, %v", audit, err)
	}
}

func TestPostgresStoreExportRecoverySnapshotIsExactDetachedAndValidated(t *testing.T) {
	raw := nonCanonicalValidIdentityRaw()
	repository := &fakePostgresIdentityRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresIdentityStore(t, repository, newTestSealer(t), PostgresStoreOptions{})
	exported, err := store.ExportRecoverySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exported, raw) {
		t.Fatalf("export bytes = %q, want exact %q", exported, raw)
	}
	exported[0] ^= 0xff
	again, err := store.ExportRecoverySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, raw) || !bytes.Equal(repository.bodyCopy(), raw) {
		t.Fatal("export retained mutable authoritative bytes")
	}
	repository.setBody(invalidSealedIdentityRaw(t))
	if _, err := store.ExportRecoverySnapshot(context.Background()); !errors.Is(err, postgresstore.ErrCorruptDocument) {
		t.Fatalf("export accepted invalid sealed state: %v", err)
	}
}

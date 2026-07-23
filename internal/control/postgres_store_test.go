package control

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"mesh/internal/postgresstore"
)

type fakePostgresControlRepository struct {
	mu             sync.Mutex
	body           []byte
	readErr        error
	updateErr      error
	readinessErr   error
	blockRead      bool
	readCalls      int
	updateCalls    int
	readinessCalls int
	mutateCalls    int
	lastOperation  string
}

func (r *fakePostgresControlRepository) Read(ctx context.Context, domain postgresstore.Domain) (postgresstore.Document, error) {
	if r.blockRead {
		<-ctx.Done()
		return postgresstore.Document{}, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readCalls++
	if r.readErr != nil {
		return postgresstore.Document{}, r.readErr
	}
	return postgresstore.Document{Domain: domain, Bytes: append([]byte(nil), r.body...)}, nil
}

func (r *fakePostgresControlRepository) Update(ctx context.Context, domain postgresstore.Domain, operation string, mutate func([]byte) ([]byte, error)) (postgresstore.WriteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateCalls++
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
	changed := !bytes.Equal(next, r.body)
	if changed {
		r.body = append([]byte(nil), next...)
	}
	return postgresstore.WriteResult{
		Changed:  changed,
		Document: postgresstore.Document{Domain: domain, Bytes: append([]byte(nil), r.body...)},
	}, nil
}

func (r *fakePostgresControlRepository) CheckReadiness(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readinessCalls++
	return r.readinessErr
}

func nonCanonicalValidControlRaw() []byte {
	return []byte("{\n  \"audit\" : [ ],\n  \"enrollments\" : [ ],\n  \"networks\" : [ ],\n  \"nodes\" : [ ],\n  \"version\" : 1\n}\n")
}

func newTestPostgresStateStore(t *testing.T, repository postgresControlRepository, options PostgresStateStoreOptions) *PostgresStateStore {
	t.Helper()
	store, err := newPostgresStateStore(repository, options)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPostgresStateStoreConstructorRejectsNilAndInvalidOptions(t *testing.T) {
	if store, err := NewPostgresStateStore(nil, PostgresStateStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidStateStore) {
		t.Fatalf("public nil constructor = (%#v, %v), want invalid store", store, err)
	}
	var typedNil *fakePostgresControlRepository
	if store, err := newPostgresStateStore(typedNil, PostgresStateStoreOptions{}); store != nil || !errors.Is(err, ErrInvalidStateStore) {
		t.Fatalf("typed-nil constructor = (%#v, %v), want invalid store", store, err)
	}
	if store, err := newPostgresStateStore(&fakePostgresControlRepository{}, PostgresStateStoreOptions{OperationTimeout: -time.Second}); store != nil || !errors.Is(err, ErrInvalidStateStore) {
		t.Fatalf("negative-timeout constructor = (%#v, %v), want invalid store", store, err)
	}
}

func TestPostgresStateStoreRejectsMalformedAndInvalidCurrentBeforeCallbacks(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "malformed", raw: []byte(`{"version":`)},
		{name: "invalid graph", raw: []byte(`{"version":3,"networks":null,"nodes":null,"enrollments":null,"audit":null}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakePostgresControlRepository{body: test.raw}
			store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
			viewCalled := false
			if err := store.View(func(State) error { viewCalled = true; return nil }); !errors.Is(err, postgresstore.ErrCorruptDocument) {
				t.Fatalf("View() error = %v, want corrupt document", err)
			}
			updateCalled := false
			if err := store.Update(func(*State) error { updateCalled = true; return nil }); !errors.Is(err, postgresstore.ErrCorruptDocument) {
				t.Fatalf("Update() error = %v, want corrupt document", err)
			}
			if viewCalled || updateCalled {
				t.Fatalf("invalid document reached callback: view=%t update=%t", viewCalled, updateCalled)
			}
		})
	}
}

func TestPostgresStateStoreNoOpPreservesExactRawBytes(t *testing.T) {
	raw := nonCanonicalValidControlRaw()
	repository := &fakePostgresControlRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	callbackCalls := 0
	if err := store.Update(func(*State) error { callbackCalls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if callbackCalls != 1 || repository.mutateCalls != 1 {
		t.Fatalf("callback counts = adapter %d repository %d, want 1/1", callbackCalls, repository.mutateCalls)
	}
	if repository.lastOperation != postgresControlUpdateOperation {
		t.Fatalf("operation class = %q, want %q", repository.lastOperation, postgresControlUpdateOperation)
	}
	if !bytes.Equal(repository.body, raw) {
		t.Fatalf("no-op rewrote exact bytes:\n got %q\nwant %q", repository.body, raw)
	}
}

func TestPostgresStateStoreChangedStateUsesCanonicalEncoding(t *testing.T) {
	raw := nonCanonicalValidControlRaw()
	repository := &fakePostgresControlRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	master := bytes.Repeat([]byte{0x41}, 32)
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'C'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(state *State) error {
		state.Version = 2
		state.MasterKeyVerifier = masterVerifier
		state.AdminCredentialVerifier = adminVerifier
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want, err := encodePersistedState(State{Version: 2, MasterKeyVerifier: masterVerifier, AdminCredentialVerifier: adminVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repository.body, want) {
		t.Fatalf("changed bytes are not canonical:\n got %s\nwant %s", repository.body, want)
	}
}

func TestPostgresStateStoreCallbackErrorRollsBack(t *testing.T) {
	raw := nonCanonicalValidControlRaw()
	repository := &fakePostgresControlRepository{body: append([]byte(nil), raw...)}
	store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	wantErr := errors.New("mutation rejected")
	err := store.Update(func(state *State) error {
		state.Version = 3
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Update() error = %v, want callback error", err)
	}
	if !bytes.Equal(repository.body, raw) {
		t.Fatalf("callback error changed stored bytes: %q", repository.body)
	}
}

func TestPostgresStateStoreBoundsContextlessOperations(t *testing.T) {
	repository := &fakePostgresControlRepository{blockRead: true}
	store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{OperationTimeout: 10 * time.Millisecond})
	started := time.Now()
	err := store.View(func(State) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("View() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded operation took %s", elapsed)
	}
}

func TestPostgresStateStoreMapsErrorsAndRetainsCauses(t *testing.T) {
	tests := []struct {
		name          string
		source        error
		controlTarget error
	}{
		{name: "closed", source: fmtWrap(postgresstore.ErrClosed), controlTarget: ErrClosed},
		{name: "uncertain", source: fmtWrap(postgresstore.ErrUncertainCommit), controlTarget: ErrUncertainCommit},
		{name: "not committed", source: fmtWrap(postgresstore.ErrNotCommitted)},
		{name: "corrupt", source: fmtWrap(postgresstore.ErrCorruptDocument)},
		{name: "deadline", source: fmtWrap(context.DeadlineExceeded)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakePostgresControlRepository{body: nonCanonicalValidControlRaw(), updateErr: test.source}
			store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
			err := store.Update(func(*State) error { return nil })
			if !errors.Is(err, test.source) {
				t.Fatalf("Update() error = %v, want source cause %v", err, test.source)
			}
			if test.controlTarget != nil && !errors.Is(err, test.controlTarget) {
				t.Fatalf("Update() error = %v, want control target %v", err, test.controlTarget)
			}
			if test.controlTarget == nil && errors.Is(err, ErrUncertainCommit) {
				t.Fatalf("definite error was mapped to uncertain commit: %v", err)
			}
		})
	}
}

func fmtWrap(err error) error { return &testWrappedError{cause: err} }

type testWrappedError struct{ cause error }

func (e *testWrappedError) Error() string { return "wrapped: " + e.cause.Error() }
func (e *testWrappedError) Unwrap() error { return e.cause }

func TestPostgresStateStoreReadinessValidatesFreshControlDocument(t *testing.T) {
	repository := &fakePostgresControlRepository{body: nonCanonicalValidControlRaw()}
	store := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	if err := store.CheckReadiness(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.readinessCalls != 1 || repository.readCalls != 1 {
		t.Fatalf("readiness/read calls = %d/%d, want 1/1", repository.readinessCalls, repository.readCalls)
	}
	repository.body = []byte(`{"version":99}`)
	if err := store.CheckReadiness(context.Background()); !errors.Is(err, postgresstore.ErrCorruptDocument) {
		t.Fatalf("readiness with invalid document = %v, want corrupt", err)
	}
	beforeReads := repository.readCalls
	repository.readinessErr = postgresstore.ErrUnwritablePrimary
	if err := store.CheckReadiness(context.Background()); !errors.Is(err, postgresstore.ErrUnwritablePrimary) {
		t.Fatalf("low-level readiness error = %v", err)
	}
	if repository.readCalls != beforeReads {
		t.Fatal("adapter read control document after low-level readiness failed")
	}
}

func TestPostgresStateStoreInstancesObserveSharedServiceCredentialBinding(t *testing.T) {
	repository := &fakePostgresControlRepository{body: nonCanonicalValidControlRaw()}
	firstStore := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	secondStore := newTestPostgresStateStore(t, repository, PostgresStateStoreOptions{})
	master := bytes.Repeat([]byte{0x51}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewServiceWithStateStore(firstStore, box, &countingIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewServiceWithStateStore(secondStore, box, &countingIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'D'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureFirewallScopeSchema(); err != nil {
		t.Fatal(err)
	}
	if err := second.CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier); err != nil {
		t.Fatalf("second adapter did not observe committed binding: %v", err)
	}
	if repository.updateCalls != 12 || repository.readCalls != 1 {
		t.Fatalf("shared repository calls = update %d read %d, want 12/1", repository.updateCalls, repository.readCalls)
	}
}

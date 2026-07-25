package control

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeStateStore struct {
	mu                 sync.Mutex
	state              State
	viewErr            error
	viewCalls          int
	updateCalls        int
	updateCallbackRuns int
	beforeUpdate       func(*State)
}

func (s *fakeStateStore) View(fn func(State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.viewCalls++
	if s.viewErr != nil {
		return s.viewErr
	}
	snapshot, err := cloneState(s.state)
	if err != nil {
		return err
	}
	return fn(snapshot)
}

type failIfCalledIssuer struct {
	called bool
}

func (i *failIfCalledIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	i.called = true
	return "", "", errors.New("issuer must not run")
}

func (*failIfCalledIssuer) SignPublicKey(context.Context, string, string, string, string, string, string, string, time.Duration) (string, string, time.Time, error) {
	return "", "", time.Time{}, errors.New("issuer must not run")
}

func (s *fakeStateStore) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateCalls++
	if s.beforeUpdate != nil {
		s.beforeUpdate(&s.state)
		s.beforeUpdate = nil
	}
	next, err := cloneState(s.state)
	if err != nil {
		return err
	}
	s.updateCallbackRuns++
	if err := fn(&next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func TestNewServiceWithStateStoreRejectsNilBackends(t *testing.T) {
	var typedNil *fakeStateStore
	tests := []struct {
		name  string
		store StateStore
	}{
		{name: "nil interface"},
		{name: "typed nil", store: typedNil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewServiceWithStateStore(test.store, nil, nil)
			if service != nil || !errors.Is(err, ErrInvalidStateStore) {
				t.Fatalf("NewServiceWithStateStore() = (%#v, %v), want nil invalid-store error", service, err)
			}
		})
	}
}

func TestServiceUsesTransactionalStateStore(t *testing.T) {
	backend := &fakeStateStore{state: State{Version: 1}}
	box, err := NewSecretBox(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewServiceWithStateStore(backend, box, &countingIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	if service.store != nil {
		t.Fatal("non-file service unexpectedly exposes a file store")
	}

	masterVerifier, err := DeriveMasterKeyVerifier(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{'A'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CheckRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if backend.viewCalls != 1 {
		t.Fatalf("read-current fallback called View %d times, want 1", backend.viewCalls)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if backend.updateCalls != 1 || backend.updateCallbackRuns != 1 {
		t.Fatalf("binding used update/callback %d/%d times, want 1/1", backend.updateCalls, backend.updateCallbackRuns)
	}
	if backend.state.Version != 2 || backend.state.MasterKeyVerifier != masterVerifier || backend.state.AdminCredentialVerifier != adminVerifier {
		t.Fatalf("binding was not committed through backend: %#v", backend.state)
	}
}

func TestServicePreservesTransactionConflictFromBackendSnapshot(t *testing.T) {
	backend := &fakeStateStore{state: State{Version: 1}}
	backend.beforeUpdate = func(state *State) {
		// Simulate another transaction committing after CreateNetwork's advisory
		// View and before its authoritative Update callback.
		state.Networks = append(state.Networks, Network{
			ID: "concurrent-network", Name: "production", CIDR: "10.80.0.0/24",
		})
	}
	box, err := NewSecretBox(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewServiceWithStateStore(backend, box, &countingIssuer{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.CreateNetwork(context.Background(), CreateNetworkInput{
		Name: "production", CIDR: "10.80.0.0/24",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateNetwork() error = %v, want conflict", err)
	}
	if backend.viewCalls != 1 || backend.updateCalls != 1 || backend.updateCallbackRuns != 1 {
		t.Fatalf("transaction calls = view %d, update %d, callback %d; want 1/1/1", backend.viewCalls, backend.updateCalls, backend.updateCallbackRuns)
	}
	if len(backend.state.Networks) != 1 || backend.state.Networks[0].ID != "concurrent-network" {
		t.Fatalf("failed transaction changed committed state: %#v", backend.state.Networks)
	}
}

func TestCreateNetworkFailsBeforeCAWorkWhenBackendReadFails(t *testing.T) {
	backendErr := errors.New("database is unavailable")
	backend := &fakeStateStore{state: State{Version: 1}, viewErr: backendErr}
	box, err := NewSecretBox(bytes.Repeat([]byte{0x34}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &failIfCalledIssuer{}
	service, err := NewServiceWithStateStore(backend, box, issuer)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "production", CIDR: "10.81.0.0/24"})
	if !errors.Is(err, backendErr) {
		t.Fatalf("CreateNetwork() error = %v, want backend error", err)
	}
	if issuer.called {
		t.Fatal("CreateNetwork invoked CA work after its backend preflight failed")
	}
}

func TestFileServiceReadCurrentStillAvoidsStateClone(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := NewSecretBox(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, &countingIssuer{})
	masterVerifier, err := DeriveMasterKeyVerifier(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{'B'}, 43))
	if err != nil {
		t.Fatal(err)
	}

	before := store.cloneCount.Load()
	if err := service.CheckRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if after := store.cloneCount.Load(); after != before {
		t.Fatalf("file read-current optimization cloned state: before=%d after=%d", before, after)
	}
}

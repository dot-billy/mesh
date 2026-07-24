package identity

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDesktopAuthorizationStoreHashesPollSecretPersistsAndConsumesApprovalOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	sealer := newTestSealer(t)
	store, err := OpenFileStore(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	secret, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	input := CreateDesktopAuthorizationInput{
		ID: desktopRequestID(t), PollSecret: secret, CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), PollInterval: 5 * time.Second,
	}
	if err := store.CreateDesktopAuthorization(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	stored := store.state.DesktopAuthorizations[0]
	if stored.PollSecretHash == secret || !ValidCredentialHash(stored.PollSecretHash) || !CredentialMatches(stored.PollSecretHash, secret) {
		t.Fatalf("poll secret was not stored only as a verifier: %#v", stored)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	principal, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DecideDesktopAuthorization(context.Background(), input.ID, principal, DesktopAuthorizationApprove, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideDesktopAuthorization(context.Background(), input.ID, principal, DesktopAuthorizationApprove, now.Add(2*time.Second)); err != nil {
		t.Fatalf("same decision was not idempotent: %v", err)
	}
	poll, err := store.PollDesktopAuthorization(context.Background(), input.ID, secret, now.Add(5*time.Second))
	if err != nil || poll.State != DesktopAuthorizationApproved || !principalsEqual(poll.Principal, principal) {
		t.Fatalf("approved poll=%#v error=%v", poll, err)
	}
	if _, err := store.PollDesktopAuthorization(context.Background(), input.ID, secret, now.Add(10*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("consumed completion error=%v, want unauthorized", err)
	}
}

func TestDesktopAuthorizationStorePendingDeniedExpiredAndPollingBounds(t *testing.T) {
	store := openDesktopAuthorizationStore(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	create := func() (string, string) {
		t.Helper()
		id, secret := desktopRequestID(t), opaqueToken(t)
		if err := store.CreateDesktopAuthorization(context.Background(), CreateDesktopAuthorizationInput{
			ID: id, PollSecret: secret, CreatedAt: now,
			ExpiresAt: now.Add(2 * time.Minute), PollInterval: 5 * time.Second,
		}); err != nil {
			t.Fatal(err)
		}
		return id, secret
	}
	pendingID, pendingSecret := create()
	poll, err := store.PollDesktopAuthorization(context.Background(), pendingID, pendingSecret, now)
	if err != nil || poll.State != DesktopAuthorizationPending {
		t.Fatalf("pending poll=%#v error=%v", poll, err)
	}
	if _, err := store.PollDesktopAuthorization(context.Background(), pendingID, pendingSecret, now.Add(time.Second)); !errors.Is(err, ErrLimit) {
		t.Fatalf("early poll error=%v, want limit", err)
	}
	if _, err := store.PollDesktopAuthorization(context.Background(), pendingID, opaqueToken(t), now.Add(5*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-secret poll error=%v, want unauthorized", err)
	}

	deniedID, deniedSecret := create()
	principal, _ := NewLegacyPrincipal(now)
	if err := store.DecideDesktopAuthorization(context.Background(), deniedID, principal, DesktopAuthorizationDeny, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	poll, err = store.PollDesktopAuthorization(context.Background(), deniedID, deniedSecret, now.Add(5*time.Second))
	if err != nil || poll.State != DesktopAuthorizationDenied {
		t.Fatalf("denied poll=%#v error=%v", poll, err)
	}

	expiredID, expiredSecret := create()
	poll, err = store.PollDesktopAuthorization(context.Background(), expiredID, expiredSecret, now.Add(3*time.Minute))
	if err != nil || poll.State != DesktopAuthorizationExpired {
		t.Fatalf("expired poll=%#v error=%v", poll, err)
	}
}

func TestDesktopAuthorizationStoreBoundsOutstandingAndSerializesCompletion(t *testing.T) {
	store := openDesktopAuthorizationStore(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var approvedID, approvedSecret string
	for index := 0; index < maxDesktopAuthorizations; index++ {
		id, secret := desktopRequestID(t), opaqueToken(t)
		if err := store.CreateDesktopAuthorization(context.Background(), CreateDesktopAuthorizationInput{
			ID: id, PollSecret: secret, CreatedAt: now,
			ExpiresAt: now.Add(5 * time.Minute), PollInterval: time.Second,
		}); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			approvedID, approvedSecret = id, secret
		}
	}
	if err := store.CreateDesktopAuthorization(context.Background(), CreateDesktopAuthorizationInput{
		ID: desktopRequestID(t), PollSecret: opaqueToken(t), CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), PollInterval: time.Second,
	}); !errors.Is(err, ErrLimit) {
		t.Fatalf("over-limit create error=%v", err)
	}
	principal, _ := NewLegacyPrincipal(now)
	if err := store.DecideDesktopAuthorization(context.Background(), approvedID, principal, DesktopAuthorizationApprove, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			poll, pollErr := store.PollDesktopAuthorization(context.Background(), approvedID, approvedSecret, now.Add(2*time.Second))
			if pollErr == nil && poll.State != DesktopAuthorizationApproved {
				pollErr = errors.New("poll succeeded without approved state")
			}
			results <- pollErr
		}()
	}
	wait.Wait()
	close(results)
	successes, unauthorized := 0, 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrUnauthorized):
			unauthorized++
		default:
			t.Fatalf("unexpected concurrent poll error: %v", result)
		}
	}
	if successes != 1 || unauthorized != 1 {
		t.Fatalf("concurrent completion successes=%d unauthorized=%d", successes, unauthorized)
	}
}

func openDesktopAuthorizationStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "identity.json"), newTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func desktopRequestID(t *testing.T) string {
	t.Helper()
	return "desktop_" + opaqueToken(t)
}

func opaqueToken(t *testing.T) string {
	t.Helper()
	value, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

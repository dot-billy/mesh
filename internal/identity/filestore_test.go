package identity

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testSealer struct{ aead cipher.AEAD }

func newTestSealer(t *testing.T) *testSealer {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testSealer{aead: aead}
}

func (s *testSealer) SealFor(purpose string, plain []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte("test-"+purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *testSealer) OpenFor(purpose, encoded string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < s.aead.NonceSize() {
		return nil, errors.New("invalid sealed value")
	}
	return s.aead.Open(nil, sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():], []byte("test-"+purpose))
}

func TestFileStoreLoginAttemptIsEncryptedOneUseAndRestartSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	input := LoginAttemptInput{
		ID: "login_1", TransactionToken: mustToken(t), StateToken: mustToken(t), Nonce: mustToken(t), PKCEVerifier: mustToken(t),
		ReturnPath: "/networks?from=login", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := store.CreateLoginAttempt(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	// Exact retries are harmless even though encryption uses a fresh nonce.
	if err := store.CreateLoginAttempt(context.Background(), input); err != nil {
		t.Fatalf("exact login-attempt retry: %v", err)
	}
	conflict := input
	conflict.Nonce = mustToken(t)
	if err := store.CreateLoginAttempt(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting login retry = %v, want conflict", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for label, secret := range map[string]string{"transaction": input.TransactionToken, "state": input.StateToken, "nonce": input.Nonce, "verifier": input.PKCEVerifier} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("persisted identity state contains raw %s credential", label)
		}
	}
	if !bytes.Contains(raw, []byte(`"transaction_hash"`)) || !bytes.Contains(raw, []byte(`"sealed_oidc_payload"`)) {
		t.Fatal("persisted identity state omitted hashed/sealed transaction fields")
	}
	if _, err := store.ConsumeLoginAttempt(context.Background(), input.TransactionToken, mustToken(t), now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong state = %v, want unauthorized", err)
	}
	// A forged state must not burn the legitimate transaction.
	consumed, err := store.ConsumeLoginAttempt(context.Background(), input.TransactionToken, input.StateToken, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ID != input.ID || consumed.Nonce != input.Nonce || consumed.PKCEVerifier != input.PKCEVerifier || consumed.ReturnPath != input.ReturnPath {
		t.Fatalf("consumed transaction mismatch: %#v", consumed)
	}
	if _, err := store.ConsumeLoginAttempt(context.Background(), input.TransactionToken, input.StateToken, now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed transaction = %v, want unauthorized", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	defer reopened.Close()
	if _, err := reopened.ConsumeLoginAttempt(context.Background(), input.TransactionToken, input.StateToken, now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("restart restored consumed transaction: %v", err)
	}
}

func TestFileStoreSessionLifecycleCASAndDeepClones(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_1", now)
	created, err := store.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 || !created.ValidCSRF(input.CSRFToken) {
		t.Fatalf("created session = %#v", created)
	}
	retried, err := store.CreateSession(context.Background(), input)
	if err != nil || retried.Version != created.Version {
		t.Fatalf("idempotent session create = %#v, %v", retried, err)
	}
	conflict := input
	conflict.Token = mustToken(t)
	if _, err := store.CreateSession(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting session create = %v, want conflict", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(input.Token)) || bytes.Contains(raw, []byte(input.CSRFToken)) {
		t.Fatal("raw session or CSRF credential was persisted")
	}
	authenticated, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authenticated.Principal.Groups[0] = "mutated"
	again, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(time.Minute))
	if err != nil || again.Principal.Groups[0] == "mutated" {
		t.Fatal("authenticated session exposed mutable store slices")
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, strings.Repeat("b", 64), now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("policy mismatch = %v, want unauthorized", err)
	}
	seen := now.Add(2 * time.Minute)
	idle := now.Add(17 * time.Minute)
	touched, err := store.TouchSession(context.Background(), created.ID, created.Version, seen, idle)
	if err != nil || touched.Version != 2 {
		t.Fatalf("touch = %#v, %v", touched, err)
	}
	if replay, err := store.TouchSession(context.Background(), created.ID, created.Version, seen, idle); err != nil || replay.Version != touched.Version {
		t.Fatalf("exact touch retry = %#v, %v", replay, err)
	}
	if _, err := store.TouchSession(context.Background(), created.ID, created.Version, seen.Add(time.Second), idle.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale touch = %v, want conflict", err)
	}
	newToken, newCSRF := mustToken(t), mustToken(t)
	rotatedSeen, rotatedIdle := now.Add(3*time.Minute), now.Add(18*time.Minute)
	rotated, err := store.RotateSession(context.Background(), created.ID, touched.Version, newToken, newCSRF, rotatedSeen, rotatedIdle)
	if err != nil || rotated.Version != 3 || !rotated.ValidCSRF(newCSRF) {
		t.Fatalf("rotation = %#v, %v", rotated, err)
	}
	if replay, err := store.RotateSession(context.Background(), created.ID, touched.Version, newToken, newCSRF, rotatedSeen, rotatedIdle); err != nil || replay.Version != rotated.Version {
		t.Fatalf("exact rotation retry = %#v, %v", replay, err)
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now.Add(4*time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old rotated token = %v, want unauthorized", err)
	}
	if _, err := store.AuthenticateSession(context.Background(), newToken, input.PolicyFingerprint, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("new rotated token: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	if _, err := store.AuthenticateSession(context.Background(), newToken, input.PolicyFingerprint, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("session did not survive restart: %v", err)
	}
	revokedAt := now.Add(5 * time.Minute)
	revoked, err := store.RevokeSession(context.Background(), created.ID, revokedAt, "operator logout")
	if err != nil || revoked.RevokedAt == nil || revoked.Version != 4 {
		t.Fatalf("revocation = %#v, %v", revoked, err)
	}
	if replay, err := store.RevokeSession(context.Background(), created.ID, revokedAt, "operator logout"); err != nil || replay.Version != revoked.Version {
		t.Fatalf("exact revoke retry = %#v, %v", replay, err)
	}
	if _, err := store.RevokeSession(context.Background(), created.ID, revokedAt, "different"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting revoke = %v, want conflict", err)
	}
	if _, err := store.AuthenticateSession(context.Background(), newToken, input.PolicyFingerprint, now.Add(6*time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token = %v, want unauthorized", err)
	}
}

func TestFileStoreRejectsSessionAuthenticationAfterClockRollback(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_clock_rollback", now)
	created, err := store.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	seenAt := now.Add(2 * time.Minute)
	if _, err := store.TouchSession(context.Background(), created.ID, created.Version, seenAt, now.Add(17*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, seenAt.Add(-time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("clock rollback authentication returned %v, want unauthorized", err)
	}
}

func TestFileStoreRetriesUncertainDirectorySyncBeforeIdempotentRevocationRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_uncertain_revoke", now)
	created, err := store.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	var syncCalls int
	store.syncRoot = func(root *os.Root) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected directory sync failure")
		}
		return syncIdentityRoot(root)
	}
	revokedAt := now.Add(time.Minute)
	if _, err := store.RevokeSession(context.Background(), created.ID, revokedAt, "administrator revocation"); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("revocation returned %v, want uncertain commit", err)
	}
	// A real HTTP retry has a fresh timestamp. The store must first repeat the
	// parent-directory barrier, then it may report the already-committed value
	// as a conflict without rewriting it.
	if _, err := store.RevokeSession(context.Background(), created.ID, revokedAt.Add(time.Second), "administrator revocation"); !errors.Is(err, ErrConflict) {
		t.Fatalf("revocation retry returned %v, want conflict", err)
	}
	if syncCalls != 2 || store.durabilityPending {
		t.Fatalf("directory sync calls=%d pending=%v, want two calls and a cleared barrier", syncCalls, store.durabilityPending)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	defer reopened.Close()
	if _, err := reopened.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, revokedAt.Add(2*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reopened store lost the revocation: %v", err)
	}
}

func TestFileStoreReadinessReportsRepairsAndRejectsClosedStore(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	now := identityTestTime()
	var syncCalls int
	store.syncRoot = func(*os.Root) error {
		syncCalls++
		return errors.New("injected persistent identity directory sync failure")
	}
	if _, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_readiness", now)); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("create session returned %v, want uncertain commit", err)
	}
	if err := store.CheckReadiness(); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("readiness returned %v, want uncertain commit", err)
	}
	if !store.durabilityPending || syncCalls != 2 {
		t.Fatalf("pending=%v sync calls=%d, want pending after two failed barriers", store.durabilityPending, syncCalls)
	}
	store.syncRoot = syncIdentityRoot
	if err := store.CheckReadiness(); err != nil {
		t.Fatalf("readiness did not repair the pending durability barrier: %v", err)
	}
	if store.durabilityPending {
		t.Fatal("readiness left a repaired durability barrier pending")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed-store readiness returned %v, want closed", err)
	}
}

func TestFileStorePrincipalRevocationBreakGlassAndCleanup(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	firstInput := testCreateSessionInput(t, "session_1", now)
	secondInput := testCreateSessionInput(t, "session_2", now)
	secondInput.Token, secondInput.CSRFToken = mustToken(t), mustToken(t)
	first, err := store.CreateSession(context.Background(), firstInput)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateSession(context.Background(), secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.Principal.ID != second.Principal.ID {
		t.Fatal("test sessions do not share a principal")
	}
	count, err := store.RevokePrincipal(context.Background(), first.Principal.ID, now.Add(time.Minute), "identity disabled")
	if err != nil || count != 2 {
		t.Fatalf("principal revocation count=%d err=%v", count, err)
	}
	if count, err := store.RevokePrincipal(context.Background(), first.Principal.ID, now.Add(time.Minute), "identity disabled"); err != nil || count != 0 {
		t.Fatalf("principal revocation retry count=%d err=%v", count, err)
	}
	for _, token := range []string{firstInput.Token, secondInput.Token} {
		if _, err := store.AuthenticateSession(context.Background(), token, firstInput.PolicyFingerprint, now.Add(2*time.Minute)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("principal-revoked session = %v", err)
		}
	}
	codeToken := mustToken(t)
	code := BreakGlassCodeInput{ID: "bg_primary", Token: codeToken, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := store.CreateBreakGlassCode(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateBreakGlassCode(context.Background(), code); err != nil {
		t.Fatalf("exact break-glass retry: %v", err)
	}
	if _, err := store.ConsumeBreakGlassCode(context.Background(), code.ID, mustToken(t), now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong break-glass token = %v", err)
	}
	consumed, err := store.ConsumeBreakGlassCode(context.Background(), code.ID, codeToken, now.Add(time.Minute))
	if err != nil || consumed.UsedAt == nil {
		t.Fatalf("consume break-glass = %#v, %v", consumed, err)
	}
	wantUsedAt := *consumed.UsedAt
	*consumed.UsedAt = now.Add(-time.Hour)
	store.mu.Lock()
	storedUsedAt := *store.state.BreakGlassCodes[0].UsedAt
	store.mu.Unlock()
	if !storedUsedAt.Equal(wantUsedAt) {
		t.Fatal("consumed break-glass result exposed mutable store state")
	}
	if _, err := store.ConsumeBreakGlassCode(context.Background(), code.ID, codeToken, now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("break-glass replay = %v, want unauthorized", err)
	}
	cleanup, err := store.CleanupExpired(context.Background(), now.Add(25*time.Hour))
	if err != nil || cleanup.Sessions != 2 || cleanup.BreakGlassCodes != 1 {
		t.Fatalf("cleanup = %#v, %v", cleanup, err)
	}
}

func TestFileStoreListsBoundedPublicSessionSummaries(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	firstInput := testCreateSessionInput(t, "session_a", now)
	secondInput := testCreateSessionInput(t, "session_b", now)
	secondInput.Token, secondInput.CSRFToken = mustToken(t), mustToken(t)
	first, err := store.CreateSession(context.Background(), firstInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSession(context.Background(), secondInput); err != nil {
		t.Fatal(err)
	}
	legacy, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	thirdInput := testCreateSessionInput(t, "session_c", now)
	thirdInput.Token, thirdInput.CSRFToken, thirdInput.Principal, thirdInput.AuthMethod = mustToken(t), mustToken(t), legacy, "legacy_token"
	if _, err := store.CreateSession(context.Background(), thirdInput); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeSession(context.Background(), secondInput.ID, now.Add(time.Minute), "operator logout"); err != nil {
		t.Fatal(err)
	}

	active, err := store.ListSessions(context.Background(), SessionListFilter{PrincipalID: first.Principal.ID, Limit: 10})
	if err != nil || len(active) != 1 || active[0].ID != first.ID {
		t.Fatalf("active principal sessions = %#v, %v", active, err)
	}
	all, err := store.ListSessions(context.Background(), SessionListFilter{PrincipalID: first.Principal.ID, IncludeRevoked: true, Limit: 10})
	if err != nil || len(all) != 2 || all[0].ID != "session_a" || all[1].ID != "session_b" {
		t.Fatalf("all principal sessions = %#v, %v", all, err)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("token_hash")) || bytes.Contains(raw, []byte("csrf_hash")) || bytes.Contains(raw, []byte(firstInput.Token)) || bytes.Contains(raw, []byte(firstInput.CSRFToken)) {
		t.Fatal("session summary exposed credential material")
	}
	all[0].Principal.Groups[0] = "mutated"
	*all[1].RevokedAt = now.Add(-time.Hour)
	again, err := store.ListSessions(context.Background(), SessionListFilter{PrincipalID: first.Principal.ID, IncludeRevoked: true, Limit: 1})
	if err != nil || len(again) != 1 || again[0].Principal.Groups[0] == "mutated" || again[0].ID != "session_a" {
		t.Fatalf("bounded cloned summary = %#v, %v", again, err)
	}
	if _, err := store.ListSessions(context.Background(), SessionListFilter{Limit: 0}); err == nil {
		t.Fatal("unbounded session listing was accepted")
	}
}

func TestFileStorePrincipalRevocationRollsBackCountOnValidationFailure(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	firstInput := testCreateSessionInput(t, "session_first", now)
	if _, err := store.CreateSession(context.Background(), firstInput); err != nil {
		t.Fatal(err)
	}
	secondInput := testCreateSessionInput(t, "session_second", now.Add(10*time.Minute))
	secondInput.Token, secondInput.CSRFToken = mustToken(t), mustToken(t)
	// Reuse the first identity while keeping the later session creation time.
	secondInput.Principal = firstInput.Principal
	if _, err := store.CreateSession(context.Background(), secondInput); err != nil {
		t.Fatal(err)
	}
	count, err := store.RevokePrincipal(context.Background(), firstInput.Principal.ID, now.Add(5*time.Minute), "identity disabled")
	if err == nil || count != 0 {
		t.Fatalf("failed atomic revocation count=%d err=%v", count, err)
	}
	if _, err := store.AuthenticateSession(context.Background(), firstInput.Token, firstInput.PolicyFingerprint, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("failed revocation partially committed: %v", err)
	}
	if events, listErr := store.ListIdentityAudit(context.Background(), IdentityAuditListFilter{Type: IdentityAuditPrincipalRevoked, Limit: 10}); listErr != nil || len(events) != 0 {
		t.Fatalf("failed revocation appended audit = %#v, %v", events, listErr)
	}
}

func TestFileStoreConcurrentLoginConsumeAndSessionRotate(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	defer store.Close()
	now := identityTestTime()
	attempt := LoginAttemptInput{ID: "login_race", TransactionToken: mustToken(t), StateToken: mustToken(t), Nonce: mustToken(t), PKCEVerifier: mustToken(t), ReturnPath: "/", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := store.CreateLoginAttempt(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.ConsumeLoginAttempt(context.Background(), attempt.TransactionToken, attempt.StateToken, now.Add(time.Minute))
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("concurrent consume: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent login successes = %d, want 1", successes.Load())
	}
	sessionInput := testCreateSessionInput(t, "session_race", now)
	session, err := store.CreateSession(context.Background(), sessionInput)
	if err != nil {
		t.Fatal(err)
	}
	type rotation struct{ token, csrf string }
	rotations := []rotation{{mustToken(t), mustToken(t)}, {mustToken(t), mustToken(t)}}
	results := make(chan error, len(rotations))
	for _, candidate := range rotations {
		candidate := candidate
		go func() {
			_, rotateErr := store.RotateSession(context.Background(), session.ID, session.Version, candidate.token, candidate.csrf, now.Add(time.Minute), now.Add(16*time.Minute))
			results <- rotateErr
		}()
	}
	rotateSuccess, rotateConflict := 0, 0
	for range rotations {
		err := <-results
		switch {
		case err == nil:
			rotateSuccess++
		case errors.Is(err, ErrConflict):
			rotateConflict++
		default:
			t.Fatalf("unexpected rotation error: %v", err)
		}
	}
	if rotateSuccess != 1 || rotateConflict != 1 {
		t.Fatalf("rotation results success=%d conflict=%d", rotateSuccess, rotateConflict)
	}
}

func TestFileStoreExpiryBoundariesAndContext(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "identity.json"))
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_expiry", now)
	if _, err := store.CreateSession(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, input.IdleExpiresAt); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("session valid at exact idle expiry: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.AuthenticateSession(cancelled, input.Token, input.PolicyFingerprint, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled authentication = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(context.Background(), input.Token, input.PolicyFingerprint, now); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed-store authentication = %v", err)
	}
}

func TestFileStorePrivateModesAndExclusiveProcessLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the FileStore intentionally fails closed until Windows DACL verification exists")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "identity.json")
	store := openTestStore(t, path)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info, err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("directory mode = %v, %v", info, err)
	}
	if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
		t.Fatal("second process lock was acquired")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func openTestStore(t *testing.T, path string) *FileStore {
	t.Helper()
	store, err := OpenFileStore(path, newTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mustToken(t *testing.T) string {
	t.Helper()
	token, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func identityTestTime() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }

func testCreateSessionInput(t *testing.T, id string, now time.Time) CreateSessionInput {
	t.Helper()
	principal, err := NewOIDCPrincipal("https://id.example.test/tenant", "subject", "Admin", "admin@example.test", []string{"admins"}, "mfa", []string{"otp", "pwd"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return CreateSessionInput{
		ID: id, Token: mustToken(t), CSRFToken: mustToken(t), Principal: principal, PolicyFingerprint: strings.Repeat("a", 64), AuthMethod: "oidc",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
}

func writePrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dumpIdentityState(t *testing.T, path string) identityState {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state identityState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func debugState(state identityState) string {
	raw, _ := json.Marshal(state)
	return fmt.Sprintf("%s", raw)
}

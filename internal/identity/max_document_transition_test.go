//go:build postgresmaxdocgate

package identity

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type maximumDocumentTransitionHarness struct {
	sealer          Sealer
	source          []byte
	cleanup         MaximumDocumentCleanupExpectation
	terminal        []byte
	expiredLogin    string
	expiredSession  string
	revokeSession   string
	survivorLogin   string
	survivorSession string
}

func TestMaximumDocumentCleanupTransitionIsExactAndSourceDerived(t *testing.T) {
	harness := newMaximumDocumentTransitionHarness(t)
	sourceBefore := bytes.Clone(harness.source)
	expectation, err := ValidateMaximumDocumentCleanupTransition(
		harness.source, harness.cleanup.CanonicalBytes, harness.sealer,
		harness.expiredLogin, harness.expiredSession,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(harness.source, sourceBefore) || !bytes.Equal(expectation.CanonicalBytes, harness.cleanup.CanonicalBytes) || expectation.SHA256 != sha256.Sum256(expectation.CanonicalBytes) {
		t.Fatal("cleanup validation mutated its source or returned the wrong canonical expectation")
	}

	tests := []struct {
		name   string
		mutate func(*identityState)
	}{
		{
			name: "surviving login attempt",
			mutate: func(state *identityState) {
				for index := range state.LoginAttempts {
					if state.LoginAttempts[index].ID == harness.survivorLogin {
						state.LoginAttempts[index].ReturnPath = "/changed"
					}
				}
			},
		},
		{
			name: "surviving session",
			mutate: func(state *identityState) {
				for index := range state.Sessions {
					if state.Sessions[index].ID == harness.survivorSession {
						state.Sessions[index].Version++
					}
				}
			},
		},
		{
			name: "break glass record",
			mutate: func(state *identityState) {
				usedAt := state.BreakGlassCodes[0].CreatedAt.Add(time.Minute)
				state.BreakGlassCodes[0].UsedAt = &usedAt
			},
		},
		{
			name: "existing audit",
			mutate: func(state *identityState) {
				state.Audit[0].Details["auth_method"] = "service_account"
			},
		},
		{
			name: "schema",
			mutate: func(state *identityState) {
				state.Schema = legacyIdentityStateSchema
				state.Audit = nil
			},
		},
		{
			name: "extra session removal",
			mutate: func(state *identityState) {
				state.Sessions = state.Sessions[:len(state.Sessions)-1]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := mutateMaximumDocumentTransition(t, harness.cleanup.CanonicalBytes, harness.sealer, test.mutate)
			if err := ValidateMaximumDocumentCleanupExpectation(changed, harness.sealer, harness.cleanup); err == nil {
				t.Fatal("non-exact cleanup transition was accepted")
			}
		})
	}

	t.Run("noncanonical result", func(t *testing.T) {
		padded := append(bytes.Clone(harness.cleanup.CanonicalBytes), ' ')
		if err := ValidateMaximumDocumentCleanupExpectation(padded, harness.sealer, harness.cleanup); err == nil {
			t.Fatal("noncanonical cleanup result was accepted")
		}
	})
	t.Run("tampered expectation digest", func(t *testing.T) {
		tampered := harness.cleanup
		tampered.CanonicalBytes = bytes.Clone(tampered.CanonicalBytes)
		tampered.CanonicalBytes[len(tampered.CanonicalBytes)-1] ^= 1
		if err := ValidateMaximumDocumentCleanupExpectation(harness.cleanup.CanonicalBytes, harness.sealer, tampered); err == nil {
			t.Fatal("tampered cleanup expectation was accepted")
		}
	})
	t.Run("wrong sealer", func(t *testing.T) {
		if _, err := BuildMaximumDocumentCleanupExpectation(harness.source, newRecoveryTestSealer(t, 0x65), harness.expiredLogin, harness.expiredSession); err == nil {
			t.Fatal("cleanup source accepted the wrong sealer")
		}
	})
}

func TestMaximumDocumentTerminalTransitionIsOneExactLegacyAdminRevocation(t *testing.T) {
	harness := newMaximumDocumentTransitionHarness(t)
	expectation, err := ValidateMaximumDocumentTerminalTransition(
		harness.source, harness.terminal, harness.sealer,
		harness.expiredLogin, harness.expiredSession, harness.revokeSession,
	)
	if err != nil {
		t.Fatal(err)
	}
	if expectation.SHA256 != harness.cleanup.SHA256 || !bytes.Equal(expectation.CanonicalBytes, harness.cleanup.CanonicalBytes) {
		t.Fatal("source-to-terminal validation returned the wrong revision-2 binding")
	}
	if err := ValidateMaximumDocumentTerminalTransitionFromCleanup(harness.cleanup, harness.terminal, harness.sealer, harness.revokeSession); err != nil {
		t.Fatalf("cleanup-to-terminal validation: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*identityState)
	}{
		{
			name: "other login attempt changed",
			mutate: func(state *identityState) {
				state.LoginAttempts[0].ReturnPath = "/changed"
			},
		},
		{
			name: "other session changed",
			mutate: func(state *identityState) {
				for index := range state.Sessions {
					if state.Sessions[index].ID == harness.survivorSession {
						state.Sessions[index].Version++
					}
				}
			},
		},
		{
			name: "break glass changed",
			mutate: func(state *identityState) {
				usedAt := state.BreakGlassCodes[0].CreatedAt.Add(time.Minute)
				state.BreakGlassCodes[0].UsedAt = &usedAt
			},
		},
		{
			name: "existing audit changed",
			mutate: func(state *identityState) {
				state.Audit[0].Details["auth_method"] = "service_account"
			},
		},
		{
			name: "revocation version skipped",
			mutate: func(state *identityState) {
				for index := range state.Sessions {
					if state.Sessions[index].ID == harness.revokeSession {
						state.Sessions[index].Version++
						state.Audit[len(state.Audit)-1].Details["session_version"] = strconv.FormatUint(state.Sessions[index].Version, 10)
					}
				}
			},
		},
		{
			name: "revocation actor has session",
			mutate: func(state *identityState) {
				state.Audit[len(state.Audit)-1].Actor.SessionID = "session_operator"
			},
		},
		{
			name: "extra appended audit",
			mutate: func(state *identityState) {
				extra := cloneIdentityAuditEvent(state.Audit[len(state.Audit)-1])
				extra.ID = "audit_" + maximumDocumentOpaqueToken("extra-terminal-audit", 1)
				state.Audit = append(state.Audit, extra)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := mutateMaximumDocumentTransition(t, harness.terminal, harness.sealer, test.mutate)
			if err := ValidateMaximumDocumentTerminalTransitionFromCleanup(harness.cleanup, changed, harness.sealer, harness.revokeSession); err == nil {
				t.Fatal("non-exact terminal transition was accepted")
			}
		})
	}

	t.Run("noncanonical result", func(t *testing.T) {
		padded := append(bytes.Clone(harness.terminal), '\n')
		if err := ValidateMaximumDocumentTerminalTransitionFromCleanup(harness.cleanup, padded, harness.sealer, harness.revokeSession); err == nil {
			t.Fatal("noncanonical terminal transition was accepted")
		}
	})
}

func newMaximumDocumentTransitionHarness(t *testing.T) maximumDocumentTransitionHarness {
	t.Helper()
	sealer := newRecoveryTestSealer(t, 0x64)
	createdAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	principal, err := NewLegacyPrincipal(createdAt)
	if err != nil {
		t.Fatal(err)
	}
	policyFingerprint := strings.Repeat("a", 64)
	makeSession := func(index int, expiresAt time.Time) (Session, IdentityAuditEvent) {
		idleExpiresAt := expiresAt
		if idleExpiresAt.After(createdAt.Add(time.Hour)) {
			idleExpiresAt = createdAt.Add(time.Hour)
		}
		session, err := canonicalSessionInput(CreateSessionInput{
			ID:        "session_" + maximumDocumentOpaqueToken("transition-session-id", index),
			Token:     maximumDocumentOpaqueToken("transition-session-token", index),
			CSRFToken: maximumDocumentOpaqueToken("transition-csrf-token", index),
			Principal: principal, PolicyFingerprint: policyFingerprint, AuthMethod: "legacy_token",
			CreatedAt: createdAt, LastSeenAt: createdAt,
			IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: expiresAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := session.Actor()
		if err != nil {
			t.Fatal(err)
		}
		audit := IdentityAuditEvent{
			ID:   "audit_" + maximumDocumentOpaqueToken("transition-created-audit", index),
			Type: IdentityAuditSessionCreated, At: createdAt, Actor: actor,
			TargetPrincipalID: principal.ID, TargetSessionID: session.ID,
			Details: map[string]string{"auth_method": "legacy_token", "session_version": "1"},
		}
		if err := validateIdentityAuditEvent(audit); err != nil {
			t.Fatal(err)
		}
		return session, audit
	}
	expiredSession, expiredAudit := makeSession(1, createdAt.Add(15*time.Minute))
	revokeSession, revokeAudit := makeSession(2, createdAt.Add(2*time.Hour))
	survivorSession, survivorAudit := makeSession(3, createdAt.Add(2*time.Hour))
	expiredLogin := maximumDocumentTransitionLoginAttempt(t, sealer, 1, createdAt, createdAt.Add(10*time.Minute))
	survivorLogin := maximumDocumentTransitionLoginAttempt(t, sealer, 2, createdAt.Add(25*time.Minute), createdAt.Add(35*time.Minute))
	breakGlassHash, err := HashOpaqueToken(maximumDocumentOpaqueToken("transition-break-glass-token", 1))
	if err != nil {
		t.Fatal(err)
	}
	state := identityState{
		Schema:        identityStateSchema,
		LoginAttempts: []persistedLoginAttempt{expiredLogin, survivorLogin},
		Sessions:      []Session{expiredSession, revokeSession, survivorSession},
		BreakGlassCodes: []BreakGlassCode{{
			ID: "bg_" + maximumDocumentOpaqueToken("transition-break-glass-id", 1), TokenHash: breakGlassHash,
			CreatedAt: createdAt, ExpiresAt: createdAt.Add(2 * time.Hour),
		}},
		Audit: []IdentityAuditEvent{expiredAudit, revokeAudit, survivorAudit},
	}
	source, err := encodeIdentityStateDocument(state)
	if err != nil {
		t.Fatal(err)
	}
	source = append(source, ' ', '\n')
	cleanup, err := BuildMaximumDocumentCleanupExpectation(source, sealer, expiredLogin.ID, expiredSession.ID)
	if err != nil {
		t.Fatal(err)
	}
	terminalState, err := validateRecoverySnapshot(cleanup.CanonicalBytes, sealer)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := createdAt.Add(31 * time.Minute)
	for index := range terminalState.Sessions {
		if terminalState.Sessions[index].ID != revokeSession.ID {
			continue
		}
		terminalState.Sessions[index].RevokedAt = &revokedAt
		terminalState.Sessions[index].RevocationReason = maximumDocumentRevocationReason
		terminalState.Sessions[index].Version++
	}
	terminalState.Audit = append(terminalState.Audit, IdentityAuditEvent{
		ID:   "audit_" + maximumDocumentOpaqueToken("transition-revoked-audit", 1),
		Type: IdentityAuditSessionRevoked, At: revokedAt,
		Actor:             Actor{ID: "legacy_admin", Kind: PrincipalLegacyAdmin},
		TargetPrincipalID: revokeSession.Principal.ID, TargetSessionID: revokeSession.ID,
		Details: map[string]string{"reason": maximumDocumentRevocationReason, "session_version": "2"},
	})
	terminal, err := encodeIdentityStateDocument(terminalState)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(terminal, sealer); err != nil {
		t.Fatal(err)
	}
	return maximumDocumentTransitionHarness{
		sealer: sealer, source: source, cleanup: cleanup, terminal: terminal,
		expiredLogin: expiredLogin.ID, expiredSession: expiredSession.ID, revokeSession: revokeSession.ID,
		survivorLogin: survivorLogin.ID, survivorSession: survivorSession.ID,
	}
}

func maximumDocumentTransitionLoginAttempt(t *testing.T, sealer Sealer, index int, createdAt, expiresAt time.Time) persistedLoginAttempt {
	t.Helper()
	input, payload, err := canonicalLoginInput(LoginAttemptInput{
		ID:               "login_" + maximumDocumentOpaqueToken("transition-login-id", index),
		TransactionToken: maximumDocumentOpaqueToken("transition-login-transaction", index),
		StateToken:       maximumDocumentOpaqueToken("transition-login-state", index),
		Nonce:            maximumDocumentOpaqueToken("transition-login-nonce", index),
		PKCEVerifier:     maximumDocumentOpaqueToken("transition-login-pkce", index),
		ReturnPath:       fmt.Sprintf("/transition/%d", index),
		CreatedAt:        createdAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := newIdentityOperations(nil, sealer).sealOIDCPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	transactionHash, err := HashOpaqueToken(input.TransactionToken)
	if err != nil {
		t.Fatal(err)
	}
	stateHash, err := HashOpaqueToken(input.StateToken)
	if err != nil {
		t.Fatal(err)
	}
	return persistedLoginAttempt{
		ID: input.ID, TransactionHash: transactionHash, StateHash: stateHash,
		SealedOIDCPayload: sealed, ReturnPath: input.ReturnPath,
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
	}
}

func mutateMaximumDocumentTransition(t *testing.T, raw []byte, sealer Sealer, mutate func(*identityState)) []byte {
	t.Helper()
	state, err := validateRecoverySnapshot(raw, sealer)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&state)
	changed, err := encodeMaximumDocumentTransitionState(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateRecoverySnapshot(changed, sealer); err != nil {
		t.Fatalf("test mutation did not remain a valid recovery document: %v", err)
	}
	if reflect.DeepEqual(changed, raw) {
		t.Fatal("test mutation did not change the document")
	}
	return changed
}

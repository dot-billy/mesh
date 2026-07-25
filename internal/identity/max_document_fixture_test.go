//go:build postgresmaxdocgate

package identity

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestBuildMaximumDocumentFixtureUsesValidatedSessionsAndWhitespace(t *testing.T) {
	sealer := newRecoveryTestSealer(t, 0x31)
	fixture, err := BuildMaximumDocumentFixture(context.Background(), MaximumDocumentFixtureOptions{
		Sealer:                sealer,
		At:                    time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		CanonicalMinimumBytes: 256 << 10, CanonicalMaximumBytes: 512 << 10, ExactBytes: 768 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.CanonicalBytes) < 256<<10 || len(fixture.CanonicalBytes) > 512<<10 || len(fixture.ExactBytes) != 768<<10 {
		t.Fatalf("fixture sizes canonical=%d exact=%d", len(fixture.CanonicalBytes), len(fixture.ExactBytes))
	}
	if fixture.OIDCClaimsBytes < 1 || fixture.OIDCClaimsBytes > MaximumDocumentOIDCClaimsBytes || fixture.OIDCGroupCount != MaximumDocumentOIDCGroups {
		t.Fatalf("fixture OIDC intake bounds=%+v", fixture)
	}
	if fixture.LoginAttemptCount != 1 || fixture.ExpiredLoginAttemptID == "" || fixture.SessionCount < 2 || fixture.AuditCount != fixture.SessionCount || fixture.ExpiredSessionID == fixture.RevokeSessionID {
		t.Fatalf("fixture counts/targets=%+v", fixture)
	}
	state, err := decodeIdentityStateDocument(fixture.CanonicalBytes, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.LoginAttempts) != 1 || state.LoginAttempts[0].ID != fixture.ExpiredLoginAttemptID || state.LoginAttempts[0].ExpiresAt.After(fixture.CleanupAt) {
		t.Fatalf("fixture sealed login-attempt target is invalid: %+v", state.LoginAttempts)
	}
	expired := 0
	for _, session := range state.Sessions {
		if !fixture.CleanupAt.Before(session.IdleExpiresAt) || !fixture.CleanupAt.Before(session.AbsoluteExpiresAt) {
			expired++
		}
	}
	if expired != 1 {
		t.Fatalf("sessions expired at cleanup=%d, want 1", expired)
	}
	principal := state.Sessions[0].Principal
	if len(principal.Issuer) != 2048 || len(principal.Subject) != 512 || len(principal.DisplayName) != 256 || len(principal.Email) != 254 || len(principal.Groups) != MaximumDocumentOIDCGroups || len(principal.ACR) != 256 || len(principal.AMR) != 16 {
		t.Fatalf("fixture OIDC principal is not max-width: %+v", principal)
	}
	if !bytes.Equal(fixture.ExactBytes[:len(fixture.CanonicalBytes)], fixture.CanonicalBytes) {
		t.Fatal("exact document does not preserve canonical prefix")
	}
	if suffix := fixture.ExactBytes[len(fixture.CanonicalBytes):]; len(bytes.Trim(suffix, " ")) != 0 {
		t.Fatal("exact document contains non-whitespace padding")
	}
	canonical, err := CanonicalizeMaximumDocumentRecoverySnapshot(fixture.ExactBytes, sealer)
	if err != nil || !bytes.Equal(canonical, fixture.CanonicalBytes) {
		t.Fatalf("canonicalize exact fixture: equal=%t err=%v", bytes.Equal(canonical, fixture.CanonicalBytes), err)
	}
	wrongSealer := newRecoveryTestSealer(t, 0x32)
	if err := ValidateRecoverySnapshot(fixture.ExactBytes, wrongSealer); err == nil {
		t.Fatal("maximum-document exact identity fixture accepted the wrong sealer")
	}
	t.Logf("canonical_bytes=%d exact_bytes=%d claims_bytes=%d groups=%d login_attempts=%d sessions=%d padding_bytes=%d", len(fixture.CanonicalBytes), len(fixture.ExactBytes), fixture.OIDCClaimsBytes, fixture.OIDCGroupCount, fixture.LoginAttemptCount, fixture.SessionCount, len(fixture.ExactBytes)-len(fixture.CanonicalBytes))
}

func TestMaximumDocumentIdentityHardLimitPlusOneIsRejected(t *testing.T) {
	if err := ValidateRecoverySnapshot(make([]byte, MaximumDocumentIdentityBytes+1), newRecoveryTestSealer(t, 0x31)); err == nil {
		t.Fatal("identity hard limit plus one was accepted")
	}
}

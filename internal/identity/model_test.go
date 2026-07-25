package identity

import (
	"strings"
	"testing"
	"time"
)

func TestOpaqueTokensAreCanonicalAndHashOnly(t *testing.T) {
	first, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 43 || !ValidOpaqueToken(first) || ValidOpaqueToken(first+"=") {
		t.Fatalf("invalid opaque tokens %q %q", first, second)
	}
	hash, err := HashOpaqueToken(first)
	if err != nil || !ValidCredentialHash(hash) || hash == first || !CredentialMatches(hash, first) || CredentialMatches(hash, second) {
		t.Fatalf("token hashing failed: hash=%q err=%v", hash, err)
	}
	if _, err := HashOpaqueToken("not-a-token"); err == nil {
		t.Fatal("invalid token was hashed")
	}
}

func TestPrincipalConstructorsAndActorConversion(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	oidc, err := NewOIDCPrincipal("https://id.example.test/tenant", "subject-1", "Admin", "admin@example.test", []string{"z", "a"}, "mfa", []string{"otp", "pwd"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(oidc.ID, "oidc_") || strings.Join(oidc.Groups, ",") != "a,z" {
		t.Fatalf("OIDC principal was not canonical: %#v", oidc)
	}
	actor, err := oidc.Actor("session_1")
	if err != nil || actor.ID != oidc.ID || actor.Kind != PrincipalOIDCAdmin || actor.SessionID != "session_1" {
		t.Fatalf("actor = %#v, %v", actor, err)
	}
	legacy, err := NewLegacyPrincipal(now)
	if err != nil || legacy.ID != "legacy_admin" {
		t.Fatalf("legacy principal = %#v, %v", legacy, err)
	}
	service, err := NewServicePrincipal("ci_1", "CI", now)
	if err != nil || service.ID != "service_ci_1" {
		t.Fatalf("service principal = %#v, %v", service, err)
	}
	breakGlass, err := NewBreakGlassPrincipal("bg_1", now)
	if err != nil || breakGlass.ID != "breakglass_bg_1" {
		t.Fatalf("break-glass principal = %#v, %v", breakGlass, err)
	}
}

func TestPrincipalRejectsIdentityDriftAndMutableClone(t *testing.T) {
	now := time.Now().UTC()
	principal, err := NewOIDCPrincipal("https://id.example.test", "subject", "", "", []string{"admins"}, "mfa", []string{"pwd"}, now)
	if err != nil {
		t.Fatal(err)
	}
	drifted := principal
	drifted.Subject = "other"
	if err := drifted.Validate(); err == nil {
		t.Fatal("issuer/subject identity drift was accepted")
	}
	clone := clonePrincipal(principal)
	clone.Groups[0] = "changed"
	clone.AMR[0] = "changed"
	if principal.Groups[0] != "admins" || principal.AMR[0] != "pwd" {
		t.Fatal("principal clone retained mutable slices")
	}
}

func TestPrincipalAndActorKindsAreStructurallyBound(t *testing.T) {
	now := identityTestTime()
	if _, err := NewServicePrincipal("", "", now); err == nil {
		t.Fatal("empty service record ID was accepted")
	}
	if _, err := NewBreakGlassPrincipal("code_1", now); err == nil {
		t.Fatal("noncanonical break-glass code ID was accepted")
	}
	for _, actor := range []Actor{
		{ID: "legacy_admin", Kind: PrincipalOIDCAdmin},
		{ID: "service_", Kind: PrincipalService},
		{ID: "breakglass_code_1", Kind: PrincipalBreakGlass},
	} {
		if err := actor.Validate(); err == nil {
			t.Fatalf("mismatched actor was accepted: %#v", actor)
		}
	}
	legacy, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Groups = []string{"admins"}
	if err := legacy.Validate(); err == nil {
		t.Fatal("OIDC claims on a legacy principal were accepted")
	}
}

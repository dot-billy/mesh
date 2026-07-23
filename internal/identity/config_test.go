package identity

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIdentityConfigNormalizesAndFingerprintsCanonically(t *testing.T) {
	config := validOIDCConfig()
	originalFirstAdmin := config.OIDC.Admins[0]
	normalized, err := config.Normalized(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Sessions.IdleTTL != defaultIdleTTL || normalized.Sessions.AbsoluteTTL != defaultAbsoluteTTL || normalized.Sessions.LoginAttemptTTL != defaultLoginAttemptTTL || normalized.Sessions.TouchInterval != defaultTouchInterval {
		t.Fatalf("session defaults were not applied: %#v", normalized.Sessions)
	}
	if config.OIDC.Admins[0] != originalFirstAdmin {
		t.Fatal("normalization mutated the caller's selector slice")
	}
	first, err := config.PolicyFingerprint(ValidationOptions{})
	if err != nil || !validPolicyFingerprint(first) {
		t.Fatalf("policy fingerprint = %q, %v", first, err)
	}
	reordered := validOIDCConfig()
	reordered.OIDC.Scopes = []string{"profile", "openid", "email"}
	reordered.OIDC.AllowedSigningAlgs = []string{"RS256", "ES256"}
	reordered.OIDC.Admins = []AdminSelector{{Kind: "group", Value: "mesh-admins"}, {Kind: "subject", Value: "admin-subject"}}
	reordered.OIDC.RequiredAMRAll = []string{"otp", "pwd"}
	second, err := reordered.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent policy order changed fingerprint: %s != %s", first, second)
	}
	changed := validOIDCConfig()
	changed.OIDC.Admins[0].Value = "different-subject"
	third, err := changed.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("authorization policy change retained the old fingerprint")
	}
	secretPathChanged := validOIDCConfig()
	secretPathChanged.OIDC.ClientSecretFile = "/run/secrets/rotated-oidc-secret"
	fourth, err := secretPathChanged.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first != fourth {
		t.Fatal("operational client-secret path changed the authorization-policy fingerprint")
	}
}

func TestIdentityConfigNormalizesRoleBindingsAndFingerprintsAuthority(t *testing.T) {
	config := validOIDCConfig()
	config.OIDC.RoleBindings = []RoleBinding{
		{Role: RoleViewer, Selector: AdminSelector{Kind: "group", Value: "mesh-viewers"}},
		{Role: RoleOperator, Selector: AdminSelector{Kind: "group", Value: "mesh-operators"}},
	}
	original := append([]RoleBinding(nil), config.OIDC.RoleBindings...)
	normalized, err := config.Normalized(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.OIDC.RoleBindings) != 2 || normalized.OIDC.RoleBindings[0].Role != RoleOperator || normalized.OIDC.RoleBindings[1].Role != RoleViewer {
		t.Fatalf("role bindings were not canonicalized: %#v", normalized.OIDC.RoleBindings)
	}
	if !reflect.DeepEqual(config.OIDC.RoleBindings, original) {
		t.Fatal("normalization mutated the caller's role bindings")
	}
	first, err := config.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reordered := validOIDCConfig()
	reordered.OIDC.RoleBindings = []RoleBinding{config.OIDC.RoleBindings[1], config.OIDC.RoleBindings[0]}
	second, err := reordered.PolicyFingerprint(ValidationOptions{})
	if err != nil || second != first {
		t.Fatalf("equivalent role binding order changed fingerprint: %s != %s, error=%v", first, second, err)
	}
	changed := validOIDCConfig()
	changed.OIDC.RoleBindings = append([]RoleBinding(nil), config.OIDC.RoleBindings...)
	changed.OIDC.RoleBindings[0].Role = RoleAdmin
	third, err := changed.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("role authority change retained the old fingerprint")
	}
}

func TestIdentityConfigRejectsUnsafeOrAmbiguousPolicy(t *testing.T) {
	tests := []struct {
		name   string
		change func(*IdentityConfig)
	}{
		{name: "unknown mode", change: func(c *IdentityConfig) { c.Mode = "magic" }},
		{name: "insecure public URL", change: func(c *IdentityConfig) { c.PublicURL = "http://mesh.example.test" }},
		{name: "public URL path", change: func(c *IdentityConfig) { c.PublicURL = "https://mesh.example.test/app" }},
		{name: "public URL default port", change: func(c *IdentityConfig) { c.PublicURL = "https://mesh.example.test:443" }},
		{name: "public URL noncanonical port", change: func(c *IdentityConfig) { c.PublicURL = "https://mesh.example.test:0443" }},
		{name: "issuer query", change: func(c *IdentityConfig) { c.OIDC.Issuer += "?tenant=x" }},
		{name: "issuer default port", change: func(c *IdentityConfig) { c.OIDC.Issuer = "https://id.example.test:443/tenant" }},
		{name: "relative client secret", change: func(c *IdentityConfig) { c.OIDC.ClientSecretFile = "secret" }},
		{name: "root client secret", change: func(c *IdentityConfig) { c.OIDC.ClientSecretFile = "/" }},
		{name: "missing openid", change: func(c *IdentityConfig) { c.OIDC.Scopes = []string{"email"} }},
		{name: "invalid scope quote", change: func(c *IdentityConfig) { c.OIDC.Scopes = append(c.OIDC.Scopes, `bad"scope`) }},
		{name: "invalid scope backslash", change: func(c *IdentityConfig) { c.OIDC.Scopes = append(c.OIDC.Scopes, `bad\scope`) }},
		{name: "offline access", change: func(c *IdentityConfig) { c.OIDC.Scopes = append(c.OIDC.Scopes, "offline_access") }},
		{name: "duplicate scope", change: func(c *IdentityConfig) { c.OIDC.Scopes = append(c.OIDC.Scopes, "openid") }},
		{name: "symmetric signing", change: func(c *IdentityConfig) { c.OIDC.AllowedSigningAlgs = []string{"HS256"} }},
		{name: "no admins", change: func(c *IdentityConfig) { c.OIDC.Admins = nil }},
		{name: "duplicate admin", change: func(c *IdentityConfig) { c.OIDC.Admins = append(c.OIDC.Admins, c.OIDC.Admins[0]) }},
		{name: "invalid role binding", change: func(c *IdentityConfig) {
			c.OIDC.RoleBindings = []RoleBinding{{Role: "owner", Selector: AdminSelector{Kind: "group", Value: "mesh-owners"}}}
		}},
		{name: "duplicate role selector", change: func(c *IdentityConfig) {
			c.OIDC.RoleBindings = []RoleBinding{{Role: RoleOperator, Selector: c.OIDC.Admins[0]}}
		}},
		{name: "unverified selector kind", change: func(c *IdentityConfig) { c.OIDC.Admins[0].Kind = "email" }},
		{name: "noncanonical email", change: func(c *IdentityConfig) {
			c.OIDC.Admins[0] = AdminSelector{Kind: "verified_email", Value: "Admin@Example.test"}
		}},
		{name: "group without claim", change: func(c *IdentityConfig) { c.OIDC.GroupsClaim = "" }},
		{name: "reserved group claim", change: func(c *IdentityConfig) { c.OIDC.GroupsClaim = "amr" }},
		{name: "no assurance", change: func(c *IdentityConfig) { c.OIDC.RequiredAMRAll = nil; c.OIDC.RequiredACRAny = nil }},
		{name: "zero max age", change: func(c *IdentityConfig) { c.OIDC.MaxAuthenticationAge = 0 }},
		{name: "fractional max age", change: func(c *IdentityConfig) { c.OIDC.MaxAuthenticationAge = time.Minute + time.Nanosecond }},
		{name: "long max age", change: func(c *IdentityConfig) { c.OIDC.MaxAuthenticationAge = 25 * time.Hour }},
		{name: "short idle", change: func(c *IdentityConfig) { c.Sessions.IdleTTL = time.Minute }},
		{name: "absolute shorter than idle", change: func(c *IdentityConfig) { c.Sessions.IdleTTL = time.Hour; c.Sessions.AbsoluteTTL = 30 * time.Minute }},
		{name: "OIDC only without recovery", change: func(c *IdentityConfig) { c.Mode = ModeOIDC; c.LegacyBearer = false; c.BreakGlass.Enabled = false }},
		{name: "OIDC only with legacy browser login", change: func(c *IdentityConfig) { c.Mode = ModeOIDC; c.LegacyBearer = false; c.LegacyBrowserLogin = true }},
		{name: "too few recovery codes", change: func(c *IdentityConfig) { c.BreakGlass.MinimumUsableCodes = 1 }},
		{name: "too many recovery codes", change: func(c *IdentityConfig) { c.BreakGlass.MinimumUsableCodes = MaxBreakGlassUsableCodes + 1 }},
		{name: "disabled recovery inventory", change: func(c *IdentityConfig) { c.BreakGlass.Enabled = false; c.BreakGlass.MinimumUsableCodes = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validOIDCConfig()
			test.change(&config)
			if err := config.Validate(ValidationOptions{}); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestIdentityConfigAcceptsExactIssuerTrailingSlash(t *testing.T) {
	config := validOIDCConfig()
	config.OIDC.Issuer = "https://id.example.test/application/o/mesh/"
	if err := config.Validate(ValidationOptions{}); err != nil {
		t.Fatalf("validate issuer with provider-defined trailing slash: %v", err)
	}

	withSlash, err := config.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	config.OIDC.Issuer = "https://id.example.test/application/o/mesh"
	withoutSlash, err := config.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if withSlash == withoutSlash {
		t.Fatal("distinct exact OIDC issuer identifiers shared a policy fingerprint")
	}
}

func TestIdentityConfigModesAndLoopbackDevelopment(t *testing.T) {
	legacy := IdentityConfig{Mode: ModeLegacyToken, PublicURL: "https://mesh.example.test", LegacyBearer: true}
	if err := legacy.Validate(ValidationOptions{}); err != nil {
		t.Fatalf("legacy mode: %v", err)
	}
	hybrid := validOIDCConfig()
	hybrid.Mode, hybrid.LegacyBearer, hybrid.BreakGlass.Enabled = ModeHybrid, true, false
	if err := hybrid.Validate(ValidationOptions{}); err != nil {
		t.Fatalf("hybrid mode: %v", err)
	}
	oidcOnly := validOIDCConfig()
	oidcOnly.Mode, oidcOnly.LegacyBearer = ModeOIDC, false
	normalizedOIDC, err := oidcOnly.Normalized(ValidationOptions{})
	if err != nil {
		t.Fatalf("OIDC-only mode: %v", err)
	}
	if normalizedOIDC.BreakGlass.MinimumUsableCodes != MinBreakGlassUsableCodes {
		t.Fatalf("OIDC-only recovery minimum = %d", normalizedOIDC.BreakGlass.MinimumUsableCodes)
	}
	legacyWithRecovery := legacy
	legacyWithRecovery.BreakGlass.Enabled = true
	if err := legacyWithRecovery.Validate(ValidationOptions{}); err == nil {
		t.Fatal("legacy mode accepted OIDC break-glass recovery")
	}
	development := validOIDCConfig()
	development.PublicURL = "http://127.0.0.1:8080"
	development.OIDC.Issuer = "http://localhost:9090/tenant"
	if err := development.Validate(ValidationOptions{}); err == nil {
		t.Fatal("loopback HTTP was accepted without the development option")
	}
	if err := development.Validate(ValidationOptions{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("explicit loopback development rejected: %v", err)
	}
	development.PublicURL = "http://192.0.2.10:8080"
	if err := development.Validate(ValidationOptions{AllowInsecureLoopback: true}); err == nil {
		t.Fatal("non-loopback HTTP was accepted")
	}
}

func TestPolicyFingerprintNeverContainsSecretPathOrValues(t *testing.T) {
	config := validOIDCConfig()
	fingerprint, err := config.PolicyFingerprint(ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fingerprint, "secret") || len(fingerprint) != 64 {
		t.Fatalf("unexpected fingerprint %q", fingerprint)
	}
}

func validOIDCConfig() IdentityConfig {
	return IdentityConfig{
		Mode: ModeHybrid, PublicURL: "https://mesh.example.test", LegacyBearer: true, BreakGlass: BreakGlassConfig{Enabled: true},
		OIDC: &OIDCConfig{
			Issuer: "https://id.example.test/tenant", ClientID: "mesh-control-plane", ClientSecretFile: "/run/secrets/mesh-oidc",
			Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups", AllowedSigningAlgs: []string{"ES256", "RS256"},
			Admins:         []AdminSelector{{Kind: "subject", Value: "admin-subject"}, {Kind: "group", Value: "mesh-admins"}},
			RequiredAMRAll: []string{"pwd", "otp"}, MaxAuthenticationAge: 15 * time.Minute,
		},
	}
}

package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/httpapi"
	"mesh/internal/identity"
)

const validHybridIdentityJSON = `{
  "schema": "mesh-hybrid-identity-v1",
  "legacy_browser_login": false,
  "oidc": {
    "issuer": "https://id.example.test/tenant",
    "client_id": "mesh-control-plane",
    "client_secret_file": "/run/secrets/mesh-oidc",
    "scopes": ["openid", "profile", "email"],
    "allowed_signing_algorithms": ["RS256", "ES256"],
    "admins": [{"kind": "subject", "value": "admin-subject"}],
    "required_amr_all": ["pwd", "otp"],
    "max_authentication_age": "15m"
  },
  "sessions": {
    "idle_ttl": "10m",
    "absolute_ttl": "1h",
    "login_attempt_ttl": "5m",
    "touch_interval": "1m"
  }
}`

const validOIDCOnlyIdentityJSON = `{
  "schema": "mesh-identity-v2",
  "mode": "oidc",
  "oidc": {
    "issuer": "https://id.example.test/tenant",
    "client_id": "mesh-control-plane",
    "client_secret_file": "/run/secrets/mesh-oidc",
    "scopes": ["openid", "profile", "email"],
    "allowed_signing_algorithms": ["RS256", "ES256"],
    "admins": [{"kind": "subject", "value": "admin-subject"}],
    "required_amr_all": ["pwd", "otp"],
    "max_authentication_age": "15m"
  },
  "sessions": {
    "idle_ttl": "10m",
    "absolute_ttl": "1h",
    "login_attempt_ttl": "5m",
    "touch_interval": "1m"
  },
  "break_glass": {
    "enabled": true,
    "minimum_usable_codes": 2
  }
}`

func TestLoadIdentityConfigurationDefaultsToLegacyToken(t *testing.T) {
	config, err := loadIdentityConfiguration("", "http://127.0.0.1:8080", identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != identity.ModeLegacyToken || !config.LegacyBrowserLogin || !config.LegacyBearer || config.OIDC != nil {
		t.Fatalf("legacy identity defaults=%#v", config)
	}
}

func TestLoadIdentityConfigurationBuildsNormalizedHybridPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hybrid OIDC fails closed until Windows DACL verification exists")
	}
	path := writeIdentityConfiguration(t, validHybridIdentityJSON, 0o600)
	config, err := loadIdentityConfiguration(path, "https://mesh.example.test", identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != identity.ModeHybrid || config.LegacyBrowserLogin || !config.LegacyBearer || config.OIDC == nil {
		t.Fatalf("hybrid identity policy=%#v", config)
	}
	if config.OIDC.MaxAuthenticationAge != 15*time.Minute || config.Sessions.IdleTTL != 10*time.Minute || config.Sessions.AbsoluteTTL != time.Hour || config.Sessions.LoginAttemptTTL != 5*time.Minute || config.Sessions.TouchInterval != time.Minute {
		t.Fatalf("hybrid durations were not parsed exactly: oidc=%s sessions=%#v", config.OIDC.MaxAuthenticationAge, config.Sessions)
	}
	if strings.Join(config.OIDC.Scopes, ",") != "email,openid,profile" || strings.Join(config.OIDC.RequiredAMRAll, ",") != "otp,pwd" {
		t.Fatalf("hybrid policy was not normalized: %#v", config.OIDC)
	}
}

func TestLoadIdentityConfigurationLoadsOIDCRoleBindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hybrid OIDC fails closed until Windows DACL verification exists")
	}
	raw := strings.Replace(validHybridIdentityJSON,
		`"admins": [{"kind": "subject", "value": "admin-subject"}],`,
		`"admins": [{"kind": "subject", "value": "admin-subject"}],
    "role_bindings": [
      {"role": "operator", "selector": {"kind": "subject", "value": "operator-subject"}},
      {"role": "viewer", "selector": {"kind": "verified_email", "value": "viewer@example.test"}}
    ],`, 1)
	config, err := loadIdentityConfiguration(writeIdentityConfiguration(t, raw, 0o600), "https://mesh.example.test", identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.OIDC.RoleBindings) != 2 || config.OIDC.RoleBindings[0].Role != identity.RoleOperator || config.OIDC.RoleBindings[1].Role != identity.RoleViewer {
		t.Fatalf("role bindings were not loaded canonically: %#v", config.OIDC.RoleBindings)
	}
}

func TestLoadIdentityConfigurationBuildsOIDCOnlyRecoveryPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OIDC fails closed until Windows DACL verification exists")
	}
	path := writeIdentityConfiguration(t, validOIDCOnlyIdentityJSON, 0o600)
	config, err := loadIdentityConfiguration(path, "https://mesh.example.test", identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != identity.ModeOIDC || config.LegacyBrowserLogin || config.LegacyBearer || config.OIDC == nil || !config.BreakGlass.Enabled || config.BreakGlass.MinimumUsableCodes != 2 {
		t.Fatalf("OIDC-only identity policy=%#v", config)
	}
	unknown := strings.Replace(validOIDCOnlyIdentityJSON, `"mode": "oidc",`, `"mode": "oidc", "legacy_bearer": true,`, 1)
	if _, err := loadIdentityConfiguration(writeIdentityConfiguration(t, unknown, 0o600), "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("OIDC-only configuration accepted an implicit legacy bearer field")
	}
}

func TestLoadIdentityConfigurationRejectsAmbiguousOrUnsafeFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hybrid OIDC fails closed until Windows DACL verification exists")
	}
	tests := []struct {
		name string
		raw  string
		mode os.FileMode
	}{
		{name: "duplicate nested name", raw: strings.Replace(validHybridIdentityJSON, `"issuer": "https://id.example.test/tenant",`, `"issuer": "https://id.example.test/tenant", "issuer": "https://attacker.example",`, 1), mode: 0o600},
		{name: "unknown field", raw: strings.Replace(validHybridIdentityJSON, `"legacy_browser_login": false,`, `"legacy_browser_login": false, "unknown": true,`, 1), mode: 0o600},
		{name: "wrong schema", raw: strings.Replace(validHybridIdentityJSON, hybridIdentitySchema, "mesh-oidc-v999", 1), mode: 0o600},
		{name: "fractional duration", raw: strings.Replace(validHybridIdentityJSON, `"15m"`, `"1.000000001s"`, 1), mode: 0o600},
		{name: "weak permissions", raw: validHybridIdentityJSON, mode: 0o644},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeIdentityConfiguration(t, test.raw, test.mode)
			if _, err := loadIdentityConfiguration(path, "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
				t.Fatal("unsafe identity configuration was accepted")
			}
		})
	}

	path := writeIdentityConfiguration(t, validHybridIdentityJSON, 0o600)
	if _, err := loadIdentityConfiguration(filepath.Base(path), "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("relative identity configuration path was accepted")
	}
	symlink := filepath.Join(t.TempDir(), "identity.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityConfiguration(symlink, "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("symlink identity configuration was accepted")
	}
	realDirectory := t.TempDir()
	realPath := filepath.Join(realDirectory, "identity.json")
	if err := os.WriteFile(realPath, []byte(validHybridIdentityJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(realDirectory, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityConfiguration(filepath.Join(linkedParent, "identity.json"), "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("identity configuration beneath a symlink directory was accepted")
	}
	hardlink := filepath.Join(filepath.Dir(path), "identity-hardlink.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityConfiguration(path, "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("multiply linked identity configuration was accepted")
	}
}

func TestHybridIdentityFileCannotSelectOIDCOnlyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hybrid OIDC fails closed until Windows DACL verification exists")
	}
	raw := strings.Replace(validHybridIdentityJSON, `"schema": "mesh-hybrid-identity-v1",`, `"schema": "mesh-hybrid-identity-v1", "mode": "oidc",`, 1)
	path := writeIdentityConfiguration(t, raw, 0o600)
	if _, err := loadIdentityConfiguration(path, "https://mesh.example.test", identity.ValidationOptions{}); err == nil {
		t.Fatal("identity file was allowed to request unsupported OIDC-only mode")
	}
}

func TestHybridOIDCStartsWithoutProviderAndPreservesBearerRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hybrid OIDC fails closed until Windows DACL verification exists")
	}
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "oidc-client-secret")
	if err := os.WriteFile(secretPath, []byte("test-oidc-client-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(validHybridIdentityJSON, "https://id.example.test/tenant", "https://127.0.0.1:1", 1)
	raw = strings.Replace(raw, "/run/secrets/mesh-oidc", secretPath, 1)
	configPath := writeIdentityConfiguration(t, raw, 0o600)
	config, err := loadIdentityConfiguration(configPath, "https://mesh.example.test", identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(directory, "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer identityStore.Close()
	flow, err := identity.NewOIDCFlow(config, identityStore, identity.OIDCFlowOptions{HTTPClient: &http.Client{Timeout: 100 * time.Millisecond}})
	if err != nil {
		t.Fatalf("lazy OIDC construction contacted the unavailable provider: %v", err)
	}
	controlStore, err := control.OpenStore(filepath.Join(directory, "control-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer controlStore.Close()
	service := control.NewService(controlStore, box, control.NebulaIssuer{})
	fingerprint, err := config.PolicyFingerprint(identity.ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("R", 43)
	api, err := httpapi.New(service, httpapi.Options{
		IdentityConfig: config, PolicyFingerprint: fingerprint, SessionStore: identityStore,
		OIDCAuthenticator: flow, AdminToken: adminToken, SecureCookies: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	bearerRequest := httptest.NewRequest(http.MethodGet, "https://mesh.example.test/api/v1/networks", nil)
	bearerRequest.Header.Set("Authorization", "Bearer "+adminToken)
	bearerResponse := httptest.NewRecorder()
	api.Handler().ServeHTTP(bearerResponse, bearerRequest)
	if bearerResponse.Code != http.StatusOK {
		t.Fatalf("hybrid bearer recovery failed while IdP was unavailable: %d %s", bearerResponse.Code, bearerResponse.Body.String())
	}

	startRequest := httptest.NewRequest(http.MethodPost, "https://mesh.example.test/api/v1/auth/oidc/start", strings.NewReader(`{"return_path":"/"}`))
	startRequest.Header.Set("Origin", "https://mesh.example.test")
	startRequest.Header.Set("Content-Type", "application/json")
	startRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	startResponse := httptest.NewRecorder()
	api.Handler().ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusServiceUnavailable || startResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unavailable IdP response=%d cache=%q body=%s", startResponse.Code, startResponse.Header().Get("Cache-Control"), startResponse.Body.String())
	}
}

func writeIdentityConfiguration(t *testing.T, raw string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(raw), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

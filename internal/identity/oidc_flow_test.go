package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	oidcTestClientID     = "mesh-test-client"
	oidcTestClientSecret = "mesh-test-client-secret"
	oidcTestAccessToken  = "provider-access-token"
	oidcTestRefreshToken = "provider-refresh-token"
	oidcTestCode         = "authorization-code"
)

var (
	oidcTestKeyOnce sync.Once
	oidcTestKey     *rsa.PrivateKey
	oidcTestKeyErr  error
)

type fakeTLSOIDCProvider struct {
	mu     sync.Mutex
	server *httptest.Server
	key    *rsa.PrivateKey
	now    time.Time

	expectedNonce      string
	expectedChallenge  string
	expectedRedirect   string
	expectedAuthMethod string
	claimMutator       func(map[string]any)
	rawClaims          func(map[string]any) string
	metadataMutator    func(map[string]any)
	rawDiscovery       func(map[string]any) string
	tokenHook          func()
	signingAlgorithm   string
	accessToken        string
	omitIDToken        bool
	corruptSignature   bool
	validAtHash        bool
	discoveryFailures  int
	discoveryDelay     time.Duration
	discoveryBlock     <-chan struct{}
	discoveryStarted   chan<- struct{}
	oversizeDiscovery  bool
	discoveryRedirect  string
	oversizeJWKS       bool

	discoveryCalls int
	tokenCalls     int
	jwksCalls      int
	errors         []string
}

type oidcFlowHarness struct {
	flow      *OIDCFlow
	store     *FileStore
	provider  *fakeTLSOIDCProvider
	statePath string
	config    IdentityConfig
}

func TestOIDCFlowStartCompleteAndReplay(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
	harness.provider.mu.Lock()
	harness.provider.validAtHash = true
	harness.provider.mu.Unlock()
	if calls, _, _ := harness.provider.counts(); calls != 0 {
		t.Fatal("OIDC discovery occurred during constructor")
	}
	start, authorization := harness.start(t, "/networks?tab=all")
	query := authorization.Query()
	if authorization.Scheme != "https" || authorization.Host != harness.provider.server.Listener.Addr().String() || authorization.Path != "/authorize" {
		t.Fatalf("authorization endpoint = %s", authorization)
	}
	if query.Get("response_type") != "code" || query.Get("client_id") != oidcTestClientID || query.Get("redirect_uri") != "https://mesh.example.test"+oidcCallbackPath {
		t.Fatalf("authorization core parameters = %v", query)
	}
	state, nonce := query.Get("state"), query.Get("nonce")
	if !ValidOpaqueToken(start.TransactionToken) || !ValidOpaqueToken(state) || !ValidOpaqueToken(nonce) || start.TransactionToken == state || start.TransactionToken == nonce || state == nonce {
		t.Fatal("transaction, state, and nonce were not independent canonical 256-bit values")
	}
	if query.Get("code_challenge_method") != "S256" || !ValidCredentialHash(query.Get("code_challenge")) {
		t.Fatalf("PKCE parameters = %v", query)
	}
	if query.Get("max_age") != "900" || query.Get("acr_values") != "urn:mesh:mfa" {
		t.Fatalf("assurance request parameters = %v", query)
	}
	if !slices.Contains(strings.Fields(query.Get("scope")), "openid") || slices.Contains(strings.Fields(query.Get("scope")), "offline_access") {
		t.Fatalf("authorization scopes = %q", query.Get("scope"))
	}
	for _, prohibited := range []string{oidcTestClientSecret, "code_verifier", oidcTestRefreshToken} {
		if strings.Contains(start.AuthorizationURL, prohibited) {
			t.Fatalf("authorization URL leaked %q", prohibited)
		}
	}
	harness.provider.captureAuthorization(authorization)
	harness.assertStateOmits(t, start.TransactionToken, state, nonce, oidcTestClientSecret, oidcTestAccessToken, oidcTestRefreshToken)
	persisted := dumpIdentityState(t, harness.statePath)
	if len(persisted.LoginAttempts) != 1 {
		t.Fatalf("persisted login attempts=%d", len(persisted.LoginAttempts))
	}
	sealed, err := harness.store.openOIDCPayload(persisted.LoginAttempts[0].SealedOIDCPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidOpaqueToken(sealed.PKCEVerifier) || sealed.PKCEVerifier == start.TransactionToken || sealed.PKCEVerifier == state || sealed.PKCEVerifier == nonce {
		t.Fatal("PKCE verifier was not an independent canonical 256-bit value")
	}

	// A forged state neither reaches the token endpoint nor burns the attempt.
	wrong, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	wrongResult, err := harness.flow.Complete(context.Background(), start.TransactionToken, wrong, oidcTestCode)
	if !errors.Is(err, ErrUnauthorized) || wrongResult.AttemptConsumed {
		t.Fatalf("wrong-state result=%#v err=%v", wrongResult, err)
	}
	if _, calls, _ := harness.provider.counts(); calls != 0 {
		t.Fatal("wrong state reached token endpoint")
	}

	// The token endpoint observes that the transaction was already atomically consumed.
	harness.provider.mu.Lock()
	harness.provider.tokenHook = func() {
		_, consumeErr := harness.store.ConsumeLoginAttempt(context.Background(), start.TransactionToken, state, harness.provider.now)
		if !errors.Is(consumeErr, ErrUnauthorized) {
			harness.provider.recordError("token exchange began before login attempt consumption")
		}
	}
	harness.provider.mu.Unlock()
	complete, err := harness.flow.Complete(context.Background(), start.TransactionToken, state, oidcTestCode)
	if err != nil {
		t.Fatal(err)
	}
	if !complete.AttemptConsumed || complete.ReturnPath != "/networks?tab=all" || complete.Principal.ID == "" || complete.Principal.Subject != "subject-1" || complete.Principal.Email != "admin@example.test" {
		t.Fatalf("completion = %#v", complete)
	}
	harness.provider.assertClean(t)
	if _, tokenCalls, _ := harness.provider.counts(); tokenCalls != 1 {
		t.Fatalf("token endpoint calls=%d, want 1", tokenCalls)
	}
	replay, err := harness.flow.Complete(context.Background(), start.TransactionToken, state, oidcTestCode)
	if !errors.Is(err, ErrUnauthorized) || replay.AttemptConsumed {
		t.Fatalf("replay result=%#v err=%v", replay, err)
	}
	if _, tokenCalls, _ := harness.provider.counts(); tokenCalls != 1 {
		t.Fatal("replay reached token endpoint")
	}
	harness.assertStateOmits(t, oidcTestClientSecret, oidcTestAccessToken, oidcTestRefreshToken, oidcTestCode)
}

func TestOIDCFlowValidatesClaimsAgainstPostExchangeTime(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
	beforeExchange := identityTestTime()
	afterExchange := beforeExchange.Add(time.Second)
	clockCalls := 0
	harness.flow.clock = func() time.Time {
		clockCalls++
		if clockCalls <= 2 {
			return beforeExchange
		}
		return afterExchange
	}
	harness.provider.mu.Lock()
	harness.provider.now = afterExchange
	harness.provider.validAtHash = true
	harness.provider.mu.Unlock()

	start, authorization := harness.start(t, "/")
	harness.provider.captureAuthorization(authorization)
	complete, err := harness.flow.Complete(
		context.Background(), start.TransactionToken, authorization.Query().Get("state"), oidcTestCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Principal.Subject != "subject-1" || clockCalls < 4 {
		t.Fatalf("completion=%#v clock calls=%d", complete, clockCalls)
	}
}

func TestOIDCFlowAdminSelectorPathsAndTrustedEmail(t *testing.T) {
	tests := []struct {
		name      string
		selector  AdminSelector
		mutate    func(map[string]any)
		wantEmail string
	}{
		{name: "subject", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, wantEmail: "", mutate: func(claims map[string]any) { claims["email_verified"] = false }},
		{name: "verified email", selector: AdminSelector{Kind: "verified_email", Value: "admin@example.test"}, wantEmail: "admin@example.test", mutate: func(claims map[string]any) { claims["sub"] = "other-subject"; claims["groups"] = []string{} }},
		{name: "group", selector: AdminSelector{Kind: "group", Value: "mesh-admins"}, wantEmail: "", mutate: func(claims map[string]any) { claims["sub"] = "other-subject"; claims["email_verified"] = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOIDCFlowHarness(t, []AdminSelector{test.selector}, OIDCFlowOptions{})
			harness.provider.mu.Lock()
			harness.provider.claimMutator = test.mutate
			harness.provider.mu.Unlock()
			start, authorization := harness.start(t, "/")
			harness.provider.captureAuthorization(authorization)
			result, err := harness.flow.Complete(context.Background(), start.TransactionToken, authorization.Query().Get("state"), oidcTestCode)
			if err != nil {
				t.Fatal(err)
			}
			if result.Principal.Email != test.wantEmail {
				t.Fatalf("trusted principal email=%q, want %q", result.Principal.Email, test.wantEmail)
			}
			harness.provider.assertClean(t)
		})
	}
}

func TestOIDCFlowConsumesAuthorizationErrorSafely(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
	start, authorization := harness.start(t, "/settings")
	harness.provider.captureAuthorization(authorization)
	state := authorization.Query().Get("state")
	wrong, _ := NewOpaqueToken()
	if path, err := harness.flow.ConsumeAuthorizationError(context.Background(), start.TransactionToken, wrong); !errors.Is(err, ErrUnauthorized) || path != "" {
		t.Fatalf("wrong-state provider error path=%q err=%v", path, err)
	}
	path, err := harness.flow.ConsumeAuthorizationError(context.Background(), start.TransactionToken, state)
	if err != nil || path != "/settings" {
		t.Fatalf("valid provider error path=%q err=%v", path, err)
	}
	if _, err := harness.flow.ConsumeAuthorizationError(context.Background(), start.TransactionToken, state); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("provider error replay=%v", err)
	}
	if _, calls, _ := harness.provider.counts(); calls != 0 {
		t.Fatal("authorization error callback reached token endpoint")
	}
}

func TestOIDCFlowRejectsInvalidTokensAfterConsumption(t *testing.T) {
	tests := []struct {
		name      string
		selector  AdminSelector
		configure func(*fakeTLSOIDCProvider)
	}{
		{name: "nonce", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["nonce"] = strings.Repeat("A", 43) }
		}},
		{name: "issuer", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["iss"] = "https://wrong.example.test" }
		}},
		{name: "audience", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["aud"] = "other-client" } }},
		{name: "multi audience missing azp", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["aud"] = []string{oidcTestClientID, "other-client"} }
		}},
		{name: "multi audience wrong azp", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) {
				c["aud"] = []string{oidcTestClientID, "other-client"}
				c["azp"] = "other-client"
			}
		}},
		{name: "expired", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["exp"] = p.now.Add(-time.Second).Unix() }
		}},
		{name: "future iat", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["iat"] = p.now.Add(time.Second).Unix() }
		}},
		{name: "stale iat", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["iat"] = p.now.Add(-2 * time.Minute).Unix() }
		}},
		{name: "future auth time", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["auth_time"] = p.now.Add(time.Second).Unix() }
		}},
		{name: "stale auth time", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["auth_time"] = p.now.Add(-16 * time.Minute).Unix() }
		}},
		{name: "future nbf", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["nbf"] = p.now.Add(time.Second).Unix() }
		}},
		{name: "acr", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["acr"] = "urn:weak" } }},
		{name: "amr", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["amr"] = []string{"pwd"} } }},
		{name: "not admin", selector: AdminSelector{Kind: "subject", Value: "not-this-subject"}},
		{name: "unverified email", selector: AdminSelector{Kind: "verified_email", Value: "admin@example.test"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["email_verified"] = false } }},
		{name: "disallowed algorithm", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.signingAlgorithm = "RS512" }},
		{name: "malformed verified", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["email_verified"] = "true" } }},
		{name: "malformed groups", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["groups"] = "mesh-admins" } }},
		{name: "duplicate groups", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["groups"] = []string{"mesh-admins", "mesh-admins"} }
		}},
		{name: "control group", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["groups"] = []string{"mesh-admins", "bad\nvalue"} }
		}},
		{name: "oversized group", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["groups"] = []string{strings.Repeat("g", 257)} }
		}},
		{name: "duplicate amr", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "otp"} }
		}},
		{name: "control amr", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "bad\nvalue"} }
		}},
		{name: "oversized amr", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["amr"] = []string{"pwd", "otp", strings.Repeat("m", 65)} }
		}},
		{name: "missing auth time", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { delete(c, "auth_time") } }},
		{name: "duplicate claim", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.rawClaims = func(c map[string]any) string {
				raw, _ := json.Marshal(c)
				return `{"sub":"duplicate",` + strings.TrimPrefix(string(raw), "{")
			}
		}},
		{name: "bad at hash", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.claimMutator = func(c map[string]any) { c["at_hash"] = "wrong" } }},
		{name: "missing id token", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.omitIDToken = true }},
		{name: "corrupt signature", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.corruptSignature = true }},
		{name: "oversized access token", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.accessToken = strings.Repeat("x", maxOIDCAccessTokenSize+1) }},
		{name: "oversized id token", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) {
			p.claimMutator = func(c map[string]any) { c["padding"] = strings.Repeat("x", maxOIDCIDTokenSize) }
		}},
		{name: "oversized jwks", selector: AdminSelector{Kind: "subject", Value: "subject-1"}, configure: func(p *fakeTLSOIDCProvider) { p.oversizeJWKS = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOIDCFlowHarness(t, []AdminSelector{test.selector}, OIDCFlowOptions{})
			harness.provider.mu.Lock()
			if test.configure != nil {
				test.configure(harness.provider)
			}
			harness.provider.mu.Unlock()
			start, authorization := harness.start(t, "/safe")
			harness.provider.captureAuthorization(authorization)
			result, err := harness.flow.Complete(context.Background(), start.TransactionToken, authorization.Query().Get("state"), oidcTestCode)
			if !errors.Is(err, ErrUnauthorized) || !result.AttemptConsumed || result.ReturnPath != "/safe" {
				t.Fatalf("invalid token result=%#v err=%v", result, err)
			}
			if _, err := harness.flow.Complete(context.Background(), start.TransactionToken, authorization.Query().Get("state"), oidcTestCode); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("failed-token replay=%v", err)
			}
			if _, calls, _ := harness.provider.counts(); calls != 1 {
				t.Fatalf("token calls=%d, want exactly one", calls)
			}
			harness.provider.assertClean(t)
			harness.assertStateOmits(t, oidcTestClientSecret, oidcTestAccessToken, oidcTestRefreshToken)
		})
	}
}

func TestOIDCFlowLazyDiscoveryRetryAndMetadataValidation(t *testing.T) {
	t.Run("retry after outage", func(t *testing.T) {
		harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
		harness.provider.mu.Lock()
		harness.provider.discoveryFailures = 1
		harness.provider.mu.Unlock()
		if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("first discovery=%v", err)
		}
		start, authorization := harness.start(t, "/")
		if start.AuthorizationURL == "" || authorization == nil {
			t.Fatal("discovery did not retry")
		}
		if calls, _, _ := harness.provider.counts(); calls != 2 {
			t.Fatalf("discovery calls=%d, want 2", calls)
		}
	})

	metadataTests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unsafe token endpoint", mutate: func(m map[string]any) { m["token_endpoint"] = "http://issuer.example.test/token" }},
		{name: "missing s256", mutate: func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} }},
		{name: "unsupported auth", mutate: func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"} }},
		{name: "algorithm no overlap", mutate: func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"ES256"} }},
		{name: "no code response", mutate: func(m map[string]any) { m["response_types_supported"] = []string{"id_token"} }},
	}
	for _, test := range metadataTests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
			harness.provider.mu.Lock()
			harness.provider.metadataMutator = test.mutate
			harness.provider.mu.Unlock()
			if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
				t.Fatalf("unsafe metadata error=%v", err)
			}
		})
	}
	t.Run("oversized discovery", func(t *testing.T) {
		harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
		harness.provider.mu.Lock()
		harness.provider.oversizeDiscovery = true
		harness.provider.mu.Unlock()
		if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("oversized discovery error=%v", err)
		}
	})
	t.Run("duplicate discovery name", func(t *testing.T) {
		harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
		harness.provider.mu.Lock()
		harness.provider.rawDiscovery = func(metadata map[string]any) string {
			raw, _ := json.Marshal(metadata)
			return `{"issuer":"duplicate",` + strings.TrimPrefix(string(raw), "{")
		}
		harness.provider.mu.Unlock()
		if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("duplicate discovery error=%v", err)
		}
	})
	t.Run("cross-origin discovery redirect", func(t *testing.T) {
		harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
		harness.provider.mu.Lock()
		harness.provider.discoveryRedirect = "https://example.com/.well-known/openid-configuration"
		harness.provider.mu.Unlock()
		if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("cross-origin redirect error=%v", err)
		}
	})
}

func TestOIDCFlowUsesExactlyDiscoveredClientAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		methods  any
		expected string
	}{
		{name: "absent defaults basic", methods: nil, expected: "basic"},
		{name: "explicit basic", methods: []string{"client_secret_basic"}, expected: "basic"},
		{name: "explicit post", methods: []string{"client_secret_post"}, expected: "post"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
			harness.provider.mu.Lock()
			harness.provider.expectedAuthMethod = test.expected
			harness.provider.metadataMutator = func(metadata map[string]any) {
				if test.methods == nil {
					delete(metadata, "token_endpoint_auth_methods_supported")
				} else {
					metadata["token_endpoint_auth_methods_supported"] = test.methods
				}
			}
			harness.provider.mu.Unlock()
			start, authorization := harness.start(t, "/")
			harness.provider.captureAuthorization(authorization)
			if _, err := harness.flow.Complete(context.Background(), start.TransactionToken, authorization.Query().Get("state"), oidcTestCode); err != nil {
				t.Fatal(err)
			}
			harness.provider.assertClean(t)
			if _, calls, _ := harness.provider.counts(); calls != 1 {
				t.Fatalf("token calls=%d, want exactly one", calls)
			}
		})
	}
}

func TestOIDCFlowDiscoverySingleFlightAndSafeReturnPaths(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{MaxConcurrentCompletions: 8})
	harness.provider.mu.Lock()
	harness.provider.discoveryFailures = 100
	harness.provider.discoveryDelay = 50 * time.Millisecond
	harness.provider.mu.Unlock()
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := harness.flow.Start(context.Background(), "/")
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("single-flight error=%v", err)
		}
	}
	if calls, _, _ := harness.provider.counts(); calls != 1 {
		t.Fatalf("concurrent failed discovery calls=%d, want 1", calls)
	}

	fresh := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
	for _, unsafe := range []string{"/%2f%2fevil.example", "/%5cevil", "/ok?next=%0d%0aLocation:evil"} {
		if _, err := fresh.flow.Start(context.Background(), unsafe); err == nil {
			t.Fatalf("unsafe encoded return path %q was accepted", unsafe)
		}
	}
	if calls, _, _ := fresh.provider.counts(); calls != 0 {
		t.Fatal("unsafe return path triggered discovery")
	}
}

func TestOIDCFlowCompletionSemaphoreBoundsDiscoveryWaiters(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{MaxConcurrentCompletions: 2})
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	harness.provider.mu.Lock()
	harness.provider.discoveryBlock = block
	harness.provider.discoveryStarted = started
	harness.provider.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wait sync.WaitGroup
	for index := 0; index < 12; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = harness.flow.Complete(ctx, "invalid", "invalid", oidcTestCode)
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("discovery did not start")
	}
	deadline := time.Now().Add(time.Second)
	for len(harness.flow.completionSem) != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := len(harness.flow.completionSem); active != 2 {
		t.Fatalf("active completion work=%d, want semaphore capacity 2", active)
	}
	cancel()
	close(block)
	wait.Wait()
	if calls, _, _ := harness.provider.counts(); calls != 1 {
		t.Fatalf("bounded callback discovery calls=%d, want 1", calls)
	}
}

func TestOIDCFlowDiscoveryUsesHardHTTPTimeout(t *testing.T) {
	harness := newOIDCFlowHarness(t, []AdminSelector{{Kind: "subject", Value: "subject-1"}}, OIDCFlowOptions{})
	harness.flow.client.Timeout = 25 * time.Millisecond
	harness.provider.mu.Lock()
	harness.provider.discoveryDelay = 200 * time.Millisecond
	harness.provider.mu.Unlock()
	started := time.Now()
	if _, err := harness.flow.Start(context.Background(), "/"); !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("timed-out discovery error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("OIDC HTTP timeout was not enforced: %v", elapsed)
	}
}

func newOIDCFlowHarness(t *testing.T, admins []AdminSelector, options OIDCFlowOptions) *oidcFlowHarness {
	t.Helper()
	key := oidcFlowTestKey(t)
	now := identityTestTime()
	provider := &fakeTLSOIDCProvider{key: key, now: now, signingAlgorithm: "RS256", accessToken: oidcTestAccessToken, expectedAuthMethod: "basic"}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	secretPath := filepath.Join(t.TempDir(), "oidc-client-secret")
	writeOIDCFlowTestSecret(t, secretPath, oidcTestClientSecret)
	config := validOIDCConfig()
	config.PublicURL = "https://mesh.example.test"
	config.OIDC.Issuer = provider.server.URL
	config.OIDC.ClientID = oidcTestClientID
	config.OIDC.ClientSecretFile = secretPath
	config.OIDC.AllowedSigningAlgs = []string{"RS256"}
	config.OIDC.Admins = append([]AdminSelector(nil), admins...)
	config.OIDC.RequiredACRAny = []string{"urn:mesh:mfa"}
	config.OIDC.RequiredAMRAll = []string{"otp", "pwd"}
	config.OIDC.MaxAuthenticationAge = 15 * time.Minute
	statePath := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, statePath)
	t.Cleanup(func() { _ = store.Close() })
	options.HTTPClient = provider.server.Client()
	options.Clock = func() time.Time { return now }
	flow, err := NewOIDCFlow(config, store, options)
	if err != nil {
		t.Fatal(err)
	}
	return &oidcFlowHarness{flow: flow, store: store, provider: provider, statePath: statePath, config: config}
}

func (h *oidcFlowHarness) start(t *testing.T, returnPath string) (OIDCStartResult, *url.URL) {
	t.Helper()
	start, err := h.flow.Start(context.Background(), returnPath)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	return start, authorization
}

func (h *oidcFlowHarness) assertStateOmits(t *testing.T, values ...string) {
	t.Helper()
	raw, err := os.ReadFile(h.statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value != "" && strings.Contains(string(raw), value) {
			t.Fatalf("identity state leaked credential material %q", value)
		}
	}
}

func (p *fakeTLSOIDCProvider) serveHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		p.serveDiscovery(response)
	case "/token":
		p.serveToken(response, request)
	case "/jwks":
		p.serveJWKS(response)
	default:
		http.NotFound(response, request)
	}
}

func (p *fakeTLSOIDCProvider) serveDiscovery(response http.ResponseWriter) {
	p.mu.Lock()
	p.discoveryCalls++
	fail := p.discoveryFailures > 0
	if fail {
		p.discoveryFailures--
	}
	delay, block, started := p.discoveryDelay, p.discoveryBlock, p.discoveryStarted
	mutate, rawDiscovery, oversized, redirect := p.metadataMutator, p.rawDiscovery, p.oversizeDiscovery, p.discoveryRedirect
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		http.Error(response, "provider unavailable", http.StatusServiceUnavailable)
		return
	}
	if redirect != "" {
		response.Header().Set("Location", redirect)
		response.WriteHeader(http.StatusFound)
		return
	}
	metadata := map[string]any{
		"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
		"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	}
	if mutate != nil {
		mutate(metadata)
	}
	if oversized {
		metadata["padding"] = strings.Repeat("x", maxOIDCNetworkResponseSize+1)
	}
	response.Header().Set("Content-Type", "application/json")
	if rawDiscovery != nil {
		_, _ = response.Write([]byte(rawDiscovery(metadata)))
		return
	}
	_ = json.NewEncoder(response).Encode(metadata)
}

func (p *fakeTLSOIDCProvider) serveToken(response http.ResponseWriter, request *http.Request) {
	p.mu.Lock()
	p.tokenCalls++
	expectedNonce, challenge, redirect := p.expectedNonce, p.expectedChallenge, p.expectedRedirect
	mutate, rawClaims, hook := p.claimMutator, p.rawClaims, p.tokenHook
	algorithm, accessToken, authMethod := p.signingAlgorithm, p.accessToken, p.expectedAuthMethod
	omitIDToken, corrupt, validAtHash := p.omitIDToken, p.corruptSignature, p.validAtHash
	p.mu.Unlock()
	if request.Method != http.MethodPost {
		p.recordError("token endpoint did not receive POST")
		http.Error(response, "bad method", http.StatusBadRequest)
		return
	}
	if err := request.ParseForm(); err != nil {
		p.recordError("token form did not parse")
		http.Error(response, "bad form", http.StatusBadRequest)
		return
	}
	clientID, secret, basic := request.BasicAuth()
	switch authMethod {
	case "basic":
		if !basic || clientID != oidcTestClientID || secret != oidcTestClientSecret {
			p.recordError("token endpoint did not receive exact HTTP Basic client authentication")
		}
		if request.Form.Get("client_id") != "" || request.Form.Get("client_secret") != "" {
			p.recordError("basic client authentication was retried in token request body")
		}
	case "post":
		if basic || request.Form.Get("client_id") != oidcTestClientID || request.Form.Get("client_secret") != oidcTestClientSecret {
			p.recordError("token endpoint did not receive exact client_secret_post authentication")
		}
	default:
		p.recordError("test provider has an invalid expected client authentication method")
	}
	verifier := request.Form.Get("code_verifier")
	if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != oidcTestCode || request.Form.Get("redirect_uri") != redirect || !ValidOpaqueToken(verifier) || oauth2.S256ChallengeFromVerifier(verifier) != challenge {
		p.recordError("token exchange omitted exact code, redirect, or PKCE verifier")
		http.Error(response, "invalid exchange", http.StatusBadRequest)
		return
	}
	if hook != nil {
		hook()
	}
	claims := map[string]any{
		"iss": p.server.URL, "sub": "subject-1", "aud": oidcTestClientID,
		"exp": p.now.Add(5 * time.Minute).Unix(), "iat": p.now.Unix(), "nonce": expectedNonce,
		"auth_time": p.now.Add(-time.Minute).Unix(), "acr": "urn:mesh:mfa", "amr": []string{"pwd", "otp"},
		"email": "admin@example.test", "email_verified": true, "name": "Admin", "groups": []string{"mesh-admins"},
	}
	if validAtHash {
		digest := sha256.Sum256([]byte(accessToken))
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	}
	if mutate != nil {
		mutate(claims)
	}
	claimsJSON := ""
	if rawClaims != nil {
		claimsJSON = rawClaims(claims)
	} else {
		raw, _ := json.Marshal(claims)
		claimsJSON = string(raw)
	}
	idToken := signOIDCTestJWT(p.key, algorithm, claimsJSON)
	if corrupt && len(idToken) > 0 {
		parts := strings.Split(idToken, ".")
		first := parts[2][0]
		replacement := byte('A')
		if first == replacement {
			replacement = 'B'
		}
		parts[2] = string(replacement) + parts[2][1:]
		idToken = strings.Join(parts, ".")
	}
	payload := map[string]any{"access_token": accessToken, "refresh_token": oidcTestRefreshToken, "token_type": "Bearer", "expires_in": 300}
	if !omitIDToken {
		payload["id_token"] = idToken
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(payload)
}

func (p *fakeTLSOIDCProvider) serveJWKS(response http.ResponseWriter) {
	p.mu.Lock()
	p.jwksCalls++
	oversized := p.oversizeJWKS
	p.mu.Unlock()
	exponent := big.NewInt(int64(p.key.PublicKey.E)).Bytes()
	payload := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "mesh-test-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
	}}}
	if oversized {
		payload["padding"] = strings.Repeat("x", maxOIDCNetworkResponseSize+1)
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(payload)
}

func (p *fakeTLSOIDCProvider) captureAuthorization(authorization *url.URL) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedNonce = authorization.Query().Get("nonce")
	p.expectedChallenge = authorization.Query().Get("code_challenge")
	p.expectedRedirect = authorization.Query().Get("redirect_uri")
}

func (p *fakeTLSOIDCProvider) recordError(message string) {
	p.mu.Lock()
	p.errors = append(p.errors, message)
	p.mu.Unlock()
}

func (p *fakeTLSOIDCProvider) assertClean(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.errors) != 0 {
		t.Fatalf("fake OIDC validation errors: %v", p.errors)
	}
}

func (p *fakeTLSOIDCProvider) counts() (discovery, token, jwks int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discoveryCalls, p.tokenCalls, p.jwksCalls
}

func oidcFlowTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	oidcTestKeyOnce.Do(func() { oidcTestKey, oidcTestKeyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if oidcTestKeyErr != nil {
		t.Fatal(oidcTestKeyErr)
	}
	return oidcTestKey
}

func writeOIDCFlowTestSecret(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signOIDCTestJWT(key *rsa.PrivateKey, algorithm, claims string) string {
	header, _ := json.Marshal(map[string]any{"alg": algorithm, "kid": "mesh-test-key", "typ": "JWT"})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString([]byte(claims))
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(fmt.Sprintf("sign test ID token: %v", err))
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

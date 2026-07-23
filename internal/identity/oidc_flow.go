package identity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcCallbackPath             = "/api/v1/auth/oidc/callback"
	maxOIDCNetworkResponseSize   = 1 << 20
	maxOIDCIDTokenSize           = 128 << 10
	maxOIDCClaimsSize            = 64 << 10
	maxOIDCAuthorizationCodeSize = 4096
	maxOIDCAccessTokenSize       = 16 << 10
	defaultOIDCHTTPTimeout       = 15 * time.Second
	maxOIDCHTTPTimeout           = 30 * time.Second
	defaultOIDCCompletions       = 8
	maxOIDCCompletions           = 64
	oidcIssuedAtSkew             = time.Minute
)

var ErrOIDCUnavailable = errors.New("OIDC provider unavailable")

type OIDCFlowOptions struct {
	HTTPClient               *http.Client
	Clock                    func() time.Time
	MaxConcurrentCompletions int
}

type OIDCStartResult struct {
	AuthorizationURL string
	TransactionToken string
}

type OIDCCompleteResult struct {
	Principal       Principal
	ReturnPath      string
	AttemptConsumed bool
}

type OIDCFlow struct {
	config        IdentityConfig
	store         SessionStore
	client        *http.Client
	clientSecret  string
	clock         func() time.Time
	completionSem chan struct{}

	providerMu sync.Mutex
	provider   *oidcProviderBundle
	discovery  *oidcDiscoveryCall
}

type oidcProviderBundle struct {
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

type oidcDiscoveryCall struct {
	done     chan struct{}
	provider *oidcProviderBundle
	err      error
}

type oidcTokenClaims struct {
	Subject       string
	Audience      []string
	Expiry        time.Time
	IssuedAt      time.Time
	Nonce         string
	AuthorizedBy  string
	AuthTime      time.Time
	ACR           string
	AMR           []string
	Email         string
	EmailVerified bool
	DisplayName   string
	Groups        []string
	AtHash        string
}

// NewOIDCFlow validates local configuration and secret-file security without
// contacting the provider. Discovery is lazy, single-flight, cached only after
// success, and therefore cannot prevent configured recovery at process start.
func NewOIDCFlow(config IdentityConfig, store SessionStore, options OIDCFlowOptions) (*OIDCFlow, error) {
	if store == nil {
		return nil, errors.New("OIDC flow requires an identity store")
	}
	normalized, err := config.Normalized(ValidationOptions{})
	if err != nil {
		return nil, err
	}
	if normalized.Mode != ModeHybrid && normalized.Mode != ModeOIDC {
		return nil, errors.New("OIDC flow requires hybrid or OIDC identity mode")
	}
	if normalized.OIDC == nil {
		return nil, errors.New("OIDC configuration is missing")
	}
	issuer, err := url.Parse(normalized.OIDC.Issuer)
	if err != nil || issuer.Scheme != "https" {
		return nil, errors.New("production OIDC discovery requires an HTTPS issuer")
	}
	publicURL, err := url.Parse(normalized.PublicURL)
	if err != nil || publicURL.Scheme != "https" {
		return nil, errors.New("production OIDC callbacks require an HTTPS public URL")
	}
	clientSecret, err := LoadOIDCClientSecret(normalized.OIDC.ClientSecretFile)
	if err != nil {
		return nil, err
	}
	client, err := hardenedOIDCHTTPClient(options.HTTPClient)
	if err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	concurrency := options.MaxConcurrentCompletions
	if concurrency == 0 {
		concurrency = defaultOIDCCompletions
	}
	if concurrency < 1 || concurrency > maxOIDCCompletions {
		return nil, fmt.Errorf("OIDC completion concurrency must be between 1 and %d", maxOIDCCompletions)
	}
	return &OIDCFlow{
		config: normalized, store: store, client: client, clientSecret: clientSecret,
		clock: clock, completionSem: make(chan struct{}, concurrency),
	}, nil
}

func (f *OIDCFlow) Start(ctx context.Context, returnPath string) (OIDCStartResult, error) {
	if err := ctx.Err(); err != nil {
		return OIDCStartResult{}, err
	}
	if !validReturnPath(returnPath) {
		return OIDCStartResult{}, errors.New("OIDC return path must be a safe relative path")
	}
	// This bounds work inside the package; HTTP callers must additionally apply
	// per-client rate limits to both start and callback endpoints.
	if err := f.acquireCompletion(ctx); err != nil {
		return OIDCStartResult{}, err
	}
	defer f.releaseCompletion()
	bundle, err := f.providerBundle(ctx)
	if err != nil {
		return OIDCStartResult{}, err
	}
	now, err := f.now()
	if err != nil {
		return OIDCStartResult{}, err
	}
	values, err := newDistinctOpaqueTokens(5)
	if err != nil {
		return OIDCStartResult{}, err
	}
	transaction, state, nonce, verifier, idEntropy := values[0], values[1], values[2], values[3], values[4]
	attemptTTL := min(f.config.Sessions.LoginAttemptTTL, defaultLoginAttemptTTL)
	attempt := LoginAttemptInput{
		ID: "login_" + idEntropy, TransactionToken: transaction, StateToken: state,
		Nonce: nonce, PKCEVerifier: verifier, ReturnPath: returnPath,
		CreatedAt: now, ExpiresAt: now.Add(attemptTTL),
	}
	if err := f.store.CreateLoginAttempt(ctx, attempt); err != nil {
		return OIDCStartResult{}, err
	}
	options := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("max_age", strconv.FormatInt(int64(f.config.OIDC.MaxAuthenticationAge/time.Second), 10)),
	}
	if len(f.config.OIDC.RequiredACRAny) != 0 {
		options = append(options, oauth2.SetAuthURLParam("acr_values", strings.Join(f.config.OIDC.RequiredACRAny, " ")))
	}
	authorizationURL := bundle.oauthConfig.AuthCodeURL(state, options...)
	return OIDCStartResult{AuthorizationURL: authorizationURL, TransactionToken: transaction}, nil
}

func (f *OIDCFlow) Complete(ctx context.Context, transactionToken, stateToken, code string) (OIDCCompleteResult, error) {
	if err := ctx.Err(); err != nil {
		return OIDCCompleteResult{}, err
	}
	if err := f.acquireCompletion(ctx); err != nil {
		return OIDCCompleteResult{}, err
	}
	defer f.releaseCompletion()
	// Resolve or retry discovery before consuming a restart-surviving attempt.
	// The attempt is still consumed atomically before any token exchange.
	bundle, err := f.providerBundle(ctx)
	if err != nil {
		return OIDCCompleteResult{}, err
	}
	now, err := f.now()
	if err != nil {
		return OIDCCompleteResult{}, err
	}
	attempt, err := f.store.ConsumeLoginAttempt(ctx, transactionToken, stateToken, now)
	if err != nil {
		if errors.Is(err, ErrUncertainCommit) {
			return OIDCCompleteResult{AttemptConsumed: true}, ErrUnauthorized
		}
		return OIDCCompleteResult{}, oidcAuthenticationError(ctx, err)
	}
	consumedResult := OIDCCompleteResult{ReturnPath: attempt.ReturnPath, AttemptConsumed: true}
	if !validAuthorizationCode(code) {
		return consumedResult, ErrUnauthorized
	}
	networkContext := oidc.ClientContext(ctx, f.client)
	oauthToken, err := bundle.oauthConfig.Exchange(networkContext, code, oauth2.VerifierOption(attempt.PKCEVerifier))
	if err != nil || oauthToken == nil {
		return consumedResult, oidcAuthenticationError(ctx, err)
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	accessToken := oauthToken.AccessToken
	// Mesh neither returns nor retains provider bearer or refresh credentials.
	oauthToken.AccessToken, oauthToken.RefreshToken = "", ""
	if len(accessToken) < 1 || len(accessToken) > maxOIDCAccessTokenSize || !ok || len(rawIDToken) < 1 || len(rawIDToken) > maxOIDCIDTokenSize || strings.TrimSpace(rawIDToken) != rawIDToken {
		return consumedResult, ErrUnauthorized
	}
	idToken, err := bundle.verifier.Verify(networkContext, rawIDToken)
	if err != nil {
		return consumedResult, oidcAuthenticationError(ctx, err)
	}
	// Token exchange and signature verification can cross a wall-clock second.
	// Validate the provider-issued timestamps against a fresh post-exchange
	// reading rather than the time captured before the network round trip.
	validationNow, err := f.now()
	if err != nil {
		return consumedResult, err
	}
	claims, err := f.validateIDTokenClaims(idToken, accessToken, attempt, validationNow)
	accessToken, rawIDToken = "", ""
	if err != nil {
		return consumedResult, ErrUnauthorized
	}
	principalEmail := ""
	if claims.EmailVerified {
		principalEmail = claims.Email
	}
	principal, err := NewOIDCPrincipal(
		f.config.OIDC.Issuer, claims.Subject, claims.DisplayName, principalEmail,
		claims.Groups, claims.ACR, claims.AMR, claims.AuthTime,
	)
	if err != nil {
		return consumedResult, ErrUnauthorized
	}
	consumedResult.Principal = principal
	return consumedResult, nil
}

// ConsumeAuthorizationError validates and burns a legitimate denied/error
// callback without contacting the provider. A wrong state remains non-burning.
func (f *OIDCFlow) ConsumeAuthorizationError(ctx context.Context, transactionToken, stateToken string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := f.acquireCompletion(ctx); err != nil {
		return "", err
	}
	defer f.releaseCompletion()
	now, err := f.now()
	if err != nil {
		return "", err
	}
	attempt, err := f.store.ConsumeLoginAttempt(ctx, transactionToken, stateToken, now)
	if err != nil {
		return "", oidcAuthenticationError(ctx, err)
	}
	return attempt.ReturnPath, nil
}

func (f *OIDCFlow) now() (time.Time, error) {
	now := f.clock()
	if now.IsZero() {
		return time.Time{}, errors.New("OIDC clock returned zero time")
	}
	return now.UTC(), nil
}

func (f *OIDCFlow) acquireCompletion(ctx context.Context) error {
	select {
	case f.completionSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *OIDCFlow) releaseCompletion() { <-f.completionSem }

func (f *OIDCFlow) providerBundle(ctx context.Context) (*oidcProviderBundle, error) {
	f.providerMu.Lock()
	if f.provider != nil {
		provider := f.provider
		f.providerMu.Unlock()
		return provider, nil
	}
	if call := f.discovery; call != nil {
		f.providerMu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				if contextError := ctx.Err(); contextError != nil {
					return nil, contextError
				}
				return nil, ErrOIDCUnavailable
			}
			return call.provider, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &oidcDiscoveryCall{done: make(chan struct{})}
	f.discovery = call
	f.providerMu.Unlock()

	call.provider, call.err = f.discover(ctx)
	f.providerMu.Lock()
	if call.err == nil {
		f.provider = call.provider
	}
	f.discovery = nil
	close(call.done)
	f.providerMu.Unlock()
	if call.err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nil, contextError
		}
		return nil, ErrOIDCUnavailable
	}
	return call.provider, nil
}

func (f *OIDCFlow) discover(ctx context.Context) (*oidcProviderBundle, error) {
	networkContext := oidc.ClientContext(ctx, f.client)
	provider, err := oidc.NewProvider(networkContext, f.config.OIDC.Issuer)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := provider.Claims(&raw); err != nil || len(raw) < 1 || len(raw) > maxOIDCNetworkResponseSize {
		return nil, errors.New("invalid OIDC discovery document")
	}
	metadata, err := decodeJSONObject(raw, maxOIDCNetworkResponseSize)
	if err != nil {
		return nil, err
	}
	issuer, err := requiredJSONString(metadata, "issuer", 2048)
	if err != nil || issuer != f.config.OIDC.Issuer {
		return nil, errors.New("OIDC discovery issuer mismatch")
	}
	authorizationEndpoint, err := requiredJSONString(metadata, "authorization_endpoint", 2048)
	if err != nil || validateOIDCEndpoint(authorizationEndpoint) != nil {
		return nil, errors.New("OIDC discovery authorization endpoint is unsafe")
	}
	tokenEndpoint, err := requiredJSONString(metadata, "token_endpoint", 2048)
	if err != nil || validateOIDCEndpoint(tokenEndpoint) != nil {
		return nil, errors.New("OIDC discovery token endpoint is unsafe")
	}
	jwksEndpoint, err := requiredJSONString(metadata, "jwks_uri", 2048)
	if err != nil || validateOIDCEndpoint(jwksEndpoint) != nil {
		return nil, errors.New("OIDC discovery JWKS endpoint is unsafe")
	}
	responseTypes, _, err := optionalJSONStringArray(metadata, "response_types_supported", 16, 128)
	if err != nil || !slices.Contains(responseTypes, "code") {
		return nil, errors.New("OIDC provider does not advertise authorization code flow")
	}
	challengeMethods, _, err := optionalJSONStringArray(metadata, "code_challenge_methods_supported", 16, 64)
	if err != nil || !slices.Contains(challengeMethods, "S256") {
		return nil, errors.New("OIDC provider does not advertise PKCE S256")
	}
	if grantTypes, present, err := optionalJSONStringArray(metadata, "grant_types_supported", 16, 128); err != nil || (present && !slices.Contains(grantTypes, "authorization_code")) {
		return nil, errors.New("OIDC provider does not support authorization_code grant")
	}
	discoveredAlgorithms, _, err := optionalJSONStringArray(metadata, "id_token_signing_alg_values_supported", 16, 16)
	if err != nil {
		return nil, err
	}
	algorithms := intersectStrings(f.config.OIDC.AllowedSigningAlgs, discoveredAlgorithms)
	if len(algorithms) == 0 {
		return nil, errors.New("OIDC provider has no allowed signing algorithm")
	}
	authMethods, methodsPresent, err := optionalJSONStringArray(metadata, "token_endpoint_auth_methods_supported", 16, 64)
	if err != nil {
		return nil, err
	}
	authStyle := oauth2.AuthStyleInHeader
	if methodsPresent {
		switch {
		case slices.Contains(authMethods, "client_secret_basic"):
			authStyle = oauth2.AuthStyleInHeader
		case slices.Contains(authMethods, "client_secret_post"):
			authStyle = oauth2.AuthStyleInParams
		default:
			return nil, errors.New("OIDC provider has no supported client-secret authentication method")
		}
	}
	endpoint := provider.Endpoint()
	if endpoint.AuthURL != authorizationEndpoint || endpoint.TokenURL != tokenEndpoint {
		return nil, errors.New("OIDC discovery endpoint mismatch")
	}
	endpoint.AuthStyle = authStyle
	oauthConfig := oauth2.Config{
		ClientID: f.config.OIDC.ClientID, ClientSecret: f.clientSecret, Endpoint: endpoint,
		RedirectURL: f.config.PublicURL + oidcCallbackPath, Scopes: append([]string(nil), f.config.OIDC.Scopes...),
	}
	verifierContext := oidc.ClientContext(context.Background(), f.client)
	verifier := provider.VerifierContext(verifierContext, &oidc.Config{
		ClientID: f.config.OIDC.ClientID, SupportedSigningAlgs: algorithms, Now: f.clock,
	})
	return &oidcProviderBundle{oauthConfig: oauthConfig, verifier: verifier}, nil
}

func (f *OIDCFlow) validateIDTokenClaims(idToken *oidc.IDToken, accessToken string, attempt ConsumedLoginAttempt, now time.Time) (oidcTokenClaims, error) {
	if idToken == nil {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	var raw json.RawMessage
	if err := idToken.Claims(&raw); err != nil || len(raw) < 1 || len(raw) > maxOIDCClaimsSize {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	claims, err := decodeJSONObject(raw, maxOIDCClaimsSize)
	if err != nil {
		return oidcTokenClaims{}, err
	}
	issuer, err := requiredJSONString(claims, "iss", 2048)
	if err != nil || issuer != f.config.OIDC.Issuer || idToken.Issuer != issuer {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	subject, err := requiredJSONString(claims, "sub", 512)
	if err != nil || !validBoundedText(subject, 1, 512) || idToken.Subject != subject {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	audience, err := oidcAudienceClaim(claims["aud"])
	if err != nil || !slices.Equal(audience, idToken.Audience) || !slices.Contains(audience, f.config.OIDC.ClientID) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	expiry, err := requiredOIDCTime(claims, "exp")
	if err != nil || !expiry.Equal(idToken.Expiry) || !now.Before(expiry) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	issuedAt, err := requiredOIDCTime(claims, "iat")
	if err != nil || !issuedAt.Equal(idToken.IssuedAt) || issuedAt.After(now) || issuedAt.Before(attempt.CreatedAt.Add(-oidcIssuedAtSkew)) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	nonce, err := requiredJSONString(claims, "nonce", 128)
	if err != nil || !ValidOpaqueToken(nonce) || !constantTimeStringEqual(nonce, attempt.Nonce) || idToken.Nonce != nonce {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	authorizedParty, azpPresent, err := optionalJSONString(claims, "azp", 256)
	if err != nil || (len(audience) > 1 && (!azpPresent || authorizedParty != f.config.OIDC.ClientID)) || (azpPresent && authorizedParty != f.config.OIDC.ClientID) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	authTime, err := requiredOIDCTime(claims, "auth_time")
	if err != nil || authTime.After(now) || authTime.After(issuedAt) || now.Sub(authTime) > f.config.OIDC.MaxAuthenticationAge {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	acr, acrPresent, err := optionalJSONString(claims, "acr", 256)
	if err != nil || (len(f.config.OIDC.RequiredACRAny) != 0 && (!acrPresent || !slices.Contains(f.config.OIDC.RequiredACRAny, acr))) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	amr, amrPresent, err := optionalJSONStringArray(claims, "amr", 16, 64)
	if err != nil || (len(f.config.OIDC.RequiredAMRAll) != 0 && !amrPresent) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	for _, required := range f.config.OIDC.RequiredAMRAll {
		if !slices.Contains(amr, required) {
			return oidcTokenClaims{}, ErrUnauthorized
		}
	}
	email, emailPresent, err := optionalJSONString(claims, "email", 254)
	if err != nil || (emailPresent && !validCanonicalEmail(email)) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	emailVerified, verifiedPresent, err := optionalJSONBool(claims, "email_verified")
	if err != nil || (emailVerified && (!verifiedPresent || !emailPresent)) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	displayName, _, err := optionalJSONString(claims, "name", 256)
	if err != nil {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	groups := []string{}
	if f.config.OIDC.GroupsClaim != "" {
		groups, _, err = optionalJSONStringArray(claims, f.config.OIDC.GroupsClaim, 256, 256)
		if err != nil {
			return oidcTokenClaims{}, ErrUnauthorized
		}
	}
	atHash, _, err := optionalJSONString(claims, "at_hash", 256)
	if err != nil || atHash != idToken.AccessTokenHash {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	if atHash != "" && idToken.VerifyAccessToken(accessToken) != nil {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	if notBefore, present, err := optionalOIDCTime(claims, "nbf"); err != nil || (present && notBefore.After(now)) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	if !f.hasAccess(subject, email, emailVerified, groups) {
		return oidcTokenClaims{}, ErrUnauthorized
	}
	return oidcTokenClaims{
		Subject: subject, Audience: audience, Expiry: expiry, IssuedAt: issuedAt, Nonce: nonce,
		AuthorizedBy: authorizedParty, AuthTime: authTime, ACR: acr, AMR: amr,
		Email: email, EmailVerified: emailVerified, DisplayName: displayName, Groups: groups, AtHash: atHash,
	}, nil
}

func (f *OIDCFlow) hasAccess(subject, email string, emailVerified bool, groups []string) bool {
	for _, selector := range f.config.OIDC.Admins {
		if selectorMatchesClaims(selector, subject, email, emailVerified, groups) {
			return true
		}
	}
	for _, binding := range f.config.OIDC.RoleBindings {
		if selectorMatchesClaims(binding.Selector, subject, email, emailVerified, groups) {
			return true
		}
	}
	return false
}

func selectorMatchesClaims(selector AdminSelector, subject, email string, emailVerified bool, groups []string) bool {
	switch selector.Kind {
	case "subject":
		return subject == selector.Value
	case "verified_email":
		return emailVerified && email == selector.Value
	case "group":
		return slices.Contains(groups, selector.Value)
	default:
		return false
	}
}

func newDistinctOpaqueTokens(count int) ([]string, error) {
	result := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for len(result) < count {
		value, err := NewOpaqueToken()
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func validAuthorizationCode(code string) bool {
	return len(code) >= 1 && len(code) <= maxOIDCAuthorizationCodeSize && utf8.ValidString(code) && validBoundedText(code, 1, maxOIDCAuthorizationCodeSize)
}

func constantTimeStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func oidcAuthenticationError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnauthorized
}

func intersectStrings(configured, advertised []string) []string {
	result := make([]string, 0, len(configured))
	for _, value := range configured {
		if slices.Contains(advertised, value) {
			result = append(result, value)
		}
	}
	return result
}

func validateOIDCEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("OIDC endpoint must be an absolute HTTPS URL without credentials or fragment")
	}
	return nil
}

func hardenedOIDCHTTPClient(input *http.Client) (*http.Client, error) {
	base := input
	if base == nil {
		base = http.DefaultClient
	}
	result := *base
	if result.Timeout <= 0 || result.Timeout > maxOIDCHTTPTimeout {
		result.Timeout = defaultOIDCHTTPTimeout
	}
	transport := result.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	result.Transport = oidcHardenedTransport{base: transport, maxBytes: maxOIDCNetworkResponseSize}
	previousRedirect := result.CheckRedirect
	result.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 || len(via) > 4 || request.URL.Scheme != "https" || request.URL.User != nil || !sameURLOrigin(request.URL, via[0].URL) {
			return errors.New("OIDC redirect was cross-origin or unsafe")
		}
		if via[0].Method != http.MethodGet && via[0].Method != http.MethodHead {
			return errors.New("OIDC token requests may not redirect")
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		return nil
	}
	result.Jar = nil
	return &result, nil
}

type oidcHardenedTransport struct {
	base     http.RoundTripper
	maxBytes int64
}

func (t oidcHardenedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
		return nil, errors.New("OIDC network request must use HTTPS")
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		response.Body = &boundedReadCloser{ReadCloser: response.Body, remaining: t.maxBytes}
	}
	return response, nil
}

type boundedReadCloser struct {
	io.ReadCloser
	remaining int64
}

func (r *boundedReadCloser) Read(buffer []byte) (int, error) {
	if r.remaining > 0 {
		if int64(len(buffer)) > r.remaining {
			buffer = buffer[:r.remaining]
		}
		count, err := r.ReadCloser.Read(buffer)
		r.remaining -= int64(count)
		return count, err
	}
	var probe [1]byte
	count, err := r.ReadCloser.Read(probe[:])
	if count > 0 {
		return 0, errors.New("OIDC network response exceeds its size limit")
	}
	return 0, err
}

func sameURLOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && left.Scheme == right.Scheme && strings.EqualFold(left.Host, right.Host)
}

func decodeJSONObject(raw []byte, maximum int) (map[string]json.RawMessage, error) {
	if len(raw) < 2 || len(raw) > maximum || !utf8.Valid(raw) {
		return nil, errors.New("JSON object is empty, oversized, or invalid UTF-8")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("JSON value is not an object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON object contains trailing data")
	}
	return object, nil
}

func requiredJSONString(object map[string]json.RawMessage, name string, maximum int) (string, error) {
	value, present, err := optionalJSONString(object, name, maximum)
	if err != nil {
		return "", err
	}
	if !present || value == "" {
		return "", fmt.Errorf("required string claim %q is missing", name)
	}
	return value, nil
}

func optionalJSONString(object map[string]json.RawMessage, name string, maximum int) (string, bool, error) {
	raw, present := object[name]
	if !present {
		return "", false, nil
	}
	var value string
	if len(raw) > maximum*6+2 || json.Unmarshal(raw, &value) != nil || !validBoundedText(value, 1, maximum) {
		return "", false, fmt.Errorf("string claim %q is invalid", name)
	}
	return value, true, nil
}

func optionalJSONBool(object map[string]json.RawMessage, name string) (bool, bool, error) {
	raw, present := object[name]
	if !present {
		return false, false, nil
	}
	if string(raw) == "true" {
		return true, true, nil
	}
	if string(raw) == "false" {
		return false, true, nil
	}
	return false, false, fmt.Errorf("boolean claim %q is invalid", name)
}

func optionalJSONStringArray(object map[string]json.RawMessage, name string, maximumCount, maximumLength int) ([]string, bool, error) {
	raw, present := object[name]
	if !present {
		return []string{}, false, nil
	}
	var values []string
	if len(raw) > maximumCount*(maximumLength*6+3)+2 || json.Unmarshal(raw, &values) != nil || values == nil || len(values) > maximumCount {
		return nil, false, fmt.Errorf("string-array claim %q is invalid", name)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedText(value, 1, maximumLength) {
			return nil, false, fmt.Errorf("string-array claim %q contains an invalid value", name)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false, fmt.Errorf("string-array claim %q contains a duplicate", name)
		}
		seen[value] = struct{}{}
	}
	slices.Sort(values)
	return values, true, nil
}

func oidcAudienceClaim(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("audience claim is missing")
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		if !validBoundedText(single, 1, 256) {
			return nil, errors.New("audience claim is invalid")
		}
		return []string{single}, nil
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) < 1 || len(values) > 16 {
		return nil, errors.New("audience claim is invalid")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedText(value, 1, 256) {
			return nil, errors.New("audience claim is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errors.New("audience claim contains a duplicate")
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

func requiredOIDCTime(object map[string]json.RawMessage, name string) (time.Time, error) {
	value, present, err := optionalOIDCTime(object, name)
	if err != nil {
		return time.Time{}, err
	}
	if !present {
		return time.Time{}, fmt.Errorf("required time claim %q is missing", name)
	}
	return value, nil
}

func optionalOIDCTime(object map[string]json.RawMessage, name string) (time.Time, bool, error) {
	raw, present := object[name]
	if !present {
		return time.Time{}, false, nil
	}
	var seconds int64
	if json.Unmarshal(raw, &seconds) != nil || seconds <= 0 {
		return time.Time{}, false, fmt.Errorf("time claim %q is invalid", name)
	}
	return time.Unix(seconds, 0).UTC(), true, nil
}

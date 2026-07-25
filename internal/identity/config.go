package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Mode string

const (
	ModeLegacyToken Mode = "legacy-token"
	ModeHybrid      Mode = "hybrid"
	ModeOIDC        Mode = "oidc"
)

const (
	defaultIdleTTL         = 15 * time.Minute
	defaultAbsoluteTTL     = time.Hour
	defaultLoginAttemptTTL = 5 * time.Minute
	defaultTouchInterval   = time.Minute
)

var (
	claimNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:/-]{0,127}$`)
	// RFC 6749 scope-token excludes space, double quote, and backslash.
	scopePattern     = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]{1,128}$`)
	hexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var reservedOIDCClaimNames = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {},
	"nonce": {}, "azp": {}, "auth_time": {}, "acr": {}, "amr": {},
	"email": {}, "email_verified": {}, "name": {}, "preferred_username": {},
	"at_hash": {}, "c_hash": {}, "sid": {}, "jti": {},
	"_claim_names": {}, "_claim_sources": {},
}

type IdentityConfig struct {
	Mode               Mode             `json:"mode"`
	PublicURL          string           `json:"public_url"`
	OIDC               *OIDCConfig      `json:"oidc,omitempty"`
	Sessions           SessionConfig    `json:"sessions"`
	LegacyBrowserLogin bool             `json:"legacy_browser_login,omitempty"`
	LegacyBearer       bool             `json:"legacy_bearer,omitempty"`
	BreakGlass         BreakGlassConfig `json:"break_glass"`
}

type OIDCConfig struct {
	Issuer               string          `json:"issuer"`
	ClientID             string          `json:"client_id"`
	ClientSecretFile     string          `json:"client_secret_file"`
	Scopes               []string        `json:"scopes"`
	GroupsClaim          string          `json:"groups_claim,omitempty"`
	AllowedSigningAlgs   []string        `json:"allowed_signing_algorithms"`
	Admins               []AdminSelector `json:"admins"`
	RoleBindings         []RoleBinding   `json:"role_bindings,omitempty"`
	RequiredACRAny       []string        `json:"required_acr_any,omitempty"`
	RequiredAMRAll       []string        `json:"required_amr_all,omitempty"`
	MaxAuthenticationAge time.Duration   `json:"max_authentication_age,omitempty"`
}

type AdminSelector struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type SessionConfig struct {
	IdleTTL         time.Duration `json:"idle_ttl,omitempty"`
	AbsoluteTTL     time.Duration `json:"absolute_ttl,omitempty"`
	LoginAttemptTTL time.Duration `json:"login_attempt_ttl,omitempty"`
	TouchInterval   time.Duration `json:"touch_interval,omitempty"`
}

type BreakGlassConfig struct {
	Enabled            bool `json:"enabled"`
	MinimumUsableCodes int  `json:"minimum_usable_codes,omitempty"`
}

const (
	MinBreakGlassUsableCodes = 2
	MaxBreakGlassUsableCodes = 32
)

type ValidationOptions struct {
	AllowInsecureLoopback bool
}

func (c IdentityConfig) Normalized(options ValidationOptions) (IdentityConfig, error) {
	out := c
	out.PublicURL = strings.TrimSpace(out.PublicURL)
	if out.Sessions.IdleTTL == 0 {
		out.Sessions.IdleTTL = defaultIdleTTL
	}
	if out.Sessions.AbsoluteTTL == 0 {
		out.Sessions.AbsoluteTTL = defaultAbsoluteTTL
	}
	if out.Sessions.LoginAttemptTTL == 0 {
		out.Sessions.LoginAttemptTTL = defaultLoginAttemptTTL
	}
	if out.Sessions.TouchInterval == 0 {
		out.Sessions.TouchInterval = defaultTouchInterval
	}
	if err := validatePublicURL(out.PublicURL, options.AllowInsecureLoopback); err != nil {
		return IdentityConfig{}, err
	}
	if err := validateSessionConfig(out.Sessions); err != nil {
		return IdentityConfig{}, err
	}
	switch out.Mode {
	case ModeLegacyToken:
		if out.OIDC != nil {
			return IdentityConfig{}, errors.New("legacy-token mode cannot contain OIDC configuration")
		}
		if !out.LegacyBearer {
			return IdentityConfig{}, errors.New("legacy-token mode requires legacy_bearer")
		}
		if out.BreakGlass.Enabled || out.BreakGlass.MinimumUsableCodes != 0 {
			return IdentityConfig{}, errors.New("legacy-token mode cannot enable OIDC break-glass recovery")
		}
	case ModeHybrid:
		if out.OIDC == nil || !out.LegacyBearer {
			return IdentityConfig{}, errors.New("hybrid mode requires OIDC configuration and legacy_bearer")
		}
	case ModeOIDC:
		if out.OIDC == nil || out.LegacyBearer || out.LegacyBrowserLogin {
			return IdentityConfig{}, errors.New("oidc mode requires OIDC configuration and forbids legacy authentication")
		}
		if !out.BreakGlass.Enabled {
			return IdentityConfig{}, errors.New("oidc mode requires break-glass recovery")
		}
	default:
		return IdentityConfig{}, fmt.Errorf("unsupported identity mode %q", out.Mode)
	}
	if out.BreakGlass.Enabled && out.BreakGlass.MinimumUsableCodes == 0 {
		out.BreakGlass.MinimumUsableCodes = MinBreakGlassUsableCodes
	}
	if out.BreakGlass.Enabled {
		if out.BreakGlass.MinimumUsableCodes < MinBreakGlassUsableCodes || out.BreakGlass.MinimumUsableCodes > MaxBreakGlassUsableCodes {
			return IdentityConfig{}, fmt.Errorf("break-glass minimum_usable_codes must be %d-%d", MinBreakGlassUsableCodes, MaxBreakGlassUsableCodes)
		}
	} else if out.BreakGlass.MinimumUsableCodes != 0 {
		return IdentityConfig{}, errors.New("break-glass minimum_usable_codes requires break-glass recovery to be enabled")
	}
	if out.OIDC != nil {
		normalized, err := normalizeOIDC(*out.OIDC, options)
		if err != nil {
			return IdentityConfig{}, err
		}
		out.OIDC = &normalized
	}
	return out, nil
}

func (c IdentityConfig) Validate(options ValidationOptions) error {
	_, err := c.Normalized(options)
	return err
}

func (c IdentityConfig) PolicyFingerprint(options ValidationOptions) (string, error) {
	normalized, err := c.Normalized(options)
	if err != nil {
		return "", err
	}
	type oidcPolicy struct {
		Issuer               string          `json:"issuer"`
		ClientID             string          `json:"client_id"`
		Scopes               []string        `json:"scopes"`
		GroupsClaim          string          `json:"groups_claim,omitempty"`
		AllowedSigningAlgs   []string        `json:"allowed_signing_algorithms"`
		Admins               []AdminSelector `json:"admins"`
		RoleBindings         []RoleBinding   `json:"role_bindings,omitempty"`
		RequiredACRAny       []string        `json:"required_acr_any,omitempty"`
		RequiredAMRAll       []string        `json:"required_amr_all,omitempty"`
		MaxAuthenticationAge int64           `json:"max_authentication_age_ns,omitempty"`
	}
	payload := struct {
		Schema             string           `json:"schema"`
		Mode               Mode             `json:"mode"`
		PublicURL          string           `json:"public_url"`
		OIDC               *oidcPolicy      `json:"oidc,omitempty"`
		Sessions           SessionConfig    `json:"sessions"`
		LegacyBrowserLogin bool             `json:"legacy_browser_login"`
		LegacyBearer       bool             `json:"legacy_bearer"`
		BreakGlass         BreakGlassConfig `json:"break_glass"`
	}{
		Schema: "mesh-identity-policy-v1", Mode: normalized.Mode, PublicURL: normalized.PublicURL,
		Sessions: normalized.Sessions, LegacyBrowserLogin: normalized.LegacyBrowserLogin,
		LegacyBearer: normalized.LegacyBearer, BreakGlass: normalized.BreakGlass,
	}
	if normalized.OIDC != nil {
		payload.OIDC = &oidcPolicy{
			Issuer: normalized.OIDC.Issuer, ClientID: normalized.OIDC.ClientID,
			Scopes: normalized.OIDC.Scopes, GroupsClaim: normalized.OIDC.GroupsClaim,
			AllowedSigningAlgs: normalized.OIDC.AllowedSigningAlgs, Admins: normalized.OIDC.Admins,
			RoleBindings:   normalized.OIDC.RoleBindings,
			RequiredACRAny: normalized.OIDC.RequiredACRAny, RequiredAMRAll: normalized.OIDC.RequiredAMRAll,
			MaxAuthenticationAge: int64(normalized.OIDC.MaxAuthenticationAge),
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validatePublicURL(raw string, allowInsecureLoopback bool) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return errors.New("public_url must contain 1-2048 characters")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("public_url must be an absolute URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return errors.New("public_url must be an origin without credentials, path, query, or fragment")
	}
	if parsed.Hostname() == "" || strings.HasSuffix(parsed.Hostname(), ".") || parsed.Host != strings.ToLower(parsed.Host) || parsed.Scheme != strings.ToLower(parsed.Scheme) {
		return errors.New("public_url must use a canonical lowercase scheme and host")
	}
	if err := validateCanonicalURLPort(parsed); err != nil {
		return fmt.Errorf("public_url: %w", err)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !allowInsecureLoopback || !isLoopbackHost(parsed.Hostname()) {
		return errors.New("public_url must use HTTPS except for explicitly allowed loopback development")
	}
	return nil
}

func normalizeOIDC(input OIDCConfig, options ValidationOptions) (OIDCConfig, error) {
	out := input
	out.Admins = append([]AdminSelector(nil), input.Admins...)
	out.RoleBindings = append([]RoleBinding(nil), input.RoleBindings...)
	out.Issuer = strings.TrimSpace(out.Issuer)
	out.ClientID = strings.TrimSpace(out.ClientID)
	out.ClientSecretFile = strings.TrimSpace(out.ClientSecretFile)
	out.GroupsClaim = strings.TrimSpace(out.GroupsClaim)
	if err := validateIssuerURL(out.Issuer, options.AllowInsecureLoopback); err != nil {
		return OIDCConfig{}, err
	}
	if !validBoundedText(out.ClientID, 1, 256) {
		return OIDCConfig{}, errors.New("OIDC client_id must be 1-256 printable characters")
	}
	if len(out.ClientSecretFile) == 0 || len(out.ClientSecretFile) > 4096 || strings.IndexByte(out.ClientSecretFile, 0) >= 0 || !filepath.IsAbs(out.ClientSecretFile) || filepath.Clean(out.ClientSecretFile) != out.ClientSecretFile || filepath.Base(out.ClientSecretFile) == "." || filepath.Base(out.ClientSecretFile) == string(filepath.Separator) {
		return OIDCConfig{}, errors.New("OIDC client_secret_file must be a clean absolute path")
	}
	if out.GroupsClaim != "" {
		if !claimNamePattern.MatchString(out.GroupsClaim) {
			return OIDCConfig{}, errors.New("OIDC groups_claim is invalid")
		}
		if _, reserved := reservedOIDCClaimNames[out.GroupsClaim]; reserved {
			return OIDCConfig{}, errors.New("OIDC groups_claim collides with a reserved security claim")
		}
	}
	var err error
	out.Scopes, err = canonicalStrings(out.Scopes, 1, 32, 128, func(value string) bool { return scopePattern.MatchString(value) })
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC scopes: %w", err)
	}
	if !containsString(out.Scopes, "openid") {
		return OIDCConfig{}, errors.New("OIDC scopes must include openid")
	}
	if containsString(out.Scopes, "offline_access") {
		return OIDCConfig{}, errors.New("OIDC offline_access is not permitted because Mesh does not retain refresh tokens")
	}
	allowedAlgorithms := map[string]bool{"RS256": true, "PS256": true, "ES256": true, "EdDSA": true}
	out.AllowedSigningAlgs, err = canonicalStrings(out.AllowedSigningAlgs, 1, 8, 16, func(value string) bool { return allowedAlgorithms[value] })
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC signing algorithms: %w", err)
	}
	if len(out.Admins)+len(out.RoleBindings) < 1 || len(out.Admins)+len(out.RoleBindings) > 256 {
		return OIDCConfig{}, errors.New("OIDC access policy must contain 1-256 admin selectors or role bindings")
	}
	selectorKeys := make(map[string]struct{}, len(out.Admins)+len(out.RoleBindings))
	for index := range out.Admins {
		selector := &out.Admins[index]
		if err := normalizeAccessSelector(selector, out.GroupsClaim); err != nil {
			return OIDCConfig{}, fmt.Errorf("OIDC admin selector %d: %w", index, err)
		}
		key := selector.Kind + "\x00" + selector.Value
		if _, duplicate := selectorKeys[key]; duplicate {
			return OIDCConfig{}, fmt.Errorf("OIDC admin selector %d is duplicated", index)
		}
		selectorKeys[key] = struct{}{}
	}
	for index := range out.RoleBindings {
		binding := &out.RoleBindings[index]
		if err := binding.Role.Validate(); err != nil {
			return OIDCConfig{}, fmt.Errorf("OIDC role binding %d: %w", index, err)
		}
		if err := normalizeAccessSelector(&binding.Selector, out.GroupsClaim); err != nil {
			return OIDCConfig{}, fmt.Errorf("OIDC role binding %d: %w", index, err)
		}
		key := binding.Selector.Kind + "\x00" + binding.Selector.Value
		if _, duplicate := selectorKeys[key]; duplicate {
			return OIDCConfig{}, fmt.Errorf("OIDC role binding %d duplicates another access selector", index)
		}
		selectorKeys[key] = struct{}{}
	}
	sort.Slice(out.Admins, func(i, j int) bool {
		if out.Admins[i].Kind == out.Admins[j].Kind {
			return out.Admins[i].Value < out.Admins[j].Value
		}
		return out.Admins[i].Kind < out.Admins[j].Kind
	})
	sort.Slice(out.RoleBindings, func(i, j int) bool {
		if out.RoleBindings[i].Role != out.RoleBindings[j].Role {
			return out.RoleBindings[i].Role < out.RoleBindings[j].Role
		}
		if out.RoleBindings[i].Selector.Kind != out.RoleBindings[j].Selector.Kind {
			return out.RoleBindings[i].Selector.Kind < out.RoleBindings[j].Selector.Kind
		}
		return out.RoleBindings[i].Selector.Value < out.RoleBindings[j].Selector.Value
	})
	out.RequiredACRAny, err = canonicalStrings(out.RequiredACRAny, 0, 16, 256, func(value string) bool { return validBoundedText(value, 1, 256) })
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC required ACR values: %w", err)
	}
	out.RequiredAMRAll, err = canonicalStrings(out.RequiredAMRAll, 0, 16, 64, func(value string) bool { return validBoundedText(value, 1, 64) })
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC required AMR values: %w", err)
	}
	if len(out.RequiredACRAny) == 0 && len(out.RequiredAMRAll) == 0 {
		return OIDCConfig{}, errors.New("OIDC production policy requires at least one ACR or AMR assurance rule")
	}
	if out.MaxAuthenticationAge < time.Second || out.MaxAuthenticationAge > 24*time.Hour || out.MaxAuthenticationAge%time.Second != 0 {
		return OIDCConfig{}, errors.New("OIDC max_authentication_age must be a positive whole-second duration no longer than 24 hours")
	}
	return out, nil
}

func normalizeAccessSelector(selector *AdminSelector, groupsClaim string) error {
	selector.Kind = strings.TrimSpace(selector.Kind)
	selector.Value = strings.TrimSpace(selector.Value)
	switch selector.Kind {
	case "subject":
		if !validBoundedText(selector.Value, 1, 512) {
			return errors.New("selector has an invalid subject")
		}
	case "verified_email":
		if !validCanonicalEmail(selector.Value) {
			return errors.New("selector has an invalid canonical email")
		}
	case "group":
		if groupsClaim == "" {
			return errors.New("group selector requires groups_claim")
		}
		if !validBoundedText(selector.Value, 1, 256) {
			return errors.New("selector has an invalid group")
		}
	default:
		return fmt.Errorf("selector has unsupported kind %q", selector.Kind)
	}
	return nil
}

func validateIssuerURL(raw string, allowInsecureLoopback bool) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return errors.New("OIDC issuer must contain 1-2048 characters")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("OIDC issuer must be an absolute URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("OIDC issuer must be canonical and contain no credentials, query, or fragment")
	}
	if parsed.Hostname() == "" || strings.HasSuffix(parsed.Hostname(), ".") || parsed.Host != strings.ToLower(parsed.Host) || parsed.Scheme != strings.ToLower(parsed.Scheme) {
		return errors.New("OIDC issuer must use a canonical lowercase scheme and host")
	}
	if err := validateCanonicalURLPort(parsed); err != nil {
		return fmt.Errorf("OIDC issuer: %w", err)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !allowInsecureLoopback || !isLoopbackHost(parsed.Hostname()) {
		return errors.New("OIDC issuer must use HTTPS except for explicitly allowed loopback development")
	}
	return nil
}

func validateSessionConfig(config SessionConfig) error {
	if config.IdleTTL < 5*time.Minute || config.IdleTTL > time.Hour {
		return errors.New("session idle_ttl must be between 5 minutes and 1 hour")
	}
	if config.AbsoluteTTL < 15*time.Minute || config.AbsoluteTTL > 8*time.Hour || config.AbsoluteTTL < config.IdleTTL {
		return errors.New("session absolute_ttl must be between 15 minutes and 8 hours and not shorter than idle_ttl")
	}
	if config.LoginAttemptTTL < time.Minute || config.LoginAttemptTTL > 10*time.Minute {
		return errors.New("session login_attempt_ttl must be between 1 and 10 minutes")
	}
	if config.TouchInterval < 30*time.Second || config.TouchInterval > 5*time.Minute || config.TouchInterval >= config.IdleTTL {
		return errors.New("session touch_interval must be between 30 seconds and 5 minutes and shorter than idle_ttl")
	}
	return nil
}

func canonicalStrings(values []string, minimum, maximum, maxLength int, valid func(string) bool) ([]string, error) {
	if len(values) < minimum || len(values) > maximum {
		return nil, fmt.Errorf("must contain %d-%d values", minimum, maximum)
	}
	result := append([]string(nil), values...)
	seen := make(map[string]struct{}, len(result))
	for index, value := range result {
		if strings.TrimSpace(value) != value || len(value) > maxLength || !valid(value) {
			return nil, fmt.Errorf("value %d is invalid", index)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("value %d is duplicated", index)
		}
		seen[value] = struct{}{}
	}
	sort.Strings(result)
	return result, nil
}

func validBoundedText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validCanonicalEmail(value string) bool {
	if value != strings.ToLower(value) || len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 || !validBoundedText(value, 3, 254) {
		return false
	}
	local, domain, _ := strings.Cut(value, "@")
	if local == "" || len(local) > 64 || domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	for _, character := range value {
		if character > 0x7f || character == ' ' || character == '<' || character == '>' || character == ',' || character == ';' {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateCanonicalURLPort(parsed *url.URL) error {
	port := parsed.Port()
	if port == "" {
		return nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("port must be a canonical decimal value between 1 and 65535")
	}
	if (parsed.Scheme == "https" && number == 443) || (parsed.Scheme == "http" && number == 80) {
		return errors.New("scheme default port must be omitted")
	}
	return nil
}

func containsString(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

func validPolicyFingerprint(value string) bool { return hexDigestPattern.MatchString(value) }

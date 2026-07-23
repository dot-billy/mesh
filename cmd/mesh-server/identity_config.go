package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"mesh/internal/identity"
)

const (
	hybridIdentitySchema  = "mesh-hybrid-identity-v1"
	identityPolicySchema  = "mesh-identity-v2"
	maxIdentityConfigSize = 64 << 10
)

type hybridIdentityFile struct {
	Schema             string            `json:"schema"`
	LegacyBrowserLogin bool              `json:"legacy_browser_login"`
	OIDC               hybridOIDCFile    `json:"oidc"`
	Sessions           hybridSessionFile `json:"sessions,omitempty"`
}

type identityPolicyFile struct {
	Schema             string                    `json:"schema"`
	Mode               identity.Mode             `json:"mode"`
	LegacyBrowserLogin bool                      `json:"legacy_browser_login,omitempty"`
	OIDC               hybridOIDCFile            `json:"oidc"`
	Sessions           hybridSessionFile         `json:"sessions,omitempty"`
	BreakGlass         identity.BreakGlassConfig `json:"break_glass"`
}

type hybridOIDCFile struct {
	Issuer               string                   `json:"issuer"`
	ClientID             string                   `json:"client_id"`
	ClientSecretFile     string                   `json:"client_secret_file"`
	Scopes               []string                 `json:"scopes"`
	GroupsClaim          string                   `json:"groups_claim,omitempty"`
	AllowedSigningAlgs   []string                 `json:"allowed_signing_algorithms"`
	Admins               []identity.AdminSelector `json:"admins"`
	RoleBindings         []identity.RoleBinding   `json:"role_bindings,omitempty"`
	RequiredACRAny       []string                 `json:"required_acr_any,omitempty"`
	RequiredAMRAll       []string                 `json:"required_amr_all,omitempty"`
	MaxAuthenticationAge string                   `json:"max_authentication_age"`
}

type hybridSessionFile struct {
	IdleTTL         string `json:"idle_ttl,omitempty"`
	AbsoluteTTL     string `json:"absolute_ttl,omitempty"`
	LoginAttemptTTL string `json:"login_attempt_ttl,omitempty"`
	TouchInterval   string `json:"touch_interval,omitempty"`
}

// loadIdentityConfiguration keeps the externally derived browser origin out
// of the policy file so redirects, cookie origin checks, and TLS exposure all
// share one source of truth. An absent file preserves the legacy-token mode.
func loadIdentityConfiguration(path, publicURL string, validation identity.ValidationOptions) (identity.IdentityConfig, error) {
	if path == "" {
		return (identity.IdentityConfig{
			Mode: identity.ModeLegacyToken, PublicURL: publicURL,
			LegacyBrowserLogin: true, LegacyBearer: true,
		}).Normalized(validation)
	}
	raw, err := readPrivateIdentityConfiguration(path)
	if err != nil {
		return identity.IdentityConfig{}, err
	}
	if err := rejectDuplicateIdentityJSONNames(raw); err != nil {
		return identity.IdentityConfig{}, fmt.Errorf("identity configuration: %w", err)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return identity.IdentityConfig{}, fmt.Errorf("decode identity configuration: %w", err)
	}
	switch header.Schema {
	case hybridIdentitySchema:
		return loadHybridIdentityConfiguration(raw, publicURL, validation)
	case identityPolicySchema:
		return loadIdentityPolicyConfiguration(raw, publicURL, validation)
	default:
		return identity.IdentityConfig{}, fmt.Errorf("identity configuration schema must be %q or %q", hybridIdentitySchema, identityPolicySchema)
	}
}

func loadHybridIdentityConfiguration(raw []byte, publicURL string, validation identity.ValidationOptions) (identity.IdentityConfig, error) {
	var file hybridIdentityFile
	if err := decodeStrictIdentityConfiguration(raw, &file); err != nil {
		return identity.IdentityConfig{}, err
	}
	sessions, err := parseHybridSessionConfiguration(file.Sessions)
	if err != nil {
		return identity.IdentityConfig{}, err
	}
	maxAuthenticationAge, err := requiredIdentityDuration("oidc.max_authentication_age", file.OIDC.MaxAuthenticationAge)
	if err != nil {
		return identity.IdentityConfig{}, err
	}
	config := identity.IdentityConfig{
		Mode: identity.ModeHybrid, PublicURL: publicURL, Sessions: sessions,
		LegacyBrowserLogin: file.LegacyBrowserLogin, LegacyBearer: true,
		OIDC: &identity.OIDCConfig{
			Issuer: file.OIDC.Issuer, ClientID: file.OIDC.ClientID,
			ClientSecretFile: file.OIDC.ClientSecretFile,
			Scopes:           file.OIDC.Scopes, GroupsClaim: file.OIDC.GroupsClaim,
			AllowedSigningAlgs: file.OIDC.AllowedSigningAlgs, Admins: file.OIDC.Admins,
			RoleBindings:   file.OIDC.RoleBindings,
			RequiredACRAny: file.OIDC.RequiredACRAny, RequiredAMRAll: file.OIDC.RequiredAMRAll,
			MaxAuthenticationAge: maxAuthenticationAge,
		},
	}
	return config.Normalized(validation)
}

func loadIdentityPolicyConfiguration(raw []byte, publicURL string, validation identity.ValidationOptions) (identity.IdentityConfig, error) {
	var file identityPolicyFile
	if err := decodeStrictIdentityConfiguration(raw, &file); err != nil {
		return identity.IdentityConfig{}, err
	}
	sessions, err := parseHybridSessionConfiguration(file.Sessions)
	if err != nil {
		return identity.IdentityConfig{}, err
	}
	maxAuthenticationAge, err := requiredIdentityDuration("oidc.max_authentication_age", file.OIDC.MaxAuthenticationAge)
	if err != nil {
		return identity.IdentityConfig{}, err
	}
	config := identity.IdentityConfig{
		Mode: file.Mode, PublicURL: publicURL, Sessions: sessions,
		LegacyBrowserLogin: file.LegacyBrowserLogin,
		LegacyBearer:       file.Mode == identity.ModeHybrid,
		BreakGlass:         file.BreakGlass,
		OIDC: &identity.OIDCConfig{
			Issuer: file.OIDC.Issuer, ClientID: file.OIDC.ClientID,
			ClientSecretFile: file.OIDC.ClientSecretFile,
			Scopes:           file.OIDC.Scopes, GroupsClaim: file.OIDC.GroupsClaim,
			AllowedSigningAlgs: file.OIDC.AllowedSigningAlgs, Admins: file.OIDC.Admins,
			RoleBindings:   file.OIDC.RoleBindings,
			RequiredACRAny: file.OIDC.RequiredACRAny, RequiredAMRAll: file.OIDC.RequiredAMRAll,
			MaxAuthenticationAge: maxAuthenticationAge,
		},
	}
	return config.Normalized(validation)
}

func decodeStrictIdentityConfiguration(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode identity configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("identity configuration contains trailing data")
	}
	return nil
}

func parseHybridSessionConfiguration(file hybridSessionFile) (identity.SessionConfig, error) {
	var result identity.SessionConfig
	for _, field := range []struct {
		name  string
		raw   string
		value *time.Duration
	}{
		{name: "sessions.idle_ttl", raw: file.IdleTTL, value: &result.IdleTTL},
		{name: "sessions.absolute_ttl", raw: file.AbsoluteTTL, value: &result.AbsoluteTTL},
		{name: "sessions.login_attempt_ttl", raw: file.LoginAttemptTTL, value: &result.LoginAttemptTTL},
		{name: "sessions.touch_interval", raw: file.TouchInterval, value: &result.TouchInterval},
	} {
		if field.raw == "" {
			continue
		}
		parsed, err := requiredIdentityDuration(field.name, field.raw)
		if err != nil {
			return identity.SessionConfig{}, err
		}
		*field.value = parsed
	}
	return result, nil
}

func requiredIdentityDuration(name, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("identity configuration %s is required", name)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 || parsed%time.Second != 0 {
		return 0, fmt.Errorf("identity configuration %s must be a positive whole-second Go duration", name)
	}
	return parsed, nil
}

func readPrivateIdentityConfiguration(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errors.New("--identity-config must be a clean absolute file path")
	}
	if err := rejectIdentityConfigurationSymlinkPath(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect identity configuration: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maxIdentityConfigSize {
		return nil, errors.New("identity configuration must be a private, owner-controlled, single-link regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity configuration: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !identityConfigFilePrivate(file, after) {
		return nil, errors.New("identity configuration changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxIdentityConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read identity configuration: %w", err)
	}
	if len(raw) < 2 || len(raw) > maxIdentityConfigSize {
		return nil, errors.New("identity configuration is empty or oversized")
	}
	return raw, nil
}

func rejectIdentityConfigurationSymlinkPath(directory string) error {
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect identity configuration path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("identity configuration path component %q is not a real directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func rejectDuplicateIdentityJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting exceeds its depth limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, structured := token.(json.Delim)
		if !structured {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("JSON object name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate JSON object name %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("invalid JSON object closing delimiter")
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("invalid JSON array closing delimiter")
			}
		default:
			return errors.New("invalid JSON opening delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

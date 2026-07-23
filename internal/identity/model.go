package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type PrincipalKind string

const (
	PrincipalOIDCAdmin   PrincipalKind = "oidc_admin"
	PrincipalLegacyAdmin PrincipalKind = "legacy_admin"
	PrincipalService     PrincipalKind = "service_account"
	PrincipalBreakGlass  PrincipalKind = "break_glass"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Principal struct {
	ID          string        `json:"id"`
	Kind        PrincipalKind `json:"kind"`
	Issuer      string        `json:"issuer,omitempty"`
	Subject     string        `json:"subject,omitempty"`
	DisplayName string        `json:"display_name,omitempty"`
	Email       string        `json:"email,omitempty"`
	Groups      []string      `json:"groups,omitempty"`
	ACR         string        `json:"acr,omitempty"`
	AMR         []string      `json:"amr,omitempty"`
	AuthTime    time.Time     `json:"auth_time"`
}

type Actor struct {
	ID        string        `json:"id"`
	Kind      PrincipalKind `json:"kind"`
	SessionID string        `json:"session_id,omitempty"`
}

func NewOIDCPrincipal(issuer, subject, displayName, email string, groups []string, acr string, amr []string, authTime time.Time) (Principal, error) {
	groups = append([]string(nil), groups...)
	amr = append([]string(nil), amr...)
	sort.Strings(groups)
	sort.Strings(amr)
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	principal := Principal{
		ID: "oidc_" + base64.RawURLEncoding.EncodeToString(digest[:]), Kind: PrincipalOIDCAdmin,
		Issuer: issuer, Subject: subject, DisplayName: displayName, Email: email,
		Groups: groups, ACR: acr, AMR: amr, AuthTime: authTime.UTC(),
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func NewLegacyPrincipal(authTime time.Time) (Principal, error) {
	principal := Principal{ID: "legacy_admin", Kind: PrincipalLegacyAdmin, AuthTime: authTime.UTC()}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func NewServicePrincipal(recordID, displayName string, authTime time.Time) (Principal, error) {
	if !identifierPattern.MatchString(recordID) || len("service_"+recordID) > 128 {
		return Principal{}, errors.New("service principal record ID is invalid")
	}
	principal := Principal{ID: "service_" + recordID, Kind: PrincipalService, DisplayName: displayName, AuthTime: authTime.UTC()}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func NewBreakGlassPrincipal(codeID string, authTime time.Time) (Principal, error) {
	if !identifierPattern.MatchString(codeID) || !strings.HasPrefix(codeID, "bg_") || len("breakglass_"+codeID) > 128 {
		return Principal{}, errors.New("break-glass code ID is invalid")
	}
	principal := Principal{ID: "breakglass_" + codeID, Kind: PrincipalBreakGlass, AuthTime: authTime.UTC()}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func (p Principal) Validate() error {
	if !identifierPattern.MatchString(p.ID) || !isCanonicalTime(p.AuthTime) {
		return errors.New("principal has an invalid identity or authentication time")
	}
	switch p.Kind {
	case PrincipalOIDCAdmin:
		if validateIssuerURL(p.Issuer, true) != nil || !validBoundedText(p.Subject, 1, 512) {
			return errors.New("OIDC principal is missing a valid issuer or subject")
		}
		digest := sha256.Sum256([]byte(p.Issuer + "\x00" + p.Subject))
		if p.ID != "oidc_"+base64.RawURLEncoding.EncodeToString(digest[:]) {
			return errors.New("OIDC principal ID does not match issuer and subject")
		}
	case PrincipalLegacyAdmin:
		if p.ID != "legacy_admin" || hasOIDCClaims(p) || p.DisplayName != "" || p.Email != "" {
			return errors.New("legacy administrator principal is not canonical")
		}
	case PrincipalService:
		if !validPrefixedID(p.ID, "service_") || hasOIDCClaims(p) || p.Email != "" {
			return errors.New("service principal is not canonical")
		}
	case PrincipalBreakGlass:
		if !validPrefixedID(p.ID, "breakglass_bg_") || hasOIDCClaims(p) || p.DisplayName != "" || p.Email != "" {
			return errors.New("break-glass principal is not canonical")
		}
	default:
		return fmt.Errorf("unsupported principal kind %q", p.Kind)
	}
	if p.DisplayName != "" && !validBoundedText(p.DisplayName, 1, 256) {
		return errors.New("principal display name is invalid")
	}
	if p.Email != "" && !validCanonicalEmail(p.Email) {
		return errors.New("principal email is not canonical")
	}
	if err := validateCanonicalClaimValues(p.Groups, 256, 256); err != nil {
		return fmt.Errorf("principal groups: %w", err)
	}
	if p.ACR != "" && !validBoundedText(p.ACR, 1, 256) {
		return errors.New("principal ACR is invalid")
	}
	if err := validateCanonicalClaimValues(p.AMR, 16, 64); err != nil {
		return fmt.Errorf("principal AMR: %w", err)
	}
	return nil
}

func (p Principal) Actor(sessionID string) (Actor, error) {
	if err := p.Validate(); err != nil {
		return Actor{}, err
	}
	if sessionID != "" && !identifierPattern.MatchString(sessionID) {
		return Actor{}, errors.New("actor session ID is invalid")
	}
	return Actor{ID: p.ID, Kind: p.Kind, SessionID: sessionID}, nil
}

func (a Actor) Validate() error {
	if !identifierPattern.MatchString(a.ID) || (a.SessionID != "" && !identifierPattern.MatchString(a.SessionID)) {
		return errors.New("actor has invalid identifiers")
	}
	switch a.Kind {
	case PrincipalOIDCAdmin:
		if validPrefixedID(a.ID, "oidc_") {
			return nil
		}
	case PrincipalLegacyAdmin:
		if a.ID == "legacy_admin" {
			return nil
		}
	case PrincipalService:
		if validPrefixedID(a.ID, "service_") {
			return nil
		}
	case PrincipalBreakGlass:
		if validPrefixedID(a.ID, "breakglass_bg_") {
			return nil
		}
	default:
		return fmt.Errorf("actor has unsupported kind %q", a.Kind)
	}
	return errors.New("actor ID does not match its kind")
}

func hasOIDCClaims(principal Principal) bool {
	return principal.Issuer != "" || principal.Subject != "" || len(principal.Groups) != 0 || principal.ACR != "" || len(principal.AMR) != 0
}

func validPrefixedID(id, prefix string) bool {
	return strings.HasPrefix(id, prefix) && identifierPattern.MatchString(strings.TrimPrefix(id, prefix))
}

func clonePrincipal(input Principal) Principal {
	out := input
	out.Groups = append([]string(nil), input.Groups...)
	out.AMR = append([]string(nil), input.AMR...)
	return out
}

func validateCanonicalClaimValues(values []string, maximum, maxLength int) error {
	if len(values) > maximum {
		return fmt.Errorf("contains more than %d values", maximum)
	}
	if !sort.StringsAreSorted(values) {
		return errors.New("values are not canonically sorted")
	}
	for index, value := range values {
		if !validBoundedText(value, 1, maxLength) {
			return fmt.Errorf("value %d is invalid", index)
		}
		if index > 0 && values[index-1] == value {
			return fmt.Errorf("value %d is duplicated", index)
		}
	}
	return nil
}

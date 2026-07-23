//go:build postgresmaxdocgate

package identity

// This file is compiled only for the explicit PostgreSQL maximum-document
// gate. Keeping construction in package identity lets the fixture reuse the
// private canonical session and audit validators instead of manufacturing a
// schema-shaped JSON document outside the identity business rules.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	MaximumDocumentIdentityBytes    = maxIdentityStateSize
	MaximumDocumentOIDCClaimsBytes  = maxOIDCClaimsSize
	MaximumDocumentOIDCGroups       = 64
	DefaultIdentityCanonicalMinimum = 7 << 20
	DefaultIdentityCanonicalMaximum = 15 << 19 // 7.5 MiB
	maximumDocumentJWTOverheadBytes = 4 << 10
)

type MaximumDocumentFixtureOptions struct {
	Sealer                Sealer
	At                    time.Time
	CanonicalMinimumBytes int
	CanonicalMaximumBytes int
	// ExactBytes defaults to the production 8 MiB ceiling. Tests may inject a
	// smaller boundary without allocating the live gate's document.
	ExactBytes int
}

type MaximumDocumentFixture struct {
	CanonicalBytes        []byte
	ExactBytes            []byte
	OIDCClaimsBytes       int
	OIDCGroupCount        int
	LoginAttemptCount     int
	ExpiredLoginAttemptID string
	SessionCount          int
	AuditCount            int
	CleanupAt             time.Time
	ExpiredSessionID      string
	RevokeSessionID       string
}

// CanonicalizeMaximumDocumentRecoverySnapshot returns the exact production
// persistence encoding of a fully validated identity recovery snapshot. The
// helper is test-only and keeps private identity-state details inside this
// package while allowing the live gate to prove canonical rewrites.
func CanonicalizeMaximumDocumentRecoverySnapshot(raw []byte, sealer Sealer) ([]byte, error) {
	state, err := validateRecoverySnapshot(raw, sealer)
	if err != nil {
		return nil, err
	}
	return encodeIdentityStateDocument(state)
}

// BuildMaximumDocumentFixture constructs production-reachable, validator-created
// OIDC sessions until canonical state reaches the requested 7-7.5 MiB band.
// The shared principal is first encoded and parsed through the hardened OIDC
// claim limits, including the aggregate 64 KiB ceiling, and is conservatively
// limited to 64 groups. Exactly one purpose-sealed login attempt and one session
// expire at CleanupAt; all other sessions remain live for the later
// bearer-attributed API revocation.
func BuildMaximumDocumentFixture(ctx context.Context, options MaximumDocumentFixtureOptions) (MaximumDocumentFixture, error) {
	if ctx == nil {
		return MaximumDocumentFixture{}, errors.New("maximum-document identity fixture requires a context")
	}
	if err := ctx.Err(); err != nil {
		return MaximumDocumentFixture{}, err
	}
	if nilInterface(options.Sealer) {
		return MaximumDocumentFixture{}, errors.New("maximum-document identity fixture requires a sealer")
	}
	fixtureTime := options.At
	if fixtureTime.IsZero() {
		fixtureTime = time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	} else {
		fixtureTime = fixtureTime.UTC().Truncate(time.Second)
	}
	minimum, maximum := options.CanonicalMinimumBytes, options.CanonicalMaximumBytes
	if minimum == 0 {
		minimum = DefaultIdentityCanonicalMinimum
	}
	if maximum == 0 {
		maximum = DefaultIdentityCanonicalMaximum
	}
	if minimum < 1 || maximum < minimum || maximum >= MaximumDocumentIdentityBytes {
		return MaximumDocumentFixture{}, errors.New("maximum-document identity canonical byte band is invalid")
	}
	exactBytes := options.ExactBytes
	if exactBytes == 0 {
		exactBytes = MaximumDocumentIdentityBytes
	}
	if exactBytes <= maximum || exactBytes > MaximumDocumentIdentityBytes {
		return MaximumDocumentFixture{}, errors.New("maximum-document identity exact byte target is invalid")
	}
	principal, claimsBytes, err := maximumDocumentOIDCPrincipal(fixtureTime)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	policyDigest := sha256.Sum256([]byte("maximum-document-policy"))
	policyFingerprint := hex.EncodeToString(policyDigest[:])
	state := identityState{
		Schema: identityStateSchema, LoginAttempts: []persistedLoginAttempt{},
		Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{}, Audit: []IdentityAuditEvent{},
	}
	loginAttempt, err := maximumDocumentLoginAttempt(options.Sealer, fixtureTime)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	state.LoginAttempts = append(state.LoginAttempts, loginAttempt)
	cleanupAt := fixtureTime.Add(30 * time.Minute)
	appendSession := func(index int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		session, audit, err := maximumDocumentSession(index, principal, policyFingerprint, fixtureTime)
		if err != nil {
			return err
		}
		state.Sessions = append(state.Sessions, session)
		state.Audit = append(state.Audit, audit)
		return nil
	}
	for index := 1; index <= 2; index++ {
		if err := appendSession(index); err != nil {
			return MaximumDocumentFixture{}, err
		}
	}
	raw, err := encodeIdentityStateDocument(state)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if len(raw) < minimum {
		beforeSample := len(raw)
		if err := appendSession(3); err != nil {
			return MaximumDocumentFixture{}, err
		}
		raw, err = encodeIdentityStateDocument(state)
		if err != nil {
			return MaximumDocumentFixture{}, err
		}
		contribution := len(raw) - beforeSample
		if contribution < 1 {
			return MaximumDocumentFixture{}, errors.New("maximum-document identity record contribution is invalid")
		}
		additional := 0
		if len(raw) < minimum {
			additional = (minimum - len(raw) + contribution - 1) / contribution
		}
		if len(state.Sessions)+additional > maxSessions {
			return MaximumDocumentFixture{}, errors.New("maximum-document identity fixture exhausted the session count limit")
		}
		targetSessionCount := len(state.Sessions) + additional
		for index := len(state.Sessions) + 1; index <= targetSessionCount; index++ {
			if err := appendSession(index); err != nil {
				return MaximumDocumentFixture{}, err
			}
		}
		raw, err = encodeIdentityStateDocument(state)
		if err != nil {
			return MaximumDocumentFixture{}, err
		}
	}
	if len(raw) < minimum || len(raw) > maximum {
		return MaximumDocumentFixture{}, fmt.Errorf("maximum-document identity canonical size %d is outside %d..%d", len(raw), minimum, maximum)
	}
	if err := newIdentityOperations(nil, options.Sealer).validateState(state); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("validate generated identity state: %w", err)
	}
	exact, err := padMaximumDocumentIdentityJSON(raw, exactBytes)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if err := ValidateRecoverySnapshot(exact, options.Sealer); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("validate exact identity recovery document: %w", err)
	}
	return MaximumDocumentFixture{
		CanonicalBytes: raw, ExactBytes: exact,
		OIDCClaimsBytes: claimsBytes, OIDCGroupCount: len(principal.Groups),
		LoginAttemptCount: len(state.LoginAttempts), ExpiredLoginAttemptID: loginAttempt.ID,
		SessionCount: len(state.Sessions), AuditCount: len(state.Audit), CleanupAt: cleanupAt,
		ExpiredSessionID: state.Sessions[0].ID, RevokeSessionID: state.Sessions[1].ID,
	}, nil
}

func maximumDocumentSession(index int, principal Principal, policyFingerprint string, fixtureTime time.Time) (Session, IdentityAuditEvent, error) {
	sessionID := "session_" + maximumDocumentOpaqueToken("session-id", index)
	idleExpiresAt := fixtureTime.Add(time.Hour)
	absoluteExpiresAt := fixtureTime.Add(8 * time.Hour)
	if index == 1 {
		idleExpiresAt = fixtureTime.Add(15 * time.Minute)
		absoluteExpiresAt = idleExpiresAt
	}
	session, err := canonicalSessionInput(CreateSessionInput{
		ID:        sessionID,
		Token:     maximumDocumentOpaqueToken("session-token", index),
		CSRFToken: maximumDocumentOpaqueToken("csrf-token", index),
		Principal: principal, PolicyFingerprint: policyFingerprint, AuthMethod: "oidc",
		CreatedAt: fixtureTime, LastSeenAt: fixtureTime,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
	})
	if err != nil {
		return Session{}, IdentityAuditEvent{}, err
	}
	actor, err := session.Actor()
	if err != nil {
		return Session{}, IdentityAuditEvent{}, err
	}
	audit := IdentityAuditEvent{
		ID:   "audit_" + maximumDocumentOpaqueToken("audit-id", index),
		Type: IdentityAuditSessionCreated, At: fixtureTime, Actor: actor,
		TargetPrincipalID: principal.ID, TargetSessionID: session.ID,
		Details: map[string]string{"auth_method": "oidc", "session_version": "1"},
	}
	if err := validateIdentityAuditEvent(audit); err != nil {
		return Session{}, IdentityAuditEvent{}, err
	}
	return session, audit, nil
}

func maximumDocumentOIDCPrincipal(fixtureTime time.Time) (Principal, int, error) {
	issuerPrefix := "https://id.example.test/"
	issuer := issuerPrefix + strings.Repeat("i", 2048-len(issuerPrefix))
	subject := strings.Repeat("s", 512)
	displayName := strings.Repeat("d", 256)
	email := strings.Repeat("e", 64) + "@" + strings.Repeat("m", 185) + ".com"
	groups := make([]string, 0, MaximumDocumentOIDCGroups)
	for index := 0; index < MaximumDocumentOIDCGroups; index++ {
		prefix := fmt.Sprintf("group-%03d-", index)
		groups = append(groups, prefix+strings.Repeat("g", 256-len(prefix)))
	}
	amr := make([]string, 0, 16)
	for index := 0; index < 16; index++ {
		prefix := fmt.Sprintf("amr-%02d-", index)
		amr = append(amr, prefix+strings.Repeat("a", 64-len(prefix)))
	}
	principal, err := NewOIDCPrincipal(
		issuer, subject, displayName, email, groups, strings.Repeat("c", 256), amr,
		fixtureTime,
	)
	if err != nil {
		return Principal{}, 0, err
	}
	claimsBytes, err := validateMaximumDocumentOIDCClaimIntake(principal, fixtureTime)
	if err != nil {
		return Principal{}, 0, err
	}
	return principal, claimsBytes, nil
}

type maximumDocumentOIDCClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Nonce         string   `json:"nonce"`
	AuthTime      int64    `json:"auth_time"`
	ACR           string   `json:"acr"`
	AMR           []string `json:"amr"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	DisplayName   string   `json:"name"`
	Groups        []string `json:"groups"`
}

func validateMaximumDocumentOIDCClaimIntake(principal Principal, fixtureTime time.Time) (int, error) {
	const audience = "mesh-maximum-document"
	claims := maximumDocumentOIDCClaims{
		Issuer: principal.Issuer, Subject: principal.Subject, Audience: audience,
		ExpiresAt: fixtureTime.Add(8 * time.Hour).Unix(), IssuedAt: fixtureTime.Unix(),
		Nonce: maximumDocumentOpaqueToken("login-nonce", 1), AuthTime: fixtureTime.Unix(),
		ACR: principal.ACR, AMR: principal.AMR, Email: principal.Email, EmailVerified: true,
		DisplayName: principal.DisplayName, Groups: principal.Groups,
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return 0, err
	}
	if len(raw) < 1 || len(raw) > maxOIDCClaimsSize || base64.RawURLEncoding.EncodedLen(len(raw))+maximumDocumentJWTOverheadBytes > maxOIDCIDTokenSize {
		return 0, errors.New("maximum-document OIDC claims exceed hardened intake limits")
	}
	decoded, err := decodeJSONObject(raw, maxOIDCClaimsSize)
	if err != nil {
		return 0, fmt.Errorf("decode maximum-document OIDC claims: %w", err)
	}
	issuer, issuerErr := requiredJSONString(decoded, "iss", 2048)
	subject, subjectErr := requiredJSONString(decoded, "sub", 512)
	audiences, audienceErr := oidcAudienceClaim(decoded["aud"])
	expiresAt, expiresErr := requiredOIDCTime(decoded, "exp")
	issuedAt, issuedErr := requiredOIDCTime(decoded, "iat")
	nonce, nonceErr := requiredJSONString(decoded, "nonce", 128)
	authTime, authErr := requiredOIDCTime(decoded, "auth_time")
	acr, acrPresent, acrErr := optionalJSONString(decoded, "acr", 256)
	amr, amrPresent, amrErr := optionalJSONStringArray(decoded, "amr", 16, 64)
	email, emailPresent, emailErr := optionalJSONString(decoded, "email", 254)
	emailVerified, verifiedPresent, verifiedErr := optionalJSONBool(decoded, "email_verified")
	displayName, displayPresent, displayErr := optionalJSONString(decoded, "name", 256)
	groups, groupsPresent, groupsErr := optionalJSONStringArray(decoded, "groups", MaximumDocumentOIDCGroups, 256)
	if errors.Join(issuerErr, subjectErr, audienceErr, expiresErr, issuedErr, nonceErr, authErr, acrErr, amrErr, emailErr, verifiedErr, displayErr, groupsErr) != nil ||
		issuer != principal.Issuer || subject != principal.Subject || !slices.Equal(audiences, []string{audience}) ||
		!expiresAt.Equal(fixtureTime.Add(8*time.Hour)) || !issuedAt.Equal(fixtureTime) || nonce != claims.Nonce || !ValidOpaqueToken(nonce) || !authTime.Equal(principal.AuthTime) ||
		!acrPresent || acr != principal.ACR || !amrPresent || !slices.Equal(amr, principal.AMR) ||
		!emailPresent || email != principal.Email || !emailVerified || !verifiedPresent || !displayPresent || displayName != principal.DisplayName ||
		!groupsPresent || !slices.Equal(groups, principal.Groups) || len(groups) > MaximumDocumentOIDCGroups {
		return 0, errors.New("maximum-document OIDC claims do not survive hardened intake")
	}
	return len(raw), nil
}

func maximumDocumentLoginAttempt(sealer Sealer, fixtureTime time.Time) (persistedLoginAttempt, error) {
	input, payload, err := canonicalLoginInput(LoginAttemptInput{
		ID:               "login_" + maximumDocumentOpaqueToken("login-id", 1),
		TransactionToken: maximumDocumentOpaqueToken("login-transaction", 1),
		StateToken:       maximumDocumentOpaqueToken("login-state", 1),
		Nonce:            maximumDocumentOpaqueToken("login-nonce", 1),
		PKCEVerifier:     maximumDocumentOpaqueToken("login-pkce", 1),
		ReturnPath:       "/maximum-document",
		CreatedAt:        fixtureTime,
		ExpiresAt:        fixtureTime.Add(10 * time.Minute),
	})
	if err != nil {
		return persistedLoginAttempt{}, err
	}
	sealed, err := newIdentityOperations(nil, sealer).sealOIDCPayload(payload)
	if err != nil {
		return persistedLoginAttempt{}, fmt.Errorf("seal maximum-document OIDC login payload: %w", err)
	}
	transactionHash, err := HashOpaqueToken(input.TransactionToken)
	if err != nil {
		return persistedLoginAttempt{}, err
	}
	stateHash, err := HashOpaqueToken(input.StateToken)
	if err != nil {
		return persistedLoginAttempt{}, err
	}
	return persistedLoginAttempt{
		ID: input.ID, TransactionHash: transactionHash, StateHash: stateHash,
		SealedOIDCPayload: sealed, ReturnPath: input.ReturnPath,
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
	}, nil
}

func maximumDocumentOpaqueToken(domain string, index int) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%08d", domain, index)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func padMaximumDocumentIdentityJSON(canonical []byte, target int) ([]byte, error) {
	if len(canonical) < 1 || len(canonical) >= target {
		return nil, errors.New("maximum-document canonical identity JSON cannot be padded to its target")
	}
	exact := make([]byte, target)
	copy(exact, canonical)
	for index := len(canonical); index < len(exact); index++ {
		exact[index] = ' '
	}
	return exact, nil
}

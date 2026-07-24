package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrLimit        = errors.New("record limit reached")
	ErrClosed       = errors.New("identity store is closed")
)

const OIDCTransactionSealPurpose = "oidc-login-transaction-v1"

// Sealer must provide authenticated confidentiality, reject tampering, bind
// ciphertext to purpose, and be safe for concurrent use.
type Sealer interface {
	SealFor(purpose string, plain []byte) (string, error)
	OpenFor(purpose, encoded string) ([]byte, error)
}

type LoginAttemptInput struct {
	ID               string
	TransactionToken string
	StateToken       string
	Nonce            string
	PKCEVerifier     string
	ReturnPath       string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

type ConsumedLoginAttempt struct {
	ID           string
	Nonce        string
	PKCEVerifier string
	ReturnPath   string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type CreateSessionInput struct {
	ID                string
	Token             string
	CSRFToken         string
	Principal         Principal
	PolicyFingerprint string
	AuthMethod        string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type Session struct {
	ID                string     `json:"id"`
	TokenHash         string     `json:"token_hash"`
	CSRFHash          string     `json:"csrf_hash"`
	Principal         Principal  `json:"principal"`
	PolicyFingerprint string     `json:"policy_fingerprint"`
	AuthMethod        string     `json:"auth_method"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	Version           uint64     `json:"version"`
}

func (s Session) ValidCSRF(token string) bool {
	return ValidOpaqueToken(token) && CredentialMatches(s.CSRFHash, token)
}

func (s Session) Actor() (Actor, error) { return s.Principal.Actor(s.ID) }

const MaxSessionListLimit = 256

type SessionListFilter struct {
	PrincipalID    string
	IncludeRevoked bool
	Limit          int
}

// SessionSummary deliberately omits bearer and CSRF credential hashes.
type SessionSummary struct {
	ID                string     `json:"id"`
	Principal         Principal  `json:"principal"`
	PolicyFingerprint string     `json:"policy_fingerprint"`
	AuthMethod        string     `json:"auth_method"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	Version           uint64     `json:"version"`
}

type BreakGlassCodeInput struct {
	ID        string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

const (
	MinBreakGlassCodeLifetime = 10 * time.Minute
	MaxBreakGlassCodeLifetime = 90 * 24 * time.Hour
)

type BreakGlassCode struct {
	ID        string     `json:"id"`
	TokenHash string     `json:"token_hash"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type BreakGlassCodeState string

const (
	BreakGlassCodeUsable  BreakGlassCodeState = "usable"
	BreakGlassCodeUsed    BreakGlassCodeState = "used"
	BreakGlassCodeRevoked BreakGlassCodeState = "revoked"
	BreakGlassCodeExpired BreakGlassCodeState = "expired"
)

// BreakGlassCodeSummary deliberately omits the credential hash.
type BreakGlassCodeSummary struct {
	ID        string              `json:"id"`
	CreatedAt time.Time           `json:"created_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	UsedAt    *time.Time          `json:"used_at,omitempty"`
	RevokedAt *time.Time          `json:"revoked_at,omitempty"`
	State     BreakGlassCodeState `json:"state"`
}

type CleanupResult struct {
	LoginAttempts         int
	Sessions              int
	BreakGlassCodes       int
	DesktopAuthorizations int
}

type SessionStore interface {
	CreateLoginAttempt(context.Context, LoginAttemptInput) error
	ConsumeLoginAttempt(ctx context.Context, transactionToken, stateToken string, now time.Time) (ConsumedLoginAttempt, error)
	CreateSession(context.Context, CreateSessionInput) (Session, error)
	AuthenticateSession(ctx context.Context, token, policyFingerprint string, now time.Time) (Session, error)
	ListSessions(context.Context, SessionListFilter) ([]SessionSummary, error)
	TouchSession(ctx context.Context, sessionID string, expectedVersion uint64, seenAt, idleExpiresAt time.Time) (Session, error)
	RotateSession(ctx context.Context, sessionID string, expectedVersion uint64, newToken, newCSRFToken string, seenAt, idleExpiresAt time.Time) (Session, error)
	RevokeSession(ctx context.Context, sessionID string, at time.Time, reason string) (Session, error)
	RevokePrincipal(ctx context.Context, principalID string, at time.Time, reason string) (int, error)
	CreateBreakGlassCode(context.Context, BreakGlassCodeInput) error
	ConsumeBreakGlassCode(ctx context.Context, codeID, token string, now time.Time) (BreakGlassCode, error)
	CreateDesktopAuthorization(context.Context, CreateDesktopAuthorizationInput) error
	DecideDesktopAuthorization(ctx context.Context, requestID string, principal Principal, decision DesktopAuthorizationDecision, now time.Time) error
	PollDesktopAuthorization(ctx context.Context, requestID, pollSecret string, now time.Time) (DesktopAuthorizationPoll, error)
	CleanupExpired(ctx context.Context, now time.Time) (CleanupResult, error)
	Close() error
}

// BreakGlassStore is the credential-free inventory and actor-attributed
// mutation surface used by the production HTTP lifecycle. SessionStore keeps
// the lower-level primitives for state migration and focused store tests.
type BreakGlassStore interface {
	RegisterBreakGlassCodeAs(ctx context.Context, actor Actor, input BreakGlassCodeInput) (BreakGlassCodeSummary, bool, error)
	ListBreakGlassCodes(ctx context.Context, now time.Time) ([]BreakGlassCodeSummary, error)
	CountUsableBreakGlassCodes(ctx context.Context, now time.Time) (int, error)
	ConsumeBreakGlassCodeAs(ctx context.Context, codeID, token string, now time.Time) (BreakGlassCode, error)
	RevokeBreakGlassCodeAs(ctx context.Context, actor Actor, codeID string, at time.Time) (BreakGlassCodeSummary, error)
}

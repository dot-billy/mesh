package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	legacyIdentityStateSchema      = "identity-state-v1"
	identityStateSchema            = "identity-state-v2"
	maxIdentityStateSize           = 8 << 20
	maxLoginAttempts               = 1024
	maxSessions                    = 4096
	maxBreakGlassCodes             = 256
	maxDesktopAuthorizationRecords = maxDesktopAuthorizations
	maxIdentityAuditEvents         = 8192
)

var ErrUncertainCommit = errors.New("identity state commit durability is uncertain")

type persistedLoginAttempt struct {
	ID                string    `json:"id"`
	TransactionHash   string    `json:"transaction_hash"`
	StateHash         string    `json:"state_hash"`
	SealedOIDCPayload string    `json:"sealed_oidc_payload"`
	ReturnPath        string    `json:"return_path"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type persistedOIDCPayload struct {
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkce_verifier"`
}

type identityState struct {
	Schema                string                       `json:"schema"`
	LoginAttempts         []persistedLoginAttempt      `json:"login_attempts"`
	Sessions              []Session                    `json:"sessions"`
	BreakGlassCodes       []BreakGlassCode             `json:"break_glass_codes"`
	DesktopAuthorizations []desktopAuthorizationRecord `json:"desktop_authorizations"`
	Audit                 []IdentityAuditEvent         `json:"audit"`
}

// legacyIdentityStateV1 intentionally has no Audit field so a v1 document
// containing one is still rejected as an unknown-field downgrade attempt.
type legacyIdentityStateV1 struct {
	Schema          string                  `json:"schema"`
	LoginAttempts   []persistedLoginAttempt `json:"login_attempts"`
	Sessions        []Session               `json:"sessions"`
	BreakGlassCodes []BreakGlassCode        `json:"break_glass_codes"`
}

type FileStore struct {
	*identityOperations
	mu                sync.Mutex
	root              *os.Root
	lock              *os.File
	fileName          string
	state             identityState
	syncRoot          func(*os.Root) error
	durabilityPending bool
	closed            bool
	// cloneCount is a lightweight regression signal for authentication and
	// list hot paths. It is neither persisted nor part of the public API.
	cloneCount atomic.Uint64
}

var _ SessionStore = (*FileStore)(nil)
var _ IdentityAuditStore = (*FileStore)(nil)
var _ BreakGlassStore = (*FileStore)(nil)

func OpenFileStore(path string, sealer Sealer) (*FileStore, error) {
	if sealer == nil {
		return nil, errors.New("identity store requires a purpose-bound sealer")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errors.New("identity state path must be a clean absolute file path")
	}
	directory, fileName := filepath.Dir(path), filepath.Base(path)
	if len(fileName) < 1 || len(fileName) > 128 {
		return nil, errors.New("identity state file name is invalid")
	}
	root, err := openOrCreatePrivateIdentityRoot(directory)
	if err != nil {
		return nil, err
	}
	store := &FileStore{root: root, fileName: fileName, syncRoot: syncIdentityRoot}
	store.identityOperations = newIdentityOperations(store, sealer)
	lockName := "." + fileName + ".lock"
	store.lock, err = openPrivateRegular(root, lockName, true)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("open identity state lock: %w", err)
	}
	if err := lockIdentityFile(store.lock); err != nil {
		store.lock.Close()
		root.Close()
		return nil, fmt.Errorf("lock identity state (is another process using it?): %w", err)
	}
	loaded, err := store.readState()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			store.closeResources()
			return nil, err
		}
		loaded = identityState{Schema: identityStateSchema, LoginAttempts: []persistedLoginAttempt{}, Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{}, DesktopAuthorizations: []desktopAuthorizationRecord{}, Audit: []IdentityAuditEvent{}}
		if err := store.persist(loaded); err != nil {
			store.closeResources()
			return nil, err
		}
	}
	if err := store.validateState(loaded); err != nil {
		store.closeResources()
		return nil, fmt.Errorf("validate identity state: %w", err)
	}
	if loaded.Schema == legacyIdentityStateSchema {
		loaded.Schema = identityStateSchema
		loaded.Audit = []IdentityAuditEvent{}
		if err := store.validateState(loaded); err != nil {
			store.closeResources()
			return nil, fmt.Errorf("validate migrated identity state: %w", err)
		}
		if err := store.persist(loaded); err != nil {
			store.closeResources()
			return nil, fmt.Errorf("migrate identity state to %s: %w", identityStateSchema, err)
		}
	}
	store.state = loaded
	return store, nil
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var durabilityErr error
	if err := s.ensureDurableLocked(); err != nil {
		durabilityErr = err
	}
	s.closed = true
	return errors.Join(durabilityErr, s.closeResources())
}

// CheckReadiness proves that the identity store is still open and that any
// atomic replacement whose parent-directory sync was uncertain has since
// crossed its durability barrier. It performs no identity-state mutation.
func (s *FileStore) CheckReadiness() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root == nil || s.lock == nil {
		return ErrClosed
	}
	return s.ensureDurableLocked()
}

func (s *FileStore) closeResources() error {
	var result error
	if s.lock != nil {
		if err := unlockIdentityFile(s.lock); err != nil {
			result = errors.Join(result, err)
		}
		if err := s.lock.Close(); err != nil {
			result = errors.Join(result, err)
		}
		s.lock = nil
	}
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			result = errors.Join(result, err)
		}
		s.root = nil
	}
	return result
}

func (s *identityOperations) CreateLoginAttempt(ctx context.Context, input LoginAttemptInput) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	canonical, payload, err := canonicalLoginInput(input)
	if err != nil {
		return err
	}
	transactionHash, _ := HashOpaqueToken(canonical.TransactionToken)
	stateHash, _ := HashOpaqueToken(canonical.StateToken)
	sealed, err := s.sealOIDCPayload(payload)
	if err != nil {
		return fmt.Errorf("seal OIDC login transaction: %w", err)
	}
	record := persistedLoginAttempt{
		ID: canonical.ID, TransactionHash: transactionHash, StateHash: stateHash,
		SealedOIDCPayload: sealed, ReturnPath: canonical.ReturnPath,
		CreatedAt: canonical.CreatedAt, ExpiresAt: canonical.ExpiresAt,
	}
	return s.update(ctx, func(state *identityState) error {
		pruneExpired(state, canonical.CreatedAt)
		for _, existing := range state.LoginAttempts {
			if existing.ID == record.ID || CredentialHashEqual(existing.TransactionHash, record.TransactionHash) || CredentialHashEqual(existing.StateHash, record.StateHash) {
				existingPayload, openErr := s.openOIDCPayload(existing.SealedOIDCPayload)
				if openErr != nil {
					return openErr
				}
				if existing.ID == record.ID && CredentialHashEqual(existing.TransactionHash, record.TransactionHash) && CredentialHashEqual(existing.StateHash, record.StateHash) &&
					existing.ReturnPath == record.ReturnPath && existing.CreatedAt.Equal(record.CreatedAt) && existing.ExpiresAt.Equal(record.ExpiresAt) &&
					existingPayload == payload {
					return nil
				}
				return fmt.Errorf("%w: login transaction identity or credential already exists", ErrConflict)
			}
		}
		if len(state.LoginAttempts) >= maxLoginAttempts {
			return ErrLimit
		}
		state.LoginAttempts = append(state.LoginAttempts, record)
		return nil
	})
}

func (s *identityOperations) ConsumeLoginAttempt(ctx context.Context, transactionToken, stateToken string, now time.Time) (ConsumedLoginAttempt, error) {
	if err := identityContextError(ctx); err != nil {
		return ConsumedLoginAttempt{}, err
	}
	transactionHash, err := HashOpaqueToken(transactionToken)
	if err != nil {
		return ConsumedLoginAttempt{}, ErrUnauthorized
	}
	stateHash, err := HashOpaqueToken(stateToken)
	if err != nil || now.IsZero() {
		return ConsumedLoginAttempt{}, ErrUnauthorized
	}
	now = now.UTC()
	var consumed ConsumedLoginAttempt
	found := false
	err = s.update(ctx, func(state *identityState) error {
		for index, attempt := range state.LoginAttempts {
			if !CredentialHashEqual(attempt.TransactionHash, transactionHash) {
				continue
			}
			if !CredentialHashEqual(attempt.StateHash, stateHash) {
				return nil
			}
			if !now.Before(attempt.ExpiresAt) {
				state.LoginAttempts = append(state.LoginAttempts[:index], state.LoginAttempts[index+1:]...)
				return nil
			}
			payload, openErr := s.openOIDCPayload(attempt.SealedOIDCPayload)
			if openErr != nil {
				return openErr
			}
			consumed = ConsumedLoginAttempt{ID: attempt.ID, Nonce: payload.Nonce, PKCEVerifier: payload.PKCEVerifier, ReturnPath: attempt.ReturnPath, CreatedAt: attempt.CreatedAt, ExpiresAt: attempt.ExpiresAt}
			state.LoginAttempts = append(state.LoginAttempts[:index], state.LoginAttempts[index+1:]...)
			found = true
			return nil
		}
		pruneExpired(state, now)
		return nil
	})
	if err != nil {
		return ConsumedLoginAttempt{}, err
	}
	if !found {
		return ConsumedLoginAttempt{}, ErrUnauthorized
	}
	return consumed, nil
}

func (s *identityOperations) CreateSession(ctx context.Context, input CreateSessionInput) (Session, error) {
	if err := identityContextError(ctx); err != nil {
		return Session{}, err
	}
	record, err := canonicalSessionInput(input)
	if err != nil {
		return Session{}, err
	}
	actor, err := record.Actor()
	if err != nil {
		return Session{}, err
	}
	audit, err := newIdentityAuditEvent(
		IdentityAuditSessionCreated, record.CreatedAt, actor, record.Principal.ID, record.ID,
		map[string]string{"auth_method": record.AuthMethod, "session_version": "1"},
	)
	if err != nil {
		return Session{}, err
	}
	err = s.update(ctx, func(state *identityState) error {
		pruneExpired(state, record.CreatedAt)
		for _, existing := range state.Sessions {
			if existing.ID == record.ID || CredentialHashEqual(existing.TokenHash, record.TokenHash) || CredentialHashEqual(existing.CSRFHash, record.CSRFHash) {
				if sessionsEqual(existing, record) {
					record = cloneSession(existing)
					return nil
				}
				return fmt.Errorf("%w: session identity or credential already exists", ErrConflict)
			}
		}
		if len(state.Sessions) >= maxSessions {
			return ErrLimit
		}
		state.Sessions = append(state.Sessions, record)
		return appendIdentityAudit(state, audit)
	})
	return cloneSession(record), err
}

func (s *identityOperations) AuthenticateSession(ctx context.Context, token, policyFingerprint string, now time.Time) (Session, error) {
	if err := identityContextError(ctx); err != nil {
		return Session{}, err
	}
	tokenHash, err := HashOpaqueToken(token)
	if err != nil || !validPolicyFingerprint(policyFingerprint) || now.IsZero() {
		return Session{}, ErrUnauthorized
	}
	now = now.UTC()
	var result Session
	err = s.view(ctx, func(state identityState) error {
		for _, session := range state.Sessions {
			if !CredentialHashEqual(session.TokenHash, tokenHash) {
				continue
			}
			if session.RevokedAt != nil || now.Before(session.LastSeenAt) || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || session.PolicyFingerprint != policyFingerprint {
				return ErrUnauthorized
			}
			result = cloneSession(session)
			return nil
		}
		return ErrUnauthorized
	})
	if err != nil {
		return Session{}, err
	}
	return result, nil
}

func (s *identityOperations) ListSessions(ctx context.Context, filter SessionListFilter) ([]SessionSummary, error) {
	if err := identityContextError(ctx); err != nil {
		return nil, err
	}
	if filter.Limit < 1 || filter.Limit > MaxSessionListLimit || (filter.PrincipalID != "" && !identifierPattern.MatchString(filter.PrincipalID)) {
		return nil, errors.New("session list filter is invalid")
	}
	var result []SessionSummary
	err := s.view(ctx, func(state identityState) error {
		result = make([]SessionSummary, 0, min(filter.Limit, len(state.Sessions)))
		for _, session := range state.Sessions {
			if (filter.PrincipalID != "" && session.Principal.ID != filter.PrincipalID) || (!filter.IncludeRevoked && session.RevokedAt != nil) {
				continue
			}
			result = append(result, sessionSummary(session))
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].CreatedAt.Equal(result[j].CreatedAt) {
				return result[i].ID < result[j].ID
			}
			return result[i].CreatedAt.After(result[j].CreatedAt)
		})
		if len(result) > filter.Limit {
			result = result[:filter.Limit]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *identityOperations) ListIdentityAudit(ctx context.Context, filter IdentityAuditListFilter) ([]IdentityAuditSummary, error) {
	if err := identityContextError(ctx); err != nil {
		return nil, err
	}
	if filter.Limit < 1 || filter.Limit > MaxIdentityAuditListLimit ||
		(filter.PrincipalID != "" && !identifierPattern.MatchString(filter.PrincipalID)) ||
		(filter.SessionID != "" && !identifierPattern.MatchString(filter.SessionID)) ||
		(filter.Type != "" && !validIdentityAuditEventType(filter.Type)) {
		return nil, errors.New("identity audit list filter is invalid")
	}
	var result []IdentityAuditSummary
	err := s.view(ctx, func(state identityState) error {
		result = make([]IdentityAuditSummary, 0, min(filter.Limit, len(state.Audit)))
		for _, event := range state.Audit {
			if (filter.PrincipalID != "" && event.TargetPrincipalID != filter.PrincipalID) ||
				(filter.SessionID != "" && event.TargetSessionID != filter.SessionID) ||
				(filter.Type != "" && event.Type != filter.Type) {
				continue
			}
			result = append(result, identityAuditSummary(event))
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].At.Equal(result[j].At) {
				return result[i].ID < result[j].ID
			}
			return result[i].At.After(result[j].At)
		})
		if len(result) > filter.Limit {
			result = result[:filter.Limit]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *identityOperations) TouchSession(ctx context.Context, sessionID string, expectedVersion uint64, seenAt, idleExpiresAt time.Time) (Session, error) {
	if !identifierPattern.MatchString(sessionID) || expectedVersion == 0 || seenAt.IsZero() || idleExpiresAt.IsZero() {
		return Session{}, fmt.Errorf("%w: invalid session touch", ErrConflict)
	}
	seenAt, idleExpiresAt = seenAt.UTC(), idleExpiresAt.UTC()
	var result Session
	err := s.update(ctx, func(state *identityState) error {
		for index := range state.Sessions {
			session := &state.Sessions[index]
			if session.ID != sessionID {
				continue
			}
			if session.RevokedAt != nil || !seenAt.Before(session.IdleExpiresAt) || !seenAt.Before(session.AbsoluteExpiresAt) {
				return ErrUnauthorized
			}
			if session.Version == expectedVersion+1 && session.LastSeenAt.Equal(seenAt) && session.IdleExpiresAt.Equal(idleExpiresAt) {
				result = cloneSession(*session)
				return nil
			}
			if session.Version != expectedVersion || seenAt.Before(session.LastSeenAt) || !idleExpiresAt.After(seenAt) || idleExpiresAt.After(session.AbsoluteExpiresAt) {
				return fmt.Errorf("%w: stale or invalid session touch", ErrConflict)
			}
			if session.LastSeenAt.Equal(seenAt) && session.IdleExpiresAt.Equal(idleExpiresAt) {
				result = cloneSession(*session)
				return nil
			}
			session.LastSeenAt, session.IdleExpiresAt = seenAt, idleExpiresAt
			session.Version++
			result = cloneSession(*session)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (s *identityOperations) RotateSession(ctx context.Context, sessionID string, expectedVersion uint64, newToken, newCSRFToken string, seenAt, idleExpiresAt time.Time) (Session, error) {
	if !identifierPattern.MatchString(sessionID) || expectedVersion == 0 || seenAt.IsZero() || idleExpiresAt.IsZero() {
		return Session{}, fmt.Errorf("%w: invalid session rotation", ErrConflict)
	}
	newTokenHash, err := HashOpaqueToken(newToken)
	if err != nil {
		return Session{}, err
	}
	newCSRFHash, err := HashOpaqueToken(newCSRFToken)
	if err != nil || CredentialHashEqual(newTokenHash, newCSRFHash) {
		return Session{}, errors.New("session and CSRF credentials must be distinct")
	}
	seenAt, idleExpiresAt = seenAt.UTC(), idleExpiresAt.UTC()
	var result Session
	err = s.update(ctx, func(state *identityState) error {
		for index := range state.Sessions {
			session := &state.Sessions[index]
			if session.ID != sessionID {
				continue
			}
			if session.Version == expectedVersion+1 && CredentialHashEqual(session.TokenHash, newTokenHash) && CredentialHashEqual(session.CSRFHash, newCSRFHash) && session.LastSeenAt.Equal(seenAt) && session.IdleExpiresAt.Equal(idleExpiresAt) {
				result = cloneSession(*session)
				return nil
			}
			if session.RevokedAt != nil || session.Version != expectedVersion || !seenAt.Before(session.IdleExpiresAt) || !seenAt.Before(session.AbsoluteExpiresAt) || seenAt.Before(session.LastSeenAt) || !idleExpiresAt.After(seenAt) || idleExpiresAt.After(session.AbsoluteExpiresAt) {
				return fmt.Errorf("%w: stale, expired, or invalid session rotation", ErrConflict)
			}
			if CredentialHashEqual(session.TokenHash, newTokenHash) || CredentialHashEqual(session.CSRFHash, newCSRFHash) {
				return fmt.Errorf("%w: rotation credentials must be new", ErrConflict)
			}
			for otherIndex, other := range state.Sessions {
				if otherIndex != index && (CredentialHashEqual(other.TokenHash, newTokenHash) || CredentialHashEqual(other.CSRFHash, newTokenHash) || CredentialHashEqual(other.TokenHash, newCSRFHash) || CredentialHashEqual(other.CSRFHash, newCSRFHash)) {
					return fmt.Errorf("%w: rotation credential already exists", ErrConflict)
				}
			}
			session.TokenHash, session.CSRFHash = newTokenHash, newCSRFHash
			session.LastSeenAt, session.IdleExpiresAt = seenAt, idleExpiresAt
			session.Version++
			result = cloneSession(*session)
			actor, actorErr := session.Actor()
			if actorErr != nil {
				return actorErr
			}
			audit, auditErr := newIdentityAuditEvent(
				IdentityAuditSessionRotated, seenAt, actor, session.Principal.ID, session.ID,
				map[string]string{"session_version": fmt.Sprintf("%d", session.Version)},
			)
			if auditErr != nil {
				return auditErr
			}
			return appendIdentityAudit(state, audit)
		}
		return ErrNotFound
	})
	return result, err
}

func (s *identityOperations) RevokeSession(ctx context.Context, sessionID string, at time.Time, reason string) (Session, error) {
	return s.revokeSession(ctx, nil, sessionID, at, reason)
}

func (s *identityOperations) RevokeSessionAs(ctx context.Context, actor Actor, sessionID string, at time.Time, reason string) (Session, error) {
	if err := actor.Validate(); err != nil {
		return Session{}, fmt.Errorf("invalid session revocation actor: %w", err)
	}
	return s.revokeSession(ctx, &actor, sessionID, at, reason)
}

func (s *identityOperations) revokeSession(ctx context.Context, caller *Actor, sessionID string, at time.Time, reason string) (Session, error) {
	if !identifierPattern.MatchString(sessionID) || at.IsZero() || !validReason(reason) {
		return Session{}, errors.New("invalid session revocation")
	}
	at = at.UTC()
	var result Session
	err := s.update(ctx, func(state *identityState) error {
		for index := range state.Sessions {
			session := &state.Sessions[index]
			if session.ID != sessionID {
				continue
			}
			if session.RevokedAt != nil {
				if session.RevokedAt.Equal(at) && session.RevocationReason == reason {
					result = cloneSession(*session)
					return nil
				}
				return fmt.Errorf("%w: session was already revoked with different metadata", ErrConflict)
			}
			if at.Before(session.CreatedAt) {
				return errors.New("session revocation predates creation")
			}
			actor := Actor{}
			if caller == nil {
				var actorErr error
				actor, actorErr = session.Actor()
				if actorErr != nil {
					return actorErr
				}
			} else {
				actor = *caller
			}
			if authErr := authenticateAuditCaller(state, actor, at); authErr != nil {
				return authErr
			}
			session.RevokedAt, session.RevocationReason = &at, reason
			session.Version++
			result = cloneSession(*session)
			audit, auditErr := newIdentityAuditEvent(
				IdentityAuditSessionRevoked, at, actor, session.Principal.ID, session.ID,
				map[string]string{"reason": reason, "session_version": fmt.Sprintf("%d", session.Version)},
			)
			if auditErr != nil {
				return auditErr
			}
			return appendIdentityAudit(state, audit)
		}
		return ErrNotFound
	})
	return result, err
}

func (s *identityOperations) RevokePrincipal(ctx context.Context, principalID string, at time.Time, reason string) (int, error) {
	return s.revokePrincipal(ctx, nil, principalID, at, reason)
}

func (s *identityOperations) RevokePrincipalAs(ctx context.Context, actor Actor, principalID string, at time.Time, reason string) (int, error) {
	if err := actor.Validate(); err != nil {
		return 0, fmt.Errorf("invalid principal revocation actor: %w", err)
	}
	return s.revokePrincipal(ctx, &actor, principalID, at, reason)
}

func (s *identityOperations) revokePrincipal(ctx context.Context, caller *Actor, principalID string, at time.Time, reason string) (int, error) {
	if !identifierPattern.MatchString(principalID) || at.IsZero() || !validReason(reason) {
		return 0, errors.New("invalid principal revocation")
	}
	at = at.UTC()
	count := 0
	err := s.update(ctx, func(state *identityState) error {
		actor := Actor{}
		if caller != nil {
			actor = *caller
			if authErr := authenticateAuditCaller(state, actor, at); authErr != nil {
				return authErr
			}
		}
		for index := range state.Sessions {
			session := &state.Sessions[index]
			if session.Principal.ID != principalID || session.RevokedAt != nil {
				continue
			}
			if at.Before(session.CreatedAt) {
				return errors.New("principal revocation predates a session")
			}
			if caller == nil && count == 0 {
				var actorErr error
				actor, actorErr = session.Principal.Actor("")
				if actorErr != nil {
					return actorErr
				}
			}
			session.RevokedAt, session.RevocationReason = &at, reason
			session.Version++
			count++
		}
		if count == 0 {
			return nil
		}
		audit, auditErr := newIdentityAuditEvent(
			IdentityAuditPrincipalRevoked, at, actor, principalID, "",
			map[string]string{"reason": reason, "revoked_sessions": fmt.Sprintf("%d", count)},
		)
		if auditErr != nil {
			return auditErr
		}
		return appendIdentityAudit(state, audit)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *identityOperations) CreateBreakGlassCode(ctx context.Context, input BreakGlassCodeInput) error {
	if !validBreakGlassCodeInput(input) {
		return errors.New("invalid break-glass code metadata")
	}
	tokenHash, err := HashOpaqueToken(input.Token)
	if err != nil {
		return err
	}
	record := BreakGlassCode{ID: input.ID, TokenHash: tokenHash, CreatedAt: input.CreatedAt.UTC(), ExpiresAt: input.ExpiresAt.UTC()}
	return s.update(ctx, func(state *identityState) error {
		pruneExpired(state, record.CreatedAt)
		for _, existing := range state.BreakGlassCodes {
			if existing.ID == record.ID || CredentialHashEqual(existing.TokenHash, record.TokenHash) {
				if reflect.DeepEqual(existing, record) {
					return nil
				}
				return fmt.Errorf("%w: break-glass identity or credential already exists", ErrConflict)
			}
		}
		if len(state.BreakGlassCodes) >= maxBreakGlassCodes {
			return ErrLimit
		}
		state.BreakGlassCodes = append(state.BreakGlassCodes, record)
		return nil
	})
}

func (s *identityOperations) RegisterBreakGlassCodeAs(ctx context.Context, actor Actor, input BreakGlassCodeInput) (BreakGlassCodeSummary, bool, error) {
	if actor.Kind == PrincipalBreakGlass {
		return BreakGlassCodeSummary{}, false, ErrUnauthorized
	}
	if !identifierPattern.MatchString(input.ID) || !strings.HasPrefix(input.ID, "bg_") || input.CreatedAt.IsZero() || input.ExpiresAt.IsZero() {
		return BreakGlassCodeSummary{}, false, errors.New("invalid break-glass code metadata")
	}
	validForCreate := validBreakGlassCodeInput(input)
	tokenHash, err := HashOpaqueToken(input.Token)
	if err != nil {
		return BreakGlassCodeSummary{}, false, err
	}
	record := BreakGlassCode{ID: input.ID, TokenHash: tokenHash, CreatedAt: input.CreatedAt.UTC(), ExpiresAt: input.ExpiresAt.UTC()}
	principal, err := NewBreakGlassPrincipal(record.ID, record.CreatedAt)
	if err != nil {
		return BreakGlassCodeSummary{}, false, err
	}
	audit, err := newIdentityAuditEvent(
		IdentityAuditBreakGlassRegistered, record.CreatedAt, actor, principal.ID, "",
		map[string]string{"expires_at": record.ExpiresAt.Format(time.RFC3339)},
	)
	if err != nil {
		return BreakGlassCodeSummary{}, false, err
	}
	created := false
	err = s.update(ctx, func(state *identityState) error {
		if err := authenticateAuditCaller(state, actor, record.CreatedAt); err != nil {
			return err
		}
		pruneExpired(state, record.CreatedAt)
		for _, existing := range state.BreakGlassCodes {
			idMatch := existing.ID == record.ID
			hashMatch := CredentialHashEqual(existing.TokenHash, record.TokenHash)
			if !idMatch && !hashMatch {
				continue
			}
			if idMatch && hashMatch && existing.ExpiresAt.Equal(record.ExpiresAt) {
				record = cloneBreakGlassCode(existing)
				return nil
			}
			return fmt.Errorf("%w: break-glass identity or credential already exists", ErrConflict)
		}
		if !validForCreate {
			return errors.New("invalid break-glass code metadata")
		}
		if len(state.BreakGlassCodes) >= maxBreakGlassCodes {
			return ErrLimit
		}
		state.BreakGlassCodes = append(state.BreakGlassCodes, record)
		if err := appendIdentityAudit(state, audit); err != nil {
			return err
		}
		created = true
		return nil
	})
	return breakGlassCodeSummary(record, record.CreatedAt), created, err
}

func (s *identityOperations) ListBreakGlassCodes(ctx context.Context, now time.Time) ([]BreakGlassCodeSummary, error) {
	if now.IsZero() {
		return nil, errors.New("break-glass inventory time is required")
	}
	now = now.UTC()
	var result []BreakGlassCodeSummary
	err := s.view(ctx, func(state identityState) error {
		result = make([]BreakGlassCodeSummary, len(state.BreakGlassCodes))
		for index, code := range state.BreakGlassCodes {
			result[index] = breakGlassCodeSummary(code, now)
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].CreatedAt.Equal(result[j].CreatedAt) {
				return result[i].ID < result[j].ID
			}
			return result[i].CreatedAt.After(result[j].CreatedAt)
		})
		return nil
	})
	return result, err
}

func (s *identityOperations) CountUsableBreakGlassCodes(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, errors.New("break-glass inventory time is required")
	}
	now = now.UTC()
	count := 0
	err := s.view(ctx, func(state identityState) error {
		for _, code := range state.BreakGlassCodes {
			if breakGlassCodeState(code, now) == BreakGlassCodeUsable {
				count++
			}
		}
		return nil
	})
	return count, err
}

func (s *identityOperations) ConsumeBreakGlassCode(ctx context.Context, codeID, token string, now time.Time) (BreakGlassCode, error) {
	return s.consumeBreakGlassCode(ctx, codeID, token, now, false)
}

func (s *identityOperations) ConsumeBreakGlassCodeAs(ctx context.Context, codeID, token string, now time.Time) (BreakGlassCode, error) {
	return s.consumeBreakGlassCode(ctx, codeID, token, now, true)
}

func (s *identityOperations) consumeBreakGlassCode(ctx context.Context, codeID, token string, now time.Time, audited bool) (BreakGlassCode, error) {
	if !identifierPattern.MatchString(codeID) || !ValidOpaqueToken(token) || now.IsZero() {
		return BreakGlassCode{}, ErrUnauthorized
	}
	now = now.UTC()
	var result BreakGlassCode
	found := false
	err := s.update(ctx, func(state *identityState) error {
		for index := range state.BreakGlassCodes {
			code := &state.BreakGlassCodes[index]
			if code.ID != codeID {
				continue
			}
			if code.UsedAt != nil || code.RevokedAt != nil || !now.Before(code.ExpiresAt) || !CredentialMatches(code.TokenHash, token) {
				return nil
			}
			if audited {
				principal, principalErr := NewBreakGlassPrincipal(code.ID, now)
				if principalErr != nil {
					return principalErr
				}
				actor, actorErr := principal.Actor("")
				if actorErr != nil {
					return actorErr
				}
				audit, auditErr := newIdentityAuditEvent(
					IdentityAuditBreakGlassConsumed, now, actor, principal.ID, "",
					map[string]string{"expires_at": code.ExpiresAt.Format(time.RFC3339)},
				)
				if auditErr != nil {
					return auditErr
				}
				if auditErr = appendIdentityAudit(state, audit); auditErr != nil {
					return auditErr
				}
			}
			code.UsedAt = &now
			result = cloneBreakGlassCode(*code)
			found = true
			return nil
		}
		return nil
	})
	if err != nil {
		return BreakGlassCode{}, err
	}
	if !found {
		return BreakGlassCode{}, ErrUnauthorized
	}
	return result, nil
}

func (s *identityOperations) RevokeBreakGlassCodeAs(ctx context.Context, actor Actor, codeID string, at time.Time) (BreakGlassCodeSummary, error) {
	if !identifierPattern.MatchString(codeID) || !strings.HasPrefix(codeID, "bg_") || at.IsZero() || actor.Kind == PrincipalBreakGlass {
		return BreakGlassCodeSummary{}, ErrUnauthorized
	}
	at = at.UTC()
	var result BreakGlassCode
	err := s.update(ctx, func(state *identityState) error {
		if err := authenticateAuditCaller(state, actor, at); err != nil {
			return err
		}
		for index := range state.BreakGlassCodes {
			code := &state.BreakGlassCodes[index]
			if code.ID != codeID {
				continue
			}
			if at.Before(code.CreatedAt) {
				return fmt.Errorf("%w: break-glass revocation predates registration", ErrConflict)
			}
			if code.UsedAt != nil {
				return fmt.Errorf("%w: used break-glass code cannot be revoked", ErrConflict)
			}
			if code.RevokedAt != nil {
				result = cloneBreakGlassCode(*code)
				return nil
			}
			principal, principalErr := NewBreakGlassPrincipal(code.ID, at)
			if principalErr != nil {
				return principalErr
			}
			audit, auditErr := newIdentityAuditEvent(
				IdentityAuditBreakGlassRevoked, at, actor, principal.ID, "",
				map[string]string{"expires_at": code.ExpiresAt.Format(time.RFC3339)},
			)
			if auditErr != nil {
				return auditErr
			}
			code.RevokedAt = &at
			result = cloneBreakGlassCode(*code)
			return appendIdentityAudit(state, audit)
		}
		return ErrNotFound
	})
	return breakGlassCodeSummary(result, at), err
}

func (s *identityOperations) CleanupExpired(ctx context.Context, now time.Time) (CleanupResult, error) {
	if now.IsZero() {
		return CleanupResult{}, errors.New("cleanup time is required")
	}
	now = now.UTC()
	var result CleanupResult
	err := s.update(ctx, func(state *identityState) error {
		beforeAttempts, beforeSessions, beforeCodes, beforeDesktop := len(state.LoginAttempts), len(state.Sessions), len(state.BreakGlassCodes), len(state.DesktopAuthorizations)
		pruneExpired(state, now)
		result = CleanupResult{
			LoginAttempts: beforeAttempts - len(state.LoginAttempts), Sessions: beforeSessions - len(state.Sessions),
			BreakGlassCodes:       beforeCodes - len(state.BreakGlassCodes),
			DesktopAuthorizations: beforeDesktop - len(state.DesktopAuthorizations),
		}
		return nil
	})
	return result, err
}

func (s *FileStore) viewIdentityState(ctx context.Context, inspect func(identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if inspect == nil {
		return errors.New("identity state view callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.ensureDurableLocked(); err != nil {
		return err
	}
	if err := identityContextError(ctx); err != nil {
		return err
	}
	s.cloneCount.Add(1)
	snapshot := cloneIdentityState(s.state)
	err := inspect(snapshot)
	if contextErr := identityContextError(ctx); contextErr != nil {
		return contextErr
	}
	return err
}

// readCurrentIdentityState is only for the package-owned, read-only callbacks
// in identityOperations. The callback executes under the store lock and must
// not mutate or retain storage-owned state.
func (s *FileStore) readCurrentIdentityState(ctx context.Context, inspect func(identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if inspect == nil {
		return errors.New("identity state view callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.ensureDurableLocked(); err != nil {
		return err
	}
	if err := identityContextError(ctx); err != nil {
		return err
	}
	err := inspect(s.state)
	if contextErr := identityContextError(ctx); contextErr != nil {
		return contextErr
	}
	return err
}

func (s *FileStore) updateIdentityState(ctx context.Context, mutate func(*identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if mutate == nil {
		return errors.New("identity state update callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.ensureDurableLocked(); err != nil {
		return err
	}
	if err := identityContextError(ctx); err != nil {
		return err
	}
	s.cloneCount.Add(1)
	next := cloneIdentityState(s.state)
	if err := mutate(&next); err != nil {
		return err
	}
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if reflect.DeepEqual(next, s.state) {
		return nil
	}
	// Detach the committed document from the callback-owned working copy. The
	// callback is package-private and does not retain state, but this keeps the
	// backend contract true even under future refactors.
	s.cloneCount.Add(1)
	committed := cloneIdentityState(next)
	if err := s.persist(committed); err != nil {
		if errors.Is(err, ErrUncertainCommit) {
			s.state = committed
			s.durabilityPending = true
		}
		return err
	}
	s.state = committed
	return nil
}

// ensureDurableLocked closes the only ambiguous window in the atomic-replace
// protocol. A rename may have committed even when syncing its parent directory
// failed. Until that directory sync succeeds, every later read and mutation
// fails closed instead of treating an in-memory idempotent retry as durable.
// s.mu must be held.
func (s *FileStore) ensureDurableLocked() error {
	if !s.durabilityPending {
		return nil
	}
	if s.root == nil || s.syncRoot == nil {
		return fmt.Errorf("%w: identity state directory is unavailable", ErrUncertainCommit)
	}
	if err := s.syncRoot(s.root); err != nil {
		return fmt.Errorf("%w: retry sync identity state directory: %v", ErrUncertainCommit, err)
	}
	s.durabilityPending = false
	return nil
}

func (s *FileStore) readState() (identityState, error) {
	info, err := s.root.Lstat(s.fileName)
	if err != nil {
		return identityState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxIdentityStateSize {
		return identityState{}, errors.New("identity state must be a bounded private regular file")
	}
	file, err := s.root.Open(s.fileName)
	if err != nil {
		return identityState{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return identityState{}, errors.New("identity state changed while opening")
	}
	if err := requirePrivateFile(file, after); err != nil {
		return identityState{}, fmt.Errorf("identity state: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxIdentityStateSize+1))
	if err != nil {
		return identityState{}, err
	}
	return decodeIdentityStateDocument(raw, true)
}

func decodeStrictJSONDocument(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("identity state contains trailing JSON data")
	}
	return nil
}

func (s *FileStore) persist(state identityState) error {
	raw, err := encodeIdentityStateDocument(state)
	if err != nil {
		return err
	}
	token, err := NewOpaqueToken()
	if err != nil {
		return err
	}
	temporaryName := ".identity-state-" + token
	temporary, err := s.root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary identity state: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = s.root.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary identity state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary identity state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary identity state: %w", err)
	}
	if err := s.root.Rename(temporaryName, s.fileName); err != nil {
		return fmt.Errorf("replace identity state: %w", err)
	}
	keep = true
	if err := s.syncRoot(s.root); err != nil {
		return fmt.Errorf("%w: sync identity state directory: %v", ErrUncertainCommit, err)
	}
	return nil
}

func (s *identityOperations) validateState(state identityState) error {
	switch state.Schema {
	case legacyIdentityStateSchema:
		if state.Audit != nil {
			return errors.New("legacy identity state must not contain an audit array")
		}
	case identityStateSchema:
		if state.Audit == nil {
			return errors.New("identity state audit array must be present and non-null")
		}
	default:
		return fmt.Errorf("unsupported identity state schema %q", state.Schema)
	}
	if state.LoginAttempts == nil || state.Sessions == nil || state.BreakGlassCodes == nil {
		return errors.New("identity state record arrays must be present and non-null")
	}
	if len(state.LoginAttempts) > maxLoginAttempts || len(state.Sessions) > maxSessions || len(state.BreakGlassCodes) > maxBreakGlassCodes || len(state.DesktopAuthorizations) > maxDesktopAuthorizationRecords || len(state.Audit) > maxIdentityAuditEvents {
		return errors.New("identity state exceeds a record-count limit")
	}
	identities := make(map[string]string)
	credentials := make(map[string]string)
	claimIdentity := func(kind, id string) error {
		if !identifierPattern.MatchString(id) {
			return fmt.Errorf("%s has invalid ID %q", kind, id)
		}
		if owner, exists := identities[id]; exists {
			return fmt.Errorf("%s ID %q is already used by %s", kind, id, owner)
		}
		identities[id] = kind
		return nil
	}
	claimCredential := func(owner, hash string) error {
		if !ValidCredentialHash(hash) {
			return fmt.Errorf("%s has an invalid credential hash", owner)
		}
		if existing, exists := credentials[hash]; exists {
			return fmt.Errorf("%s reuses a credential hash from %s", owner, existing)
		}
		credentials[hash] = owner
		return nil
	}
	for index, attempt := range state.LoginAttempts {
		owner := fmt.Sprintf("login attempt %d", index)
		if err := claimIdentity(owner, attempt.ID); err != nil {
			return err
		}
		if err := claimCredential(owner+" transaction", attempt.TransactionHash); err != nil {
			return err
		}
		if err := claimCredential(owner+" state", attempt.StateHash); err != nil {
			return err
		}
		if !isCanonicalTime(attempt.CreatedAt) || !isCanonicalTime(attempt.ExpiresAt) || !attempt.ExpiresAt.After(attempt.CreatedAt) || attempt.ExpiresAt.Sub(attempt.CreatedAt) < time.Minute || attempt.ExpiresAt.Sub(attempt.CreatedAt) > 10*time.Minute || !validReturnPath(attempt.ReturnPath) || len(attempt.SealedOIDCPayload) < 1 || len(attempt.SealedOIDCPayload) > 8192 {
			return fmt.Errorf("%s has invalid lifecycle metadata", owner)
		}
		if _, err := s.openOIDCPayload(attempt.SealedOIDCPayload); err != nil {
			return fmt.Errorf("%s payload: %w", owner, err)
		}
	}
	for index, session := range state.Sessions {
		owner := fmt.Sprintf("session %d", index)
		if err := claimIdentity(owner, session.ID); err != nil {
			return err
		}
		if err := claimCredential(owner+" token", session.TokenHash); err != nil {
			return err
		}
		if err := claimCredential(owner+" CSRF", session.CSRFHash); err != nil {
			return err
		}
		if err := validateSession(session); err != nil {
			return fmt.Errorf("%s: %w", owner, err)
		}
	}
	for index, code := range state.BreakGlassCodes {
		owner := fmt.Sprintf("break-glass code %d", index)
		if err := claimIdentity(owner, code.ID); err != nil {
			return err
		}
		if !strings.HasPrefix(code.ID, "bg_") {
			return fmt.Errorf("%s has a noncanonical ID", owner)
		}
		if err := claimCredential(owner, code.TokenHash); err != nil {
			return err
		}
		if !isCanonicalTime(code.CreatedAt) || !isCanonicalTime(code.ExpiresAt) || !code.ExpiresAt.After(code.CreatedAt) || code.ExpiresAt.Sub(code.CreatedAt) < MinBreakGlassCodeLifetime || code.ExpiresAt.Sub(code.CreatedAt) > MaxBreakGlassCodeLifetime ||
			(code.UsedAt != nil && (!isCanonicalTime(*code.UsedAt) || code.UsedAt.Before(code.CreatedAt) || !code.UsedAt.Before(code.ExpiresAt))) ||
			(code.RevokedAt != nil && (!isCanonicalTime(*code.RevokedAt) || code.RevokedAt.Before(code.CreatedAt))) ||
			(code.UsedAt != nil && code.RevokedAt != nil) {
			return fmt.Errorf("%s has invalid lifecycle metadata", owner)
		}
	}
	for index, record := range state.DesktopAuthorizations {
		owner := fmt.Sprintf("desktop authorization %d", index)
		if err := claimIdentity(owner, record.ID); err != nil {
			return err
		}
		if !ValidDesktopAuthorizationRequestID(record.ID) {
			return fmt.Errorf("%s has a noncanonical ID", owner)
		}
		if err := claimCredential(owner, record.PollSecretHash); err != nil {
			return err
		}
		if err := validateDesktopAuthorizationRecord(record); err != nil {
			return fmt.Errorf("%s: %w", owner, err)
		}
	}
	auditIDs := make(map[string]struct{}, len(state.Audit))
	for index, event := range state.Audit {
		if err := validateIdentityAuditEvent(event); err != nil {
			return fmt.Errorf("identity audit event %d: %w", index, err)
		}
		if _, duplicate := auditIDs[event.ID]; duplicate {
			return fmt.Errorf("identity audit event %d duplicates ID %q", index, event.ID)
		}
		auditIDs[event.ID] = struct{}{}
	}
	return nil
}

func canonicalLoginInput(input LoginAttemptInput) (LoginAttemptInput, persistedOIDCPayload, error) {
	if !identifierPattern.MatchString(input.ID) || !ValidOpaqueToken(input.TransactionToken) || !ValidOpaqueToken(input.StateToken) || !ValidOpaqueToken(input.Nonce) || !ValidOpaqueToken(input.PKCEVerifier) {
		return LoginAttemptInput{}, persistedOIDCPayload{}, errors.New("login transaction contains invalid identifiers or credentials")
	}
	if input.CreatedAt.IsZero() || input.ExpiresAt.IsZero() || !input.ExpiresAt.After(input.CreatedAt) || input.ExpiresAt.Sub(input.CreatedAt) < time.Minute || input.ExpiresAt.Sub(input.CreatedAt) > 10*time.Minute || !validReturnPath(input.ReturnPath) {
		return LoginAttemptInput{}, persistedOIDCPayload{}, errors.New("login transaction contains invalid lifecycle metadata")
	}
	input.CreatedAt, input.ExpiresAt = input.CreatedAt.UTC(), input.ExpiresAt.UTC()
	return input, persistedOIDCPayload{Nonce: input.Nonce, PKCEVerifier: input.PKCEVerifier}, nil
}

func (s *identityOperations) sealOIDCPayload(payload persistedOIDCPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return s.sealer.SealFor(OIDCTransactionSealPurpose, raw)
}

func (s *identityOperations) openOIDCPayload(encoded string) (persistedOIDCPayload, error) {
	raw, err := s.sealer.OpenFor(OIDCTransactionSealPurpose, encoded)
	if err != nil {
		return persistedOIDCPayload{}, err
	}
	defer clear(raw)
	if len(raw) > 4096 {
		return persistedOIDCPayload{}, errors.New("OIDC login payload exceeds its size limit")
	}
	if !utf8.Valid(raw) {
		return persistedOIDCPayload{}, errors.New("OIDC login payload is not valid UTF-8")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return persistedOIDCPayload{}, err
	}
	var payload persistedOIDCPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return persistedOIDCPayload{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return persistedOIDCPayload{}, errors.New("OIDC login payload contains trailing data")
	}
	if !ValidOpaqueToken(payload.Nonce) || !ValidOpaqueToken(payload.PKCEVerifier) {
		return persistedOIDCPayload{}, errors.New("OIDC login payload contains invalid credentials")
	}
	return payload, nil
}

func canonicalSessionInput(input CreateSessionInput) (Session, error) {
	tokenHash, err := HashOpaqueToken(input.Token)
	if err != nil {
		return Session{}, err
	}
	csrfHash, err := HashOpaqueToken(input.CSRFToken)
	if err != nil {
		return Session{}, err
	}
	if CredentialHashEqual(tokenHash, csrfHash) {
		return Session{}, errors.New("session and CSRF credentials must be distinct")
	}
	record := Session{
		ID: input.ID, TokenHash: tokenHash, CSRFHash: csrfHash, Principal: clonePrincipal(input.Principal),
		PolicyFingerprint: input.PolicyFingerprint, AuthMethod: input.AuthMethod,
		CreatedAt: input.CreatedAt.UTC(), LastSeenAt: input.LastSeenAt.UTC(), IdleExpiresAt: input.IdleExpiresAt.UTC(), AbsoluteExpiresAt: input.AbsoluteExpiresAt.UTC(), Version: 1,
	}
	if err := validateSession(record); err != nil {
		return Session{}, err
	}
	return record, nil
}

func validateSession(session Session) error {
	if !identifierPattern.MatchString(session.ID) || !ValidCredentialHash(session.TokenHash) || !ValidCredentialHash(session.CSRFHash) || CredentialHashEqual(session.TokenHash, session.CSRFHash) || !validPolicyFingerprint(session.PolicyFingerprint) || session.Version < 1 {
		return errors.New("invalid identity, credential, policy, or version")
	}
	if err := session.Principal.Validate(); err != nil {
		return err
	}
	wantMethod := map[PrincipalKind]string{PrincipalOIDCAdmin: "oidc", PrincipalLegacyAdmin: "legacy_token", PrincipalService: "service_account", PrincipalBreakGlass: "break_glass"}[session.Principal.Kind]
	if session.AuthMethod != wantMethod {
		return errors.New("authentication method does not match principal kind")
	}
	if !isCanonicalTime(session.CreatedAt) || !isCanonicalTime(session.LastSeenAt) || !isCanonicalTime(session.IdleExpiresAt) || !isCanonicalTime(session.AbsoluteExpiresAt) || session.LastSeenAt.Before(session.CreatedAt) || !session.IdleExpiresAt.After(session.LastSeenAt) || session.IdleExpiresAt.Sub(session.LastSeenAt) > time.Hour || !session.AbsoluteExpiresAt.After(session.CreatedAt) || session.AbsoluteExpiresAt.Sub(session.CreatedAt) < 15*time.Minute || session.IdleExpiresAt.After(session.AbsoluteExpiresAt) || session.AbsoluteExpiresAt.Sub(session.CreatedAt) > 8*time.Hour {
		return errors.New("invalid session lifetime")
	}
	if session.Principal.AuthTime.After(session.CreatedAt.Add(2 * time.Minute)) {
		return errors.New("principal authentication time is after session creation")
	}
	if (session.RevokedAt == nil) != (session.RevocationReason == "") || (session.RevokedAt != nil && (!isCanonicalTime(*session.RevokedAt) || session.RevokedAt.Before(session.CreatedAt))) || (session.RevocationReason != "" && !validReason(session.RevocationReason)) {
		return errors.New("invalid session revocation metadata")
	}
	return nil
}

func validReturnPath(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\r\n\\") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || containsUnsafeRedirectText(parsed.Path) {
		return false
	}
	decodedQuery, err := url.QueryUnescape(parsed.RawQuery)
	return err == nil && !containsUnsafeRedirectText(decodedQuery)
}

func containsUnsafeRedirectText(value string) bool {
	if strings.ContainsRune(value, '\\') {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validReason(reason string) bool { return validBoundedText(reason, 1, 256) }

func appendIdentityAudit(state *identityState, event IdentityAuditEvent) error {
	if err := validateIdentityAuditEvent(event); err != nil {
		return err
	}
	if len(state.Audit) >= maxIdentityAuditEvents {
		return fmt.Errorf("%w: identity audit log is full", ErrLimit)
	}
	for _, existing := range state.Audit {
		if existing.ID == event.ID {
			return fmt.Errorf("%w: identity audit ID already exists", ErrConflict)
		}
	}
	state.Audit = append(state.Audit, cloneIdentityAuditEvent(event))
	return nil
}

func authenticateAuditCaller(state *identityState, actor Actor, at time.Time) error {
	if err := actor.Validate(); err != nil || !isCanonicalTime(at) {
		return ErrUnauthorized
	}
	if actor.SessionID == "" {
		if actor.Kind == PrincipalLegacyAdmin || actor.Kind == PrincipalService {
			return nil
		}
		return ErrUnauthorized
	}
	for _, session := range state.Sessions {
		if session.ID != actor.SessionID {
			continue
		}
		if session.Principal.ID != actor.ID || session.Principal.Kind != actor.Kind || session.RevokedAt != nil || at.Before(session.LastSeenAt) || !at.Before(session.IdleExpiresAt) || !at.Before(session.AbsoluteExpiresAt) {
			return ErrUnauthorized
		}
		return nil
	}
	return ErrUnauthorized
}

func isCanonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func cloneIdentityState(input identityState) identityState {
	out := input
	out.LoginAttempts = make([]persistedLoginAttempt, len(input.LoginAttempts))
	copy(out.LoginAttempts, input.LoginAttempts)
	out.Sessions = make([]Session, len(input.Sessions))
	for index := range input.Sessions {
		out.Sessions[index] = cloneSession(input.Sessions[index])
	}
	out.BreakGlassCodes = make([]BreakGlassCode, len(input.BreakGlassCodes))
	for index := range input.BreakGlassCodes {
		out.BreakGlassCodes[index] = cloneBreakGlassCode(input.BreakGlassCodes[index])
	}
	out.DesktopAuthorizations = make([]desktopAuthorizationRecord, len(input.DesktopAuthorizations))
	for index := range input.DesktopAuthorizations {
		out.DesktopAuthorizations[index] = cloneDesktopAuthorizationRecord(input.DesktopAuthorizations[index])
	}
	out.Audit = make([]IdentityAuditEvent, len(input.Audit))
	for index := range input.Audit {
		out.Audit[index] = cloneIdentityAuditEvent(input.Audit[index])
	}
	return out
}

func cloneSession(input Session) Session {
	out := input
	out.Principal = clonePrincipal(input.Principal)
	if input.RevokedAt != nil {
		value := *input.RevokedAt
		out.RevokedAt = &value
	}
	return out
}

func cloneBreakGlassCode(input BreakGlassCode) BreakGlassCode {
	out := input
	if input.UsedAt != nil {
		value := *input.UsedAt
		out.UsedAt = &value
	}
	if input.RevokedAt != nil {
		value := *input.RevokedAt
		out.RevokedAt = &value
	}
	return out
}

func validBreakGlassCodeInput(input BreakGlassCodeInput) bool {
	return identifierPattern.MatchString(input.ID) && strings.HasPrefix(input.ID, "bg_") &&
		!input.CreatedAt.IsZero() && !input.ExpiresAt.IsZero() && input.ExpiresAt.After(input.CreatedAt) &&
		input.ExpiresAt.Sub(input.CreatedAt) >= MinBreakGlassCodeLifetime && input.ExpiresAt.Sub(input.CreatedAt) <= MaxBreakGlassCodeLifetime
}

func breakGlassCodeSummary(input BreakGlassCode, now time.Time) BreakGlassCodeSummary {
	out := BreakGlassCodeSummary{
		ID: input.ID, CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
		UsedAt: input.UsedAt, RevokedAt: input.RevokedAt, State: breakGlassCodeState(input, now),
	}
	if input.UsedAt != nil {
		value := *input.UsedAt
		out.UsedAt = &value
	}
	if input.RevokedAt != nil {
		value := *input.RevokedAt
		out.RevokedAt = &value
	}
	return out
}

func breakGlassCodeState(input BreakGlassCode, now time.Time) BreakGlassCodeState {
	if input.UsedAt != nil {
		return BreakGlassCodeUsed
	}
	if input.RevokedAt != nil {
		return BreakGlassCodeRevoked
	}
	if !now.Before(input.ExpiresAt) {
		return BreakGlassCodeExpired
	}
	return BreakGlassCodeUsable
}

func sessionSummary(input Session) SessionSummary {
	out := SessionSummary{
		ID: input.ID, Principal: clonePrincipal(input.Principal), PolicyFingerprint: input.PolicyFingerprint,
		AuthMethod: input.AuthMethod, CreatedAt: input.CreatedAt, LastSeenAt: input.LastSeenAt,
		IdleExpiresAt: input.IdleExpiresAt, AbsoluteExpiresAt: input.AbsoluteExpiresAt,
		RevocationReason: input.RevocationReason, Version: input.Version,
	}
	if input.RevokedAt != nil {
		value := *input.RevokedAt
		out.RevokedAt = &value
	}
	return out
}

func sessionsEqual(left, right Session) bool { return reflect.DeepEqual(left, right) }

func pruneExpired(state *identityState, now time.Time) {
	state.LoginAttempts = keepLoginAttempts(state.LoginAttempts, func(value persistedLoginAttempt) bool { return now.Before(value.ExpiresAt) })
	state.Sessions = keepSessions(state.Sessions, func(value Session) bool {
		return now.Before(value.IdleExpiresAt) && now.Before(value.AbsoluteExpiresAt)
	})
	state.BreakGlassCodes = keepBreakGlassCodes(state.BreakGlassCodes, func(value BreakGlassCode) bool { return now.Before(value.ExpiresAt) })
	pruneDesktopAuthorizations(state, now, true)
}

func keepLoginAttempts(values []persistedLoginAttempt, keep func(persistedLoginAttempt) bool) []persistedLoginAttempt {
	result := make([]persistedLoginAttempt, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func keepSessions(values []Session, keep func(Session) bool) []Session {
	result := make([]Session, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func keepBreakGlassCodes(values []BreakGlassCode, keep func(BreakGlassCode) bool) []BreakGlassCode {
	result := make([]BreakGlassCode, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func openPrivateRegular(root *os.Root, name string, create bool) (*os.File, error) {
	info, statErr := root.Lstat(name)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("path is not a real regular file")
		}
		file, err := root.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err != nil || !os.SameFile(info, after) {
			file.Close()
			return nil, errors.New("private file changed while opening")
		}
		if err := requirePrivateFile(file, after); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) || !create {
		return nil, statErr
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("new private file is not regular")
	}
	if err := requirePrivateFile(file, info); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func rejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	remainder := strings.TrimPrefix(clean, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect identity path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("identity path component %q is a symbolic link", current)
		}
	}
	return nil
}

// openOrCreatePrivateIdentityRoot walks from the filesystem root one directory
// handle at a time. It never asks MkdirAll to resolve an unchecked prefix, so
// an existing or raced symlink cannot redirect even the directory-creation
// side effect outside the requested path.
func openOrCreatePrivateIdentityRoot(directory string) (*os.Root, error) {
	clean := filepath.Clean(directory)
	volume := filepath.VolumeName(clean)
	rootPath := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(strings.TrimPrefix(clean, volume), string(filepath.Separator))
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open identity filesystem root: %w", err)
	}
	currentPath := rootPath
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		before, statErr := current.Lstat(component)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := current.Mkdir(component, 0o700); err != nil {
				current.Close()
				return nil, fmt.Errorf("create identity path component %q: %w", filepath.Join(currentPath, component), err)
			}
			before, statErr = current.Lstat(component)
		}
		componentPath := filepath.Join(currentPath, component)
		if statErr != nil {
			current.Close()
			return nil, fmt.Errorf("inspect identity path component %q: %w", componentPath, statErr)
		}
		if before.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, fmt.Errorf("identity path component %q is a symbolic link", componentPath)
		}
		if !before.IsDir() {
			current.Close()
			return nil, fmt.Errorf("identity path component %q is not a directory", componentPath)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			current.Close()
			return nil, fmt.Errorf("open identity path component %q: %w", componentPath, err)
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			next.Close()
			current.Close()
			return nil, fmt.Errorf("identity path component %q changed while opening", componentPath)
		}
		current.Close()
		current, currentPath = next, componentPath
	}
	info, err := current.Stat(".")
	if err != nil {
		current.Close()
		return nil, fmt.Errorf("inspect identity state directory: %w", err)
	}
	if err := requirePrivateRoot(directory, current, info); err != nil {
		current.Close()
		return nil, fmt.Errorf("identity state directory: %w", err)
	}
	return current, nil
}

func rejectDuplicateJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
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

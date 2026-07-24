package identity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	MinDesktopAuthorizationLifetime = time.Minute
	MaxDesktopAuthorizationLifetime = 10 * time.Minute
	MinDesktopAuthorizationInterval = time.Second
	MaxDesktopAuthorizationInterval = 30 * time.Second
	desktopAuthorizationExpiryGrace = 5 * time.Minute
	maxDesktopAuthorizations        = 256
)

var desktopAuthorizationRequestIDPattern = regexp.MustCompile(`^desktop_[A-Za-z0-9_-]{43}$`)

type DesktopAuthorizationDecision string

const (
	DesktopAuthorizationApprove DesktopAuthorizationDecision = "approve"
	DesktopAuthorizationDeny    DesktopAuthorizationDecision = "deny"
)

type DesktopAuthorizationState string

const (
	DesktopAuthorizationPending  DesktopAuthorizationState = "pending"
	DesktopAuthorizationApproved DesktopAuthorizationState = "approved"
	DesktopAuthorizationDenied   DesktopAuthorizationState = "denied"
	DesktopAuthorizationExpired  DesktopAuthorizationState = "expired"
)

type CreateDesktopAuthorizationInput struct {
	ID           string
	PollSecret   string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	PollInterval time.Duration
}

type DesktopAuthorizationPoll struct {
	State        DesktopAuthorizationState
	Principal    Principal
	ExpiresAt    time.Time
	PollInterval time.Duration
}

type desktopAuthorizationRecord struct {
	ID                  string                    `json:"id"`
	PollSecretHash      string                    `json:"poll_secret_hash"`
	State               DesktopAuthorizationState `json:"state"`
	Principal           Principal                 `json:"principal"`
	CreatedAt           time.Time                 `json:"created_at"`
	ExpiresAt           time.Time                 `json:"expires_at"`
	PollIntervalSeconds int64                     `json:"poll_interval_seconds"`
	LastPolledAt        *time.Time                `json:"last_polled_at,omitempty"`
	DecidedAt           *time.Time                `json:"decided_at,omitempty"`
	Version             uint64                    `json:"version"`
}

// ValidDesktopAuthorizationRequestID accepts only the public request identifier
// emitted by the desktop authorization start endpoint. The poll credential is
// a separate secret and must never be placed in a browser URL.
func ValidDesktopAuthorizationRequestID(value string) bool {
	return desktopAuthorizationRequestIDPattern.MatchString(value)
}

func (s *identityOperations) CreateDesktopAuthorization(ctx context.Context, input CreateDesktopAuthorizationInput) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if !ValidDesktopAuthorizationRequestID(input.ID) || !ValidOpaqueToken(input.PollSecret) ||
		!isCanonicalTime(input.CreatedAt) || !isCanonicalTime(input.ExpiresAt) ||
		!input.ExpiresAt.After(input.CreatedAt) ||
		input.ExpiresAt.Sub(input.CreatedAt) < MinDesktopAuthorizationLifetime ||
		input.ExpiresAt.Sub(input.CreatedAt) > MaxDesktopAuthorizationLifetime ||
		input.PollInterval < MinDesktopAuthorizationInterval ||
		input.PollInterval > MaxDesktopAuthorizationInterval ||
		input.PollInterval%time.Second != 0 {
		return errors.New("desktop authorization request is invalid")
	}
	hash, err := HashOpaqueToken(input.PollSecret)
	if err != nil {
		return errors.New("desktop authorization request is invalid")
	}
	record := desktopAuthorizationRecord{
		ID: input.ID, PollSecretHash: hash, State: DesktopAuthorizationPending,
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
		PollIntervalSeconds: int64(input.PollInterval / time.Second), Version: 1,
	}
	return s.update(ctx, func(state *identityState) error {
		pruneDesktopAuthorizations(state, input.CreatedAt, false)
		for _, existing := range state.DesktopAuthorizations {
			if existing.ID == record.ID || CredentialHashEqual(existing.PollSecretHash, record.PollSecretHash) {
				return fmt.Errorf("%w: desktop authorization identity or credential already exists", ErrConflict)
			}
		}
		if len(state.DesktopAuthorizations) >= maxDesktopAuthorizations {
			return ErrLimit
		}
		state.DesktopAuthorizations = append(state.DesktopAuthorizations, record)
		return nil
	})
}

func (s *identityOperations) DecideDesktopAuthorization(ctx context.Context, requestID string, principal Principal, decision DesktopAuthorizationDecision, now time.Time) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if !ValidDesktopAuthorizationRequestID(requestID) || principal.Validate() != nil ||
		(decision != DesktopAuthorizationApprove && decision != DesktopAuthorizationDeny) || !isCanonicalTime(now) {
		return errors.New("desktop authorization decision is invalid")
	}
	return s.update(ctx, func(state *identityState) error {
		for index := range state.DesktopAuthorizations {
			record := &state.DesktopAuthorizations[index]
			if record.ID != requestID {
				continue
			}
			if !now.Before(record.ExpiresAt) {
				return fmt.Errorf("%w: desktop authorization request expired", ErrConflict)
			}
			targetState := DesktopAuthorizationApproved
			if decision == DesktopAuthorizationDeny {
				targetState = DesktopAuthorizationDenied
			}
			if record.State != DesktopAuthorizationPending {
				if record.State == targetState && principalsEqual(record.Principal, principal) {
					return nil
				}
				return fmt.Errorf("%w: desktop authorization request is already decided", ErrConflict)
			}
			record.State = targetState
			record.Principal = clonePrincipal(principal)
			decidedAt := now
			record.DecidedAt = &decidedAt
			record.Version++
			return nil
		}
		pruneDesktopAuthorizations(state, now, false)
		return ErrNotFound
	})
}

func (s *identityOperations) PollDesktopAuthorization(ctx context.Context, requestID, pollSecret string, now time.Time) (DesktopAuthorizationPoll, error) {
	if err := identityContextError(ctx); err != nil {
		return DesktopAuthorizationPoll{}, err
	}
	hash, err := HashOpaqueToken(pollSecret)
	if err != nil || !ValidDesktopAuthorizationRequestID(requestID) || !isCanonicalTime(now) {
		return DesktopAuthorizationPoll{}, ErrUnauthorized
	}
	var result DesktopAuthorizationPoll
	found := false
	err = s.update(ctx, func(state *identityState) error {
		for index := range state.DesktopAuthorizations {
			record := &state.DesktopAuthorizations[index]
			if record.ID != requestID || !CredentialHashEqual(record.PollSecretHash, hash) {
				continue
			}
			found = true
			interval := time.Duration(record.PollIntervalSeconds) * time.Second
			if record.LastPolledAt != nil && now.Before(record.LastPolledAt.Add(interval)) {
				return ErrLimit
			}
			result = DesktopAuthorizationPoll{
				State: record.State, ExpiresAt: record.ExpiresAt, PollInterval: interval,
			}
			switch {
			case !now.Before(record.ExpiresAt):
				result.State = DesktopAuthorizationExpired
				state.DesktopAuthorizations = append(state.DesktopAuthorizations[:index], state.DesktopAuthorizations[index+1:]...)
			case record.State == DesktopAuthorizationDenied:
				state.DesktopAuthorizations = append(state.DesktopAuthorizations[:index], state.DesktopAuthorizations[index+1:]...)
			case record.State == DesktopAuthorizationApproved:
				result.Principal = clonePrincipal(record.Principal)
				state.DesktopAuthorizations = append(state.DesktopAuthorizations[:index], state.DesktopAuthorizations[index+1:]...)
			default:
				polledAt := now
				record.LastPolledAt = &polledAt
				record.Version++
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return DesktopAuthorizationPoll{}, err
	}
	if !found {
		return DesktopAuthorizationPoll{}, ErrUnauthorized
	}
	return result, nil
}

func pruneDesktopAuthorizations(state *identityState, now time.Time, removeExpired bool) {
	kept := make([]desktopAuthorizationRecord, 0, len(state.DesktopAuthorizations))
	for _, record := range state.DesktopAuthorizations {
		removeAt := record.ExpiresAt.Add(desktopAuthorizationExpiryGrace)
		if removeExpired {
			removeAt = record.ExpiresAt
		}
		if now.Before(removeAt) {
			kept = append(kept, record)
		}
	}
	state.DesktopAuthorizations = kept
}

func validateDesktopAuthorizationRecord(record desktopAuthorizationRecord) error {
	interval := time.Duration(record.PollIntervalSeconds) * time.Second
	if !isCanonicalTime(record.CreatedAt) || !isCanonicalTime(record.ExpiresAt) ||
		!record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) < MinDesktopAuthorizationLifetime ||
		record.ExpiresAt.Sub(record.CreatedAt) > MaxDesktopAuthorizationLifetime ||
		interval < MinDesktopAuthorizationInterval || interval > MaxDesktopAuthorizationInterval ||
		record.Version < 1 {
		return errors.New("invalid lifecycle metadata")
	}
	if record.LastPolledAt != nil &&
		(!isCanonicalTime(*record.LastPolledAt) || record.LastPolledAt.Before(record.CreatedAt) || !record.LastPolledAt.Before(record.ExpiresAt)) {
		return errors.New("invalid poll metadata")
	}
	switch record.State {
	case DesktopAuthorizationPending:
		if record.DecidedAt != nil || record.Principal.ID != "" {
			return errors.New("pending request contains decision data")
		}
	case DesktopAuthorizationApproved, DesktopAuthorizationDenied:
		if record.DecidedAt == nil || !isCanonicalTime(*record.DecidedAt) ||
			record.DecidedAt.Before(record.CreatedAt) || !record.DecidedAt.Before(record.ExpiresAt) ||
			record.Principal.Validate() != nil {
			return errors.New("decided request contains invalid decision data")
		}
	default:
		return errors.New("invalid state")
	}
	return nil
}

func cloneDesktopAuthorizationRecord(input desktopAuthorizationRecord) desktopAuthorizationRecord {
	out := input
	out.Principal = clonePrincipal(input.Principal)
	if input.LastPolledAt != nil {
		value := *input.LastPolledAt
		out.LastPolledAt = &value
	}
	if input.DecidedAt != nil {
		value := *input.DecidedAt
		out.DecidedAt = &value
	}
	return out
}

func principalsEqual(left, right Principal) bool {
	if left.ID != right.ID || left.Kind != right.Kind || left.Issuer != right.Issuer || left.Subject != right.Subject ||
		left.DisplayName != right.DisplayName || left.Email != right.Email || left.ACR != right.ACR || !left.AuthTime.Equal(right.AuthTime) ||
		len(left.Groups) != len(right.Groups) || len(left.AMR) != len(right.AMR) {
		return false
	}
	for index := range left.Groups {
		if left.Groups[index] != right.Groups[index] {
			return false
		}
	}
	for index := range left.AMR {
		if left.AMR[index] != right.AMR[index] {
			return false
		}
	}
	return true
}

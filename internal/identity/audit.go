package identity

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type IdentityAuditEventType string

const (
	IdentityAuditSessionCreated       IdentityAuditEventType = "session.created"
	IdentityAuditSessionRotated       IdentityAuditEventType = "session.rotated"
	IdentityAuditSessionRevoked       IdentityAuditEventType = "session.revoked"
	IdentityAuditPrincipalRevoked     IdentityAuditEventType = "principal.revoked"
	IdentityAuditBreakGlassRegistered IdentityAuditEventType = "break_glass.registered"
	IdentityAuditBreakGlassConsumed   IdentityAuditEventType = "break_glass.consumed"
	IdentityAuditBreakGlassRevoked    IdentityAuditEventType = "break_glass.revoked"

	MaxIdentityAuditListLimit = 256
	maxIdentityAuditDetails   = 8
)

// IdentityAuditEvent is the durable, credential-free record stored with the
// identity mutation it describes. Actor attribution is structural and cannot
// be supplied through Details.
type IdentityAuditEvent struct {
	ID                string                 `json:"id"`
	Type              IdentityAuditEventType `json:"type"`
	At                time.Time              `json:"at"`
	Actor             Actor                  `json:"actor"`
	TargetPrincipalID string                 `json:"target_principal_id"`
	TargetSessionID   string                 `json:"target_session_id,omitempty"`
	Details           map[string]string      `json:"details"`
}

type IdentityAuditListFilter struct {
	PrincipalID string
	SessionID   string
	Type        IdentityAuditEventType
	Limit       int
}

// IdentityAuditSummary is deliberately credential-free and detached from the
// store's mutable state.
type IdentityAuditSummary struct {
	ID                string                 `json:"id"`
	Type              IdentityAuditEventType `json:"type"`
	At                time.Time              `json:"at"`
	Actor             Actor                  `json:"actor"`
	TargetPrincipalID string                 `json:"target_principal_id"`
	TargetSessionID   string                 `json:"target_session_id,omitempty"`
	Details           map[string]string      `json:"details"`
}

// IdentityAuditStore is an optional SessionStore extension. Keeping these
// methods out of SessionStore preserves source compatibility for other store
// implementations.
type IdentityAuditStore interface {
	ListIdentityAudit(context.Context, IdentityAuditListFilter) ([]IdentityAuditSummary, error)
	RevokeSessionAs(ctx context.Context, actor Actor, sessionID string, at time.Time, reason string) (Session, error)
	RevokePrincipalAs(ctx context.Context, actor Actor, principalID string, at time.Time, reason string) (int, error)
}

func newIdentityAuditEvent(eventType IdentityAuditEventType, at time.Time, actor Actor, targetPrincipalID, targetSessionID string, details map[string]string) (IdentityAuditEvent, error) {
	token, err := NewOpaqueToken()
	if err != nil {
		return IdentityAuditEvent{}, fmt.Errorf("generate identity audit ID: %w", err)
	}
	event := IdentityAuditEvent{
		ID: "audit_" + token, Type: eventType, At: at.UTC(), Actor: actor,
		TargetPrincipalID: targetPrincipalID, TargetSessionID: targetSessionID,
		Details: cloneAuditDetails(details),
	}
	if err := validateIdentityAuditEvent(event); err != nil {
		return IdentityAuditEvent{}, err
	}
	return event, nil
}

func validateIdentityAuditEvent(event IdentityAuditEvent) error {
	if len(event.ID) <= len("audit_") || event.ID[:len("audit_")] != "audit_" || !ValidOpaqueToken(event.ID[len("audit_"):]) {
		return errors.New("identity audit event has an invalid ID")
	}
	if !isCanonicalTime(event.At) {
		return errors.New("identity audit event has an invalid timestamp")
	}
	if err := event.Actor.Validate(); err != nil {
		return fmt.Errorf("identity audit actor: %w", err)
	}
	if !identifierPattern.MatchString(event.TargetPrincipalID) || (event.TargetSessionID != "" && !identifierPattern.MatchString(event.TargetSessionID)) {
		return errors.New("identity audit event has an invalid target")
	}
	if event.Details == nil || len(event.Details) > maxIdentityAuditDetails {
		return errors.New("identity audit event details must be present and bounded")
	}
	reserved := map[string]struct{}{
		"id": {}, "type": {}, "at": {}, "actor": {}, "actor_id": {}, "actor_kind": {}, "actor_session_id": {},
		"target_principal_id": {}, "target_session_id": {}, "details": {},
	}
	for key, value := range event.Details {
		if _, found := reserved[key]; found || !identifierPattern.MatchString(key) || !validBoundedText(value, 1, 256) {
			return fmt.Errorf("identity audit event has invalid detail %q", key)
		}
	}

	switch event.Type {
	case IdentityAuditSessionCreated:
		if event.TargetSessionID == "" || event.Actor.ID != event.TargetPrincipalID || event.Actor.SessionID != event.TargetSessionID || !exactAuditDetailKeys(event.Details, "auth_method", "session_version") || !validAuditSessionVersion(event.Details["session_version"]) || !validAuditAuthMethod(event.Details["auth_method"]) {
			return errors.New("session.created audit event is not canonical")
		}
	case IdentityAuditSessionRotated:
		if event.TargetSessionID == "" || event.Actor.ID != event.TargetPrincipalID || event.Actor.SessionID != event.TargetSessionID || !exactAuditDetailKeys(event.Details, "session_version") || !validAuditSessionVersion(event.Details["session_version"]) {
			return errors.New("session.rotated audit event is not canonical")
		}
	case IdentityAuditSessionRevoked:
		if event.TargetSessionID == "" || !exactAuditDetailKeys(event.Details, "reason", "session_version") || !validReason(event.Details["reason"]) || !validAuditSessionVersion(event.Details["session_version"]) {
			return errors.New("session.revoked audit event is not canonical")
		}
	case IdentityAuditPrincipalRevoked:
		if event.TargetSessionID != "" || !exactAuditDetailKeys(event.Details, "reason", "revoked_sessions") || !validReason(event.Details["reason"]) || !validAuditRevokedCount(event.Details["revoked_sessions"]) {
			return errors.New("principal.revoked audit event is not canonical")
		}
	case IdentityAuditBreakGlassRegistered:
		if event.TargetSessionID != "" || event.Actor.Kind == PrincipalBreakGlass || !validPrefixedID(event.TargetPrincipalID, "breakglass_bg_") || !exactAuditDetailKeys(event.Details, "expires_at") || !validCanonicalAuditTime(event.Details["expires_at"]) {
			return errors.New("break_glass.registered audit event is not canonical")
		}
	case IdentityAuditBreakGlassConsumed:
		if event.TargetSessionID != "" || event.Actor.Kind != PrincipalBreakGlass || event.Actor.ID != event.TargetPrincipalID || !exactAuditDetailKeys(event.Details, "expires_at") || !validCanonicalAuditTime(event.Details["expires_at"]) {
			return errors.New("break_glass.consumed audit event is not canonical")
		}
	case IdentityAuditBreakGlassRevoked:
		if event.TargetSessionID != "" || event.Actor.Kind == PrincipalBreakGlass || !validPrefixedID(event.TargetPrincipalID, "breakglass_bg_") || !exactAuditDetailKeys(event.Details, "expires_at") || !validCanonicalAuditTime(event.Details["expires_at"]) {
			return errors.New("break_glass.revoked audit event is not canonical")
		}
	default:
		return fmt.Errorf("unsupported identity audit event type %q", event.Type)
	}
	return nil
}

func validAuditAuthMethod(value string) bool {
	switch value {
	case "oidc", "legacy_token", "service_account", "break_glass":
		return true
	default:
		return false
	}
}

func validIdentityAuditEventType(value IdentityAuditEventType) bool {
	switch value {
	case IdentityAuditSessionCreated, IdentityAuditSessionRotated, IdentityAuditSessionRevoked, IdentityAuditPrincipalRevoked,
		IdentityAuditBreakGlassRegistered, IdentityAuditBreakGlassConsumed, IdentityAuditBreakGlassRevoked:
		return true
	default:
		return false
	}
}

func validCanonicalAuditTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func validAuditSessionVersion(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func validAuditRevokedCount(value string) bool {
	parsed, err := strconv.Atoi(value)
	return err == nil && parsed > 0 && parsed <= maxSessions && strconv.Itoa(parsed) == value
}

func exactAuditDetailKeys(details map[string]string, keys ...string) bool {
	if len(details) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, found := details[key]; !found {
			return false
		}
	}
	return true
}

func cloneIdentityAuditEvent(input IdentityAuditEvent) IdentityAuditEvent {
	out := input
	out.Details = cloneAuditDetails(input.Details)
	return out
}

func cloneAuditDetails(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func identityAuditSummary(input IdentityAuditEvent) IdentityAuditSummary {
	return IdentityAuditSummary{
		ID: input.ID, Type: input.Type, At: input.At, Actor: input.Actor,
		TargetPrincipalID: input.TargetPrincipalID, TargetSessionID: input.TargetSessionID,
		Details: cloneAuditDetails(input.Details),
	}
}

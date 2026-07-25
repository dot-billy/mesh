package control

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	ActorKindOIDCAdmin      = "oidc_admin"
	ActorKindLegacyAdmin    = "legacy_admin"
	ActorKindServiceAccount = "service_account"
	ActorKindBreakGlass     = "break_glass"
	ActorKindNodeAgent      = "node_agent"
	legacyAdminActorID      = "legacy_admin"

	auditActorIDKey        = "actor_id"
	auditActorKindKey      = "actor_kind"
	auditActorSessionIDKey = "actor_session_id"
)

// Actor is the bounded, non-secret identity attached to a mutation. SessionID
// is optional for direct bearer, service-account, and node-agent requests;
// when present it must be an opaque record ID, never a raw token.
type Actor struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	SessionID string `json:"session_id,omitempty"`
}

// LegacyAdminActor returns the single canonical actor used by the existing
// shared administrator credential until request identity is supplied by the
// identity layer. Returning a value prevents process-global attribution state
// from being mutated. Cookie and bearer authentication both map to this actor.
func LegacyAdminActor() Actor {
	return Actor{ID: legacyAdminActorID, Kind: ActorKindLegacyAdmin}
}

func validateActor(actor Actor) error {
	if !validPersistedID(actor.ID) {
		return fmt.Errorf("%w: actor id must match [A-Za-z0-9_-]{1,128}", ErrInvalid)
	}
	switch actor.Kind {
	case ActorKindOIDCAdmin:
		suffix := strings.TrimPrefix(actor.ID, "oidc_")
		decoded, err := base64.RawURLEncoding.DecodeString(suffix)
		if suffix == actor.ID || len(suffix) != 43 || err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != suffix {
			return fmt.Errorf("%w: oidc administrator actor id must contain a canonical SHA-256 base64url digest", ErrInvalid)
		}
	case ActorKindLegacyAdmin:
		if actor.ID != legacyAdminActorID {
			return fmt.Errorf("%w: legacy administrator actor id must be %q", ErrInvalid, legacyAdminActorID)
		}
	case ActorKindServiceAccount:
		if suffix := strings.TrimPrefix(actor.ID, "service_"); suffix == actor.ID || !validPersistedID(suffix) {
			return fmt.Errorf("%w: service account actor id must use the canonical service record form", ErrInvalid)
		}
	case ActorKindBreakGlass:
		if suffix := strings.TrimPrefix(actor.ID, "breakglass_"); suffix == actor.ID || !validPersistedID(suffix) {
			return fmt.Errorf("%w: break-glass actor id must use the canonical code record form", ErrInvalid)
		}
	case ActorKindNodeAgent:
		if actor.SessionID != "" {
			return fmt.Errorf("%w: node-agent actor cannot carry an administrator session", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported actor kind %q", ErrInvalid, actor.Kind)
	}
	if actor.SessionID != "" && !validPersistedID(actor.SessionID) {
		return fmt.Errorf("%w: actor session id must be empty or match [A-Za-z0-9_-]{1,128}", ErrInvalid)
	}
	return nil
}

func newAttributedAudit(at time.Time, action, resource, id string, details map[string]any, actor Actor) (AuditEvent, error) {
	if err := validateActor(actor); err != nil {
		return AuditEvent{}, err
	}
	for _, key := range []string{auditActorIDKey, auditActorKindKey, auditActorSessionIDKey} {
		if _, collision := details[key]; collision {
			return AuditEvent{}, fmt.Errorf("%w: audit detail key %q is reserved for actor attribution", ErrInvalid, key)
		}
	}
	attributed := make(map[string]any, len(details)+3)
	for key, value := range details {
		attributed[key] = value
	}
	attributed[auditActorIDKey] = actor.ID
	attributed[auditActorKindKey] = actor.Kind
	attributed[auditActorSessionIDKey] = actor.SessionID
	return newAudit(at, action, resource, id, attributed), nil
}

func newOptionalAttributedAudit(at time.Time, action, resource, id string, details map[string]any, actor *Actor) (AuditEvent, error) {
	if actor == nil {
		return newAudit(at, action, resource, id, details), nil
	}
	return newAttributedAudit(at, action, resource, id, details, *actor)
}

func validateAuditActorMetadata(details map[string]any) error {
	present := 0
	for _, key := range []string{auditActorIDKey, auditActorKindKey, auditActorSessionIDKey} {
		if _, ok := details[key]; ok {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != 3 {
		return fmt.Errorf("partial actor attribution metadata")
	}
	id, idOK := details[auditActorIDKey].(string)
	kind, kindOK := details[auditActorKindKey].(string)
	sessionID, sessionOK := details[auditActorSessionIDKey].(string)
	if !idOK || !kindOK || !sessionOK {
		return fmt.Errorf("actor attribution metadata must contain strings")
	}
	if err := validateActor(Actor{ID: id, Kind: kind, SessionID: sessionID}); err != nil {
		return err
	}
	return nil
}

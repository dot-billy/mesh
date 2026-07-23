package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// decodeIdentityStateDocument is the single strict, side-effect-free decoder
// for identity state. Filesystem migration/recovery may opt into the legacy v1
// schema; authoritative PostgreSQL rows must require the current schema.
func decodeIdentityStateDocument(raw []byte, allowLegacy bool) (identityState, error) {
	if len(raw) == 0 {
		return identityState{}, errors.New("identity state is empty")
	}
	if len(raw) > maxIdentityStateSize {
		return identityState{}, errors.New("identity state exceeds its size limit")
	}
	if !utf8.Valid(raw) {
		return identityState{}, errors.New("identity state is not valid UTF-8")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return identityState{}, fmt.Errorf("decode identity state: %w", err)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return identityState{}, fmt.Errorf("decode identity state schema: %w", err)
	}
	switch header.Schema {
	case legacyIdentityStateSchema:
		if !allowLegacy {
			return identityState{}, fmt.Errorf("unsupported identity state schema %q", header.Schema)
		}
		var legacy legacyIdentityStateV1
		if err := decodeStrictJSONDocument(raw, &legacy); err != nil {
			return identityState{}, fmt.Errorf("decode identity state: %w", err)
		}
		return identityState{
			Schema: legacy.Schema, LoginAttempts: legacy.LoginAttempts, Sessions: legacy.Sessions,
			BreakGlassCodes: legacy.BreakGlassCodes,
		}, nil
	case identityStateSchema:
		var state identityState
		if err := decodeStrictJSONDocument(raw, &state); err != nil {
			return identityState{}, fmt.Errorf("decode identity state: %w", err)
		}
		return state, nil
	default:
		return identityState{}, fmt.Errorf("unsupported identity state schema %q", header.Schema)
	}
}

func encodeIdentityStateDocument(state identityState) ([]byte, error) {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode identity state: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxIdentityStateSize {
		return nil, errors.New("identity state exceeds its size limit")
	}
	return raw, nil
}

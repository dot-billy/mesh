//go:build postgresmaxdocgate

package identity

// This file is compiled only for the explicit PostgreSQL maximum-document
// gate. Transition validation stays in package identity so it can compare the
// private durable model after the same strict decode and purpose-bound sealed
// payload validation used by recovery.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

const maximumDocumentRevocationReason = "administrator revocation"

// MaximumDocumentCleanupExpectation is the deterministic revision-2 identity
// document derived from the imported source. SHA256 binds both the expected
// PostgreSQL document digest and its write receipt without trusting the
// cleanup implementation to describe its own result.
type MaximumDocumentCleanupExpectation struct {
	CanonicalBytes []byte
	SHA256         [sha256.Size]byte
}

// BuildMaximumDocumentCleanupExpectation strictly recovers source and removes
// only the named expired login attempt and session. Every other record, its
// ordering, and the document schema are preserved exactly in the returned
// canonical document.
func BuildMaximumDocumentCleanupExpectation(source []byte, sealer Sealer, expiredLoginAttemptID, expiredSessionID string) (MaximumDocumentCleanupExpectation, error) {
	if !identifierPattern.MatchString(expiredLoginAttemptID) || !identifierPattern.MatchString(expiredSessionID) || expiredLoginAttemptID == expiredSessionID {
		return MaximumDocumentCleanupExpectation{}, errors.New("maximum-document cleanup target IDs are invalid")
	}
	state, err := validateRecoverySnapshot(source, sealer)
	if err != nil {
		return MaximumDocumentCleanupExpectation{}, fmt.Errorf("validate maximum-document cleanup source: %w", err)
	}
	expected := cloneMaximumDocumentTransitionState(state)

	removedAttempts := 0
	attempts := make([]persistedLoginAttempt, 0, len(expected.LoginAttempts))
	for _, attempt := range expected.LoginAttempts {
		if attempt.ID == expiredLoginAttemptID {
			removedAttempts++
			continue
		}
		attempts = append(attempts, attempt)
	}
	removedSessions := 0
	sessions := make([]Session, 0, len(expected.Sessions))
	for _, session := range expected.Sessions {
		if session.ID == expiredSessionID {
			removedSessions++
			continue
		}
		sessions = append(sessions, session)
	}
	if removedAttempts != 1 || removedSessions != 1 {
		return MaximumDocumentCleanupExpectation{}, fmt.Errorf("maximum-document cleanup source contains target counts login_attempt=%d session=%d, want exactly one each", removedAttempts, removedSessions)
	}
	expected.LoginAttempts = attempts
	expected.Sessions = sessions
	canonical, err := encodeMaximumDocumentTransitionState(expected)
	if err != nil {
		return MaximumDocumentCleanupExpectation{}, fmt.Errorf("encode maximum-document cleanup expectation: %w", err)
	}
	if _, err := validateRecoverySnapshot(canonical, sealer); err != nil {
		return MaximumDocumentCleanupExpectation{}, fmt.Errorf("validate maximum-document cleanup expectation: %w", err)
	}
	return MaximumDocumentCleanupExpectation{
		CanonicalBytes: bytes.Clone(canonical),
		SHA256:         sha256.Sum256(canonical),
	}, nil
}

// ValidateMaximumDocumentCleanupExpectation proves that actual is the exact
// canonical document described by a source-derived expectation.
func ValidateMaximumDocumentCleanupExpectation(actual []byte, sealer Sealer, expectation MaximumDocumentCleanupExpectation) error {
	if _, err := decodeMaximumDocumentCleanupExpectation(expectation, sealer); err != nil {
		return err
	}
	if _, err := validateRecoverySnapshot(actual, sealer); err != nil {
		return fmt.Errorf("validate maximum-document cleanup result: %w", err)
	}
	if !bytes.Equal(actual, expectation.CanonicalBytes) {
		return errors.New("maximum-document cleanup result does not match its source-derived canonical expectation")
	}
	return nil
}

// ValidateMaximumDocumentCleanupTransition derives revision 2 from source and
// proves that cleanup removed exactly the named records. The returned digest
// can be compared directly with the revision-2 PostgreSQL row and receipt.
func ValidateMaximumDocumentCleanupTransition(source, cleanup []byte, sealer Sealer, expiredLoginAttemptID, expiredSessionID string) (MaximumDocumentCleanupExpectation, error) {
	expectation, err := BuildMaximumDocumentCleanupExpectation(source, sealer, expiredLoginAttemptID, expiredSessionID)
	if err != nil {
		return MaximumDocumentCleanupExpectation{}, err
	}
	if err := ValidateMaximumDocumentCleanupExpectation(cleanup, sealer, expectation); err != nil {
		return MaximumDocumentCleanupExpectation{}, err
	}
	return expectation, nil
}

// ValidateMaximumDocumentTerminalTransition reconstructs revision 2 solely
// from source, then proves the terminal state is revision 2 plus one exact
// legacy-administrator session revocation. It supports verification after a
// restart without retaining cleanup bytes in process memory.
func ValidateMaximumDocumentTerminalTransition(source, terminal []byte, sealer Sealer, expiredLoginAttemptID, expiredSessionID, revokeSessionID string) (MaximumDocumentCleanupExpectation, error) {
	expectation, err := BuildMaximumDocumentCleanupExpectation(source, sealer, expiredLoginAttemptID, expiredSessionID)
	if err != nil {
		return MaximumDocumentCleanupExpectation{}, err
	}
	if err := ValidateMaximumDocumentTerminalTransitionFromCleanup(expectation, terminal, sealer, revokeSessionID); err != nil {
		return MaximumDocumentCleanupExpectation{}, err
	}
	return expectation, nil
}

// ValidateMaximumDocumentTerminalTransitionFromCleanup proves that terminal
// changes only the named session's revocation fields and appends exactly one
// matching, sessionless legacy-administrator session.revoked audit event.
func ValidateMaximumDocumentTerminalTransitionFromCleanup(expectation MaximumDocumentCleanupExpectation, terminal []byte, sealer Sealer, revokeSessionID string) error {
	if !identifierPattern.MatchString(revokeSessionID) {
		return errors.New("maximum-document revocation target ID is invalid")
	}
	cleanup, err := decodeMaximumDocumentCleanupExpectation(expectation, sealer)
	if err != nil {
		return err
	}
	if cleanup.Schema != identityStateSchema {
		return errors.New("maximum-document terminal transition requires the current identity schema")
	}
	terminalState, err := validateRecoverySnapshot(terminal, sealer)
	if err != nil {
		return fmt.Errorf("validate maximum-document terminal result: %w", err)
	}

	targetIndex := -1
	for index := range cleanup.Sessions {
		if cleanup.Sessions[index].ID == revokeSessionID {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 {
		return errors.New("maximum-document cleanup expectation does not contain the revocation target")
	}
	cleanupTarget := cleanup.Sessions[targetIndex]
	if cleanupTarget.RevokedAt != nil || cleanupTarget.RevocationReason != "" || cleanupTarget.Version == ^uint64(0) {
		return errors.New("maximum-document cleanup revocation target is not an unrevoked incrementable session")
	}

	var terminalTarget *Session
	for index := range terminalState.Sessions {
		if terminalState.Sessions[index].ID == revokeSessionID {
			terminalTarget = &terminalState.Sessions[index]
			break
		}
	}
	if terminalTarget == nil || terminalTarget.RevokedAt == nil {
		return errors.New("maximum-document terminal result does not contain the revoked target")
	}
	if len(terminalState.Audit) != len(cleanup.Audit)+1 {
		return fmt.Errorf("maximum-document terminal result appended %d audit events, want exactly one", len(terminalState.Audit)-len(cleanup.Audit))
	}

	expected := cloneMaximumDocumentTransitionState(cleanup)
	revokedAt := *terminalTarget.RevokedAt
	expectedTarget := &expected.Sessions[targetIndex]
	expectedTarget.RevokedAt = &revokedAt
	expectedTarget.RevocationReason = maximumDocumentRevocationReason
	expectedTarget.Version++
	appended := terminalState.Audit[len(cleanup.Audit)]
	expectedAudit := IdentityAuditEvent{
		ID: appended.ID, Type: IdentityAuditSessionRevoked, At: revokedAt,
		Actor:             Actor{ID: "legacy_admin", Kind: PrincipalLegacyAdmin},
		TargetPrincipalID: cleanupTarget.Principal.ID,
		TargetSessionID:   cleanupTarget.ID,
		Details: map[string]string{
			"reason":          maximumDocumentRevocationReason,
			"session_version": strconv.FormatUint(expectedTarget.Version, 10),
		},
	}
	if err := validateIdentityAuditEvent(expectedAudit); err != nil {
		return fmt.Errorf("construct maximum-document terminal audit expectation: %w", err)
	}
	expected.Audit = append(expected.Audit, expectedAudit)
	if !reflect.DeepEqual(terminalState, expected) {
		return errors.New("maximum-document terminal result changed identity state outside the exact session revocation transition")
	}
	canonical, err := encodeMaximumDocumentTransitionState(expected)
	if err != nil {
		return fmt.Errorf("encode maximum-document terminal expectation: %w", err)
	}
	if !bytes.Equal(terminal, canonical) {
		return errors.New("maximum-document terminal result is not the exact canonical transition document")
	}
	return nil
}

func decodeMaximumDocumentCleanupExpectation(expectation MaximumDocumentCleanupExpectation, sealer Sealer) (identityState, error) {
	if len(expectation.CanonicalBytes) == 0 || sha256.Sum256(expectation.CanonicalBytes) != expectation.SHA256 {
		return identityState{}, errors.New("maximum-document cleanup expectation digest is invalid")
	}
	state, err := validateRecoverySnapshot(expectation.CanonicalBytes, sealer)
	if err != nil {
		return identityState{}, fmt.Errorf("validate maximum-document cleanup expectation: %w", err)
	}
	canonical, err := encodeMaximumDocumentTransitionState(state)
	if err != nil {
		return identityState{}, fmt.Errorf("canonicalize maximum-document cleanup expectation: %w", err)
	}
	if !bytes.Equal(canonical, expectation.CanonicalBytes) {
		return identityState{}, errors.New("maximum-document cleanup expectation is not canonical")
	}
	return state, nil
}

func cloneMaximumDocumentTransitionState(input identityState) identityState {
	out := cloneIdentityState(input)
	if input.Audit == nil {
		out.Audit = nil
	}
	return out
}

func encodeMaximumDocumentTransitionState(state identityState) ([]byte, error) {
	if state.Schema != legacyIdentityStateSchema {
		return encodeIdentityStateDocument(state)
	}
	raw, err := json.MarshalIndent(legacyIdentityStateV1{
		Schema: state.Schema, LoginAttempts: state.LoginAttempts, Sessions: state.Sessions,
		BreakGlassCodes: state.BreakGlassCodes,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode legacy identity state: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxIdentityStateSize {
		return nil, errors.New("identity state exceeds its size limit")
	}
	return raw, nil
}

package iosmobile

import (
	"errors"
	"fmt"
)

// IdentityRemovalSession exposes deletion only. It cannot load, return, replace,
// or create node authority, and the containing app cannot construct it because
// only the Packet Tunnel extension has the identity Keychain access group.
type IdentityRemovalSession struct {
	deletePrivateKey         func() error
	deleteAgentSecret        func() error
	deletePendingAgentSecret func() error
}

func NewIdentityRemovalSession(
	accessGroup string,
	identityID string,
) (*IdentityRemovalSession, error) {
	if err := validateIdentityScope(accessGroup, identityID); err != nil {
		return nil, err
	}
	return &IdentityRemovalSession{
		deletePrivateKey: func() error {
			return deleteSecret(accessGroup, identityService, identityID)
		},
		deleteAgentSecret: func() error {
			return deleteSecret(
				accessGroup,
				agentCredentialService,
				identityID,
			)
		},
		deletePendingAgentSecret: func() error {
			return deleteSecret(
				accessGroup,
				pendingAgentCredentialService,
				identityID,
			)
		},
	}, nil
}

func newIdentityRemovalSession(
	deletePrivateKey func() error,
	deleteAgentSecret func() error,
	deletePendingAgentSecret func() error,
) *IdentityRemovalSession {
	return &IdentityRemovalSession{
		deletePrivateKey:         deletePrivateKey,
		deleteAgentSecret:        deleteAgentSecret,
		deletePendingAgentSecret: deletePendingAgentSecret,
	}
}

// Remove makes the local node identity unusable even when one Keychain delete
// fails: every fixed deletion is attempted and failures are joined without
// including service, account, or secret values.
func (s *IdentityRemovalSession) Remove() error {
	if s == nil ||
		s.deletePrivateKey == nil ||
		s.deleteAgentSecret == nil ||
		s.deletePendingAgentSecret == nil {
		return errors.New("identity removal session is unavailable")
	}
	var failures []error
	if err := s.deleteAgentSecret(); err != nil {
		failures = append(failures, fmt.Errorf("delete agent credential: %w", err))
	}
	if err := s.deletePendingAgentSecret(); err != nil {
		failures = append(
			failures,
			fmt.Errorf("delete pending agent credential: %w", err),
		)
	}
	if err := s.deletePrivateKey(); err != nil {
		failures = append(failures, fmt.Errorf("delete node private key: %w", err))
	}
	return errors.Join(failures...)
}

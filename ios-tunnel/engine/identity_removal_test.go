package iosmobile

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestIdentityRemovalAttemptsEveryFixedSecretAndReturnsNoValue(t *testing.T) {
	var operations []string
	session := newIdentityRemovalSession(
		func() error {
			operations = append(operations, "private")
			return nil
		},
		func() error {
			operations = append(operations, "agent")
			return errors.New("rejected")
		},
		func() error {
			operations = append(operations, "pending")
			return nil
		},
	)
	err := session.Remove()
	if !slices.Equal(operations, []string{"agent", "pending", "private"}) {
		t.Fatalf("identity removal operations=%v", operations)
	}
	if err == nil ||
		!strings.Contains(err.Error(), "delete agent credential") ||
		strings.Contains(err.Error(), identityService) ||
		strings.Contains(err.Error(), agentCredentialService) {
		t.Fatalf("identity removal error=%v", err)
	}
}

func TestIdentityRemovalValidatesNarrowScope(t *testing.T) {
	if _, err := NewIdentityRemovalSession(
		"TEAM.wrong",
		"primary",
	); err == nil {
		t.Fatal("identity removal accepted another Keychain group")
	}
}

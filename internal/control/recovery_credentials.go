package control

import (
	"errors"
	"fmt"
)

// ValidateRecoverySnapshotCredentials proves that the exact recovered control
// state is both decryptable by masterKey and bound to adminToken. Unlike the
// compatibility-oriented live store decoder, this recovery boundary rejects
// legacy snapshots that have never completed an authenticated server startup.
func ValidateRecoverySnapshotCredentials(raw, masterKey, adminToken []byte) error {
	box, err := NewSecretBox(masterKey)
	if err != nil {
		return err
	}
	state, err := validateRecoverySnapshot(raw, box)
	if err != nil {
		return err
	}
	if (state.Version != ControlStateVersionCredentialBinding && state.Version != ControlStateVersionTopology && state.Version != ControlStateVersionNetworkDNS && state.Version != ControlStateVersionNetworkRelays && state.Version != ControlStateVersionCARotation && state.Version != ControlStateVersionFirewallRollout && state.Version != ControlStateVersionFirewallPause && state.Version != ControlStateVersionRouteTransfer && state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes) || state.AdminCredentialVerifier == "" {
		return errors.New("recovery snapshot is not bound to an administrator credential; start mesh-server successfully before creating a backup")
	}
	masterVerifier, err := DeriveMasterKeyVerifier(masterKey)
	if err != nil {
		return fmt.Errorf("derive master-key verifier: %w", err)
	}
	if !masterKeyVerifierEqual(state.MasterKeyVerifier, masterVerifier) {
		return errors.New("master key does not match the recovery snapshot")
	}
	verifier, err := DeriveAdminCredentialVerifier(masterKey, adminToken)
	if err != nil {
		return fmt.Errorf("derive administrator credential verifier: %w", err)
	}
	if !adminCredentialVerifierEqual(state.AdminCredentialVerifier, verifier) {
		return errors.New("administrator credential does not match the recovery snapshot")
	}
	return nil
}

package windowsinstall

import (
	"errors"
	"fmt"

	"mesh/internal/agentstate"
)

const WindowsInstallStateSchema = "mesh-windows-install-state-v1"

type WindowsInstallState struct {
	Schema               string                       `json:"schema"`
	BootstrapTrustSHA256 string                       `json:"bootstrap_trust_sha256"`
	Channel              string                       `json:"channel"`
	Arch                 string                       `json:"arch"`
	HighWater            AuthenticatedWindowsRelease  `json:"high_water"`
	Active               *AuthenticatedWindowsRelease `json:"active,omitempty"`
	Previous             *AuthenticatedWindowsRelease `json:"previous,omitempty"`
}

func (state WindowsInstallState) Validate() error {
	if state.Schema != WindowsInstallStateSchema {
		return errors.New("Windows install-state schema is invalid")
	}
	if !digestPattern.MatchString(state.BootstrapTrustSHA256) {
		return errors.New("Windows installer bootstrap-trust digest is not canonical")
	}
	if !windowsChannelPattern.MatchString(state.Channel) {
		return errors.New("Windows installer release channel is not canonical")
	}
	if state.Arch != "amd64" && state.Arch != "arm64" {
		return errors.New("Windows installer architecture is unsupported")
	}
	if err := state.HighWater.Validate(); err != nil {
		return fmt.Errorf("Windows high-water release: %w", err)
	}
	if state.HighWater.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 ||
		state.HighWater.Channel != state.Channel || state.HighWater.Arch != state.Arch {
		return errors.New("Windows high-water release differs from installer trust or architecture")
	}
	for label, identity := range map[string]*AuthenticatedWindowsRelease{"active": state.Active, "previous": state.Previous} {
		if identity == nil {
			continue
		}
		if err := identity.Validate(); err != nil {
			return fmt.Errorf("Windows %s release: %w", label, err)
		}
		if identity.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 || identity.Channel != state.Channel || identity.Arch != state.Arch {
			return fmt.Errorf("Windows %s release differs from installer trust or architecture", label)
		}
		position := compareWindowsReleasePosition(*identity, state.HighWater)
		if position > 0 {
			return fmt.Errorf("Windows %s release exceeds the accepted high-water position", label)
		}
		if position == 0 && *identity != state.HighWater {
			return fmt.Errorf("Windows %s release equivocates at the accepted high-water position", label)
		}
	}
	if state.Active != nil && state.Previous != nil && state.Active.InstalledID == state.Previous.InstalledID {
		return errors.New("Windows active and previous releases must be distinct")
	}
	if state.Active == nil && state.Previous != nil {
		return errors.New("Windows previous release cannot exist without an active release")
	}
	return nil
}

func (state WindowsInstallState) CheckCandidate(candidate AuthenticatedWindowsRelease) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if candidate.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 || candidate.Channel != state.Channel || candidate.Arch != state.Arch {
		return errors.New("Windows candidate differs from installer trust or architecture")
	}
	position := compareWindowsReleasePosition(candidate, state.HighWater)
	if position < 0 {
		return fmt.Errorf("Windows candidate position (%d,%d) is below accepted position (%d,%d)", candidate.ReleaseEpoch, candidate.Sequence, state.HighWater.ReleaseEpoch, state.HighWater.Sequence)
	}
	if candidate.MinimumSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return fmt.Errorf("Windows candidate security floor %d is below accepted floor %d", candidate.MinimumSecurityFloor, state.HighWater.MinimumSecurityFloor)
	}
	if position == 0 && candidate != state.HighWater {
		return errors.New("same-position Windows candidate differs from the accepted authenticated release")
	}
	if position > 0 && candidate.TrustedRootVersion < state.HighWater.TrustedRootVersion {
		return fmt.Errorf("Windows candidate trusted-root version %d is below accepted version %d", candidate.TrustedRootVersion, state.HighWater.TrustedRootVersion)
	}
	return nil
}

func (state WindowsInstallState) AdvanceHighWater(candidate AuthenticatedWindowsRelease) (WindowsInstallState, error) {
	if err := state.CheckCandidate(candidate); err != nil {
		return WindowsInstallState{}, err
	}
	next := cloneWindowsInstallState(state)
	next.HighWater = candidate
	return next, next.Validate()
}

func (state WindowsInstallState) ActivateAccepted() (WindowsInstallState, error) {
	if err := state.Validate(); err != nil {
		return WindowsInstallState{}, err
	}
	target := state.HighWater
	if target.BundleSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return WindowsInstallState{}, errors.New("Windows activation target cannot process the persisted security floor")
	}
	if state.Active == nil {
		if target.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
			return WindowsInstallState{}, fmt.Errorf("first Windows activation target writes agent-state schema %d, want %d", target.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
		}
	} else if err := validateWindowsAgentStateRollbackPair(*state.Active, target); err != nil {
		return WindowsInstallState{}, err
	}
	next := cloneWindowsInstallState(state)
	if next.Active != nil && *next.Active == target {
		return next, nil
	}
	next.Previous = cloneAuthenticatedWindowsRelease(next.Active)
	next.Active = &target
	return next, next.Validate()
}

func (state WindowsInstallState) RollbackPrevious() (WindowsInstallState, error) {
	if err := state.Validate(); err != nil {
		return WindowsInstallState{}, err
	}
	if state.Active == nil || state.Previous == nil {
		return WindowsInstallState{}, errors.New("Windows rollback requires active and previous releases")
	}
	if state.Previous.BundleSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return WindowsInstallState{}, errors.New("Windows rollback target cannot process the persisted security floor")
	}
	if err := validateWindowsAgentStateRollbackPair(*state.Active, *state.Previous); err != nil {
		return WindowsInstallState{}, err
	}
	next := cloneWindowsInstallState(state)
	next.Active, next.Previous = next.Previous, next.Active
	return next, next.Validate()
}

// DeactivateRuntime clears only the active and previous runtime selections. It
// deliberately preserves the authenticated high-water authority, compiled
// bootstrap binding, channel, and architecture so uninstall cannot reset
// anti-rollback state. Repeating an already-deactivated transition is
// idempotent.
func (state WindowsInstallState) DeactivateRuntime() (WindowsInstallState, error) {
	if err := state.Validate(); err != nil {
		return WindowsInstallState{}, err
	}
	next := cloneWindowsInstallState(state)
	next.Active = nil
	next.Previous = nil
	return next, next.Validate()
}

func validateWindowsAgentStateRollbackPair(source, target AuthenticatedWindowsRelease) error {
	if target.AgentStateReadMin > source.AgentStateWriteVersion || target.AgentStateReadMax < source.AgentStateWriteVersion {
		return fmt.Errorf("Windows target cannot read source agent-state schema %d", source.AgentStateWriteVersion)
	}
	if source.AgentStateReadMin > target.AgentStateWriteVersion || source.AgentStateReadMax < target.AgentStateWriteVersion {
		return fmt.Errorf("Windows source cannot read target agent-state schema %d for rollback", target.AgentStateWriteVersion)
	}
	return nil
}

func compareWindowsReleasePosition(left, right AuthenticatedWindowsRelease) int {
	if left.ReleaseEpoch < right.ReleaseEpoch {
		return -1
	}
	if left.ReleaseEpoch > right.ReleaseEpoch {
		return 1
	}
	if left.Sequence < right.Sequence {
		return -1
	}
	if left.Sequence > right.Sequence {
		return 1
	}
	return 0
}

func cloneWindowsInstallState(state WindowsInstallState) WindowsInstallState {
	copy := state
	copy.Active = cloneAuthenticatedWindowsRelease(state.Active)
	copy.Previous = cloneAuthenticatedWindowsRelease(state.Previous)
	return copy
}

func cloneAuthenticatedWindowsRelease(identity *AuthenticatedWindowsRelease) *AuthenticatedWindowsRelease {
	if identity == nil {
		return nil
	}
	copy := *identity
	return &copy
}

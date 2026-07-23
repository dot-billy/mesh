package windowsinstall

import (
	"reflect"
	"strings"
	"testing"

	"mesh/internal/agentstate"
)

func TestWindowsHighWaterRejectsRollbackEquivocationAndFloorDecrease(t *testing.T) {
	accepted := validAuthenticatedWindowsRelease(1, 10, 2, "a", "b")
	state := validWindowsInstallState(accepted)
	for name, candidate := range map[string]AuthenticatedWindowsRelease{
		"lower sequence":     validAuthenticatedWindowsRelease(1, 9, 2, "c", "d"),
		"same equivocation":  validAuthenticatedWindowsRelease(1, 10, 2, "1", "2"),
		"lower floor":        validAuthenticatedWindowsRelease(1, 11, 1, "3", "4"),
		"older trusted root": validAuthenticatedWindowsRelease(1, 11, 2, "5", "6"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "older trusted root" {
				candidate.TrustedRootVersion = 1
				candidate.TrustedRootSHA256 = strings.Repeat("7", 64)
			}
			if err := state.CheckCandidate(candidate); err == nil {
				t.Fatal("unauthorized Windows candidate was accepted")
			}
		})
	}
	if err := state.CheckCandidate(accepted); err != nil {
		t.Fatalf("exact Windows retry rejected: %v", err)
	}
	nextEpoch := validAuthenticatedWindowsRelease(2, 1, 2, "8", "9")
	nextEpoch.TrustedRootVersion = 3
	nextEpoch.TrustedRootSHA256 = strings.Repeat("e", 64)
	if err := state.CheckCandidate(nextEpoch); err != nil {
		t.Fatalf("authorized epoch reset rejected: %v", err)
	}
}

func TestWindowsHighWaterActivationAndRollback(t *testing.T) {
	active := validAuthenticatedWindowsRelease(1, 9, 1, "1", "2")
	active.BundleSecurityFloor = 2
	candidate := validAuthenticatedWindowsRelease(1, 10, 2, "3", "4")
	state := validWindowsInstallState(active)
	state.Active = &active
	advanced, err := state.AdvanceHighWater(candidate)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := advanced.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if activated.HighWater != candidate || activated.Active == nil || *activated.Active != candidate || activated.Previous == nil || *activated.Previous != active {
		t.Fatalf("Windows activation state = %+v", activated)
	}
	rolledBack, err := activated.RollbackPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.HighWater != candidate || rolledBack.Active == nil || *rolledBack.Active != active || rolledBack.Previous == nil || *rolledBack.Previous != candidate {
		t.Fatalf("Windows rollback state = %+v", rolledBack)
	}
}

func TestWindowsRuntimeDeactivationPreservesAuthorityAndIsIdempotent(t *testing.T) {
	active := validAuthenticatedWindowsRelease(2, 7, 4, "a", "b")
	previous := validAuthenticatedWindowsRelease(2, 6, 4, "c", "d")
	state := validWindowsInstallState(active)
	state.Active = &active
	state.Previous = &previous
	deactivated, err := state.DeactivateRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if deactivated.Active != nil || deactivated.Previous != nil || deactivated.HighWater != state.HighWater ||
		deactivated.BootstrapTrustSHA256 != state.BootstrapTrustSHA256 || deactivated.Channel != state.Channel || deactivated.Arch != state.Arch {
		t.Fatalf("deactivated state changed authority: %+v", deactivated)
	}
	replayed, err := deactivated.DeactivateRuntime()
	if err != nil || !reflect.DeepEqual(replayed, deactivated) {
		t.Fatalf("deactivation replay = %+v, %v", replayed, err)
	}
	invalid := deactivated
	invalid.Previous = &previous
	if err := invalid.Validate(); err == nil {
		t.Fatal("previous release without active release accepted")
	}
}

func TestWindowsActivationRequiresBidirectionalAgentStateCompatibility(t *testing.T) {
	active := validAuthenticatedWindowsRelease(1, 9, 1, "1", "2")
	target := validAuthenticatedWindowsRelease(1, 10, 1, "3", "4")
	target.AgentStateWriteVersion = active.AgentStateWriteVersion + 1
	target.AgentStateReadMax = target.AgentStateWriteVersion
	state := validWindowsInstallState(target)
	state.Active = &active
	if _, err := state.ActivateAccepted(); err == nil || !strings.Contains(err.Error(), "source cannot read target") {
		t.Fatalf("irreversible Windows activation accepted: %v", err)
	}
	active.AgentStateReadMax = target.AgentStateWriteVersion
	state.Active = &active
	if _, err := state.ActivateAccepted(); err != nil {
		t.Fatalf("reversible Windows activation rejected: %v", err)
	}
}

func validWindowsInstallState(highWater AuthenticatedWindowsRelease) WindowsInstallState {
	return WindowsInstallState{
		Schema: WindowsInstallStateSchema, BootstrapTrustSHA256: highWater.InstallerBootstrapRootSHA256,
		Channel: "stable", Arch: highWater.Arch, HighWater: highWater,
	}
}

func validAuthenticatedWindowsRelease(epoch, sequence, floor uint64, releaseDigit, artifactDigit string) AuthenticatedWindowsRelease {
	identity := AuthenticatedWindowsRelease{
		ReleaseEpoch: epoch, Sequence: sequence, TrustedRootVersion: 2,
		TrustedRootSHA256: strings.Repeat("a", 64), InstallerBootstrapRootSHA256: strings.Repeat("b", 64),
		ChannelManifestSHA256: strings.Repeat("c", 64), ReleaseManifestSHA256: strings.Repeat(releaseDigit, 64),
		ArtifactSHA256: strings.Repeat(artifactDigit, 64), PackageJSONSHA256: strings.Repeat("d", 64),
		Version: "1.2.3", MinimumSecurityFloor: floor, BundleSecurityFloor: floor,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion, Channel: "stable", Arch: "amd64", VerifiedAt: "2026-07-21T20:00:00Z",
	}
	identity.InstalledID = WindowsInstalledID(identity)
	return identity
}

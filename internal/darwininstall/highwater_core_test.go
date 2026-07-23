package darwininstall

import (
	"strings"
	"testing"

	"mesh/internal/agentstate"
)

func TestDarwinHighWaterRejectsRollbackEquivocationAndFloorDecrease(t *testing.T) {
	accepted := validAuthenticatedDarwinRelease(1, 10, 2, "a", "b")
	state := validDarwinInstallState(accepted)
	for name, candidate := range map[string]AuthenticatedDarwinRelease{
		"lower sequence":     validAuthenticatedDarwinRelease(1, 9, 2, "c", "d"),
		"lower epoch":        validAuthenticatedDarwinRelease(0, 20, 2, "e", "f"),
		"same equivocation":  validAuthenticatedDarwinRelease(1, 10, 2, "1", "2"),
		"lower floor":        validAuthenticatedDarwinRelease(1, 11, 1, "3", "4"),
		"older trusted root": validAuthenticatedDarwinRelease(1, 11, 2, "5", "6"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "older trusted root" {
				candidate.TrustedRootVersion = 1
				candidate.TrustedRootSHA256 = strings.Repeat("7", 64)
			}
			if err := state.CheckCandidate(candidate); err == nil {
				t.Fatal("unauthorized Darwin candidate was accepted")
			}
		})
	}
	if err := state.CheckCandidate(accepted); err != nil {
		t.Fatalf("exact Darwin retry rejected: %v", err)
	}
	nextEpoch := validAuthenticatedDarwinRelease(2, 1, 2, "8", "9")
	nextEpoch.TrustedRootVersion = 3
	nextEpoch.TrustedRootSHA256 = strings.Repeat("e", 64)
	if err := state.CheckCandidate(nextEpoch); err != nil {
		t.Fatalf("authorized epoch reset rejected: %v", err)
	}
}

func TestDarwinHighWaterAdvancePreservesActiveUntilActivation(t *testing.T) {
	active := validAuthenticatedDarwinRelease(1, 9, 1, "1", "2")
	candidate := validAuthenticatedDarwinRelease(1, 10, 2, "3", "4")
	state := validDarwinInstallState(active)
	state.Active = &active
	advanced, err := state.AdvanceHighWater(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if advanced.HighWater != candidate || advanced.Active == nil || *advanced.Active != active || advanced.Previous != nil {
		t.Fatalf("high-water advance changed active releases: %+v", advanced)
	}
	activated, err := advanced.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if activated.HighWater != candidate || activated.Active == nil || *activated.Active != candidate || activated.Previous == nil || *activated.Previous != active {
		t.Fatalf("Darwin activation state = %+v", activated)
	}
}

func TestDarwinRollbackSwapsOnlyRecordedReversiblePrevious(t *testing.T) {
	previous := validAuthenticatedDarwinRelease(1, 9, 1, "1", "2")
	previous.BundleSecurityFloor = 2
	active := validAuthenticatedDarwinRelease(1, 10, 2, "3", "4")
	state := validDarwinInstallState(active)
	state.Active, state.Previous = &active, &previous
	rolledBack, err := state.RollbackPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.HighWater != active || rolledBack.Active == nil || *rolledBack.Active != previous || rolledBack.Previous == nil || *rolledBack.Previous != active {
		t.Fatalf("Darwin rollback state = %+v", rolledBack)
	}
	incompatible := state
	incompatible.Previous = cloneAuthenticatedDarwinRelease(state.Previous)
	incompatible.Previous.BundleSecurityFloor = 1
	incompatible.HighWater.MinimumSecurityFloor = 2
	if _, err := incompatible.RollbackPrevious(); err == nil || !strings.Contains(err.Error(), "persisted security floor") {
		t.Fatalf("incapable rollback target accepted: %v", err)
	}
}

func TestDarwinActivationRequiresBidirectionalAgentStateCompatibility(t *testing.T) {
	active := validAuthenticatedDarwinRelease(1, 9, 1, "1", "2")
	target := validAuthenticatedDarwinRelease(1, 10, 1, "3", "4")
	target.AgentStateWriteVersion = active.AgentStateWriteVersion + 1
	target.AgentStateReadMax = target.AgentStateWriteVersion
	state := validDarwinInstallState(target)
	state.Active = &active
	if _, err := state.ActivateAccepted(); err == nil || !strings.Contains(err.Error(), "source cannot read target") {
		t.Fatalf("irreversible Darwin activation accepted: %v", err)
	}
	active.AgentStateReadMax = target.AgentStateWriteVersion
	state.Active = &active
	if _, err := state.ActivateAccepted(); err != nil {
		t.Fatalf("reversible Darwin activation rejected: %v", err)
	}
}

func validDarwinInstallState(highWater AuthenticatedDarwinRelease) DarwinInstallState {
	return DarwinInstallState{
		Schema: DarwinInstallStateSchema, BootstrapTrustSHA256: highWater.InstallerBootstrapRootSHA256,
		Channel: "stable", Arch: highWater.Arch, HighWater: highWater,
	}
}

func validAuthenticatedDarwinRelease(epoch, sequence, floor uint64, releaseDigit, artifactDigit string) AuthenticatedDarwinRelease {
	identity := AuthenticatedDarwinRelease{
		ReleaseEpoch: epoch, Sequence: sequence, TrustedRootVersion: 2,
		TrustedRootSHA256: strings.Repeat("a", 64), InstallerBootstrapRootSHA256: strings.Repeat("b", 64),
		ChannelManifestSHA256: strings.Repeat("c", 64), ReleaseManifestSHA256: strings.Repeat(releaseDigit, 64),
		ArtifactSHA256: strings.Repeat(artifactDigit, 64), PackageJSONSHA256: strings.Repeat("d", 64),
		Version:              "1.2.3",
		MinimumSecurityFloor: floor, BundleSecurityFloor: floor,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion, Channel: "stable", Arch: "amd64", VerifiedAt: "2026-07-21T20:00:00Z",
	}
	identity.InstalledID = DarwinInstalledID(identity)
	return identity
}

//go:build linux

package linuxinstall

import (
	"strings"
	"testing"

	"mesh/internal/agentstate"
)

func TestStateCandidateHighWaterRules(t *testing.T) {
	accepted := testRelease(10, "a", "b", 2)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: accepted, Active: releasePointer(testRelease(9, "c", "d", 1)),
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	exact := accepted
	exact.VerifiedAt = "2026-07-20T00:00:00Z"
	if err := state.CheckCandidate(exact); err != nil {
		t.Fatalf("exact same-sequence retry rejected: %v", err)
	}
	equivocation := exact
	equivocation.ArtifactSHA256 = strings.Repeat("e", 64)
	equivocation.InstalledID = InstalledID(equivocation)
	if err := state.CheckCandidate(equivocation); err == nil {
		t.Fatal("same-sequence equivocation accepted")
	}
	rangeEquivocation := exact
	rangeEquivocation.AgentStateReadMax++
	if err := state.CheckCandidate(rangeEquivocation); err == nil {
		t.Fatal("same-sequence agent-state read-range equivocation accepted")
	}
	writeEquivocation := exact
	writeEquivocation.AgentStateReadMax++
	writeEquivocation.AgentStateWriteVersion++
	if err := state.CheckCandidate(writeEquivocation); err == nil {
		t.Fatal("same-sequence agent-state write-version equivocation accepted")
	}
	lower := testRelease(9, "1", "2", 2)
	if err := state.CheckCandidate(lower); err == nil {
		t.Fatal("lower sequence accepted")
	}
	higher := testRelease(11, "3", "4", 2)
	if err := state.CheckCandidate(higher); err != nil {
		t.Fatalf("higher sequence rejected: %v", err)
	}
	downgradedFloor := testRelease(11, "5", "6", 1)
	if err := state.CheckCandidate(downgradedFloor); err == nil {
		t.Fatal("security-floor downgrade accepted")
	}
}

func TestStatePendingMustBindHighWaterAndActive(t *testing.T) {
	active := testRelease(4, "1", "2", 1)
	previous := testRelease(3, "5", "6", 1)
	candidate := testRelease(5, "3", "4", 1)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("a", 64), Channel: "stable",
		HighWater: candidate, Active: &active, Previous: &previous,
		Pending: &PendingTransaction{
			Operation: OperationActivate, Candidate: candidate, SourceActive: &active, SourcePrevious: &previous,
			TargetActive: candidate, Phase: PhasePrepared,
			AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true, StartedAt: "2026-07-19T12:00:00Z",
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	state.Pending.Candidate.ArtifactSHA256 = strings.Repeat("9", 64)
	state.Pending.Candidate.InstalledID = InstalledID(state.Pending.Candidate)
	if err := state.Validate(); err == nil {
		t.Fatal("pending candidate not bound to high-water release")
	}
}

func TestStatePendingOperationInvariants(t *testing.T) {
	active := testRelease(7, "1", "2", 1)
	previous := testRelease(6, "3", "4", 1)
	candidate := testRelease(8, "5", "6", 2)
	base := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("a", 64), Channel: "stable",
		HighWater: candidate, Active: &active, Previous: &previous,
	}
	activate := base
	activate.Pending = &PendingTransaction{
		Operation: OperationActivate, Candidate: candidate, SourceActive: &active, SourcePrevious: &previous,
		TargetActive: candidate, Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
	}
	if err := activate.Validate(); err != nil {
		t.Fatalf("valid activate transaction rejected: %v", err)
	}
	wrongActivateTarget := activate
	wrongActivateTarget.Pending = clonePendingForStateTest(activate.Pending)
	wrongActivateTarget.Pending.TargetActive = previous
	if err := wrongActivateTarget.Validate(); err == nil {
		t.Fatal("activate transaction with a different target accepted")
	}

	rollbackState := base
	rollbackState.HighWater = active
	rollbackState.Pending = &PendingTransaction{
		Operation: OperationRollback, Candidate: active, SourceActive: &active, SourcePrevious: &previous,
		TargetActive: previous, Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
	}
	if err := rollbackState.Validate(); err != nil {
		t.Fatalf("valid rollback transaction rejected: %v", err)
	}
	missingPrevious := rollbackState
	missingPrevious.Previous = nil
	missingPrevious.Pending = clonePendingForStateTest(rollbackState.Pending)
	missingPrevious.Pending.SourcePrevious = nil
	if err := missingPrevious.Validate(); err == nil {
		t.Fatal("rollback transaction without a previous release accepted")
	}
	wrongSource := rollbackState
	wrongSource.Pending = clonePendingForStateTest(rollbackState.Pending)
	other := testRelease(5, "7", "8", 1)
	wrongSource.Pending.SourcePrevious = &other
	if err := wrongSource.Validate(); err == nil {
		t.Fatal("rollback transaction with a changed source snapshot accepted")
	}
}

func TestPendingRejectsNebulaWithoutLifecycleAgent(t *testing.T) {
	pending := PendingTransaction{
		Operation:       OperationActivate,
		Candidate:       testRelease(10, "a", "b", 2),
		TargetActive:    testRelease(10, "a", "b", 2),
		Phase:           PhasePrepared,
		NebulaWasActive: true,
		StartedAt:       "2026-07-19T12:00:00Z",
	}
	if err := pending.Validate(); err == nil || !strings.Contains(err.Error(), "without an active lifecycle agent") {
		t.Fatalf("invalid runtime intent accepted: %v", err)
	}
}

func TestPendingRejectsActiveRuntimeWithClosedGate(t *testing.T) {
	pending := PendingTransaction{
		Operation:      OperationActivate,
		Candidate:      testRelease(10, "a", "b", 2),
		TargetActive:   testRelease(10, "a", "b", 2),
		Phase:          PhasePrepared,
		AgentWasActive: true,
		StartedAt:      "2026-07-19T12:00:00Z",
	}
	if err := pending.Validate(); err == nil || !strings.Contains(err.Error(), "runtime gate closed") {
		t.Fatalf("active runtime with closed gate accepted: %v", err)
	}
}

func TestStateRejectsRollbackTargetBelowPersistedSecurityFloor(t *testing.T) {
	active := testRelease(7, "6", "7", 1)
	previous := testRelease(6, "8", "9", 1)
	previous.BundleSecurityFloor = 1
	previous.InstalledID = InstalledID(previous)
	highWater := testRelease(8, "a", "b", 2)
	highWater.BundleSecurityFloor = 2
	highWater.InstalledID = InstalledID(highWater)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: highWater, Active: &active, Previous: &previous,
	}
	state.Pending = &PendingTransaction{
		Operation: OperationRollback, Candidate: highWater,
		SourceActive: &active, SourcePrevious: &previous, TargetActive: previous,
		Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
	}
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "persisted installer security floor") {
		t.Fatalf("rollback to an incapable bundle was accepted: %v", err)
	}
}

func TestStateRequiresBidirectionallyReversibleAgentStateSchemas(t *testing.T) {
	makeActivation := func(source, target ReleaseIdentity) State {
		return State{
			Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
			HighWater: target, Active: &source,
			Pending: &PendingTransaction{
				Operation: OperationActivate, Candidate: target, SourceActive: &source,
				TargetActive: target, Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
			},
		}
	}

	source := testRelease(7, "6", "7", 1)
	target := testRelease(8, "a", "b", 1)
	if err := makeActivation(source, target).Validate(); err != nil {
		t.Fatalf("same-schema activation rejected: %v", err)
	}

	// A reversible writer advance is accepted only when the old release can
	// read the new writer and the new release can read the old writer.
	source.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
	target.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
	target.AgentStateWriteVersion = agentstate.CurrentWriteVersion + 1
	if err := makeActivation(source, target).Validate(); err != nil {
		t.Fatalf("bidirectionally readable writer advance rejected: %v", err)
	}

	oldCannotRollback := source
	oldCannotRollback.AgentStateReadMax = agentstate.CurrentSchemaVersion
	if err := makeActivation(oldCannotRollback, target).Validate(); err == nil || !strings.Contains(err.Error(), "source cannot read target") {
		t.Fatalf("irreversible target writer advance accepted: %v", err)
	}

	newCannotReadOld := testRelease(8, "c", "d", 1)
	oldWriter := testRelease(7, "e", "1", 1)
	oldWriter.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
	oldWriter.AgentStateWriteVersion = agentstate.CurrentWriteVersion + 1
	if err := makeActivation(oldWriter, newCannotReadOld).Validate(); err == nil || !strings.Contains(err.Error(), "target cannot read source") {
		t.Fatalf("target unable to read source writer accepted: %v", err)
	}
}

func TestStateFirstActivationMustWriteCurrentAgentStateSchema(t *testing.T) {
	target := testRelease(1, "a", "b", 1)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: target,
		Pending: &PendingTransaction{
			Operation: OperationActivate, Candidate: target, TargetActive: target,
			Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("current-schema first activation rejected: %v", err)
	}
	target.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
	target.AgentStateWriteVersion = agentstate.CurrentWriteVersion + 1
	state.HighWater = target
	state.Pending.Candidate = target
	state.Pending.TargetActive = target
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "first activation target writes") {
		t.Fatalf("noncurrent first-activation writer accepted: %v", err)
	}
}

func TestStateRejectsSameSequenceEquivocationAndPendingSupersession(t *testing.T) {
	high := testRelease(8, "a", "b", 2)
	equivocated := testRelease(8, "c", "d", 2)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: high, Active: &equivocated,
	}
	if err := state.Validate(); err == nil {
		t.Fatal("same-sequence active equivocation accepted")
	}
	state.Active = nil
	state.Pending = &PendingTransaction{
		Operation: OperationActivate, Candidate: high, TargetActive: high,
		Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := state.CheckCandidate(testRelease(9, "e", "1", 2)); err == nil {
		t.Fatal("unfinished transaction was superseded")
	}
}

func TestInstalledIDBindsSequenceAndDigests(t *testing.T) {
	identity := testRelease(42, "a", "b", 1)
	want := "s00000000000000000042-r" + strings.Repeat("a", 16) + "-a" + strings.Repeat("b", 16)
	if identity.InstalledID != want {
		t.Fatalf("installed ID = %q, want %q", identity.InstalledID, want)
	}
	identity.InstalledID += "-other"
	if err := identity.Validate(); err == nil {
		t.Fatal("mismatched installed ID accepted")
	}
}

func TestReleaseIdentityRejectsNoncanonicalSemVer(t *testing.T) {
	for _, version := range []string{"1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3+", "1.2.3+bad value"} {
		identity := testRelease(1, "a", "b", 1)
		identity.Version = version
		if err := identity.Validate(); err == nil {
			t.Fatalf("noncanonical version %q accepted", version)
		}
	}
}

func TestReleaseIdentityRejectsInvalidAgentStateCompatibility(t *testing.T) {
	for name, mutate := range map[string]func(*ReleaseIdentity){
		"zero minimum": func(identity *ReleaseIdentity) { identity.AgentStateReadMin = 0 },
		"zero maximum": func(identity *ReleaseIdentity) { identity.AgentStateReadMax = 0 },
		"zero writer":  func(identity *ReleaseIdentity) { identity.AgentStateWriteVersion = 0 },
		"inverted": func(identity *ReleaseIdentity) {
			identity.AgentStateReadMin = 3
			identity.AgentStateReadMax = 2
		},
		"writer below range": func(identity *ReleaseIdentity) {
			identity.AgentStateReadMin = 2
			identity.AgentStateWriteVersion = 1
		},
		"writer above range": func(identity *ReleaseIdentity) {
			identity.AgentStateReadMax = 2
			identity.AgentStateWriteVersion = 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			identity := testRelease(1, "a", "b", 1)
			mutate(&identity)
			if err := identity.Validate(); err == nil || !strings.Contains(err.Error(), "agent-state read range") {
				t.Fatalf("invalid agent-state read range accepted: %v", err)
			}
		})
	}
}

func TestSameAuthenticatedReleaseBindsAgentStateCompatibility(t *testing.T) {
	accepted := testRelease(1, "a", "b", 1)
	changed := accepted
	changed.AgentStateReadMax++
	if sameAuthenticatedRelease(accepted, changed) {
		t.Fatal("agent-state read-range change accepted as the same authenticated release")
	}
	changed = accepted
	changed.AgentStateWriteVersion++
	changed.AgentStateReadMax++
	if sameAuthenticatedRelease(accepted, changed) {
		t.Fatal("agent-state write-version change accepted as the same authenticated release")
	}
}

func testRelease(sequence uint64, releaseDigit, artifactDigit string, floor uint64) ReleaseIdentity {
	identity := ReleaseIdentity{
		Sequence:              sequence,
		ChannelManifestSHA256: strings.Repeat("c", 64),
		ReleaseManifestSHA256: strings.Repeat(releaseDigit, 64),
		ArtifactSHA256:        strings.Repeat(artifactDigit, 64),
		BundleManifestSHA256:  strings.Repeat("d", 64),
		Version:               "1.2.3", MinimumSecurityFloor: floor, BundleSecurityFloor: 7,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
		VerifiedAt:             "2026-07-19T12:00:00Z",
	}
	identity.InstalledID = InstalledID(identity)
	return identity
}

func releasePointer(identity ReleaseIdentity) *ReleaseIdentity { return &identity }

func clonePendingForStateTest(pending *PendingTransaction) *PendingTransaction {
	if pending == nil {
		return nil
	}
	clone := *pending
	clone.SourceActive = releasePointerCopy(pending.SourceActive)
	clone.SourcePrevious = releasePointerCopy(pending.SourcePrevious)
	return &clone
}

func releasePointerCopy(identity *ReleaseIdentity) *ReleaseIdentity {
	if identity == nil {
		return nil
	}
	clone := *identity
	return &clone
}

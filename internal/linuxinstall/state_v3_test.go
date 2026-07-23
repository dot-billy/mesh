//go:build linux

package linuxinstall

import (
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

func TestStateV3BindsReleaseEpochAndTrustedRoot(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	high := testRootedRelease(2, 7, 4, bootstrap.InitialRootSHA256, "a", "b", 2)
	active := testRootedRelease(1, 99, 1, bootstrap.InitialRootSHA256, "c", "d", 1)
	state := State{
		Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256, Channel: "stable",
		HighWater: high, Active: &active,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid v3 state rejected: %v", err)
	}

	for name, mutate := range map[string]func(*ReleaseIdentity){
		"zero epoch":                func(identity *ReleaseIdentity) { identity.ReleaseEpoch = 0 },
		"zero root version":         func(identity *ReleaseIdentity) { identity.TrustedRootVersion = 0 },
		"bad root digest":           func(identity *ReleaseIdentity) { identity.TrustedRootSHA256 = "bad" },
		"bad bootstrap root digest": func(identity *ReleaseIdentity) { identity.InstallerBootstrapRootSHA256 = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := state
			candidate.HighWater = high
			mutate(&candidate.HighWater)
			candidate.HighWater.InstalledID = InstalledID(candidate.HighWater)
			if err := candidate.Validate(); err == nil {
				t.Fatal("incomplete root binding accepted")
			}
		})
	}

	legacy := state
	legacy.TrustPolicySHA256 = strings.Repeat("f", 64)
	if err := legacy.Validate(); err == nil {
		t.Fatal("v3 state carrying a legacy trust-policy digest accepted")
	}
}

func TestStateV3UsesLexicographicEpochSequenceHighWater(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	accepted := testRootedRelease(2, 50, 4, bootstrap.InitialRootSHA256, "a", "b", 2)
	state := State{
		Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256, Channel: "stable",
		HighWater: accepted, Active: &accepted,
	}

	if err := state.CheckCandidate(testRootedRelease(1, 5000, 1, bootstrap.InitialRootSHA256, "c", "d", 2)); err == nil {
		t.Fatal("lower epoch with a larger sequence accepted")
	}
	if err := state.CheckCandidate(testRootedRelease(2, 49, 4, bootstrap.InitialRootSHA256, "c", "d", 2)); err == nil {
		t.Fatal("lower sequence in the current epoch accepted")
	}
	reset := testRootedRelease(3, 1, 5, strings.Repeat("e", 64), "c", "d", 2)
	if err := state.CheckCandidate(reset); err != nil {
		t.Fatalf("next-epoch sequence reset rejected: %v", err)
	}

	exact := accepted
	if err := state.CheckCandidate(exact); err != nil {
		t.Fatalf("exact v3 retry rejected: %v", err)
	}
	changedTime := accepted
	changedTime.VerifiedAt = "2026-07-20T00:00:00Z"
	if err := state.CheckCandidate(changedTime); err == nil {
		t.Fatal("same-position retry with a different trust-decision time accepted")
	}
	changedRoot := accepted
	changedRoot.TrustedRootVersion++
	changedRoot.TrustedRootSHA256 = strings.Repeat("e", 64)
	changedRoot.InstalledID = InstalledID(changedRoot)
	if err := state.CheckCandidate(changedRoot); err == nil {
		t.Fatal("same-position retry rebound to a different root")
	}
}

func TestStateV3ValidatesActivePreviousAndPendingPositions(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	high := testRootedRelease(2, 2, 3, strings.Repeat("e", 64), "a", "b", 2)
	active := testRootedRelease(2, 1, 3, strings.Repeat("e", 64), "c", "d", 2)
	previous := testRootedRelease(1, 99, 1, bootstrap.InitialRootSHA256, "e", "f", 1)
	state := State{
		Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256, Channel: "stable",
		HighWater: high, Active: &active, Previous: &previous,
		Pending: &PendingTransaction{
			Operation: OperationActivate, Candidate: high, SourceActive: &active, SourcePrevious: &previous,
			TargetActive: high, Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid cross-epoch pending state rejected: %v", err)
	}

	badActive := state
	badActive.Pending = nil
	future := testRootedRelease(3, 1, 4, strings.Repeat("9", 64), "1", "2", 2)
	badActive.Active = &future
	if err := badActive.Validate(); err == nil {
		t.Fatal("active release ahead of high-water accepted")
	}

	badPending := state
	badPending.Pending = clonePendingForStateTest(state.Pending)
	badPending.Pending.SourcePrevious = releasePointer(testRootedRelease(3, 1, 4, strings.Repeat("9", 64), "3", "4", 2))
	if err := badPending.Validate(); err == nil {
		t.Fatal("pending source ahead of its candidate accepted")
	}
}

func TestMigrateStateV2ToV3RequiresExactBootstrapAndEmptyHistory(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	high := testRelease(7, "a", "b", 2)
	active := testRelease(6, "c", "d", 1)
	previous := testRelease(5, "e", "f", 1)
	legacy := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: bootstrap.LegacyPolicySHA256, Channel: "stable",
		HighWater: high, Active: &active, Previous: &previous,
	}

	migrated, err := MigrateStateV2(legacy, bootstrap, true)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != StateSchemaV3 || migrated.TrustPolicySHA256 != "" || migrated.BootstrapTrustSHA256 != bootstrap.SHA256 {
		t.Fatalf("unexpected migrated state header: %+v", migrated)
	}
	for label, identity := range map[string]ReleaseIdentity{
		"high-water": migrated.HighWater, "active": *migrated.Active, "previous": *migrated.Previous,
	} {
		if identity.ReleaseEpoch != 1 || identity.TrustedRootVersion != 1 || identity.TrustedRootSHA256 != bootstrap.InitialRootSHA256 ||
			identity.InstallerBootstrapRootSHA256 != bootstrap.InitialRootSHA256 {
			t.Fatalf("%s did not bind initial root: %+v", label, identity)
		}
		if identity.InstalledID != legacyInstalledID(identity) || !strings.HasPrefix(identity.InstalledID, "s") {
			t.Fatalf("%s legacy directory ID was not preserved: %q", label, identity.InstalledID)
		}
	}
	if err := migrated.Validate(); err != nil {
		t.Fatalf("migrated state is invalid: %v", err)
	}

	tests := map[string]func(State, installtrust.Bootstrap) (State, installtrust.Bootstrap, bool){
		"policy mismatch": func(state State, root installtrust.Bootstrap) (State, installtrust.Bootstrap, bool) {
			state.TrustPolicySHA256 = strings.Repeat("0", 64)
			return state, root, true
		},
		"preexisting history": func(state State, root installtrust.Bootstrap) (State, installtrust.Bootstrap, bool) {
			return state, root, false
		},
		"pending transaction": func(state State, root installtrust.Bootstrap) (State, installtrust.Bootstrap, bool) {
			state.Pending = &PendingTransaction{
				Operation: OperationActivate, Candidate: state.HighWater, SourceActive: state.Active, SourcePrevious: state.Previous,
				TargetActive: state.HighWater, Phase: PhasePrepared, StartedAt: "2026-07-19T12:00:00Z",
			}
			return state, root, true
		},
		"malformed v2": func(state State, root installtrust.Bootstrap) (State, installtrust.Bootstrap, bool) {
			state.Channel = "INVALID"
			return state, root, true
		},
		"wrong bootstrap version": func(state State, root installtrust.Bootstrap) (State, installtrust.Bootstrap, bool) {
			root.InitialRoot.Document.Version = 2
			return state, root, true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state, root, empty := mutate(deepCopyState(legacy), bootstrap)
			if _, err := MigrateStateV2(state, root, empty); err == nil {
				t.Fatal("unsafe state migration accepted")
			}
		})
	}
}

func TestMigratedExactCandidatePreservesPublishedLegacyDirectoryID(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	legacy := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: bootstrap.LegacyPolicySHA256, Channel: "stable",
		HighWater: testRelease(7, "a", "b", 2),
	}
	legacy.Active = releasePointer(legacy.HighWater)
	migrated, err := MigrateStateV2(legacy, bootstrap, true)
	if err != nil {
		t.Fatal(err)
	}
	candidate := CandidateMetadata{
		ReleaseEpoch: 1, Sequence: migrated.HighWater.Sequence,
		ChannelManifestSHA256: migrated.HighWater.ChannelManifestSHA256,
		ReleaseManifestSHA256: migrated.HighWater.ReleaseManifestSHA256,
		Artifact:              releasetrust.Artifact{SHA256: migrated.HighWater.ArtifactSHA256},
	}
	if got := migratedInstalledIDForExactCandidate(&migrated, candidate); got != legacy.HighWater.InstalledID {
		t.Fatalf("preserved installed ID = %q, want %q", got, legacy.HighWater.InstalledID)
	}
	candidate.Artifact.SHA256 = strings.Repeat("c", 64)
	if got := migratedInstalledIDForExactCandidate(&migrated, candidate); got != "" {
		t.Fatalf("different candidate reused legacy installed ID %q", got)
	}
}

func TestStoreLockPublishesV3MigrationAtomically(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	store := newTestStateStore(t)
	legacy := validState()
	legacy.TrustPolicySHA256 = bootstrap.LegacyPolicySHA256
	writeStateFile(t, store.Path(), legacy)

	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, found, err := lock.Load(); err != nil || !found {
		t.Fatalf("load legacy state: found=%v err=%v", found, err)
	}
	migrated, err := lock.MigrateV2(bootstrap, true)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != StateSchemaV3 {
		t.Fatalf("migration returned schema %q", migrated.Schema)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !sameStateExact(migrated, loaded) {
		t.Fatal("persisted migrated state differs from the committed state")
	}
}

func TestPrepareRootedActivationAndRollbackRetainExactTrustBindings(t *testing.T) {
	bootstrap := stateV3Bootstrap(t)
	first := testRootedRelease(1, 7, 1, bootstrap.InitialRootSHA256, "a", "b", 1)
	prepared, err := prepareRootedActivationState(nil, bootstrap, first, ServiceSnapshot{}, timeForStateV3Test())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Schema != StateSchemaV3 || prepared.BootstrapTrustSHA256 != bootstrap.SHA256 || prepared.Pending == nil || prepared.Pending.Candidate != first {
		t.Fatalf("unexpected first rooted transaction: %+v", prepared)
	}
	completed := prepared
	completed.Active = &first
	completed.Pending = nil
	if err := completed.Validate(); err != nil {
		t.Fatal(err)
	}

	second := testRootedRelease(2, 1, 2, strings.Repeat("e", 64), "c", "d", 2)
	secondPrepared, err := prepareRootedActivationState(&completed, bootstrap, second, ServiceSnapshot{}, timeForStateV3Test())
	if err != nil {
		t.Fatal(err)
	}
	if secondPrepared.Pending.SourceActive == nil || *secondPrepared.Pending.SourceActive != first || secondPrepared.HighWater != second {
		t.Fatalf("rooted activation did not retain its exact source: %+v", secondPrepared)
	}
	secondCompleted := secondPrepared
	secondCompleted.Active = &second
	secondCompleted.Previous = &first
	secondCompleted.Pending = nil
	rollback, err := prepareRollbackState(secondCompleted, ServiceSnapshot{}, timeForStateV3Test())
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Pending == nil || rollback.Pending.TargetActive != first || rollback.HighWater != second || rollback.Pending.Candidate != second {
		t.Fatalf("rollback lost exact rooted identities: %+v", rollback)
	}
}

func timeForStateV3Test() time.Time {
	return time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
}

func testRootedRelease(epoch, sequence, rootVersion uint64, rootDigest, releaseDigit, artifactDigit string, floor uint64) ReleaseIdentity {
	identity := testRelease(sequence, releaseDigit, artifactDigit, floor)
	identity.ReleaseEpoch = epoch
	identity.TrustedRootVersion = rootVersion
	identity.TrustedRootSHA256 = rootDigest
	identity.InstallerBootstrapRootSHA256 = strings.Repeat("8", 64)
	identity.InstalledID = InstalledID(identity)
	return identity
}

func stateV3Bootstrap(t *testing.T) installtrust.Bootstrap {
	t.Helper()
	files := make([]releasetrust.PublicKeyFile, 4)
	for index := range files {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		files[index], err = releasetrust.PublicKeyFileFromPrivate(privateKey)
		clear(privateKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(files, func(left, right int) bool { return files[left].KeyID < files[right].KeyID })
	root := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	raw, err := releasetrust.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrap, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: raw})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap
}

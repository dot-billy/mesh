//go:build linux

package linuxinstall

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

func TestRootAwareVerifierBindsV2CandidateAndInitialRootBridge(t *testing.T) {
	bootstrap, initial, releaseKeys := rootVerifierInitial(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	for name, legacy := range map[string]bool{"v2": false, "legacy v1 bridge": true} {
		t.Run(name, func(t *testing.T) {
			metadata := rootCandidateMetadata(t, initial, releaseKeys, 1, 4, now.Add(-time.Hour), now.Add(time.Hour), "a", legacy)
			candidate, err := verifySignedCandidateWithRoots(metadata, bootstrap, initial, initial, nil, now, 3)
			if err != nil {
				t.Fatal(err)
			}
			if candidate.ReleaseEpoch != 1 || candidate.TrustedRootVersion != 1 || candidate.TrustedRootSHA256 != initial.SHA256 {
				t.Fatalf("candidate lost root binding: %+v", candidate)
			}
			identity, err := candidate.releaseIdentity(strings.Repeat("b", 64), bootstrap.InitialRootSHA256, 3,
				agentstate.CurrentSchemaVersion, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion)
			if err != nil {
				t.Fatal(err)
			}
			if identity.ReleaseEpoch != 1 || identity.InstallerBootstrapRootSHA256 != bootstrap.InitialRootSHA256 ||
				!strings.HasPrefix(identity.InstalledID, "e00000000000000000001-s") {
				t.Fatalf("release identity is not root bound: %+v", identity)
			}
		})
	}
}

func TestRootAwareVerifierUsesLatestDelegationAndRejectsLegacyAfterRotation(t *testing.T) {
	bootstrap, initial, oldReleaseKeys := rootVerifierInitial(t)
	current, newReleaseKeys := rootVerifierSuccessor(t, initial, 2, 2, 1, 2)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	valid := rootCandidateMetadata(t, current, newReleaseKeys, 2, 1, now.Add(-time.Hour), now.Add(time.Hour), "a", false)
	candidate, err := verifySignedCandidateWithRoots(valid, bootstrap, current, current, nil, now, 3)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ReleaseEpoch != 2 || candidate.TrustedRootVersion != 2 {
		t.Fatalf("unexpected rotated candidate: %+v", candidate)
	}

	revoked := rootCandidateMetadata(t, current, oldReleaseKeys, 2, 2, now.Add(-time.Hour), now.Add(time.Hour), "b", false)
	if _, err := verifySignedCandidateWithRoots(revoked, bootstrap, current, current, nil, now, 3); err == nil {
		t.Fatal("release signed only by revoked keys was accepted")
	}
	legacy := rootCandidateMetadata(t, current, newReleaseKeys, 2, 2, now.Add(-time.Hour), now.Add(time.Hour), "b", true)
	if _, err := verifySignedCandidateWithRoots(legacy, bootstrap, current, current, nil, now, 3); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy metadata after root rotation returned %v", err)
	}
}

func TestRootAwarePrivilegedRecheckRejectsSignerRevokedDuringOnlineDownload(t *testing.T) {
	bootstrap, initial, oldReleaseKeys := rootVerifierInitial(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	downloaded := rootCandidateMetadata(t, initial, oldReleaseKeys, 1, 8, now.Add(-time.Hour), now.Add(time.Hour), "a", false)
	if _, err := verifySignedCandidateWithRoots(downloaded, bootstrap, initial, initial, nil, now, 3); err != nil {
		t.Fatalf("online preflight under root v1 failed: %v", err)
	}

	rotated, _ := rootVerifierSuccessor(t, initial, 2, 1, 1, 1)
	if _, err := verifySignedCandidateWithRoots(downloaded, bootstrap, rotated, rotated, nil, now, 3); err == nil {
		t.Fatal("privileged recheck accepted metadata signed only by a release key revoked during download")
	}
}

func TestRootAwareVerifierAllowsEpochResetButEnforcesRootFloors(t *testing.T) {
	bootstrap, initial, _ := rootVerifierInitial(t)
	current, releaseKeys := rootVerifierSuccessor(t, initial, 2, 2, 3, 2)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	accepted := testRootedRelease(1, 100, 1, initial.SHA256, "a", "b", 2)
	prior := State{
		Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256, Channel: "stable",
		HighWater: accepted, Active: &accepted,
	}

	reset := rootCandidateMetadata(t, current, releaseKeys, 2, 3, now.Add(-time.Hour), now.Add(time.Hour), "c", false)
	if _, err := verifySignedCandidateWithRoots(reset, bootstrap, current, current, &prior, now, 3); err != nil {
		t.Fatalf("new-epoch sequence reset rejected: %v", err)
	}
	belowRootSequence := rootCandidateMetadata(t, current, releaseKeys, 2, 2, now.Add(-time.Hour), now.Add(time.Hour), "d", false)
	if _, err := verifySignedCandidateWithRoots(belowRootSequence, bootstrap, current, current, &prior, now, 3); err == nil {
		t.Fatal("candidate below the new root sequence floor accepted")
	}
	belowRootFloor := rootCandidateMetadataWithFloor(t, current, releaseKeys, 2, 3, 1, now.Add(-time.Hour), now.Add(time.Hour), "e", false)
	if _, err := verifySignedCandidateWithRoots(belowRootFloor, bootstrap, current, current, &prior, now, 3); err == nil {
		t.Fatal("candidate below the root security floor accepted")
	}
}

func TestRootAwareVerifierResumesExactPendingDecisionUnderHistoricalRoot(t *testing.T) {
	bootstrap, initial, oldReleaseKeys := rootVerifierInitial(t)
	current, _ := rootVerifierSuccessor(t, initial, 2, 2, 1, 2)
	acceptedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	metadata := rootCandidateMetadata(t, initial, oldReleaseKeys, 1, 7, acceptedAt.Add(-time.Hour), acceptedAt.Add(time.Hour), "a", false)
	accepted, err := verifySignedCandidateWithRoots(metadata, bootstrap, initial, initial, nil, acceptedAt, 3)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := accepted.releaseIdentity(strings.Repeat("b", 64), bootstrap.InitialRootSHA256, 3,
		agentstate.CurrentSchemaVersion, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion)
	if err != nil {
		t.Fatal(err)
	}
	prior := State{
		Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256, Channel: "stable", HighWater: identity,
		Pending: &PendingTransaction{
			Operation: OperationActivate, Candidate: identity, TargetActive: identity,
			Phase: PhasePrepared, StartedAt: acceptedAt.Format(time.RFC3339),
		},
	}
	later := acceptedAt.Add(48 * time.Hour)
	resumed, err := verifySignedCandidateWithRoots(metadata, bootstrap, current, initial, &prior, later, 3)
	if err != nil {
		t.Fatalf("exact historical resume rejected: %v", err)
	}
	if resumed.VerifiedAt != identity.VerifiedAt || resumed.TrustedRootSHA256 != initial.SHA256 {
		t.Fatalf("resume changed the accepted trust decision: %+v", resumed)
	}

	withoutPending := prior
	withoutPending.Pending = nil
	withoutPending.Active = &withoutPending.HighWater
	if _, err := verifySignedCandidateWithRoots(metadata, bootstrap, current, initial, &withoutPending, later, 3); err == nil {
		t.Fatal("historical authority used without a pending transaction")
	}
}

func rootVerifierInitial(t *testing.T) (installtrust.Bootstrap, releasetrust.ParsedRoot, []ed25519.PrivateKey) {
	t.Helper()
	files, privateByID := rootVerifierKeys(t)
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T00:00:00Z", ExpiresAt: "2027-07-20T00:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrap, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: raw})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, parsed, []ed25519.PrivateKey{privateByID[files[2].KeyID], privateByID[files[3].KeyID]}
}

func rootVerifierSuccessor(t *testing.T, initial releasetrust.ParsedRoot, version, epoch, sequenceFloor, securityFloor uint64) (releasetrust.ParsedRoot, []ed25519.PrivateKey) {
	t.Helper()
	files, privateByID := rootVerifierKeys(t)
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: version, Channel: initial.Document.Channel, ReleaseEpoch: epoch,
		MinimumReleaseSequence: sequenceFloor, MinimumSecurityFloor: securityFloor,
		IssuedAt: "2026-07-22T00:00:00Z", ExpiresAt: "2027-07-20T00:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, []ed25519.PrivateKey{privateByID[files[2].KeyID], privateByID[files[3].KeyID]}
}

func rootVerifierKeys(t *testing.T) ([]releasetrust.PublicKeyFile, map[string]ed25519.PrivateKey) {
	t.Helper()
	files := make([]releasetrust.PublicKeyFile, 4)
	privateByID := make(map[string]ed25519.PrivateKey, 4)
	for index := range files {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		file, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			clear(privateKey)
			t.Fatal(err)
		}
		files[index] = file
		privateByID[file.KeyID] = privateKey
	}
	sort.Slice(files, func(left, right int) bool { return files[left].KeyID < files[right].KeyID })
	t.Cleanup(func() {
		for _, key := range privateByID {
			clear(key)
		}
	})
	return files, privateByID
}

func rootCandidateMetadata(t *testing.T, root releasetrust.ParsedRoot, keys []ed25519.PrivateKey, epoch, sequence uint64, issued, expires time.Time, digestDigit string, legacy bool) SignedMetadata {
	return rootCandidateMetadataWithFloor(t, root, keys, epoch, sequence, root.Document.MinimumSecurityFloor, issued, expires, digestDigit, legacy)
}

func rootCandidateMetadataWithFloor(t *testing.T, root releasetrust.ParsedRoot, keys []ed25519.PrivateKey, epoch, sequence, floor uint64, issued, expires time.Time, digestDigit string, legacy bool) SignedMetadata {
	t.Helper()
	releaseSchema, channelSchema := releasetrust.ReleaseSchemaV2, releasetrust.ChannelSchemaV2
	declaredEpoch := epoch
	if legacy {
		releaseSchema, channelSchema = releasetrust.ReleaseSchema, releasetrust.ChannelSchema
		declaredEpoch = 0
	}
	releaseDocument := releasetrust.ReleaseManifest{
		Schema: releaseSchema, Channel: root.Document.Channel, ReleaseEpoch: declaredEpoch,
		Version: "1.2.3", Sequence: sequence, MinimumSecurityFloor: floor,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		Artifacts: []releasetrust.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://releases.example.test/bundle.tar", Size: 1024, SHA256: strings.Repeat(digestDigit, 64)}},
	}
	releaseRaw, err := json.Marshal(releaseDocument)
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest := sha256.Sum256(releaseRaw)
	channelDocument := releasetrust.ChannelManifest{
		Schema: channelSchema, Channel: root.Document.Channel, ReleaseEpoch: declaredEpoch,
		Sequence: sequence, MinimumSecurityFloor: floor,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		Release: releasetrust.ReleaseReference{
			Version: "1.2.3", Sequence: sequence, ManifestURL: "https://releases.example.test/release.json",
			ManifestSize: int64(len(releaseRaw)), ManifestSHA256: hex.EncodeToString(releaseDigest[:]),
		},
	}
	channelRaw, err := json.Marshal(channelDocument)
	if err != nil {
		t.Fatal(err)
	}
	return SignedMetadata{
		ChannelManifest: channelRaw, ReleaseManifest: releaseRaw,
		ChannelSignatures: signCandidate(t, releasetrust.ChannelManifestKind, channelRaw, keys),
		ReleaseSignatures: signCandidate(t, releasetrust.ReleaseManifestKind, releaseRaw, keys),
	}
}

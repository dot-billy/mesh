//go:build linux

package linuxinstall

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

func TestVerifySignedCandidateAndExactExpiredResume(t *testing.T) {
	policy, privateKeys := candidateTrust(t)
	issued := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := candidateMetadata(t, policy, privateKeys, 5, issued, issued.Add(time.Hour), "a")
	verified, err := verifySignedCandidateWithPolicy(metadata, policy, nil, issued.Add(10*time.Minute), 3)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Sequence != 5 || verified.Version != "1.2.3" || len(verified.ChannelSignerKeyIDs) != 2 || len(verified.ReleaseSignerKeyIDs) != 2 {
		t.Fatalf("unexpected verified candidate: %+v", verified)
	}
	identity, err := verified.releaseIdentity(
		strings.Repeat("b", 64), "", 3,
		agentstate.CurrentSchemaVersion, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AgentStateReadMin != agentstate.CurrentSchemaVersion || identity.AgentStateReadMax != agentstate.CurrentSchemaVersion ||
		identity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		t.Fatalf("release identity lost bundle agent-state compatibility: %+v", identity)
	}
	if _, err := verified.releaseIdentity(strings.Repeat("b", 64), "", 3, 0, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion); err == nil {
		t.Fatal("release identity accepted an invalid bundle agent-state compatibility range")
	}
	state := State{Schema: LegacyStateSchema, TrustPolicySHA256: policy.SHA256, Channel: policy.Channel, HighWater: identity, Active: &identity}
	if _, err := verifySignedCandidateWithPolicy(metadata, policy, &state, issued.Add(24*time.Hour), 3); err != nil {
		t.Fatalf("exact fsynced candidate did not resume after expiry: %v", err)
	}

	equivocated := candidateMetadata(t, policy, privateKeys, 5, issued, issued.Add(48*time.Hour), "c")
	if _, err := verifySignedCandidateWithPolicy(equivocated, policy, &state, issued.Add(20*time.Minute), 3); err == nil {
		t.Fatal("same-sequence different release accepted")
	}
}

func TestVerifySignedCandidateRejectsPolicyDriftAndLowerSequence(t *testing.T) {
	policy, privateKeys := candidateTrust(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := candidateMetadata(t, policy, privateKeys, 4, now.Add(-time.Minute), now.Add(time.Hour), "a")
	accepted := testRelease(5, "d", "e", 1)
	state := State{Schema: LegacyStateSchema, TrustPolicySHA256: policy.SHA256, Channel: policy.Channel, HighWater: accepted, Active: &accepted}
	if _, err := verifySignedCandidateWithPolicy(metadata, policy, &state, now, 3); err == nil {
		t.Fatal("lower sequence accepted")
	}
	drifted := policy
	drifted.SHA256 = strings.Repeat("0", 64)
	if _, err := verifySignedCandidateWithPolicy(metadata, drifted, &state, now, 3); err == nil {
		t.Fatal("trust policy drift accepted")
	}
}

func TestVerifySignedCandidateProductionBoundaryFailsClosedWithoutCompiledTrust(t *testing.T) {
	if _, err := VerifySignedCandidate(SignedMetadata{}, nil); err == nil {
		t.Fatal("production verification accepted a development build without compiled trust")
	}
}

func TestVerifySignedCandidateRejectsZeroTimeOversizeAndPendingSupersession(t *testing.T) {
	policy, privateKeys := candidateTrust(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := candidateMetadata(t, policy, privateKeys, 5, now.Add(-time.Minute), now.Add(time.Hour), "a")
	if _, err := verifySignedCandidateWithPolicy(metadata, policy, nil, time.Time{}, 3); err == nil {
		t.Fatal("zero verification time accepted")
	}
	oversized := metadata
	oversized.ChannelManifest = make([]byte, releasetrust.MaxManifestSize+1)
	if _, err := verifySignedCandidateWithPolicy(oversized, policy, nil, now, 3); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	accepted, err := verifySignedCandidateWithPolicy(metadata, policy, nil, now, 3)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := accepted.releaseIdentity(
		strings.Repeat("b", 64), "", 3,
		agentstate.CurrentSchemaVersion, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: policy.SHA256, Channel: policy.Channel,
		HighWater: identity, Pending: &PendingTransaction{Candidate: identity, Phase: PhasePrepared, StartedAt: now.Format(time.RFC3339)},
	}
	other := candidateMetadata(t, policy, privateKeys, 6, now.Add(-time.Minute), now.Add(time.Hour), "c")
	if _, err := verifySignedCandidateWithPolicy(other, policy, &state, now, 3); err == nil {
		t.Fatal("different release superseded unfinished transaction")
	}
}

func candidateTrust(t *testing.T) (installtrust.Policy, []ed25519.PrivateKey) {
	t.Helper()
	policy := installtrust.Policy{
		Channel: "stable", SignatureThreshold: 2, MinimumSequence: 1, MinimumSecurityFloor: 1,
		SHA256: strings.Repeat("f", 64),
	}
	privateKeys := make([]ed25519.PrivateKey, 0, 2)
	for range 2 {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		privateKeys = append(privateKeys, privateKey)
		keyID, err := releasetrust.KeyID(privateKey.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		policy.TrustedKeys = append(policy.TrustedKeys, releasetrust.TrustedKey{KeyID: keyID, PublicKey: privateKey.Public().(ed25519.PublicKey)})
	}
	t.Cleanup(func() {
		for _, key := range privateKeys {
			clear(key)
		}
	})
	return policy, privateKeys
}

func candidateMetadata(t *testing.T, policy installtrust.Policy, privateKeys []ed25519.PrivateKey, sequence uint64, issued, expires time.Time, digestDigit string) SignedMetadata {
	t.Helper()
	artifactDigest := strings.Repeat(digestDigit, 64)
	releaseDocument := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchema, Channel: policy.Channel, Version: "1.2.3", Sequence: sequence,
		MinimumSecurityFloor: 1, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		Artifacts: []releasetrust.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://releases.example.test/bundle.tar", Size: 1024, SHA256: artifactDigest}},
	}
	releaseRaw, err := json.Marshal(releaseDocument)
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest := sha256.Sum256(releaseRaw)
	channelDocument := releasetrust.ChannelManifest{
		Schema: releasetrust.ChannelSchema, Channel: policy.Channel, Sequence: sequence,
		MinimumSecurityFloor: 1, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
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
		ChannelSignatures: signCandidate(t, releasetrust.ChannelManifestKind, channelRaw, privateKeys),
		ReleaseSignatures: signCandidate(t, releasetrust.ReleaseManifestKind, releaseRaw, privateKeys),
	}
}

func signCandidate(t *testing.T, kind releasetrust.ManifestKind, raw []byte, keys []ed25519.PrivateKey) [][]byte {
	t.Helper()
	result := make([][]byte, 0, len(keys))
	for _, key := range keys {
		signature, err := releasetrust.SignManifest(kind, raw, key)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, signature)
	}
	return result
}

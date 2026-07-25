package darwininstall

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/darwinbundle"
	releasetrust "mesh/internal/release"
)

func TestVerifyAndCompleteDarwinCandidateBindsOuterAndInnerAuthority(t *testing.T) {
	inspection := validDarwinCandidateInspection(t)
	root, releaseKeys := darwinCandidateTestRoot(t)
	metadata := darwinCandidateTestMetadata(t, root, releaseKeys, inspection, 4)
	bootstrapDigest := strings.Repeat("e", 64)
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	candidate, err := VerifyDarwinCandidateWithRoots(metadata, bootstrapDigest, root, root, nil, now, 4, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := CompleteDarwinAuthority(candidate, inspection, bootstrapDigest)
	if err != nil {
		t.Fatal(err)
	}
	if authority.ReleaseEpoch != root.Document.ReleaseEpoch || authority.Sequence != 4 ||
		authority.ArtifactSHA256 != inspection.ArtifactSHA256 || authority.PackageJSONSHA256 != inspection.PackageJSONSHA256 ||
		authority.InstalledID != DarwinInstalledID(authority) {
		t.Fatalf("completed Darwin authority = %+v", authority)
	}
	state := validDarwinInstallState(authority)
	retry, err := VerifyDarwinCandidateWithRoots(metadata, bootstrapDigest, root, root, &state, now.Add(2*time.Hour), 4, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if retry.VerifiedAt != authority.VerifiedAt {
		t.Fatalf("exact retry changed accepted verification time: %q != %q", retry.VerifiedAt, authority.VerifiedAt)
	}
}

func TestCompleteDarwinAuthorityRejectsOuterInnerDrift(t *testing.T) {
	inspection := validDarwinCandidateInspection(t)
	candidate := VerifiedDarwinCandidate{
		ReleaseEpoch: 1, TrustedRootVersion: 1, TrustedRootSHA256: strings.Repeat("1", 64),
		Sequence: 1, Version: inspection.Package.Version, MinimumSecurityFloor: inspection.Package.SecurityFloor,
		Channel: "stable", ChannelManifestSHA256: strings.Repeat("2", 64), ReleaseManifestSHA256: strings.Repeat("3", 64),
		Artifact:   releasetrust.Artifact{OS: "darwin", Arch: inspection.Package.Target.Arch, Size: inspection.ArtifactSize, SHA256: inspection.ArtifactSHA256},
		VerifiedAt: "2026-07-21T20:00:00Z",
	}
	for name, mutate := range map[string]func(*VerifiedDarwinCandidate){
		"artifact": func(value *VerifiedDarwinCandidate) { value.Artifact.SHA256 = strings.Repeat("f", 64) },
		"size":     func(value *VerifiedDarwinCandidate) { value.Artifact.Size++ },
		"arch":     func(value *VerifiedDarwinCandidate) { value.Artifact.Arch = "arm64" },
		"version":  func(value *VerifiedDarwinCandidate) { value.Version = "9.9.9" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := candidate
			mutate(&changed)
			if _, err := CompleteDarwinAuthority(changed, inspection, strings.Repeat("4", 64)); err == nil {
				t.Fatal("outer/inner Darwin drift was accepted")
			}
		})
	}
}

func darwinCandidateTestRoot(t *testing.T) (releasetrust.ParsedRoot, []ed25519.PrivateKey) {
	root, _, releasePrivate := darwinCandidateTestAuthority(t)
	return root, releasePrivate
}

func darwinCandidateTestAuthority(t *testing.T) (releasetrust.ParsedRoot, []ed25519.PrivateKey, []ed25519.PrivateKey) {
	t.Helper()
	rootPrivate := make([]ed25519.PrivateKey, 2)
	releasePrivate := make([]ed25519.PrivateKey, 2)
	keys := make([]releasetrust.PublicKeyFile, 0, 4)
	rootIDs := make([]string, 2)
	releaseIDs := make([]string, 2)
	for index := 0; index < 2; index++ {
		rootFile, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		rootPublic, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		rootPrivate[index] = privateKey
		keys = append(keys, rootPublic)
		rootIDs[index] = rootFile.KeyID
		releaseFile, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		releasePrivate[index] = privateKey
		releasePublic, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, releasePublic)
		releaseIDs[index] = releaseFile.KeyID
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	sort.Strings(rootIDs)
	sort.Strings(releaseIDs)
	raw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T00:00:00Z", ExpiresAt: "2026-08-20T00:00:00Z", Keys: keys,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: rootIDs},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: releaseIDs},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := releasetrust.ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root, rootPrivate, releasePrivate
}

func darwinCandidateTestMetadata(t *testing.T, root releasetrust.ParsedRoot, keys []ed25519.PrivateKey, inspection darwinbundle.CandidateInspection, sequence uint64) DarwinSignedMetadata {
	t.Helper()
	releaseDocument := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchemaV2, Channel: root.Document.Channel, ReleaseEpoch: root.Document.ReleaseEpoch,
		Version: inspection.Package.Version, Sequence: sequence, MinimumSecurityFloor: inspection.Package.SecurityFloor,
		IssuedAt: "2026-07-21T19:00:00Z", ExpiresAt: "2026-07-22T19:00:00Z",
		Artifacts: []releasetrust.Artifact{{
			OS: "darwin", Arch: inspection.Package.Target.Arch, URL: "https://releases.invalid/mesh-darwin.tar",
			Size: inspection.ArtifactSize, SHA256: inspection.ArtifactSHA256,
		}},
	}
	releaseRaw, err := json.Marshal(releaseDocument)
	if err != nil {
		t.Fatal(err)
	}
	releaseRaw = append(releaseRaw, '\n')
	releaseDigest := sha256.Sum256(releaseRaw)
	channelDocument := releasetrust.ChannelManifest{
		Schema: releasetrust.ChannelSchemaV2, Channel: root.Document.Channel, ReleaseEpoch: root.Document.ReleaseEpoch,
		Sequence: sequence, MinimumSecurityFloor: inspection.Package.SecurityFloor,
		IssuedAt: "2026-07-21T19:00:00Z", ExpiresAt: "2026-07-22T19:00:00Z",
		Release: releasetrust.ReleaseReference{
			Version: inspection.Package.Version, Sequence: sequence, ManifestURL: "https://releases.invalid/release.json",
			ManifestSize: int64(len(releaseRaw)), ManifestSHA256: hex.EncodeToString(releaseDigest[:]),
		},
	}
	channelRaw, err := json.Marshal(channelDocument)
	if err != nil {
		t.Fatal(err)
	}
	channelRaw = append(channelRaw, '\n')
	metadata := DarwinSignedMetadata{ChannelManifest: channelRaw, ReleaseManifest: releaseRaw}
	for _, key := range keys {
		channelSignature, err := releasetrust.SignManifest(releasetrust.ChannelManifestKind, channelRaw, key)
		if err != nil {
			t.Fatal(err)
		}
		releaseSignature, err := releasetrust.SignManifest(releasetrust.ReleaseManifestKind, releaseRaw, key)
		if err != nil {
			t.Fatal(err)
		}
		metadata.ChannelSignatures = append(metadata.ChannelSignatures, channelSignature)
		metadata.ReleaseSignatures = append(metadata.ReleaseSignatures, releaseSignature)
	}
	return metadata
}

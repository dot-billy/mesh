package windowsinstall

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/agentstate"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsbundle"
)

func TestVerifyAndCompleteWindowsCandidateBindsOuterAndInnerAuthority(t *testing.T) {
	inspection := validWindowsCandidateInspection(t)
	root, releaseKeys := windowsCandidateTestRoot(t)
	metadata := windowsCandidateTestMetadata(t, root, releaseKeys, inspection, 4)
	bootstrapDigest := strings.Repeat("e", 64)
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	candidate, err := VerifyWindowsCandidateWithRoots(metadata, bootstrapDigest, root, root, nil, now, 4, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := CompleteWindowsAuthority(candidate, inspection, bootstrapDigest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := authority.CurrentDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if authority.ReleaseEpoch != root.Document.ReleaseEpoch || authority.Sequence != 4 ||
		authority.ArtifactSHA256 != inspection.ArtifactSHA256 || authority.PackageJSONSHA256 != inspection.PackageJSONSHA256 ||
		authority.InstalledID != WindowsInstalledID(authority) || descriptor.InstalledID != authority.InstalledID ||
		descriptor.ArtifactSHA256 != inspection.ArtifactSHA256 {
		t.Fatalf("completed Windows authority = %+v, descriptor = %+v", authority, descriptor)
	}
	intake := VerifiedWindowsIntake{Candidate: candidate, InstallerBootstrapRootSHA256: bootstrapDigest}
	installedID, err := WindowsCandidateInstalledID(candidate)
	if err != nil || installedID != authority.InstalledID {
		t.Fatalf("candidate installed ID = %q, error = %v", installedID, err)
	}
	stageName, err := WindowsAcceptedStageName(intake)
	if err != nil || !strings.HasPrefix(stageName, ".stage-"+authority.InstalledID+"-") {
		t.Fatalf("accepted stage name = %q, error = %v", stageName, err)
	}
	state := validWindowsInstallState(authority)
	retry, err := VerifyWindowsCandidateWithRoots(metadata, bootstrapDigest, root, root, &state, now.Add(2*time.Hour), 4, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if retry.VerifiedAt != authority.VerifiedAt {
		t.Fatalf("exact retry changed accepted verification time: %q != %q", retry.VerifiedAt, authority.VerifiedAt)
	}
}

func TestCompleteWindowsAuthorityRejectsOuterInnerDrift(t *testing.T) {
	inspection := validWindowsCandidateInspection(t)
	candidate := VerifiedWindowsCandidate{
		ReleaseEpoch: 1, TrustedRootVersion: 1, TrustedRootSHA256: strings.Repeat("1", 64),
		Sequence: 1, Version: inspection.Package.Version, MinimumSecurityFloor: inspection.Package.SecurityFloor,
		Channel: "stable", ChannelManifestSHA256: strings.Repeat("2", 64), ReleaseManifestSHA256: strings.Repeat("3", 64),
		Artifact: releasetrust.Artifact{
			OS: "windows", Arch: inspection.Package.Target.Arch, Size: inspection.ArtifactSize, SHA256: inspection.ArtifactSHA256,
		},
		VerifiedAt: "2026-07-21T20:00:00Z",
	}
	for name, mutate := range map[string]func(*VerifiedWindowsCandidate){
		"artifact": func(value *VerifiedWindowsCandidate) { value.Artifact.SHA256 = strings.Repeat("e", 64) },
		"size":     func(value *VerifiedWindowsCandidate) { value.Artifact.Size++ },
		"arch":     func(value *VerifiedWindowsCandidate) { value.Artifact.Arch = "arm64" },
		"version":  func(value *VerifiedWindowsCandidate) { value.Version = "9.9.9" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := candidate
			mutate(&changed)
			if _, err := CompleteWindowsAuthority(changed, inspection, strings.Repeat("4", 64)); err == nil {
				t.Fatal("outer/inner Windows drift was accepted")
			}
		})
	}
}

func windowsCandidateTestRoot(t *testing.T) (releasetrust.ParsedRoot, []ed25519.PrivateKey) {
	t.Helper()
	keys := make([]releasetrust.PublicKeyFile, 0, 4)
	rootIDs := make([]string, 0, 2)
	releaseIDs := make([]string, 0, 2)
	releasePrivate := make([]ed25519.PrivateKey, 0, 2)
	for range 2 {
		rootFile, rootPrivate, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		rootPublic, err := releasetrust.PublicKeyFileFromPrivate(rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, rootPublic)
		rootIDs = append(rootIDs, rootFile.KeyID)
		releaseFile, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		releasePublic, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, releasePublic)
		releaseIDs = append(releaseIDs, releaseFile.KeyID)
		releasePrivate = append(releasePrivate, privateKey)
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
	return root, releasePrivate
}

func windowsCandidateTestMetadata(t *testing.T, root releasetrust.ParsedRoot, keys []ed25519.PrivateKey, inspection windowsbundle.CandidateInspection, sequence uint64) WindowsSignedMetadata {
	t.Helper()
	releaseDocument := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchemaV2, Channel: root.Document.Channel, ReleaseEpoch: root.Document.ReleaseEpoch,
		Version: inspection.Package.Version, Sequence: sequence, MinimumSecurityFloor: inspection.Package.SecurityFloor,
		IssuedAt: "2026-07-21T19:00:00Z", ExpiresAt: "2026-07-22T19:00:00Z",
		Artifacts: []releasetrust.Artifact{{
			OS: "windows", Arch: inspection.Package.Target.Arch, URL: "https://releases.invalid/mesh-windows.tar",
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
	metadata := WindowsSignedMetadata{ChannelManifest: channelRaw, ReleaseManifest: releaseRaw}
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

func validWindowsCandidateInspection(t *testing.T) windowsbundle.CandidateInspection {
	t.Helper()
	arch := "amd64"
	entries := []windowsbundle.Entry{
		{Path: "bin/dist/windows/wintun/LICENSE.txt", ArchiveMode: 0o444},
		{Path: "bin/dist/windows/wintun/README.md", ArchiveMode: 0o444},
		{Path: "bin/dist/windows/wintun/bin/amd64/wintun.dll", ArchiveMode: 0o444},
		{Path: "bin/meshctl.exe", ArchiveMode: 0o555},
		{Path: "bin/nebula-cert.exe", ArchiveMode: 0o555},
		{Path: "bin/nebula.exe", ArchiveMode: 0o555},
		{Path: "share/licenses/nebula/LICENSE", ArchiveMode: 0o444},
	}
	for index := range entries {
		entries[index].Size = 1
		entries[index].SHA256 = strings.Repeat(fmtHexDigit(index+1), 64)
	}
	metadata := windowsbundle.Package{
		Schema: windowsbundle.Schema, Version: "1.2.3", Commit: strings.Repeat("a", 40), BuildTime: "2026-07-21T19:00:00Z",
		SecurityFloor: 2, AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion, GoVersion: "go1.26.5", Target: windowsbundle.Target{OS: "windows", Arch: arch},
		Nebula: windowsbundle.NebulaIdentity{
			Version: "v1.10.3", LockSHA256: strings.Repeat("b", 64), AssetID: 1,
			AssetName: "nebula-windows-amd64.zip", ArchiveSize: 1, ArchiveSHA256: strings.Repeat("c", 64),
		},
		Runtime: windowsbundle.RuntimeIdentity{
			Version: "v1.10.3", Commit: strings.Repeat("d", 40), UpstreamLockSHA256: strings.Repeat("1", 64),
			SourceBuildLockSHA256: strings.Repeat("2", 64), WindowsBuildLockSHA256: strings.Repeat("3", 64),
			SourceTreeSHA256: strings.Repeat("4", 64), PatchedTreeSHA256: strings.Repeat("5", 64),
			PatchSetSHA256: strings.Repeat("6", 64), GoVersion: "go1.26.5",
		},
		Entries: entries,
	}
	packageJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	packageJSON = append(packageJSON, '\n')
	inspection, err := windowsbundle.ReconstructCandidateInspection(strings.Repeat("f", 64), packageJSON)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func fmtHexDigit(value int) string {
	const digits = "0123456789abcdef"
	return string(digits[value%len(digits)])
}

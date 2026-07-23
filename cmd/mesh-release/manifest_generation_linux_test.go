//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	releasetrust "mesh/internal/release"
)

func TestCreateReleaseAndChannelManifestsDeterministicallyPinExactInputs(t *testing.T) {
	directory := t.TempDir()
	type fixture struct {
		platformOS   string
		platformArch string
		url          string
		path         string
		raw          []byte
	}
	fixtures := []fixture{
		{platformOS: "darwin", platformArch: "amd64"},
		{platformOS: "darwin", platformArch: "arm64"},
		{platformOS: "linux", platformArch: "amd64"},
		{platformOS: "linux", platformArch: "arm64"},
		{platformOS: "windows", platformArch: "amd64"},
		{platformOS: "windows", platformArch: "arm64"},
	}
	for index := range fixtures {
		item := &fixtures[index]
		item.url = "https://releases.example/mesh/1.2.3/" + item.platformOS + "-" + item.platformArch
		item.path = filepath.Join(directory, item.platformOS+"-"+item.platformArch+".artifact")
		item.raw = []byte("exact " + item.platformOS + "/" + item.platformArch + " artifact\n")
		if err := os.WriteFile(item.path, item.raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	issuedAt, expiresAt := manifestTestTimes()
	releaseOne := filepath.Join(directory, "release-one.json")
	releaseTwo := filepath.Join(directory, "release-two.json")
	optionsForOrder := func(outputPath string, order []int) releaseManifestOptions {
		options := releaseManifestOptions{
			outputPath: outputPath, channel: "stable", version: "1.2.3", sequence: 9, securityFloor: 3,
			issuedAt: issuedAt, expiresAt: expiresAt,
		}
		for _, fixtureIndex := range order {
			item := fixtures[fixtureIndex]
			options.platformOSes = append(options.platformOSes, item.platformOS)
			options.platformArches = append(options.platformArches, item.platformArch)
			options.artifactURLs = append(options.artifactURLs, item.url)
			options.artifactPaths = append(options.artifactPaths, item.path)
		}
		return options
	}
	firstOptions := optionsForOrder(releaseOne, []int{5, 2, 1, 4, 0, 3})
	firstIdentity, err := createLegacyV1ReleaseManifestForTestUsing(firstOptions, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	secondOptions := optionsForOrder(releaseTwo, []int{0, 1, 2, 3, 4, 5})
	secondIdentity, err := createLegacyV1ReleaseManifestForTestUsing(secondOptions, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	firstRaw := mustReadTestFile(t, releaseOne)
	secondRaw := mustReadTestFile(t, releaseTwo)
	if !bytes.Equal(firstRaw, secondRaw) || firstIdentity != secondIdentity {
		t.Fatal("permuted release inputs did not produce identical manifest bytes and identity")
	}
	if len(firstRaw) == 0 || firstRaw[len(firstRaw)-1] != '\n' || bytes.Contains(firstRaw[:len(firstRaw)-1], []byte{'\n'}) {
		t.Fatalf("release manifest is not compact JSON followed by one LF: %q", firstRaw)
	}
	parsedRelease, err := releasetrust.ParseManifest(firstRaw, releasetrust.VerificationPolicy{Now: time.Now(), ExpectedChannel: "stable"})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedRelease.Release.Artifacts) != len(fixtures) {
		t.Fatalf("release has %d artifacts, want %d", len(parsedRelease.Release.Artifacts), len(fixtures))
	}
	for index, artifact := range parsedRelease.Release.Artifacts {
		item := fixtures[index]
		digest := sha256.Sum256(item.raw)
		if artifact.OS != item.platformOS || artifact.Arch != item.platformArch || artifact.URL != item.url ||
			artifact.Size != int64(len(item.raw)) || artifact.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("artifact %d did not bind the canonical target and exact local bytes: %+v", index, artifact)
		}
	}
	canonicalRelease, err := json.Marshal(parsedRelease.Release)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRelease = append(canonicalRelease, '\n')
	if !bytes.Equal(firstRaw, canonicalRelease) {
		t.Fatal("release output is not the canonical encoding of the validated release type")
	}

	channelOne := filepath.Join(directory, "channel-one.json")
	channelTwo := filepath.Join(directory, "channel-two.json")
	baseChannel := channelManifestOptions{
		releaseManifestPath: releaseOne,
		manifestURL:         "https://releases.example/mesh/1.2.3/release.json",
		issuedAt:            issuedAt,
		expiresAt:           expiresAt,
	}
	firstChannelOptions := baseChannel
	firstChannelOptions.outputPath = channelOne
	firstChannelIdentity, err := createLegacyV1ChannelManifestForTestUsing(firstChannelOptions, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	secondChannelOptions := baseChannel
	secondChannelOptions.outputPath = channelTwo
	secondChannelIdentity, err := createLegacyV1ChannelManifestForTestUsing(secondChannelOptions, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	firstChannelRaw := mustReadTestFile(t, channelOne)
	secondChannelRaw := mustReadTestFile(t, channelTwo)
	if !bytes.Equal(firstChannelRaw, secondChannelRaw) || firstChannelIdentity != secondChannelIdentity {
		t.Fatal("identical channel inputs did not produce identical manifest bytes and identity")
	}
	parsedChannel, err := releasetrust.ParseManifest(firstChannelRaw, releasetrust.VerificationPolicy{Now: time.Now(), ExpectedChannel: "stable"})
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest := sha256.Sum256(firstRaw)
	reference := parsedChannel.Channel.Release
	if parsedChannel.Channel.Channel != parsedRelease.Release.Channel ||
		parsedChannel.Channel.Sequence != parsedRelease.Release.Sequence ||
		parsedChannel.Channel.MinimumSecurityFloor != parsedRelease.Release.MinimumSecurityFloor ||
		reference.Version != parsedRelease.Release.Version || reference.Sequence != parsedRelease.Release.Sequence ||
		reference.ManifestSize != int64(len(firstRaw)) || reference.ManifestSHA256 != hex.EncodeToString(releaseDigest[:]) ||
		reference.ManifestURL != baseChannel.manifestURL {
		t.Fatalf("channel did not derive release identity or pin exact bytes: %+v", parsedChannel.Channel)
	}
	canonicalChannel, err := json.Marshal(parsedChannel.Channel)
	if err != nil {
		t.Fatal(err)
	}
	canonicalChannel = append(canonicalChannel, '\n')
	if !bytes.Equal(firstChannelRaw, canonicalChannel) {
		t.Fatal("channel output is not the canonical encoding of the validated channel type")
	}
}

func TestRootedManifestGenerationDerivesV2AuthorityAndFloors(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 3, 2, 5, 3)
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("rooted artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release-v2.json")
	identity, err := createRootedReleaseManifestUsing(releaseManifestOptions{
		outputPath: releasePath, rootPath: rootPath, version: "2.0.0", sequence: 5,
		issuedAt: issuedAt, expiresAt: expiresAt,
		platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
		artifactURLs: []string{"https://releases.example/bundle.tar"}, artifactPaths: []string{artifactPath},
	}, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if identity.rootVersion != 3 || identity.releaseEpoch != 2 || identity.releaseThreshold != 2 {
		t.Fatalf("generator did not report root authority: %+v", identity)
	}
	parsedRelease, err := releasetrust.ParseManifest(mustReadTestFile(t, releasePath), releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: "stable", ExpectedReleaseEpoch: 2,
		MinimumReleaseEpoch: 2, MinimumSequence: 5, MinimumSecurityFloor: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsedRelease.Release.Schema != releasetrust.ReleaseSchemaV2 || parsedRelease.Release.ReleaseEpoch != 2 || parsedRelease.Release.MinimumSecurityFloor != 3 {
		t.Fatalf("release did not derive current root values: %+v", parsedRelease.Release)
	}

	channelPath := filepath.Join(directory, "channel-v2.json")
	channelIdentity, err := createRootedChannelManifestUsing(channelManifestOptions{
		outputPath: channelPath, rootPath: rootPath, releaseManifestPath: releasePath,
		manifestURL: "https://releases.example/release-v2.json", issuedAt: issuedAt, expiresAt: expiresAt,
	}, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if channelIdentity.rootVersion != 3 || channelIdentity.releaseEpoch != 2 || channelIdentity.releaseThreshold != 2 {
		t.Fatalf("channel generator did not report root authority: %+v", channelIdentity)
	}
	parsedChannel, err := releasetrust.ParseManifest(mustReadTestFile(t, channelPath), releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: "stable", ExpectedReleaseEpoch: 2, MinimumReleaseEpoch: 2,
	})
	if err != nil || parsedChannel.Channel.Schema != releasetrust.ChannelSchemaV2 || parsedChannel.Channel.ReleaseEpoch != 2 {
		t.Fatalf("channel did not derive v2 root epoch: %+v, %v", parsedChannel.Channel, err)
	}
}

func TestRootedManifestGenerationRejectsContradictionsAndUnstableRoot(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 3, 2, 5, 3)
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	base := releaseManifestOptions{
		rootPath: rootPath, version: "2.0.0", sequence: 5, issuedAt: issuedAt, expiresAt: expiresAt,
		platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
		artifactURLs: []string{"https://releases.example/bundle.tar"}, artifactPaths: []string{artifactPath},
	}

	belowSequence := base
	belowSequence.outputPath = filepath.Join(directory, "below-sequence.json")
	belowSequence.sequence = 4
	if _, err := createRootedReleaseManifestUsing(belowSequence, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("sequence below root floor returned %v", err)
	}
	belowFloor := base
	belowFloor.outputPath = filepath.Join(directory, "below-floor.json")
	belowFloor.securityFloor = 2
	if _, err := createRootedReleaseManifestUsing(belowFloor, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "security-floor") {
		t.Fatalf("security floor below root returned %v", err)
	}
	unstable := base
	unstable.outputPath = filepath.Join(directory, "unstable.json")
	originalRoot := mustReadTestFile(t, rootPath)
	if _, err := createRootedReleaseManifestUsing(unstable, manifestGenerationHooks{afterRootRead: func(path string) {
		if writeErr := os.WriteFile(path, append(append([]byte(nil), originalRoot...), ' '), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("root mutation returned %v", err)
	}

	var inconsistent releasetrust.Root
	if err := json.Unmarshal(originalRoot, &inconsistent); err != nil {
		t.Fatal(err)
	}
	inconsistent.Roles.Release.KeyIDs[0] = inconsistent.Roles.Root.KeyIDs[0]
	inconsistentRaw, err := json.Marshal(inconsistent)
	if err != nil {
		t.Fatal(err)
	}
	inconsistentRaw = append(inconsistentRaw, '\n')
	if err := os.WriteFile(rootPath, inconsistentRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	badRole := base
	badRole.outputPath = filepath.Join(directory, "bad-role.json")
	if _, err := createRootedReleaseManifestUsing(badRole, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("inconsistent release role returned %v", err)
	}

	if err := os.WriteFile(rootPath, originalRoot, 0o600); err != nil {
		t.Fatal(err)
	}
	validRelease := base
	validRelease.outputPath = filepath.Join(directory, "valid-v2.json")
	if _, err := createRootedReleaseManifestUsing(validRelease, manifestGenerationHooks{}); err != nil {
		t.Fatal(err)
	}
	nextRoot := writeManifestGenerationRoot(t, directory, 4, 3, 1, 3)
	if _, err := createRootedChannelManifestUsing(channelManifestOptions{
		outputPath: filepath.Join(directory, "wrong-epoch-channel.json"), rootPath: nextRoot,
		releaseManifestPath: validRelease.outputPath, manifestURL: "https://releases.example/valid-v2.json",
		issuedAt: issuedAt, expiresAt: expiresAt,
	}, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("release from a different root epoch returned %v", err)
	}
}

func TestCreateManifestCommandsParseRepeatableFlags(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 1, 1, 1, 1)
	windowsPath := filepath.Join(directory, "windows-arm64.zip")
	darwinPath := filepath.Join(directory, "darwin-amd64.tar")
	if err := os.WriteFile(windowsPath, []byte("windows bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(darwinPath, []byte("darwin bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release.json")
	var output bytes.Buffer
	if err := createReleaseManifest([]string{
		"--output", releasePath, "--root", rootPath, "--version", "2.0.0", "--sequence", "11",
		"--security-floor", "4", "--issued", issuedAt, "--expires", expiresAt,
		"--test-only-allow-unscanned-windows-artifact", "--test-only-allow-unscanned-darwin-artifact",
		"--os", "windows", "--arch", "arm64", "--artifact-url", "https://releases.example/windows-arm64.zip", "--artifact", windowsPath,
		"--os", "darwin", "--arch", "amd64", "--artifact-url", "https://releases.example/darwin-amd64.tar", "--artifact", darwinPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Created exact v2 release manifest") || !strings.Contains(output.String(), "binding 2 artifacts") || !strings.Contains(output.String(), "requiring 2 release-role signatures") || strings.Contains(output.String(), "Linux release manifest") {
		t.Fatalf("unexpected release output %q", output.String())
	}
	parsed, err := releasetrust.ParseManifest(mustReadTestFile(t, releasePath), releasetrust.VerificationPolicy{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Release.Artifacts; len(got) != 2 || got[0].OS != "darwin" || got[0].Arch != "amd64" || got[1].OS != "windows" || got[1].Arch != "arm64" {
		t.Fatalf("repeatable flags produced non-canonical artifacts: %+v", got)
	}
	channelPath := filepath.Join(directory, "channel.json")
	output.Reset()
	if err := createChannelManifest([]string{
		"--output", channelPath, "--root", rootPath, "--release-manifest", releasePath,
		"--manifest-url", "https://releases.example/release.json",
		"--issued", issuedAt, "--expires", expiresAt,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "pins the exact bytes") {
		t.Fatalf("unexpected channel output %q", output.String())
	}
}

func TestCreateReleaseManifestSingleArtifactCLICompatibility(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 1, 1, 1, 1)
	artifactPath := filepath.Join(directory, "bundle.tar")
	artifactRaw := []byte("single artifact")
	if err := os.WriteFile(artifactPath, artifactRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release.json")
	var output bytes.Buffer
	baseArgs := []string{
		"--output", releasePath, "--root", rootPath, "--version", "1.2.3", "--sequence", "1",
		"--security-floor", "1", "--issued", issuedAt, "--expires", expiresAt,
		"--os", "linux", "--arch", "amd64", "--artifact-url", "https://releases.example/linux-amd64.tar",
		"--artifact", artifactPath,
	}
	if err := createReleaseManifest(baseArgs, &output); err == nil || !strings.Contains(err.Error(), "requires one --linux-package-security-receipt") || output.Len() != 0 {
		t.Fatalf("unscanned Linux artifact returned output %q, error %v", output.String(), err)
	}
	baseArgs = append(baseArgs, "--test-only-allow-unscanned-linux-artifact")
	if err := createReleaseManifest(baseArgs, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "binding 1 artifact with an explicit test-only unscanned-Linux bypass and requiring 2 release-role signatures") {
		t.Fatalf("unexpected single-artifact output %q", output.String())
	}
	parsed, err := releasetrust.ParseManifest(mustReadTestFile(t, releasePath), releasetrust.VerificationPolicy{
		Now: time.Now(), PlatformOS: "linux", PlatformArch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifactRaw)
	artifact := parsed.SelectedArtifact
	if artifact == nil || artifact.Size != int64(len(artifactRaw)) || artifact.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("single-artifact flags did not retain exact-byte compatibility: %+v", artifact)
	}
}

func TestCreateReleaseManifestRequiresWindowsSecurityEvidence(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 1, 1, 1, 1)
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("synthetic Windows artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release.json")
	baseArgs := []string{
		"--output", releasePath, "--root", rootPath, "--version", "1.2.3", "--sequence", "1",
		"--security-floor", "1", "--issued", issuedAt, "--expires", expiresAt,
		"--os", "windows", "--arch", "amd64", "--artifact-url", "https://releases.example/windows-amd64.tar",
		"--artifact", artifactPath,
	}
	var output bytes.Buffer
	if err := createReleaseManifest(baseArgs, &output); err == nil || !strings.Contains(err.Error(), "requires one --windows-package-security-receipt") || output.Len() != 0 {
		t.Fatalf("unscanned Windows artifact returned output %q, error %v", output.String(), err)
	}
	withPackageOnly := append(append([]string(nil), baseArgs...),
		"--windows-package-security-receipt", filepath.Join(directory, "package-receipt.json"))
	if err := createReleaseManifest(withPackageOnly, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires one --windows-authenticode-receipt") {
		t.Fatalf("Windows artifact without native receipt returned %v", err)
	}
	withBypass := append(append([]string(nil), baseArgs...), "--test-only-allow-unscanned-windows-artifact")
	if err := createReleaseManifest(withBypass, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "explicit test-only unscanned-Windows bypass") {
		t.Fatalf("unexpected Windows bypass output %q", output.String())
	}
	combined := append(append([]string(nil), baseArgs...),
		"--test-only-allow-unscanned-windows-artifact", "--windows-package-security-receipt", filepath.Join(directory, "receipt.json"))
	if err := createReleaseManifest(combined, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("Windows receipt and bypass combination returned %v", err)
	}
	authenticodeCombined := append(append([]string(nil), baseArgs...),
		"--test-only-allow-unscanned-windows-artifact", "--windows-authenticode-receipt", filepath.Join(directory, "authenticode.json"))
	if err := createReleaseManifest(authenticodeCombined, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("Windows Authenticode receipt and bypass combination returned %v", err)
	}
}

func TestCreateReleaseManifestRequiresDarwinSecurityEvidence(t *testing.T) {
	directory := t.TempDir()
	rootPath := writeManifestGenerationRoot(t, directory, 1, 1, 1, 1)
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("synthetic Darwin artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release.json")
	baseArgs := []string{
		"--output", releasePath, "--root", rootPath, "--version", "1.2.3", "--sequence", "1",
		"--security-floor", "1", "--issued", issuedAt, "--expires", expiresAt,
		"--os", "darwin", "--arch", "amd64", "--artifact-url", "https://releases.example/darwin-amd64.tar",
		"--artifact", artifactPath,
	}
	var output bytes.Buffer
	if err := createReleaseManifest(baseArgs, &output); err == nil || !strings.Contains(err.Error(), "requires one --darwin-package-security-receipt") || output.Len() != 0 {
		t.Fatalf("unscanned Darwin artifact returned output %q, error %v", output.String(), err)
	}
	withBypass := append(append([]string(nil), baseArgs...), "--test-only-allow-unscanned-darwin-artifact")
	if err := createReleaseManifest(withBypass, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "explicit test-only unscanned-Darwin bypass") {
		t.Fatalf("unexpected Darwin bypass output %q", output.String())
	}
	combined := append(append([]string(nil), baseArgs...),
		"--test-only-allow-unscanned-darwin-artifact", "--darwin-package-security-receipt", filepath.Join(directory, "receipt.json"))
	if err := createReleaseManifest(combined, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("Darwin receipt and bypass combination returned %v", err)
	}
}

func TestCreateReleaseManifestRejectsTamperSymlinkBoundAndOverwrite(t *testing.T) {
	issuedAt, expiresAt := manifestTestTimes()
	newOptions := func(artifactPath, outputPath string) releaseManifestOptions {
		return releaseManifestOptions{
			outputPath: outputPath, channel: "stable", version: "1.0.0", sequence: 1, securityFloor: 1,
			issuedAt: issuedAt, expiresAt: expiresAt,
			platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
			artifactURLs: []string{"https://releases.example/bundle.tar"}, artifactPaths: []string{artifactPath},
		}
	}

	t.Run("tamper after streaming", func(t *testing.T) {
		directory := t.TempDir()
		artifactPath := filepath.Join(directory, "bundle.tar")
		if err := os.WriteFile(artifactPath, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "release.json")
		_, err := createLegacyV1ReleaseManifestForTestUsing(newOptions(artifactPath, outputPath), manifestGenerationHooks{
			afterArtifactRead: func(path string) {
				if writeErr := os.WriteFile(path, []byte("tampered"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "changed while hashing") {
			t.Fatalf("post-read artifact tamper returned %v", err)
		}
		assertTestPathAbsent(t, outputPath)
	})

	t.Run("path replacement after streaming", func(t *testing.T) {
		directory := t.TempDir()
		artifactPath := filepath.Join(directory, "bundle.tar")
		if err := os.WriteFile(artifactPath, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "release.json")
		_, err := createLegacyV1ReleaseManifestForTestUsing(newOptions(artifactPath, outputPath), manifestGenerationHooks{
			afterArtifactRead: func(path string) {
				replacement := path + ".replacement"
				if writeErr := os.WriteFile(replacement, []byte("replacement"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				if renameErr := os.Rename(replacement, path); renameErr != nil {
					t.Fatal(renameErr)
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "changed while hashing") {
			t.Fatalf("post-read artifact replacement returned %v", err)
		}
		assertTestPathAbsent(t, outputPath)
	})

	t.Run("later repeated artifact tamper", func(t *testing.T) {
		directory := t.TempDir()
		linuxPath := filepath.Join(directory, "linux-amd64.tar")
		windowsPath := filepath.Join(directory, "windows-arm64.zip")
		if err := os.WriteFile(linuxPath, []byte("linux artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(windowsPath, []byte("windows artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "release.json")
		options := newOptions(linuxPath, outputPath)
		options.platformOSes = []string{"windows", "linux"}
		options.platformArches = []string{"arm64", "amd64"}
		options.artifactURLs = []string{"https://releases.example/windows-arm64.zip", "https://releases.example/linux-amd64.tar"}
		options.artifactPaths = []string{windowsPath, linuxPath}
		var visited []string
		_, err := createLegacyV1ReleaseManifestForTestUsing(options, manifestGenerationHooks{
			afterArtifactRead: func(path string) {
				visited = append(visited, path)
				if path == windowsPath {
					if writeErr := os.WriteFile(path, []byte("tampered artifact"), 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact windows/arm64") || !strings.Contains(err.Error(), "changed while hashing") {
			t.Fatalf("later repeated artifact tamper returned %v", err)
		}
		if len(visited) != 2 || visited[0] != linuxPath || visited[1] != windowsPath {
			t.Fatalf("artifacts were not descriptor-hashed in canonical target order: %q", visited)
		}
		assertTestPathAbsent(t, outputPath)
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "bundle.tar")
		link := filepath.Join(directory, "bundle-link.tar")
		if err := os.WriteFile(target, []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "release.json")
		_, err := createLegacyV1ReleaseManifestForTestUsing(newOptions(link, outputPath), manifestGenerationHooks{})
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink artifact returned %v", err)
		}
		assertTestPathAbsent(t, outputPath)
	})

	t.Run("release artifact bound", func(t *testing.T) {
		directory := t.TempDir()
		artifactPath := filepath.Join(directory, "oversize.tar")
		file, err := os.OpenFile(artifactPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(releasetrust.MaxArtifactSize + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "release.json")
		_, err = createLegacyV1ReleaseManifestForTestUsing(newOptions(artifactPath, outputPath), manifestGenerationHooks{})
		if err == nil || !strings.Contains(err.Error(), "between 1 and") {
			t.Fatalf("oversize artifact returned %v", err)
		}
		assertTestPathAbsent(t, outputPath)
	})

	t.Run("no overwrite", func(t *testing.T) {
		directory := t.TempDir()
		artifactPath := filepath.Join(directory, "bundle.tar")
		outputPath := filepath.Join(directory, "release.json")
		if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outputPath, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := createLegacyV1ReleaseManifestForTestUsing(newOptions(artifactPath, outputPath), manifestGenerationHooks{})
		if err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("existing output returned %v", err)
		}
		if raw := mustReadTestFile(t, outputPath); string(raw) != "keep" {
			t.Fatalf("existing output changed to %q", raw)
		}
	})
}

func TestCreateReleaseManifestRejectsMismatchedCountsDuplicateAndUnsupportedTargets(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "artifact")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	validOptions := func() releaseManifestOptions {
		return releaseManifestOptions{
			outputPath: filepath.Join(directory, "release.json"), channel: "stable", version: "1.0.0",
			sequence: 1, securityFloor: 1, issuedAt: issuedAt, expiresAt: expiresAt,
			platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
			artifactURLs: []string{"https://releases.example/linux-amd64.tar"}, artifactPaths: []string{artifactPath},
		}
	}

	for _, test := range []struct {
		name   string
		change func(*releaseManifestOptions)
	}{
		{name: "extra os", change: func(options *releaseManifestOptions) { options.platformOSes = append(options.platformOSes, "darwin") }},
		{name: "extra arch", change: func(options *releaseManifestOptions) {
			options.platformArches = append(options.platformArches, "arm64")
		}},
		{name: "extra URL", change: func(options *releaseManifestOptions) {
			options.artifactURLs = append(options.artifactURLs, "https://releases.example/extra")
		}},
		{name: "extra path", change: func(options *releaseManifestOptions) {
			options.artifactPaths = append(options.artifactPaths, artifactPath)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := validOptions()
			test.change(&options)
			if _, err := createLegacyV1ReleaseManifestForTestUsing(options, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "must have equal counts") {
				t.Fatalf("mismatched repeat counts returned %v", err)
			}
			assertTestPathAbsent(t, options.outputPath)
		})
	}

	t.Run("no artifacts", func(t *testing.T) {
		options := validOptions()
		options.platformOSes = nil
		options.platformArches = nil
		options.artifactURLs = nil
		options.artifactPaths = nil
		if _, err := createLegacyV1ReleaseManifestForTestUsing(options, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "are required") {
			t.Fatalf("empty artifact lists returned %v", err)
		}
		assertTestPathAbsent(t, options.outputPath)
	})

	t.Run("duplicate target", func(t *testing.T) {
		options := validOptions()
		options.platformOSes = append(options.platformOSes, "linux")
		options.platformArches = append(options.platformArches, "amd64")
		options.artifactURLs = append(options.artifactURLs, "https://releases.example/duplicate.tar")
		options.artifactPaths = append(options.artifactPaths, artifactPath)
		if _, err := createLegacyV1ReleaseManifestForTestUsing(options, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "duplicate artifact target linux/amd64") {
			t.Fatalf("duplicate target returned %v", err)
		}
		assertTestPathAbsent(t, options.outputPath)
	})

	for _, target := range []struct {
		name         string
		platformOS   string
		platformArch string
	}{
		{name: "unsupported os", platformOS: "freebsd", platformArch: "amd64"},
		{name: "noncanonical os", platformOS: "Linux", platformArch: "amd64"},
		{name: "unsupported arch", platformOS: "linux", platformArch: "riscv64"},
	} {
		t.Run(target.name, func(t *testing.T) {
			options := validOptions()
			options.platformOSes[0] = target.platformOS
			options.platformArches[0] = target.platformArch
			if _, err := createLegacyV1ReleaseManifestForTestUsing(options, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "unsupported target") {
				t.Fatalf("unsupported target %s/%s returned %v", target.platformOS, target.platformArch, err)
			}
			assertTestPathAbsent(t, options.outputPath)
		})
	}
}

func TestCreateChannelManifestRejectsReleaseTamperSymlinkAndOverwrite(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	releasePath := filepath.Join(directory, "release.json")
	_, err := createLegacyV1ReleaseManifestForTestUsing(releaseManifestOptions{
		outputPath: releasePath, channel: "stable", version: "1.0.0", sequence: 1, securityFloor: 1,
		issuedAt: issuedAt, expiresAt: expiresAt,
		platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
		artifactURLs: []string{"https://releases.example/bundle.tar"}, artifactPaths: []string{artifactPath},
	}, manifestGenerationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	base := channelManifestOptions{
		releaseManifestPath: releasePath, manifestURL: "https://releases.example/release.json",
		issuedAt: issuedAt, expiresAt: expiresAt,
	}

	t.Run("tamper after read", func(t *testing.T) {
		options := base
		options.outputPath = filepath.Join(directory, "tampered-channel.json")
		original := mustReadTestFile(t, releasePath)
		_, err := createLegacyV1ChannelManifestForTestUsing(options, manifestGenerationHooks{
			afterReleaseManifestRead: func(path string) {
				if writeErr := os.WriteFile(path, append(append([]byte(nil), original...), ' '), 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "identity, size, mode, ownership, link count, or timestamps changed") {
			t.Fatalf("post-read release tamper returned %v", err)
		}
		assertTestPathAbsent(t, options.outputPath)
		if err := os.WriteFile(releasePath, original, 0o644); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(directory, "release-link.json")
		if err := os.Symlink(releasePath, link); err != nil {
			t.Fatal(err)
		}
		options := base
		options.releaseManifestPath = link
		options.outputPath = filepath.Join(directory, "symlink-channel.json")
		_, err := createLegacyV1ChannelManifestForTestUsing(options, manifestGenerationHooks{})
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink release manifest returned %v", err)
		}
		assertTestPathAbsent(t, options.outputPath)
	})

	t.Run("no overwrite", func(t *testing.T) {
		options := base
		options.outputPath = filepath.Join(directory, "existing-channel.json")
		if err := os.WriteFile(options.outputPath, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := createLegacyV1ChannelManifestForTestUsing(options, manifestGenerationHooks{})
		if err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("existing channel output returned %v", err)
		}
		if raw := mustReadTestFile(t, options.outputPath); string(raw) != "keep" {
			t.Fatalf("existing channel output changed to %q", raw)
		}
	})
}

func TestCreateManifestsValidateHTTPSSemantics(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "bundle.tar")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := manifestTestTimes()
	baseRelease := releaseManifestOptions{
		channel: "stable", version: "1.0.0", sequence: 1, securityFloor: 1,
		issuedAt: issuedAt, expiresAt: expiresAt,
		platformOSes: []string{"linux"}, platformArches: []string{"amd64"},
		artifactURLs: []string{"http://releases.example/bundle.tar"}, artifactPaths: []string{artifactPath},
		outputPath: filepath.Join(directory, "bad-release.json"),
	}
	if _, err := createLegacyV1ReleaseManifestForTestUsing(baseRelease, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("HTTP artifact URL returned %v", err)
	}
	assertTestPathAbsent(t, baseRelease.outputPath)

	baseRelease.artifactURLs[0] = "https://releases.example/bundle.tar"
	baseRelease.outputPath = filepath.Join(directory, "release.json")
	if _, err := createLegacyV1ReleaseManifestForTestUsing(baseRelease, manifestGenerationHooks{}); err != nil {
		t.Fatal(err)
	}
	channel := channelManifestOptions{
		outputPath: filepath.Join(directory, "bad-channel.json"), releaseManifestPath: baseRelease.outputPath,
		manifestURL: "http://releases.example/release.json", issuedAt: issuedAt, expiresAt: expiresAt,
	}
	if _, err := createLegacyV1ChannelManifestForTestUsing(channel, manifestGenerationHooks{}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("HTTP manifest URL returned %v", err)
	}
	assertTestPathAbsent(t, channel.outputPath)
}

func manifestTestTimes() (string, string) {
	now := time.Now().UTC().Truncate(time.Second)
	return now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertTestPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %q unexpectedly exists or cannot be inspected: %v", path, err)
	}
}

func writeManifestGenerationRoot(t *testing.T, directory string, version, epoch, sequenceFloor, securityFloor uint64) string {
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
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: version, Channel: "stable", ReleaseEpoch: epoch,
		MinimumReleaseSequence: sequenceFloor, MinimumSecurityFloor: securityFloor,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, fmt.Sprintf("root-%d.json", version))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

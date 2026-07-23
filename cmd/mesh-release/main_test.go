package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
	"mesh/internal/releaseorigin"
)

func TestReleaseUsageIncludesOnlineBundleAssembler(t *testing.T) {
	if !strings.Contains(releaseUsage, "assemble-online-bundle") || !strings.Contains(releaseUsage, "assemble-darwin-snapshot") || !strings.Contains(releaseUsage, "create-origin-index") || !strings.Contains(releaseUsage, "create-bootstrap-handoff") || !strings.Contains(releaseUsage, "create-bootstrap-anchor") || !strings.Contains(releaseUsage, "publish-origin-generation") || !strings.Contains(releaseUsage, "inspect-origin-generation") {
		t.Fatalf("release usage omits online bundle assembler: %q", releaseUsage)
	}
}

func TestCreateBootstrapHandoffRequiresExactInputs(t *testing.T) {
	if err := createBootstrapHandoff(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty bootstrap handoff request accepted")
	}
	if err := createBootstrapHandoff([]string{
		"--output", "/tmp/handoff.json", "--root", "/tmp/root.json",
		"--issued", "2026-07-21T12:00:00Z", "--expires", "2026-07-22T12:00:00Z",
		"--verifier-package", "/tmp/amd64.tar",
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exactly four") {
		t.Fatalf("one verifier package returned %v", err)
	}
}

func TestCreateBootstrapAnchorRequiresExactInputs(t *testing.T) {
	if err := createBootstrapAnchor(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--handoff and --output") {
		t.Fatalf("empty bootstrap anchor request returned %v", err)
	}
	if err := createBootstrapAnchor([]string{"handoff.json"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("positional bootstrap anchor request returned %v", err)
	}
}

func TestCreateOriginIndexPublishesExactAllowlistWithoutOverwrite(t *testing.T) {
	root := t.TempDir()
	channelPath := "/channels/stable/bundle.json"
	artifactPath := "/releases/1.0.0/mesh-linux-bundle.tar"
	for _, path := range []string{channelPath, artifactPath} {
		target := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, "/")))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := onlinerelease.Encode(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   []byte("channel\n"),
		ChannelSignatures: [][]byte{[]byte("channel-signature")},
		ReleaseManifest:   []byte("release\n"),
		ReleaseSignatures: [][]byte{[]byte("release-signature")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "channels/stable/bundle.json"), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "releases/1.0.0/mesh-linux-bundle.tar"), []byte("artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "origin-index.json")
	var output bytes.Buffer
	arguments := []string{"--root", root, "--output", outputPath, "--object", artifactPath, "--object", channelPath}
	if err := createOriginIndex(arguments, &output); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	index, err := releaseorigin.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Objects) != 2 || index.Objects[0].Path != channelPath || index.Objects[1].Path != artifactPath {
		t.Fatalf("unexpected origin index: %+v", index)
	}
	if !strings.Contains(output.String(), "2 explicitly published objects") || strings.Contains(output.String(), string(bundle)) {
		t.Fatalf("unexpected origin authoring output: %q", output.String())
	}
	if err := createOriginIndex(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("origin index overwrite accepted")
	}
}

func TestPublishAndInspectOriginGenerationCommands(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("no-replace origin generation publication is Linux-only")
	}
	sourceRoot := t.TempDir()
	channelPath := "/channels/stable/bundle.json"
	artifactPath := "/releases/1.0.0/mesh-linux-bundle.tar"
	for _, path := range []string{channelPath, artifactPath} {
		target := filepath.Join(sourceRoot, filepath.FromSlash(strings.TrimPrefix(path, "/")))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := onlinerelease.Encode(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   []byte("channel\n"),
		ChannelSignatures: [][]byte{[]byte("channel-signature")},
		ReleaseManifest:   []byte("release\n"),
		ReleaseSignatures: [][]byte{[]byte("release-signature")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "channels/stable/bundle.json"), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "releases/1.0.0/mesh-linux-bundle.tar"), []byte("artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := releaseorigin.BuildIndex(sourceRoot, []string{channelPath, artifactPath})
	if err != nil {
		t.Fatal(err)
	}
	indexRaw, err := releaseorigin.Encode(index)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(t.TempDir(), "origin-index.json")
	if err := releaseorigin.WriteNewIndex(indexPath, indexRaw); err != nil {
		t.Fatal(err)
	}
	generationsRoot := filepath.Join(t.TempDir(), "generations")
	if err := os.Mkdir(generationsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	var publishOutput bytes.Buffer
	arguments := []string{"--source-root", sourceRoot, "--index", indexPath, "--generations-root", generationsRoot}
	if err := publishOriginGeneration(arguments, &publishOutput); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(indexRaw)
	generationPath := filepath.Join(generationsRoot, hex.EncodeToString(digest[:]))
	t.Cleanup(func() {
		_ = filepath.WalkDir(generationPath, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	if !strings.Contains(publishOutput.String(), generationPath) || !strings.Contains(publishOutput.String(), "2 objects") || strings.Contains(publishOutput.String(), string(bundle)) {
		t.Fatalf("unexpected generation publication output: %q", publishOutput.String())
	}
	var inspectOutput bytes.Buffer
	if err := inspectOriginGeneration([]string{"--generation", generationPath}, &inspectOutput); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectOutput.String(), "Validated release-origin generation") || !strings.Contains(inspectOutput.String(), "not release authority") {
		t.Fatalf("unexpected generation inspection output: %q", inspectOutput.String())
	}
	if err := publishOriginGeneration(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("generation command replaced existing publication")
	}
	if err := inspectOriginGeneration(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("generation inspection accepted missing path")
	}
}

func TestOfflineKeyExportAndExactSigningWorkflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private-key operations deliberately fail closed on Windows")
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "signer.private.json")
	publicPath := filepath.Join(directory, "signer.public.json")
	manifestPath := filepath.Join(directory, "release.json")
	signaturePath := filepath.Join(directory, "release.sig.json")

	var output bytes.Buffer
	if err := generateKey([]string{"--private", privatePath}, &output); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private mode = %o", privateInfo.Mode().Perm())
	}
	privateRaw, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateFile, privateKey, err := releasetrust.ParsePrivateKeyFile(privateRaw)
	if err != nil {
		t.Fatal(err)
	}
	clear(privateKey)
	if strings.Contains(output.String(), privateFile.PrivateKey) {
		t.Fatal("generate-key printed private key material")
	}
	if err := generateKey([]string{"--private", privatePath}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("overwrite returned %v", err)
	}

	output.Reset()
	if err := exportPublic([]string{"--private", privatePath, "--public", publicPath}, &output); err != nil {
		t.Fatal(err)
	}
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := releasetrust.ParseTrustedPublicKey(publicRaw)
	if err != nil || trusted.KeyID != privateFile.KeyID {
		t.Fatalf("public export = %+v, %v", trusted, err)
	}
	if strings.Contains(output.String(), privateFile.PrivateKey) {
		t.Fatal("export-public printed private key material")
	}

	artifact := []byte("artifact")
	digest := sha256.Sum256(artifact)
	manifest := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchema, Channel: "stable", Version: "1.0.0", Sequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Artifacts: []releasetrust.Artifact{{OS: "linux", Arch: "amd64", URL: "https://releases.example/meshctl", Size: int64(len(artifact)), SHA256: hex.EncodeToString(digest[:])}},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := sign([]string{"--private", privatePath, "--manifest", manifestPath, "--signature", signaturePath}, &output); err != nil {
		t.Fatal(err)
	}
	signatureRaw, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releasetrust.VerifyManifest(manifestRaw, [][]byte{signatureRaw}, []releasetrust.TrustedKey{trusted}, releasetrust.VerificationPolicy{
		Now: time.Now(), Threshold: 1, MinimumSecurityFloor: 1, SupportedSecurityFloor: 1, PlatformOS: "linux", PlatformArch: "amd64",
	}); err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), manifestRaw...), '\n')
	if _, err := releasetrust.VerifyManifest(tampered, [][]byte{signatureRaw}, []releasetrust.TrustedKey{trusted}, releasetrust.VerificationPolicy{
		Now: time.Now(), Threshold: 1, MinimumSecurityFloor: 1, SupportedSecurityFloor: 1, PlatformOS: "linux", PlatformArch: "amd64",
	}); err == nil {
		t.Fatal("signature accepted different exact bytes")
	}
	if strings.Contains(output.String(), privateFile.PrivateKey) {
		t.Fatal("sign printed private key material")
	}
}

func TestBuildIdentityProducesCanonicalSoleLinkerValue(t *testing.T) {
	var output bytes.Buffer
	err := buildIdentity([]string{
		"--version", "1.2.3-rc.1", "--commit", strings.Repeat("a", 40),
		"--build-time", "2026-07-19T12:34:56Z", "--security-floor", "7",
		"--agent-state-read-min", "1", "--agent-state-read-max", "2",
		"--agent-state-write-version", "2",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := buildinfo.ParseIdentity(strings.TrimSuffix(output.String(), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Version != "1.2.3-rc.1" || identity.Commit != strings.Repeat("a", 40) || identity.BuildTime != "2026-07-19T12:34:56Z" || identity.SecurityFloor != 7 ||
		identity.AgentStateReadMin != 1 || identity.AgentStateReadMax != 2 || identity.AgentStateWriteVersion != 2 {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if err := buildIdentity([]string{"--version", "dev"}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete release identity accepted")
	}
	if err := buildIdentity([]string{
		"--version", "1.2.3", "--commit", strings.Repeat("a", 40),
		"--build-time", "2026-07-19T12:34:56Z", "--security-floor", "7",
		"--agent-state-read-min", "3", "--agent-state-read-max", "2",
		"--agent-state-write-version", "2",
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("reversed agent-state compatibility range accepted")
	}
	if err := buildIdentity([]string{
		"--version", "1.2.3", "--commit", strings.Repeat("a", 40),
		"--build-time", "2026-07-19T12:34:56Z", "--security-floor", "7",
		"--agent-state-read-min", "1", "--agent-state-read-max", "2",
		"--agent-state-write-version", "3",
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("agent-state writer outside its read range accepted")
	}
	if err := buildIdentity([]string{
		"--version", "1.2.3", "--commit", strings.Repeat("a", 40),
		"--build-time", "2026-07-19T12:34:56Z", "--security-floor", "7",
		"--agent-state-read-min", "1", "--agent-state-read-max", "2",
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("release identity without an agent-state writer accepted")
	}
}

func TestInstallerPolicyProducesCanonicalThresholdBootstrapValue(t *testing.T) {
	directory := t.TempDir()
	files := make([]releasetrust.PublicKeyFile, 0, 4)
	for range 4 {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		publicFile, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		clear(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, publicFile)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].KeyID < files[right].KeyID })
	root := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 7, MinimumSecurityFloor: 3,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
		},
	}
	rootRaw, err := releasetrust.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(directory, "1.root.json")
	if err := os.WriteFile(rootPath, rootRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := installerPolicy([]string{"--root", rootPath}, &output); err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSuffix(output.String(), "\n")
	bootstrap, err := installtrust.ParseBootstrapIdentity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.InitialRoot.Document.Channel != "stable" || bootstrap.InitialRoot.Document.Roles.Release.Threshold != 2 || bootstrap.InitialRoot.Document.MinimumReleaseSequence != 7 || bootstrap.InitialRoot.Document.MinimumSecurityFloor != 3 || len(bootstrap.InitialRoot.ReleaseKeys) != 2 {
		t.Fatalf("unexpected encoded bootstrap: %+v", bootstrap)
	}
	if _, _, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{}); err == nil {
		t.Fatal("empty installer bootstrap accepted")
	}
}

func TestPrivateKeyPermissionAndSymlinkChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission and symlink behavior")
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.json")
	if err := generateKey([]string{"--private", privatePath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPrivateKey(privatePath); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("public private-key mode returned %v", err)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPrivateKey(privatePath); err != nil {
		t.Fatalf("0600 private key rejected: %v", err)
	}
	if err := os.Chmod(privatePath, 0o400); err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := loadPrivateKey(privatePath)
	if err != nil {
		t.Fatalf("0400 private key rejected: %v", err)
	}
	clear(privateKey)
	symlink := filepath.Join(directory, "private-link.json")
	if err := os.Symlink(privatePath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPrivateKey(symlink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink private key returned %v", err)
	}
}

func TestNewOutputNoClobberAndPartialCleanup(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(existing, []byte("replace"), 0o600); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("no-clobber returned %v", err)
	}
	content, err := os.ReadFile(existing)
	if err != nil || string(content) != "keep" {
		t.Fatalf("existing output changed: %q, %v", content, err)
	}
	partial := filepath.Join(directory, "partial")
	injected := errors.New("injected write failure")
	err = writeNewFileUsing(partial, []byte("secret"), 0o600, func(file *os.File, _ []byte) error {
		if _, err := file.Write([]byte("s")); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("partial write returned %v", err)
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output was not removed: %v", err)
	}

	syncFailure := filepath.Join(directory, "sync-failure")
	injectedSync := errors.New("injected directory sync failure")
	syncCalls := 0
	err = writeNewFileUsingAndSync(syncFailure, []byte("content"), 0o600, func(file *os.File, content []byte) error {
		_, err := file.Write(content)
		return err
	}, func(string) error {
		syncCalls++
		return injectedSync
	})
	if !errors.Is(err, injectedSync) {
		t.Fatalf("directory sync failure returned %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("sync called %d times, want success-path attempt plus cleanup attempt", syncCalls)
	}
	if _, err := os.Lstat(syncFailure); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output remained after directory sync failure: %v", err)
	}

	success := filepath.Join(directory, "success")
	syncCalls = 0
	if err := writeNewFileUsingAndSync(success, []byte("content"), 0o600, func(file *os.File, content []byte) error {
		_, err := file.Write(content)
		return err
	}, func(string) error {
		syncCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 1 {
		t.Fatalf("successful output synced parent %d times", syncCalls)
	}
}

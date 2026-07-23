//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"mesh/internal/darwinpackagesecurity"
	"mesh/internal/linuxpackagesecurity"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsbundle"
	"mesh/internal/windowspackagesecurity"
)

type releaseManifestOptions struct {
	outputPath                  string
	rootPath                    string
	channel                     string
	version                     string
	sequence                    uint64
	securityFloor               uint64
	issuedAt                    string
	expiresAt                   string
	platformOSes                []string
	platformArches              []string
	artifactURLs                []string
	artifactPaths               []string
	darwinSecurityReceiptPaths  []string
	linuxSecurityReceiptPaths   []string
	windowsSecurityReceiptPaths []string
	windowsAuthenticodeReceipts []string
	enforceDarwinSecurity       bool
	enforceLinuxSecurity        bool
	enforceWindowsSecurity      bool
	allowUnscannedDarwin        bool
	allowUnscannedLinux         bool
	allowUnscannedWindows       bool
}

type releaseArtifactInput struct {
	platformOS   string
	platformArch string
	artifactURL  string
	artifactPath string
}

type channelManifestOptions struct {
	outputPath          string
	rootPath            string
	releaseManifestPath string
	manifestURL         string
	issuedAt            string
	expiresAt           string
}

// manifestGenerationHooks exposes deterministic input-race seams to tests.
// Production generation never installs hooks.
type manifestGenerationHooks struct {
	afterArtifactRead        func(path string)
	afterReleaseManifestRead func(path string)
	afterRootRead            func(path string)
}

func createReleaseManifest(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-release-manifest", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new release manifest file (never overwritten)")
	rootPath := flags.String("root", "", "canonical current release root that supplies channel, epoch, role, and floors")
	version := flags.String("version", "", "canonical release SemVer")
	sequence := flags.Uint64("sequence", 0, "positive channel replay sequence")
	securityFloor := flags.Uint64("security-floor", 0, "optional minimum installer security floor; defaults to and cannot be below the root floor")
	issuedAt := flags.String("issued", "", "canonical UTC RFC3339 issue time")
	expiresAt := flags.String("expires", "", "canonical UTC RFC3339 expiration time")
	var platformOSes repeatedFlag
	var platformArches repeatedFlag
	var artifactURLs repeatedFlag
	var artifactPaths repeatedFlag
	var darwinSecurityReceiptPaths repeatedFlag
	var linuxSecurityReceiptPaths repeatedFlag
	var windowsSecurityReceiptPaths repeatedFlag
	var windowsAuthenticodeReceipts repeatedFlag
	flags.Var(&platformOSes, "os", "artifact operating system (linux, darwin, or windows; repeat once per artifact)")
	flags.Var(&platformArches, "arch", "artifact architecture (amd64 or arm64; repeat once per artifact)")
	flags.Var(&artifactURLs, "artifact-url", "absolute HTTPS artifact URL (repeat once per artifact)")
	flags.Var(&artifactPaths, "artifact", "exact local artifact to hash (repeat once per artifact)")
	flags.Var(&darwinSecurityReceiptPaths, "darwin-package-security-receipt", "canonical security receipt for one exact Darwin artifact (repeat once per Darwin artifact)")
	flags.Var(&linuxSecurityReceiptPaths, "linux-package-security-receipt", "canonical security receipt for one exact Linux artifact (repeat once per Linux artifact)")
	flags.Var(&windowsSecurityReceiptPaths, "windows-package-security-receipt", "canonical security receipt for one exact Windows artifact (repeat once per Windows artifact)")
	flags.Var(&windowsAuthenticodeReceipts, "windows-authenticode-receipt", "fresh native Authenticode receipt for one exact final Windows artifact (repeat once per Windows artifact)")
	allowUnscannedDarwin := flags.Bool("test-only-allow-unscanned-darwin-artifact", false, "explicitly bypass Darwin package security evidence in non-production proofs")
	allowUnscannedLinux := flags.Bool("test-only-allow-unscanned-linux-artifact", false, "explicitly bypass Linux package security evidence in non-production proofs")
	allowUnscannedWindows := flags.Bool("test-only-allow-unscanned-windows-artifact", false, "explicitly bypass Windows package security evidence in non-production proofs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-release-manifest does not accept positional arguments")
	}
	options := releaseManifestOptions{
		outputPath: *outputPath, rootPath: *rootPath, version: *version,
		sequence: *sequence, securityFloor: *securityFloor,
		issuedAt: *issuedAt, expiresAt: *expiresAt,
		platformOSes:                append([]string(nil), platformOSes...),
		platformArches:              append([]string(nil), platformArches...),
		artifactURLs:                append([]string(nil), artifactURLs...),
		artifactPaths:               append([]string(nil), artifactPaths...),
		darwinSecurityReceiptPaths:  append([]string(nil), darwinSecurityReceiptPaths...),
		linuxSecurityReceiptPaths:   append([]string(nil), linuxSecurityReceiptPaths...),
		windowsSecurityReceiptPaths: append([]string(nil), windowsSecurityReceiptPaths...),
		windowsAuthenticodeReceipts: append([]string(nil), windowsAuthenticodeReceipts...),
		enforceDarwinSecurity:       true, enforceLinuxSecurity: true, enforceWindowsSecurity: true,
		allowUnscannedDarwin: *allowUnscannedDarwin,
		allowUnscannedLinux:  *allowUnscannedLinux, allowUnscannedWindows: *allowUnscannedWindows,
	}
	manifest, err := createRootedReleaseManifestUsing(options, manifestGenerationHooks{})
	if err != nil {
		return err
	}
	artifactLabel := "artifacts"
	if len(options.artifactPaths) == 1 {
		artifactLabel = "artifact"
	}
	securityLabels := make([]string, 0, 3)
	if slicesContain(options.platformOSes, "darwin") {
		label := fmt.Sprintf("%d Darwin package security receipts", len(options.darwinSecurityReceiptPaths))
		if options.allowUnscannedDarwin {
			label = "an explicit test-only unscanned-Darwin bypass"
		}
		securityLabels = append(securityLabels, label)
	}
	if slicesContain(options.platformOSes, "linux") {
		label := fmt.Sprintf("%d Linux package security receipts", len(options.linuxSecurityReceiptPaths))
		if options.allowUnscannedLinux {
			label = "an explicit test-only unscanned-Linux bypass"
		}
		securityLabels = append(securityLabels, label)
	}
	if slicesContain(options.platformOSes, "windows") {
		label := fmt.Sprintf("%d Windows package security receipts and %d native Authenticode receipts", len(options.windowsSecurityReceiptPaths), len(options.windowsAuthenticodeReceipts))
		if options.allowUnscannedWindows {
			label = "an explicit test-only unscanned-Windows bypass"
		}
		securityLabels = append(securityLabels, label)
	}
	if len(securityLabels) == 0 {
		securityLabels = append(securityLabels, "no Darwin, Linux, or Windows package artifacts")
	}
	securityLabel := strings.Join(securityLabels, " and ")
	_, err = fmt.Fprintf(output, "Created exact v2 release manifest %s (%d bytes, SHA-256 %s) for root %d epoch %d, binding %d %s with %s and requiring %d release-role signatures. No software was installed or started.\n",
		options.outputPath, manifest.size, manifest.sha256, manifest.rootVersion, manifest.releaseEpoch, len(options.artifactPaths), artifactLabel, securityLabel, manifest.releaseThreshold)
	return err
}

func createChannelManifest(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-channel-manifest", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new channel manifest file (never overwritten)")
	rootPath := flags.String("root", "", "canonical current release root that must authorize the referenced release epoch")
	releaseManifestPath := flags.String("release-manifest", "", "exact local release manifest to pin")
	manifestURL := flags.String("manifest-url", "", "absolute HTTPS URL for those exact release manifest bytes")
	issuedAt := flags.String("issued", "", "canonical UTC RFC3339 issue time")
	expiresAt := flags.String("expires", "", "canonical UTC RFC3339 expiration time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-channel-manifest does not accept positional arguments")
	}
	options := channelManifestOptions{
		outputPath: *outputPath, rootPath: *rootPath, releaseManifestPath: *releaseManifestPath,
		manifestURL: *manifestURL, issuedAt: *issuedAt, expiresAt: *expiresAt,
	}
	manifest, err := createRootedChannelManifestUsing(options, manifestGenerationHooks{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Created exact v2 channel manifest %s (%d bytes, SHA-256 %s) for root %d epoch %d, requiring %d release-role signatures. It pins the exact bytes of %s.\n",
		options.outputPath, manifest.size, manifest.sha256, manifest.rootVersion, manifest.releaseEpoch, manifest.releaseThreshold, options.releaseManifestPath)
	return err
}

type generatedManifestIdentity struct {
	size             int64
	sha256           string
	rootVersion      uint64
	releaseEpoch     uint64
	releaseThreshold int
}

func createRootedReleaseManifestUsing(options releaseManifestOptions, hooks manifestGenerationHooks) (generatedManifestIdentity, error) {
	root, err := readStableCurrentRoot(options.rootPath, hooks.afterRootRead)
	if err != nil {
		return generatedManifestIdentity{}, err
	}
	options.channel = root.Document.Channel
	if options.securityFloor == 0 {
		options.securityFloor = root.Document.MinimumSecurityFloor
	}
	if options.sequence < root.Document.MinimumReleaseSequence {
		return generatedManifestIdentity{}, fmt.Errorf("--sequence %d is below current root floor %d", options.sequence, root.Document.MinimumReleaseSequence)
	}
	if options.securityFloor < root.Document.MinimumSecurityFloor {
		return generatedManifestIdentity{}, fmt.Errorf("--security-floor %d is below current root floor %d", options.securityFloor, root.Document.MinimumSecurityFloor)
	}
	if err := validateReleaseManifestOptions(options); err != nil {
		return generatedManifestIdentity{}, err
	}
	artifacts, err := releaseArtifactsUsing(options, hooks)
	if err != nil {
		return generatedManifestIdentity{}, err
	}
	if options.enforceDarwinSecurity {
		if err := validateDarwinSecurityReceipts(options, artifacts); err != nil {
			return generatedManifestIdentity{}, err
		}
	}
	if options.enforceLinuxSecurity {
		if err := validateLinuxSecurityReceipts(options, artifacts); err != nil {
			return generatedManifestIdentity{}, err
		}
	}
	if options.enforceWindowsSecurity {
		if err := validateWindowsSecurityReceipts(options, artifacts); err != nil {
			return generatedManifestIdentity{}, err
		}
	}
	manifest := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchemaV2, Channel: root.Document.Channel,
		ReleaseEpoch: root.Document.ReleaseEpoch, Version: options.version, Sequence: options.sequence,
		MinimumSecurityFloor: options.securityFloor, IssuedAt: options.issuedAt, ExpiresAt: options.expiresAt,
		Artifacts: artifacts,
	}
	raw, err := marshalCanonicalManifest(manifest)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("encode release manifest: %w", err)
	}
	parsed, err := releasetrust.ParseManifest(raw, releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: root.Document.Channel,
		ExpectedReleaseEpoch: root.Document.ReleaseEpoch, MinimumReleaseEpoch: root.Document.ReleaseEpoch,
		MinimumSequence: root.Document.MinimumReleaseSequence, MinimumSecurityFloor: root.Document.MinimumSecurityFloor,
	})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate root-derived release manifest: %w", err)
	}
	if parsed.Kind != releasetrust.ReleaseManifestKind || parsed.Release == nil {
		return generatedManifestIdentity{}, errors.New("release manifest validation returned an unexpected type")
	}
	if err := writeNewFile(options.outputPath, raw, 0o644); err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("write release manifest: %w", err)
	}
	identity := identityForManifest(raw)
	identity.rootVersion = root.Document.Version
	identity.releaseEpoch = root.Document.ReleaseEpoch
	identity.releaseThreshold = root.Document.Roles.Release.Threshold
	return identity, nil
}

func validateDarwinSecurityReceipts(options releaseManifestOptions, artifacts []releasetrust.Artifact) error {
	darwinArtifacts := make(map[string]releasetrust.Artifact)
	for _, artifact := range artifacts {
		if artifact.OS == "darwin" {
			darwinArtifacts[artifact.Arch] = artifact
		}
	}
	if len(darwinArtifacts) == 0 {
		if len(options.darwinSecurityReceiptPaths) != 0 || options.allowUnscannedDarwin {
			return errors.New("Darwin package security options were supplied without a Darwin artifact")
		}
		return nil
	}
	if options.allowUnscannedDarwin {
		if len(options.darwinSecurityReceiptPaths) != 0 {
			return errors.New("test-only unscanned-Darwin bypass cannot be combined with security receipts")
		}
		return nil
	}
	if len(options.darwinSecurityReceiptPaths) != len(darwinArtifacts) {
		return fmt.Errorf("every Darwin artifact requires one --darwin-package-security-receipt (got %d for %d artifacts)", len(options.darwinSecurityReceiptPaths), len(darwinArtifacts))
	}
	seen := make(map[string]struct{}, len(darwinArtifacts))
	for _, path := range options.darwinSecurityReceiptPaths {
		raw, err := readAuthoringPublicFile("Darwin package security receipt", path, darwinpackagesecurity.MaxReceiptSize)
		if err != nil {
			return err
		}
		receipt, err := darwinpackagesecurity.ParseReceipt(raw)
		if err != nil {
			return err
		}
		artifact, ok := darwinArtifacts[receipt.Candidate.Architecture]
		if !ok {
			return fmt.Errorf("Darwin package security receipt for %s has no release artifact", receipt.Candidate.Architecture)
		}
		if _, duplicate := seen[receipt.Candidate.Architecture]; duplicate {
			return fmt.Errorf("Darwin package security receipt repeats architecture %s", receipt.Candidate.Architecture)
		}
		if err := receipt.MatchArtifact(time.Now(), artifact.Arch, options.version, options.securityFloor, artifact.Size, artifact.SHA256); err != nil {
			return err
		}
		seen[receipt.Candidate.Architecture] = struct{}{}
	}
	return nil
}

func validateLinuxSecurityReceipts(options releaseManifestOptions, artifacts []releasetrust.Artifact) error {
	linuxArtifacts := make(map[string]releasetrust.Artifact)
	for _, artifact := range artifacts {
		if artifact.OS == "linux" {
			linuxArtifacts[artifact.Arch] = artifact
		}
	}
	if len(linuxArtifacts) == 0 {
		if len(options.linuxSecurityReceiptPaths) != 0 || options.allowUnscannedLinux {
			return errors.New("Linux package security options were supplied without a Linux artifact")
		}
		return nil
	}
	if options.allowUnscannedLinux {
		if len(options.linuxSecurityReceiptPaths) != 0 {
			return errors.New("test-only unscanned-Linux bypass cannot be combined with security receipts")
		}
		return nil
	}
	if len(options.linuxSecurityReceiptPaths) != len(linuxArtifacts) {
		return fmt.Errorf("every Linux artifact requires one --linux-package-security-receipt (got %d for %d artifacts)", len(options.linuxSecurityReceiptPaths), len(linuxArtifacts))
	}
	seen := make(map[string]struct{}, len(linuxArtifacts))
	for _, path := range options.linuxSecurityReceiptPaths {
		raw, err := readAuthoringPublicFile("Linux package security receipt", path, linuxpackagesecurity.MaxReceiptSize)
		if err != nil {
			return err
		}
		receipt, err := linuxpackagesecurity.ParseReceipt(raw)
		if err != nil {
			return err
		}
		artifact, ok := linuxArtifacts[receipt.Candidate.Architecture]
		if !ok {
			return fmt.Errorf("Linux package security receipt for %s has no release artifact", receipt.Candidate.Architecture)
		}
		if _, duplicate := seen[receipt.Candidate.Architecture]; duplicate {
			return fmt.Errorf("Linux package security receipt repeats architecture %s", receipt.Candidate.Architecture)
		}
		if err := receipt.MatchArtifact(time.Now(), artifact.Arch, options.version, options.securityFloor, artifact.Size, artifact.SHA256); err != nil {
			return err
		}
		seen[receipt.Candidate.Architecture] = struct{}{}
	}
	return nil
}

func validateWindowsSecurityReceipts(options releaseManifestOptions, artifacts []releasetrust.Artifact) error {
	windowsArtifacts := make(map[string]releasetrust.Artifact)
	for _, artifact := range artifacts {
		if artifact.OS == "windows" {
			windowsArtifacts[artifact.Arch] = artifact
		}
	}
	if len(windowsArtifacts) == 0 {
		if len(options.windowsSecurityReceiptPaths) != 0 || len(options.windowsAuthenticodeReceipts) != 0 || options.allowUnscannedWindows {
			return errors.New("Windows package security options were supplied without a Windows artifact")
		}
		return nil
	}
	if options.allowUnscannedWindows {
		if len(options.windowsSecurityReceiptPaths) != 0 || len(options.windowsAuthenticodeReceipts) != 0 {
			return errors.New("test-only unscanned-Windows bypass cannot be combined with package-security or Authenticode receipts")
		}
		return nil
	}
	if len(options.windowsSecurityReceiptPaths) != len(windowsArtifacts) {
		return fmt.Errorf("every Windows artifact requires one --windows-package-security-receipt (got %d for %d artifacts)", len(options.windowsSecurityReceiptPaths), len(windowsArtifacts))
	}
	if len(options.windowsAuthenticodeReceipts) != len(windowsArtifacts) {
		return fmt.Errorf("every Windows artifact requires one --windows-authenticode-receipt (got %d for %d artifacts)", len(options.windowsAuthenticodeReceipts), len(windowsArtifacts))
	}
	seen := make(map[string]struct{}, len(windowsArtifacts))
	for _, path := range options.windowsSecurityReceiptPaths {
		raw, err := readAuthoringPublicFile("Windows package security receipt", path, windowspackagesecurity.MaxReceiptSize)
		if err != nil {
			return err
		}
		receipt, err := windowspackagesecurity.ParseReceipt(raw)
		if err != nil {
			return err
		}
		artifact, ok := windowsArtifacts[receipt.Candidate.Architecture]
		if !ok {
			return fmt.Errorf("Windows package security receipt for %s has no release artifact", receipt.Candidate.Architecture)
		}
		if _, duplicate := seen[receipt.Candidate.Architecture]; duplicate {
			return fmt.Errorf("Windows package security receipt repeats architecture %s", receipt.Candidate.Architecture)
		}
		if err := receipt.MatchArtifact(time.Now(), artifact.Arch, options.version, options.securityFloor, artifact.Size, artifact.SHA256); err != nil {
			return err
		}
		seen[receipt.Candidate.Architecture] = struct{}{}
	}
	policy, err := windowsauthenticode.LoadPolicy()
	if err != nil {
		return fmt.Errorf("load release-authoring Windows Authenticode policy: %w", err)
	}
	artifactPaths := make(map[string]string, len(windowsArtifacts))
	for index, platformOS := range options.platformOSes {
		if platformOS == "windows" {
			artifactPaths[options.platformArches[index]] = options.artifactPaths[index]
		}
	}
	seen = make(map[string]struct{}, len(windowsArtifacts))
	for _, path := range options.windowsAuthenticodeReceipts {
		raw, err := readAuthoringPublicFile("Windows Authenticode receipt", path, windowsauthenticode.MaximumReceiptSize)
		if err != nil {
			return err
		}
		receipt, err := windowsauthenticode.ParseReceipt(raw)
		if err != nil {
			return err
		}
		artifact, ok := windowsArtifacts[receipt.Architecture]
		if !ok {
			return fmt.Errorf("Windows Authenticode receipt for %s has no release artifact", receipt.Architecture)
		}
		if _, duplicate := seen[receipt.Architecture]; duplicate {
			return fmt.Errorf("Windows Authenticode receipt repeats architecture %s", receipt.Architecture)
		}
		artifactRaw, err := readAuthoringPublicFile("final signed Windows artifact", artifactPaths[receipt.Architecture], int(windowsbundle.MaxArchiveSize))
		if err != nil {
			return err
		}
		artifactDigest := sha256.Sum256(artifactRaw)
		if int64(len(artifactRaw)) != artifact.Size || hex.EncodeToString(artifactDigest[:]) != artifact.SHA256 {
			return errors.New("final signed Windows artifact changed after release-manifest hashing")
		}
		expanded, err := windowsbundle.InspectCandidateArchive(artifactRaw)
		if err != nil {
			return fmt.Errorf("inspect final signed Windows artifact for native receipt: %w", err)
		}
		if expanded.Inspection.Package.Schema != windowsbundle.SignedSchema || expanded.Inspection.Package.Target.Arch != receipt.Architecture {
			return errors.New("Windows Authenticode receipt requires the matching final signed bundle-v3 artifact")
		}
		identities := windowsAuthenticodeArtifactIdentities(expanded)
		if err := receipt.Match(time.Now(), policy.SHA256, receipt.Architecture, identities); err != nil {
			return err
		}
		seen[receipt.Architecture] = struct{}{}
	}
	return nil
}

func windowsAuthenticodeArtifactIdentities(expanded windowsbundle.ExpandedCandidate) []windowsauthenticode.ArtifactIdentity {
	arch := expanded.Inspection.Package.Target.Arch
	wanted := map[string]struct{}{
		"bin/dist/windows/wintun/bin/" + arch + "/wintun.dll": {},
		"bin/meshctl.exe": {}, "bin/nebula-cert.exe": {}, "bin/nebula.exe": {},
	}
	identities := make([]windowsauthenticode.ArtifactIdentity, 0, len(wanted))
	for _, file := range expanded.Files {
		if _, ok := wanted[file.Path]; !ok {
			continue
		}
		digest := sha256.Sum256(file.Content)
		identities = append(identities, windowsauthenticode.ArtifactIdentity{
			Path: file.Path, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(file.Content)),
		})
	}
	return identities
}

func slicesContain(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func createRootedChannelManifestUsing(options channelManifestOptions, hooks manifestGenerationHooks) (generatedManifestIdentity, error) {
	if err := validateChannelManifestOptions(options); err != nil {
		return generatedManifestIdentity{}, err
	}
	root, err := readStableCurrentRoot(options.rootPath, hooks.afterRootRead)
	if err != nil {
		return generatedManifestIdentity{}, err
	}
	releaseRaw, releaseIdentity, err := readStableManifestInput(options.releaseManifestPath, releasetrust.MaxManifestSize, hooks.afterReleaseManifestRead)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("read exact release manifest: %w", err)
	}
	parsedRelease, err := releasetrust.ParseManifest(releaseRaw, releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: root.Document.Channel,
		ExpectedReleaseEpoch: root.Document.ReleaseEpoch, MinimumReleaseEpoch: root.Document.ReleaseEpoch,
		MinimumSequence: root.Document.MinimumReleaseSequence, MinimumSecurityFloor: root.Document.MinimumSecurityFloor,
	})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate release manifest against current root: %w", err)
	}
	if parsedRelease.Kind != releasetrust.ReleaseManifestKind || parsedRelease.Release == nil || parsedRelease.Release.Schema != releasetrust.ReleaseSchemaV2 {
		return generatedManifestIdentity{}, errors.New("--release-manifest must contain root-aware v2 release metadata")
	}
	release := parsedRelease.Release
	manifest := releasetrust.ChannelManifest{
		Schema: releasetrust.ChannelSchemaV2, Channel: root.Document.Channel, ReleaseEpoch: root.Document.ReleaseEpoch,
		Sequence: release.Sequence, MinimumSecurityFloor: release.MinimumSecurityFloor,
		IssuedAt: options.issuedAt, ExpiresAt: options.expiresAt,
		Release: releasetrust.ReleaseReference{
			Version: release.Version, Sequence: release.Sequence,
			ManifestURL: options.manifestURL, ManifestSize: releaseIdentity.size,
			ManifestSHA256: releaseIdentity.sha256,
		},
	}
	raw, err := marshalCanonicalManifest(manifest)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("encode channel manifest: %w", err)
	}
	parsed, err := releasetrust.ParseManifest(raw, releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: root.Document.Channel,
		ExpectedReleaseEpoch: root.Document.ReleaseEpoch, MinimumReleaseEpoch: root.Document.ReleaseEpoch,
		MinimumSequence: root.Document.MinimumReleaseSequence, MinimumSecurityFloor: root.Document.MinimumSecurityFloor,
	})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate root-derived channel manifest: %w", err)
	}
	if parsed.Kind != releasetrust.ChannelManifestKind || parsed.Channel == nil {
		return generatedManifestIdentity{}, errors.New("channel manifest validation returned an unexpected type")
	}
	if err := writeNewFile(options.outputPath, raw, 0o644); err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("write channel manifest: %w", err)
	}
	identity := identityForManifest(raw)
	identity.rootVersion = root.Document.Version
	identity.releaseEpoch = root.Document.ReleaseEpoch
	identity.releaseThreshold = root.Document.Roles.Release.Threshold
	return identity, nil
}

func readStableCurrentRoot(path string, afterRead func(string)) (releasetrust.ParsedRoot, error) {
	if strings.TrimSpace(path) == "" {
		return releasetrust.ParsedRoot{}, errors.New("--root is required")
	}
	raw, _, err := readStableManifestInput(path, releasetrust.MaxRootSize, afterRead)
	if err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("read current root: %w", err)
	}
	root, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("parse current root: %w", err)
	}
	if err := releasetrust.ValidateCurrentRoot(root, time.Now().UTC(), 0); err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("current root validity: %w", err)
	}
	return root, nil
}

func releaseArtifactsUsing(options releaseManifestOptions, hooks manifestGenerationHooks) ([]releasetrust.Artifact, error) {
	inputs := make([]releaseArtifactInput, len(options.platformOSes))
	for index := range inputs {
		inputs[index] = releaseArtifactInput{
			platformOS: options.platformOSes[index], platformArch: options.platformArches[index],
			artifactURL: options.artifactURLs[index], artifactPath: options.artifactPaths[index],
		}
	}
	sort.Slice(inputs, func(left, right int) bool {
		if inputs[left].platformOS != inputs[right].platformOS {
			return inputs[left].platformOS < inputs[right].platformOS
		}
		return inputs[left].platformArch < inputs[right].platformArch
	})
	artifacts := make([]releasetrust.Artifact, len(inputs))
	for index, input := range inputs {
		role := fmt.Sprintf("artifact %s/%s", input.platformOS, input.platformArch)
		identity, err := hashStableManifestInput(role, input.artifactPath, releasetrust.MaxArtifactSize, hooks.afterArtifactRead)
		if err != nil {
			return nil, err
		}
		artifacts[index] = releasetrust.Artifact{
			OS: input.platformOS, Arch: input.platformArch, URL: input.artifactURL,
			Size: identity.size, SHA256: identity.sha256,
		}
	}
	return artifacts, nil
}

// createLegacyV1ReleaseManifestForTestUsing preserves the pre-root generator
// only for compatibility tests. No production command calls this helper.
func createLegacyV1ReleaseManifestForTestUsing(options releaseManifestOptions, hooks manifestGenerationHooks) (generatedManifestIdentity, error) {
	if err := validateReleaseManifestOptions(options); err != nil {
		return generatedManifestIdentity{}, err
	}
	artifacts, err := releaseArtifactsUsing(options, hooks)
	if err != nil {
		return generatedManifestIdentity{}, err
	}
	manifest := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchema, Channel: options.channel,
		Version: options.version, Sequence: options.sequence,
		MinimumSecurityFloor: options.securityFloor,
		IssuedAt:             options.issuedAt, ExpiresAt: options.expiresAt,
		Artifacts: artifacts,
	}
	raw, err := marshalCanonicalManifest(manifest)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("encode release manifest: %w", err)
	}
	parsed, err := releasetrust.ParseManifest(raw, releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: options.channel,
	})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate release manifest: %w", err)
	}
	if parsed.Kind != releasetrust.ReleaseManifestKind || parsed.Release == nil {
		return generatedManifestIdentity{}, errors.New("release manifest validation returned an unexpected type")
	}
	if err := writeNewFile(options.outputPath, raw, 0o644); err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("write release manifest: %w", err)
	}
	return identityForManifest(raw), nil
}

// createLegacyV1ChannelManifestForTestUsing preserves deterministic v1 fixture
// generation. New production metadata always requires a current root.
func createLegacyV1ChannelManifestForTestUsing(options channelManifestOptions, hooks manifestGenerationHooks) (generatedManifestIdentity, error) {
	if err := validateChannelManifestOptions(options); err != nil {
		return generatedManifestIdentity{}, err
	}
	releaseRaw, releaseIdentity, err := readStableManifestInput(options.releaseManifestPath, releasetrust.MaxManifestSize, hooks.afterReleaseManifestRead)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("read exact release manifest: %w", err)
	}
	parsedRelease, err := releasetrust.ParseManifest(releaseRaw, releasetrust.VerificationPolicy{Now: time.Now()})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate release manifest: %w", err)
	}
	if parsedRelease.Kind != releasetrust.ReleaseManifestKind || parsedRelease.Release == nil {
		return generatedManifestIdentity{}, errors.New("--release-manifest must contain a release manifest")
	}
	release := parsedRelease.Release
	manifest := releasetrust.ChannelManifest{
		Schema: releasetrust.ChannelSchema, Channel: release.Channel,
		Sequence: release.Sequence, MinimumSecurityFloor: release.MinimumSecurityFloor,
		IssuedAt: options.issuedAt, ExpiresAt: options.expiresAt,
		Release: releasetrust.ReleaseReference{
			Version: release.Version, Sequence: release.Sequence,
			ManifestURL: options.manifestURL, ManifestSize: releaseIdentity.size,
			ManifestSHA256: releaseIdentity.sha256,
		},
	}
	raw, err := marshalCanonicalManifest(manifest)
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("encode channel manifest: %w", err)
	}
	parsed, err := releasetrust.ParseManifest(raw, releasetrust.VerificationPolicy{
		Now: time.Now(), ExpectedChannel: release.Channel,
	})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("validate channel manifest: %w", err)
	}
	if parsed.Kind != releasetrust.ChannelManifestKind || parsed.Channel == nil {
		return generatedManifestIdentity{}, errors.New("channel manifest validation returned an unexpected type")
	}
	if err := writeNewFile(options.outputPath, raw, 0o644); err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("write channel manifest: %w", err)
	}
	return identityForManifest(raw), nil
}

func validateReleaseManifestOptions(options releaseManifestOptions) error {
	required := []struct {
		name  string
		value string
	}{
		{"--output", options.outputPath}, {"--channel", options.channel},
		{"--version", options.version}, {"--issued", options.issuedAt},
		{"--expires", options.expiresAt},
	}
	for _, option := range required {
		if strings.TrimSpace(option.value) == "" {
			return fmt.Errorf("%s is required", option.name)
		}
	}
	if options.sequence == 0 {
		return errors.New("--sequence must be positive")
	}
	if options.securityFloor == 0 {
		return errors.New("--security-floor must be positive")
	}
	counts := []int{len(options.platformOSes), len(options.platformArches), len(options.artifactURLs), len(options.artifactPaths)}
	if counts[0] != counts[1] || counts[0] != counts[2] || counts[0] != counts[3] {
		return fmt.Errorf("--os, --arch, --artifact-url, and --artifact must have equal counts (got %d, %d, %d, and %d)", counts[0], counts[1], counts[2], counts[3])
	}
	if counts[0] == 0 {
		return errors.New("--os, --arch, --artifact-url, and --artifact are required")
	}
	targets := make(map[string]struct{}, counts[0])
	for index := range options.platformOSes {
		values := []struct {
			name  string
			value string
		}{
			{"--os", options.platformOSes[index]},
			{"--arch", options.platformArches[index]},
			{"--artifact-url", options.artifactURLs[index]},
			{"--artifact", options.artifactPaths[index]},
		}
		for _, value := range values {
			if strings.TrimSpace(value.value) == "" {
				return fmt.Errorf("%s occurrence %d cannot be empty", value.name, index+1)
			}
		}
		platformOS, platformArch := options.platformOSes[index], options.platformArches[index]
		if !supportedReleaseArtifactTarget(platformOS, platformArch) {
			return fmt.Errorf("artifact %d has unsupported target %q/%q (supported: linux, darwin, or windows with amd64 or arm64)", index+1, platformOS, platformArch)
		}
		target := platformOS + "\x00" + platformArch
		if _, duplicate := targets[target]; duplicate {
			return fmt.Errorf("duplicate artifact target %s/%s", platformOS, platformArch)
		}
		targets[target] = struct{}{}
	}
	return nil
}

func supportedReleaseArtifactTarget(platformOS, platformArch string) bool {
	return (platformOS == "linux" || platformOS == "darwin" || platformOS == "windows") &&
		(platformArch == "amd64" || platformArch == "arm64")
}

func validateChannelManifestOptions(options channelManifestOptions) error {
	required := []struct {
		name  string
		value string
	}{
		{"--output", options.outputPath},
		{"--release-manifest", options.releaseManifestPath},
		{"--manifest-url", options.manifestURL},
		{"--issued", options.issuedAt},
		{"--expires", options.expiresAt},
	}
	for _, option := range required {
		if strings.TrimSpace(option.value) == "" {
			return fmt.Errorf("%s is required", option.name)
		}
	}
	return nil
}

func marshalCanonicalManifest(manifest any) ([]byte, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > releasetrust.MaxManifestSize {
		return nil, fmt.Errorf("manifest exceeds %d bytes", releasetrust.MaxManifestSize)
	}
	return append(raw, '\n'), nil
}

func hashStableManifestInput(role, path string, limit int64, afterRead func(string)) (generatedManifestIdentity, error) {
	input, err := openSnapshotInput(snapshotInputSpec{role: role, path: path, limit: limit})
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("open %s %q: %w", role, path, err)
	}
	defer input.file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(input.file, input.identity.size+1))
	if err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("hash %s %q: %w", role, path, err)
	}
	if written != input.identity.size {
		return generatedManifestIdentity{}, fmt.Errorf("%s %q was truncated or appended while hashing", role, path)
	}
	if afterRead != nil {
		afterRead(path)
	}
	if err := validateOpenedSnapshotInput(input); err != nil {
		return generatedManifestIdentity{}, fmt.Errorf("%s %q changed while hashing: %w", role, path, err)
	}
	return generatedManifestIdentity{size: written, sha256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func readStableManifestInput(path string, limit int, afterRead func(string)) ([]byte, generatedManifestIdentity, error) {
	input, err := openSnapshotInput(snapshotInputSpec{role: "release manifest", path: path, limit: int64(limit)})
	if err != nil {
		return nil, generatedManifestIdentity{}, err
	}
	defer input.file.Close()
	raw, err := io.ReadAll(io.LimitReader(input.file, input.identity.size+1))
	if err != nil {
		return nil, generatedManifestIdentity{}, err
	}
	if int64(len(raw)) != input.identity.size {
		return nil, generatedManifestIdentity{}, errors.New("release manifest was truncated or appended while reading")
	}
	if afterRead != nil {
		afterRead(path)
	}
	if err := validateOpenedSnapshotInput(input); err != nil {
		return nil, generatedManifestIdentity{}, err
	}
	return raw, identityForManifest(raw), nil
}

func identityForManifest(raw []byte) generatedManifestIdentity {
	digest := sha256.Sum256(raw)
	return generatedManifestIdentity{size: int64(len(raw)), sha256: hex.EncodeToString(digest[:])}
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"mesh/internal/bootstrapverify"
	"mesh/internal/installerinspect"
	releasetrust "mesh/internal/release"
)

func createBootstrapManifest(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-bootstrap-manifest", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new canonical bootstrap manifest (never overwritten)")
	rootPath := flags.String("root", "", "canonical version-1, epoch-1 release root")
	installerPath := flags.String("installer", "", "exact production mesh-install ELF")
	platformOS := flags.String("os", "linux", "installer operating system: linux or windows")
	arch := flags.String("arch", "", "installer architecture: amd64 or arm64")
	issuedText := flags.String("issued", "", "canonical UTC RFC3339 issue time")
	expiresText := flags.String("expires", "", "canonical UTC RFC3339 expiration time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-bootstrap-manifest does not accept positional arguments")
	}
	if strings.TrimSpace(*outputPath) == "" || strings.TrimSpace(*rootPath) == "" || strings.TrimSpace(*installerPath) == "" || strings.TrimSpace(*arch) == "" || strings.TrimSpace(*issuedText) == "" || strings.TrimSpace(*expiresText) == "" {
		return errors.New("--output, --root, --installer, --arch, --issued, and --expires are required")
	}
	rootRaw, err := readAuthoringPublicFile("bootstrap root", *rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read bootstrap root: %w", err)
	}
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		return fmt.Errorf("parse bootstrap root: %w", err)
	}
	if root.Document.Version != 1 || root.Document.ReleaseEpoch != 1 {
		return errors.New("bootstrap manifest requires root version 1 and release epoch 1")
	}
	installer, err := readAuthoringPublicFile("bootstrap installer", *installerPath, int(releasetrust.MaxBootstrapArtifactSize))
	if err != nil {
		return fmt.Errorf("read bootstrap installer: %w", err)
	}
	inspection, err := installerinspect.InspectBootstrap(installer, strings.TrimSpace(*platformOS), *arch)
	if err != nil {
		return fmt.Errorf("inspect bootstrap installer: %w", err)
	}
	if inspection.Bootstrap.InitialRootSHA256 != root.SHA256 {
		return errors.New("installer compiled bootstrap root differs from the authorizing root")
	}
	artifactDigest := sha256.Sum256(installer)
	artifactName := "mesh-install"
	if strings.TrimSpace(*platformOS) == "windows" {
		artifactName = "mesh-install-windows.exe"
	}
	document := releasetrust.BootstrapManifest{
		Schema: releasetrust.BootstrapManifestSchema, Channel: root.Document.Channel,
		RootVersion: 1, ReleaseEpoch: 1, RootSHA256: root.SHA256,
		InstallerBootstrapSHA256: inspection.Bootstrap.SHA256,
		IssuedAt:                 strings.TrimSpace(*issuedText), ExpiresAt: strings.TrimSpace(*expiresText),
		Build: inspection.Identity, GoVersion: inspection.GoVersion,
		Artifact: releasetrust.BootstrapArtifact{
			Name: artifactName, OS: strings.TrimSpace(*platformOS), Arch: *arch, Size: int64(len(installer)),
			SHA256: hex.EncodeToString(artifactDigest[:]),
		},
	}
	raw, err := releasetrust.EncodeBootstrapManifest(document)
	if err != nil {
		return err
	}
	issuedAt, err := parseCommandTime(document.IssuedAt, "--issued")
	if err != nil {
		return err
	}
	expiresAt, err := parseCommandTime(document.ExpiresAt, "--expires")
	if err != nil {
		return err
	}
	if err := releasetrust.ValidateCurrentRoot(root, issuedAt, 0); err != nil {
		return fmt.Errorf("bootstrap root at manifest issuance: %w", err)
	}
	if issuedAt.Before(root.IssuedAt) || expiresAt.After(root.ExpiresAt) {
		return errors.New("bootstrap manifest validity must stay within the authorizing root validity")
	}
	if document.Build.SecurityFloor < root.Document.MinimumSecurityFloor {
		return errors.New("bootstrap build security floor is below the authorizing root floor")
	}
	if err := writeAuthoringPublicFile("bootstrap manifest", *outputPath, raw, 0o644); err != nil {
		return err
	}
	manifestDigest := sha256.Sum256(raw)
	_, err = fmt.Fprintf(output, "Created root-authorizable %s/%s bootstrap manifest SHA-256 %s for installer SHA-256 %s and root SHA-256 %s at %s. No signature was created and no software was executed.\n",
		document.Artifact.OS, *arch, hex.EncodeToString(manifestDigest[:]), document.Artifact.SHA256, root.SHA256, *outputPath)
	return err
}

func verifyBootstrap(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-bootstrap", flag.ContinueOnError)
	rootPath := flags.String("root", "", "canonical version-1 root obtained with the bootstrap materials")
	expectedRootSHA := flags.String("expected-root-sha256", "", "root digest authenticated through an independent channel")
	handoffPath := flags.String("handoff", "", "canonical bootstrap handoff obtained with the courier materials")
	expectedHandoffSHA := flags.String("expected-handoff-sha256", "", "handoff digest authenticated through an independent channel")
	handoffAnchorPath := flags.String("handoff-anchor", "", "canonical bootstrap anchor transferred independently of the release origin")
	manifestPath := flags.String("manifest", "", "canonical root-authorized bootstrap manifest")
	installerPath := flags.String("installer", "", "downloaded mesh-install ELF to authenticate")
	nowText := flags.String("now", "", "optional fixed canonical UTC RFC3339 verification time")
	var signaturePaths repeatedFlag
	flags.Var(&signaturePaths, "signature", "detached root-role bootstrap signature (repeat)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-bootstrap does not accept positional arguments")
	}
	if strings.TrimSpace(*rootPath) == "" || strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*installerPath) == "" || len(signaturePaths) == 0 {
		return errors.New("--root, --manifest, --installer, and at least one --signature are required")
	}
	directRootMode := strings.TrimSpace(*expectedRootSHA) != ""
	handoffProvided := strings.TrimSpace(*handoffPath) != ""
	directHandoffMode := strings.TrimSpace(*expectedHandoffSHA) != ""
	anchorHandoffMode := strings.TrimSpace(*handoffAnchorPath) != ""
	handoffMode := handoffProvided && directHandoffMode != anchorHandoffMode
	if (directRootMode && (handoffProvided || directHandoffMode || anchorHandoffMode)) || (!directRootMode && !handoffMode) {
		return errors.New("use exactly one trust anchor: --expected-root-sha256, --handoff with --expected-handoff-sha256, or --handoff with --handoff-anchor")
	}
	now := time.Now().UTC()
	if *nowText != "" {
		parsed, err := parseCommandTime(*nowText, "--now")
		if err != nil {
			return err
		}
		now = parsed
	}
	var result bootstrapverify.Result
	var err error
	if handoffMode {
		result, err = bootstrapverify.VerifyHandoffFiles(bootstrapverify.HandoffFileInput{
			HandoffPath: *handoffPath, ExpectedHandoffSHA256: *expectedHandoffSHA, AnchorPath: *handoffAnchorPath, RootPath: *rootPath,
			ManifestPath: *manifestPath, SignaturePaths: append([]string(nil), signaturePaths...),
			InstallerPath: *installerPath, Now: now,
		})
	} else {
		result, err = bootstrapverify.VerifyFiles(bootstrapverify.FileInput{
			RootPath: *rootPath, ExpectedRootSHA256: *expectedRootSHA,
			ManifestPath: *manifestPath, SignaturePaths: append([]string(nil), signaturePaths...),
			InstallerPath: *installerPath, Now: now,
		})
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode bootstrap verification result: %w", err)
	}
	return nil
}

func parseCommandTime(value, flagName string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must be canonical UTC RFC3339 without fractional seconds", flagName)
	}
	return parsed.UTC(), nil
}

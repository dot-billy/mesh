package bootstrapverify

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"mesh/internal/bootstrapanchor"
	"mesh/internal/bootstraphandoff"
	releasetrust "mesh/internal/release"
)

// FileInput names untrusted courier files. Every file is read as one stable,
// bounded regular-file snapshot before Verify authenticates its contents.
type FileInput struct {
	RootPath           string
	ExpectedRootSHA256 string
	ManifestPath       string
	SignaturePaths     []string
	InstallerPath      string
	Now                time.Time
}

// HandoffFileInput uses exactly one independent authority: either an exact
// handoff digest or a small bootstrap anchor file transferred outside the
// release origin. It selects and binds the exact root and verifier package for
// the current operating system and architecture. The selected verifier package must be
// authenticated before this already-extracted verifier is executed.
type HandoffFileInput struct {
	HandoffPath           string
	ExpectedHandoffSHA256 string
	AnchorPath            string
	RootPath              string
	ManifestPath          string
	SignaturePaths        []string
	InstallerPath         string
	Now                   time.Time
}

func VerifyFiles(input FileInput) (Result, error) {
	if strings.TrimSpace(input.RootPath) == "" || strings.TrimSpace(input.ManifestPath) == "" || strings.TrimSpace(input.InstallerPath) == "" {
		return Result{}, errors.New("bootstrap root, manifest, and installer paths are required")
	}
	if !digestPattern.MatchString(input.ExpectedRootSHA256) {
		return Result{}, errors.New("expected root SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(input.SignaturePaths) == 0 || len(input.SignaturePaths) > releasetrust.MaxSignatureEnvelopes {
		return Result{}, fmt.Errorf("bootstrap signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	for index, path := range input.SignaturePaths {
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("bootstrap signature %d path cannot be empty", index)
		}
	}

	root, err := readStableRegularFile("bootstrap root", input.RootPath, int64(releasetrust.MaxRootSize))
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap root: %w", err)
	}
	// Authenticate the small independent anchor before opening the larger
	// courier-provided manifest, signatures, or installer.
	if _, err := authenticateRoot(root, input.ExpectedRootSHA256); err != nil {
		return Result{}, err
	}
	manifest, err := readStableRegularFile("bootstrap manifest", input.ManifestPath, int64(releasetrust.MaxManifestSize))
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	signatures := make([][]byte, len(input.SignaturePaths))
	for index, path := range input.SignaturePaths {
		signature, err := readStableRegularFile("bootstrap signature", path, int64(releasetrust.MaxEnvelopeSize))
		if err != nil {
			return Result{}, fmt.Errorf("read bootstrap signature %d: %w", index, err)
		}
		signatures[index] = signature
	}
	installer, err := readStableRegularFile("bootstrap installer", input.InstallerPath, releasetrust.MaxBootstrapArtifactSize)
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap installer: %w", err)
	}
	result, err := Verify(Input{
		Root: root, ExpectedRootSHA256: input.ExpectedRootSHA256,
		Manifest: manifest, Signatures: signatures, Installer: installer, Now: input.Now,
	})
	if err != nil {
		return Result{}, err
	}
	return bindPlatformAuthenticode(result, input.InstallerPath)
}

// VerifyHandoffFiles authenticates the small handoff before opening the root,
// then authenticates that root before opening the larger courier manifest,
// signatures, or installer.
func VerifyHandoffFiles(input HandoffFileInput) (Result, error) {
	if strings.TrimSpace(input.HandoffPath) == "" || strings.TrimSpace(input.RootPath) == "" || strings.TrimSpace(input.ManifestPath) == "" || strings.TrimSpace(input.InstallerPath) == "" {
		return Result{}, errors.New("bootstrap handoff, root, manifest, and installer paths are required")
	}
	directDigestMode := strings.TrimSpace(input.ExpectedHandoffSHA256) != ""
	anchorMode := strings.TrimSpace(input.AnchorPath) != ""
	if directDigestMode == anchorMode {
		return Result{}, errors.New("use exactly one independent handoff authority: expected handoff SHA-256 or bootstrap anchor path")
	}
	if directDigestMode && !digestPattern.MatchString(input.ExpectedHandoffSHA256) {
		return Result{}, errors.New("expected handoff SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(input.SignaturePaths) == 0 || len(input.SignaturePaths) > releasetrust.MaxSignatureEnvelopes {
		return Result{}, fmt.Errorf("bootstrap signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	for index, path := range input.SignaturePaths {
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("bootstrap signature %d path cannot be empty", index)
		}
	}
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	arch := runtime.GOARCH
	platformOS := runtime.GOOS
	var anchor []byte
	if anchorMode {
		var err error
		anchor, err = readStableRegularFile("bootstrap anchor", input.AnchorPath, int64(bootstrapanchor.MaxDocumentSize))
		if err != nil {
			return Result{}, fmt.Errorf("read bootstrap anchor: %w", err)
		}
	}
	handoff, err := readStableRegularFile("bootstrap handoff", input.HandoffPath, int64(bootstraphandoff.MaxDocumentSize))
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap handoff: %w", err)
	}
	// Do not open even the root until the independent authority has authenticated
	// the courier handoff's exact bytes and current validity.
	expectedHandoffSHA256 := input.ExpectedHandoffSHA256
	anchorSHA256 := ""
	if anchorMode {
		anchorResolution, err := bootstrapanchor.Resolve(anchor, handoff, now)
		if err != nil {
			return Result{}, err
		}
		expectedHandoffSHA256 = anchorResolution.HandoffSHA256
		anchorSHA256 = anchorResolution.AnchorSHA256
	} else if _, err := bootstraphandoff.Authenticate(handoff, expectedHandoffSHA256, now); err != nil {
		return Result{}, err
	}
	root, err := readStableRegularFile("bootstrap root", input.RootPath, int64(releasetrust.MaxRootSize))
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap root: %w", err)
	}
	resolution, err := bootstraphandoff.Resolve(handoff, expectedHandoffSHA256, root, platformOS, arch, now)
	if err != nil {
		return Result{}, err
	}
	manifest, err := readStableRegularFile("bootstrap manifest", input.ManifestPath, int64(releasetrust.MaxManifestSize))
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	signatures := make([][]byte, len(input.SignaturePaths))
	for index, path := range input.SignaturePaths {
		signature, err := readStableRegularFile("bootstrap signature", path, int64(releasetrust.MaxEnvelopeSize))
		if err != nil {
			return Result{}, fmt.Errorf("read bootstrap signature %d: %w", index, err)
		}
		signatures[index] = signature
	}
	installer, err := readStableRegularFile("bootstrap installer", input.InstallerPath, releasetrust.MaxBootstrapArtifactSize)
	if err != nil {
		return Result{}, fmt.Errorf("read bootstrap installer: %w", err)
	}
	result, err := Verify(Input{
		Root: root, ExpectedRootSHA256: resolution.RootSHA256,
		Manifest: manifest, Signatures: signatures, Installer: installer, Now: now,
	})
	if err != nil {
		return Result{}, err
	}
	result, err = bindPlatformAuthenticode(result, input.InstallerPath)
	if err != nil {
		return Result{}, err
	}
	if result.OS != resolution.Verifier.OS || result.Arch != resolution.Verifier.Arch {
		return Result{}, errors.New("root-authorized installer platform differs from the authenticated handoff selection")
	}
	result.Schema = HandoffResultSchema
	if anchorMode {
		result.Schema = AnchorResultSchema
		result.AnchorSHA256 = anchorSHA256
	}
	result.HandoffSHA256 = resolution.HandoffSHA256
	result.VerifierPackageSHA256 = resolution.Verifier.SHA256
	return result, nil
}

func bindPlatformAuthenticode(result Result, installerPath string) (Result, error) {
	verification, err := verifyPlatformAuthenticode(result.OS, installerPath)
	if err != nil {
		return Result{}, fmt.Errorf("verify bootstrap installer Authenticode: %w", err)
	}
	if result.OS == "windows" {
		if !digestPattern.MatchString(result.AuthenticodePolicySHA256) {
			return Result{}, errors.New("Windows bootstrap installer has no statically authenticated publisher policy")
		}
		if runtime.GOOS == "windows" && verification.PolicySHA256 != result.AuthenticodePolicySHA256 {
			return Result{}, errors.New("Windows installer publisher policy differs from the standalone verifier policy")
		}
	}
	if result.OS == "windows" && runtime.GOOS == "windows" {
		result.AuthenticodeSignerSPKI = verification.SignerSPKISHA256
		result.AuthenticodeCertificate = verification.CertificateSHA256
	}
	return result, nil
}

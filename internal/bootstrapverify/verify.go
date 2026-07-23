// Package bootstrapverify authenticates a separately distributed first
// installer without executing it or mutating the host. It intentionally has
// no signing, download, extraction, or installation API.
package bootstrapverify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"mesh/internal/installerinspect"
	releasetrust "mesh/internal/release"
)

const (
	ResultSchema        = "mesh-bootstrap-verification-v1"
	HandoffResultSchema = "mesh-bootstrap-verification-v2"
	AnchorResultSchema  = "mesh-bootstrap-verification-v3"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Input contains already-bounded exact bytes. RootSHA256 must be obtained
// through a channel independent of every other field in this structure.
type Input struct {
	Root               []byte
	ExpectedRootSHA256 string
	Manifest           []byte
	Signatures         [][]byte
	Installer          []byte
	Now                time.Time
}

// Result is the bounded machine-readable receipt emitted after every trust,
// signature, manifest, platform, identity, and exact-byte check succeeds.
type Result struct {
	Schema                   string   `json:"schema"`
	AnchorSHA256             string   `json:"anchor_sha256,omitempty"`
	HandoffSHA256            string   `json:"handoff_sha256,omitempty"`
	VerifierPackageSHA256    string   `json:"verifier_package_sha256,omitempty"`
	RootSHA256               string   `json:"root_sha256"`
	ManifestSHA256           string   `json:"manifest_sha256"`
	InstallerSHA256          string   `json:"installer_sha256"`
	InstallerBootstrapSHA256 string   `json:"installer_bootstrap_sha256"`
	AuthenticodePolicySHA256 string   `json:"authenticode_policy_sha256,omitempty"`
	AuthenticodeSignerSPKI   string   `json:"authenticode_signer_spki_sha256,omitempty"`
	AuthenticodeCertificate  string   `json:"authenticode_certificate_sha256,omitempty"`
	Version                  string   `json:"version"`
	OS                       string   `json:"os"`
	Arch                     string   `json:"arch"`
	SignerKeyIDs             []string `json:"signer_key_ids"`
}

// Verify authenticates exact installer bytes without running them. A zero Now
// uses the verifier host's current UTC time.
func Verify(input Input) (Result, error) {
	if !digestPattern.MatchString(input.ExpectedRootSHA256) {
		return Result{}, errors.New("expected root SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(input.Root) == 0 || len(input.Root) > releasetrust.MaxRootSize {
		return Result{}, fmt.Errorf("bootstrap root size must be between 1 and %d bytes", releasetrust.MaxRootSize)
	}
	root, err := authenticateRoot(input.Root, input.ExpectedRootSHA256)
	if err != nil {
		return Result{}, err
	}
	if len(input.Manifest) == 0 || len(input.Manifest) > releasetrust.MaxManifestSize {
		return Result{}, fmt.Errorf("bootstrap manifest size must be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	if len(input.Signatures) == 0 || len(input.Signatures) > releasetrust.MaxSignatureEnvelopes {
		return Result{}, fmt.Errorf("bootstrap signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	for index, signature := range input.Signatures {
		if len(signature) == 0 || len(signature) > releasetrust.MaxEnvelopeSize {
			return Result{}, fmt.Errorf("bootstrap signature %d size must be between 1 and %d bytes", index, releasetrust.MaxEnvelopeSize)
		}
	}
	if len(input.Installer) == 0 || int64(len(input.Installer)) > releasetrust.MaxBootstrapArtifactSize {
		return Result{}, fmt.Errorf("bootstrap installer size must be between 1 and %d bytes", releasetrust.MaxBootstrapArtifactSize)
	}

	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	verified, err := releasetrust.VerifyBootstrapManifest(input.Manifest, input.Signatures, root, now.UTC(), 0)
	if err != nil {
		return Result{}, err
	}

	document := verified.Document
	artifactDigest := sha256.Sum256(input.Installer)
	if document.Artifact.Size != int64(len(input.Installer)) || document.Artifact.SHA256 != hex.EncodeToString(artifactDigest[:]) {
		return Result{}, errors.New("bootstrap installer bytes differ from the root-authorized manifest")
	}
	// Parse platform executable structures only after root signatures have
	// authorized this exact size and digest. In particular, debug/pe does not
	// claim hardened parsing of arbitrary hostile bytes.
	inspection, err := installerinspect.InspectBootstrap(input.Installer, document.Artifact.OS, document.Artifact.Arch)
	if err != nil {
		return Result{}, fmt.Errorf("inspect authenticated bootstrap installer: %w", err)
	}
	if inspection.Bootstrap.InitialRootSHA256 != root.SHA256 || inspection.Bootstrap.SHA256 != document.InstallerBootstrapSHA256 {
		return Result{}, errors.New("bootstrap installer compiled trust differs from the independently authenticated root or authorized manifest")
	}
	if inspection.Identity != document.Build || inspection.GoVersion != document.GoVersion {
		return Result{}, errors.New("bootstrap installer build identity differs from the root-authorized manifest")
	}

	result := Result{
		Schema: ResultSchema, RootSHA256: root.SHA256,
		ManifestSHA256: verified.SHA256, InstallerSHA256: document.Artifact.SHA256,
		InstallerBootstrapSHA256: document.InstallerBootstrapSHA256,
		Version:                  document.Build.Version, OS: document.Artifact.OS, Arch: document.Artifact.Arch,
		SignerKeyIDs: append([]string(nil), verified.SignerKeyIDs...),
	}
	if result.OS == "windows" {
		if !digestPattern.MatchString(inspection.Authenticode.SHA256) {
			return Result{}, errors.New("Windows bootstrap installer Authenticode policy is absent")
		}
		result.AuthenticodePolicySHA256 = inspection.Authenticode.SHA256
	}
	return result, nil
}

func authenticateRoot(raw []byte, expectedSHA256 string) (releasetrust.ParsedRoot, error) {
	root, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("parse bootstrap root: %w", err)
	}
	if root.SHA256 != expectedSHA256 {
		return releasetrust.ParsedRoot{}, errors.New("bootstrap root digest differs from the independently authenticated digest")
	}
	return root, nil
}

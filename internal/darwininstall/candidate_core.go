package darwininstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"mesh/internal/darwinbundle"
	releasetrust "mesh/internal/release"
)

type DarwinSignedMetadata struct {
	ChannelManifest   []byte
	ChannelSignatures [][]byte
	ReleaseManifest   []byte
	ReleaseSignatures [][]byte
}

// VerifiedDarwinIntake retains the immutable compiled-root binding needed to
// complete an outer trust decision after exact Darwin bundle inspection.
type VerifiedDarwinIntake struct {
	Candidate                    VerifiedDarwinCandidate
	InstallerBootstrapRootSHA256 string
}

func (intake VerifiedDarwinIntake) Complete(inspection darwinbundle.CandidateInspection) (AuthenticatedDarwinRelease, error) {
	return CompleteDarwinAuthority(intake.Candidate, inspection, intake.InstallerBootstrapRootSHA256)
}

// VerifiedDarwinCandidate is the threshold-authenticated outer release
// decision before the captured artifact is inspected as an exact Darwin
// bundle.
type VerifiedDarwinCandidate struct {
	ReleaseEpoch          uint64
	TrustedRootVersion    uint64
	TrustedRootSHA256     string
	Sequence              uint64
	Version               string
	MinimumSecurityFloor  uint64
	Channel               string
	ChannelManifestSHA256 string
	ReleaseManifestSHA256 string
	Artifact              releasetrust.Artifact
	VerifiedAt            string
}

// VerifyDarwinCandidateWithRoots verifies metadata using roots already
// replayed from one authenticated history. Production callers must supply the
// compiled bootstrap digest and a supported floor from their build identity;
// candidate-controlled values are never authority.
func VerifyDarwinCandidateWithRoots(metadata DarwinSignedMetadata, bootstrapTrustSHA256 string, currentRoot, authorityRoot releasetrust.ParsedRoot, prior *DarwinInstallState, now time.Time, supportedSecurityFloor uint64, arch string) (VerifiedDarwinCandidate, error) {
	if !darwinDigestPattern.MatchString(bootstrapTrustSHA256) {
		return VerifiedDarwinCandidate{}, errors.New("Darwin installer bootstrap digest is not canonical")
	}
	if arch != "amd64" && arch != "arm64" {
		return VerifiedDarwinCandidate{}, errors.New("Darwin release verification architecture is unsupported")
	}
	if now.IsZero() || supportedSecurityFloor == 0 {
		return VerifiedDarwinCandidate{}, errors.New("Darwin verification time and supported security floor are required")
	}
	current, err := canonicalDarwinRoot(currentRoot)
	if err != nil {
		return VerifiedDarwinCandidate{}, fmt.Errorf("current Darwin release root: %w", err)
	}
	authority, err := canonicalDarwinRoot(authorityRoot)
	if err != nil {
		return VerifiedDarwinCandidate{}, fmt.Errorf("Darwin release authority: %w", err)
	}
	if authority.Document.Channel != current.Document.Channel || authority.Document.Version > current.Document.Version {
		return VerifiedDarwinCandidate{}, errors.New("Darwin release authority is not in the current root history")
	}
	if err := releasetrust.ValidateCurrentRoot(current, now, 0); err != nil {
		return VerifiedDarwinCandidate{}, fmt.Errorf("current Darwin release root: %w", err)
	}
	channelDigest, releaseDigest, err := darwinSignedMetadataDigests(metadata)
	if err != nil {
		return VerifiedDarwinCandidate{}, err
	}
	minimumSequence := authority.Document.MinimumReleaseSequence
	minimumFloor := authority.Document.MinimumSecurityFloor
	verificationTime := now.UTC()
	resuming := false
	if prior != nil {
		if err := prior.Validate(); err != nil {
			return VerifiedDarwinCandidate{}, err
		}
		if prior.BootstrapTrustSHA256 != bootstrapTrustSHA256 || prior.Channel != current.Document.Channel || prior.Arch != arch {
			return VerifiedDarwinCandidate{}, errors.New("Darwin persisted state differs from compiled trust, channel, or architecture")
		}
		if prior.HighWater.ReleaseEpoch > current.Document.ReleaseEpoch {
			return VerifiedDarwinCandidate{}, errors.New("Darwin persisted release epoch is ahead of the trusted root")
		}
		exactAccepted := channelDigest == prior.HighWater.ChannelManifestSHA256 &&
			releaseDigest == prior.HighWater.ReleaseManifestSHA256 &&
			authority.Document.Version == prior.HighWater.TrustedRootVersion &&
			authority.SHA256 == prior.HighWater.TrustedRootSHA256 &&
			authority.Document.ReleaseEpoch == prior.HighWater.ReleaseEpoch
		historical := authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256
		if exactAccepted {
			verificationTime, err = parseDarwinCanonicalTime(prior.HighWater.VerifiedAt)
			if err != nil {
				return VerifiedDarwinCandidate{}, err
			}
			resuming = true
		} else if historical {
			return VerifiedDarwinCandidate{}, errors.New("historical Darwin release authority is allowed only for an exact accepted retry")
		}
		if prior.HighWater.ReleaseEpoch == authority.Document.ReleaseEpoch && prior.HighWater.Sequence > minimumSequence {
			minimumSequence = prior.HighWater.Sequence
		}
		if prior.HighWater.MinimumSecurityFloor > minimumFloor {
			minimumFloor = prior.HighWater.MinimumSecurityFloor
		}
	} else if authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256 {
		return VerifiedDarwinCandidate{}, errors.New("historical Darwin release authority requires persisted state")
	}
	if err := releasetrust.ValidateCurrentRoot(authority, verificationTime, 0); err != nil {
		return VerifiedDarwinCandidate{}, fmt.Errorf("Darwin release authority at verification time: %w", err)
	}
	allowLegacy := current.Document.Version == 1 && current.Document.ReleaseEpoch == 1 &&
		authority.Document.Version == 1 && authority.Document.ReleaseEpoch == 1
	_, verifiedRelease, err := releasetrust.VerifyChannelRelease(
		metadata.ChannelManifest, metadata.ChannelSignatures,
		metadata.ReleaseManifest, metadata.ReleaseSignatures,
		authority.ReleaseKeys,
		releasetrust.VerificationPolicy{
			Now: verificationTime, Threshold: authority.Document.Roles.Release.Threshold,
			MinimumSequence: minimumSequence, MinimumSecurityFloor: minimumFloor,
			SupportedSecurityFloor: supportedSecurityFloor,
			ExpectedChannel:        authority.Document.Channel, ExpectedReleaseEpoch: authority.Document.ReleaseEpoch,
			MinimumReleaseEpoch: authority.Document.ReleaseEpoch, AllowLegacyEpochOne: allowLegacy,
			PlatformOS: "darwin", PlatformArch: arch,
		},
	)
	if err != nil {
		return VerifiedDarwinCandidate{}, err
	}
	if verifiedRelease.SelectedArtifact == nil {
		return VerifiedDarwinCandidate{}, errors.New("verified release did not select a Darwin artifact")
	}
	verifiedAt := now.UTC().Truncate(time.Second)
	if resuming {
		verifiedAt = verificationTime
	}
	result := VerifiedDarwinCandidate{
		ReleaseEpoch: verifiedRelease.ReleaseEpoch, TrustedRootVersion: authority.Document.Version,
		TrustedRootSHA256: authority.SHA256, Sequence: verifiedRelease.Release.Sequence,
		Version: verifiedRelease.Release.Version, MinimumSecurityFloor: verifiedRelease.Release.MinimumSecurityFloor,
		Channel: authority.Document.Channel, ChannelManifestSHA256: channelDigest,
		ReleaseManifestSHA256: releaseDigest, Artifact: *verifiedRelease.SelectedArtifact,
		VerifiedAt: verifiedAt.Format(time.RFC3339),
	}
	if prior != nil && compareDarwinReleasePosition(AuthenticatedDarwinRelease{ReleaseEpoch: result.ReleaseEpoch, Sequence: result.Sequence}, prior.HighWater) == 0 {
		if result.ChannelManifestSHA256 != prior.HighWater.ChannelManifestSHA256 ||
			result.ReleaseManifestSHA256 != prior.HighWater.ReleaseManifestSHA256 ||
			result.Artifact.SHA256 != prior.HighWater.ArtifactSHA256 ||
			result.TrustedRootVersion != prior.HighWater.TrustedRootVersion ||
			result.TrustedRootSHA256 != prior.HighWater.TrustedRootSHA256 ||
			result.VerifiedAt != prior.HighWater.VerifiedAt {
			return VerifiedDarwinCandidate{}, errors.New("same-position Darwin candidate differs from its accepted trust decision")
		}
	}
	return result, nil
}

// CompleteDarwinAuthority binds the verified outer release to the exact
// inspected bundle before a stage or journal can become install authority.
func CompleteDarwinAuthority(candidate VerifiedDarwinCandidate, inspection darwinbundle.CandidateInspection, bootstrapTrustSHA256 string) (AuthenticatedDarwinRelease, error) {
	if !darwinDigestPattern.MatchString(bootstrapTrustSHA256) {
		return AuthenticatedDarwinRelease{}, errors.New("Darwin installer bootstrap digest is not canonical")
	}
	if err := darwinbundle.ValidateCandidateInspection(inspection); err != nil {
		return AuthenticatedDarwinRelease{}, err
	}
	if candidate.Artifact.OS != "darwin" || candidate.Artifact.Arch != inspection.Package.Target.Arch ||
		candidate.Artifact.SHA256 != inspection.ArtifactSHA256 || candidate.Artifact.Size != inspection.ArtifactSize {
		return AuthenticatedDarwinRelease{}, errors.New("verified Darwin artifact differs from exact bundle inspection")
	}
	if candidate.Version != inspection.Package.Version {
		return AuthenticatedDarwinRelease{}, errors.New("verified Darwin release version differs from bundle version")
	}
	identity := AuthenticatedDarwinRelease{
		ReleaseEpoch: candidate.ReleaseEpoch, Sequence: candidate.Sequence,
		TrustedRootVersion: candidate.TrustedRootVersion, TrustedRootSHA256: candidate.TrustedRootSHA256,
		InstallerBootstrapRootSHA256: bootstrapTrustSHA256,
		ChannelManifestSHA256:        candidate.ChannelManifestSHA256, ReleaseManifestSHA256: candidate.ReleaseManifestSHA256,
		ArtifactSHA256: candidate.Artifact.SHA256, PackageJSONSHA256: inspection.PackageJSONSHA256,
		Version: candidate.Version, MinimumSecurityFloor: candidate.MinimumSecurityFloor,
		BundleSecurityFloor: inspection.Package.SecurityFloor,
		AgentStateReadMin:   inspection.Package.AgentStateReadMin, AgentStateReadMax: inspection.Package.AgentStateReadMax,
		AgentStateWriteVersion: inspection.Package.AgentStateWriteVersion,
		Channel:                candidate.Channel, Arch: candidate.Artifact.Arch, VerifiedAt: candidate.VerifiedAt,
	}
	identity.InstalledID = DarwinInstalledID(identity)
	if err := identity.Validate(); err != nil {
		return AuthenticatedDarwinRelease{}, fmt.Errorf("complete authenticated Darwin release: %w", err)
	}
	return identity, nil
}

func canonicalDarwinRoot(input releasetrust.ParsedRoot) (releasetrust.ParsedRoot, error) {
	raw, err := releasetrust.EncodeRoot(input.Document)
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if input.SHA256 == "" || input.SHA256 != parsed.SHA256 {
		return releasetrust.ParsedRoot{}, errors.New("Darwin trusted-root digest differs from its canonical document")
	}
	return parsed, nil
}

func darwinSignedMetadataDigests(metadata DarwinSignedMetadata) (string, string, error) {
	if len(metadata.ChannelManifest) == 0 || len(metadata.ChannelManifest) > releasetrust.MaxManifestSize ||
		len(metadata.ReleaseManifest) == 0 || len(metadata.ReleaseManifest) > releasetrust.MaxManifestSize {
		return "", "", fmt.Errorf("Darwin channel and release manifests must each be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	channel := sha256.Sum256(metadata.ChannelManifest)
	release := sha256.Sum256(metadata.ReleaseManifest)
	return hex.EncodeToString(channel[:]), hex.EncodeToString(release[:]), nil
}

package windowsinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	releasetrust "mesh/internal/release"
	"mesh/internal/windowsbundle"
)

var windowsChannelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

type WindowsSignedMetadata struct {
	ChannelManifest   []byte
	ChannelSignatures [][]byte
	ReleaseManifest   []byte
	ReleaseSignatures [][]byte
}

// VerifiedWindowsIntake retains the compiled bootstrap-root binding needed to
// complete a threshold-authenticated release after exact bundle inspection.
type VerifiedWindowsIntake struct {
	Candidate                    VerifiedWindowsCandidate
	InstallerBootstrapRootSHA256 string
}

func (intake VerifiedWindowsIntake) Validate() error {
	if !digestPattern.MatchString(intake.InstallerBootstrapRootSHA256) {
		return errors.New("Windows verified-intake bootstrap digest is invalid")
	}
	return intake.Candidate.Validate()
}

func (intake VerifiedWindowsIntake) Complete(inspection windowsbundle.CandidateInspection) (AuthenticatedWindowsRelease, error) {
	return CompleteWindowsAuthority(intake.Candidate, inspection, intake.InstallerBootstrapRootSHA256)
}

// VerifiedWindowsCandidate is the threshold-authenticated outer decision
// before the captured artifact is inspected as an exact Windows bundle.
type VerifiedWindowsCandidate struct {
	ReleaseEpoch          uint64                `json:"release_epoch"`
	TrustedRootVersion    uint64                `json:"trusted_root_version"`
	TrustedRootSHA256     string                `json:"trusted_root_sha256"`
	Sequence              uint64                `json:"sequence"`
	Version               string                `json:"version"`
	MinimumSecurityFloor  uint64                `json:"minimum_security_floor"`
	Channel               string                `json:"channel"`
	ChannelManifestSHA256 string                `json:"channel_manifest_sha256"`
	ReleaseManifestSHA256 string                `json:"release_manifest_sha256"`
	Artifact              releasetrust.Artifact `json:"artifact"`
	VerifiedAt            string                `json:"verified_at"`
}

func (candidate VerifiedWindowsCandidate) Validate() error {
	if candidate.ReleaseEpoch == 0 || candidate.TrustedRootVersion == 0 || candidate.Sequence == 0 || candidate.MinimumSecurityFloor == 0 {
		return errors.New("verified Windows candidate positions and security floor must be positive")
	}
	for label, digest := range map[string]string{
		"trusted root": candidate.TrustedRootSHA256, "channel manifest": candidate.ChannelManifestSHA256,
		"release manifest": candidate.ReleaseManifestSHA256,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("verified Windows candidate %s digest is not canonical", label)
		}
	}
	if err := validateWindowsSemVer(candidate.Version); err != nil {
		return errors.New("verified Windows candidate version is invalid")
	}
	if !windowsChannelPattern.MatchString(candidate.Channel) {
		return errors.New("verified Windows candidate channel is invalid")
	}
	if err := releasetrust.ValidateArtifactReference(candidate.Artifact); err != nil {
		return fmt.Errorf("verified Windows candidate artifact: %w", err)
	}
	if candidate.Artifact.OS != "windows" || candidate.Artifact.Arch != "amd64" && candidate.Artifact.Arch != "arm64" {
		return errors.New("verified Windows candidate artifact platform is unsupported")
	}
	if candidate.Artifact.Size > windowsbundle.MaxArchiveSize {
		return fmt.Errorf("verified Windows candidate artifact exceeds %d bytes", windowsbundle.MaxArchiveSize)
	}
	if _, err := parseWindowsCanonicalTime(candidate.VerifiedAt); err != nil {
		return fmt.Errorf("verified Windows candidate time: %w", err)
	}
	return nil
}

// AuthenticatedWindowsRelease is the comparable authority retained after
// threshold verification and exact Windows bundle inspection.
type AuthenticatedWindowsRelease struct {
	ReleaseEpoch                 uint64 `json:"release_epoch"`
	Sequence                     uint64 `json:"sequence"`
	TrustedRootVersion           uint64 `json:"trusted_root_version"`
	TrustedRootSHA256            string `json:"trusted_root_sha256"`
	InstallerBootstrapRootSHA256 string `json:"installer_bootstrap_root_sha256"`
	ChannelManifestSHA256        string `json:"channel_manifest_sha256"`
	ReleaseManifestSHA256        string `json:"release_manifest_sha256"`
	ArtifactSHA256               string `json:"artifact_sha256"`
	PackageJSONSHA256            string `json:"package_json_sha256"`
	Version                      string `json:"version"`
	MinimumSecurityFloor         uint64 `json:"minimum_security_floor"`
	BundleSecurityFloor          uint64 `json:"bundle_security_floor"`
	AgentStateReadMin            uint64 `json:"agent_state_read_min"`
	AgentStateReadMax            uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion       uint64 `json:"agent_state_write_version"`
	Channel                      string `json:"channel"`
	Arch                         string `json:"arch"`
	VerifiedAt                   string `json:"verified_at"`
	InstalledID                  string `json:"installed_id"`
}

func WindowsInstalledID(identity AuthenticatedWindowsRelease) string {
	if identity.ReleaseEpoch == 0 || identity.Sequence == 0 ||
		!digestPattern.MatchString(identity.ReleaseManifestSHA256) ||
		!digestPattern.MatchString(identity.ArtifactSHA256) {
		return ""
	}
	return fmt.Sprintf("e%020d-s%020d-r%s-a%s", identity.ReleaseEpoch, identity.Sequence, identity.ReleaseManifestSHA256[:16], identity.ArtifactSHA256[:16])
}

func WindowsCandidateInstalledID(candidate VerifiedWindowsCandidate) (string, error) {
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	identity := AuthenticatedWindowsRelease{
		ReleaseEpoch: candidate.ReleaseEpoch, Sequence: candidate.Sequence,
		ReleaseManifestSHA256: candidate.ReleaseManifestSHA256, ArtifactSHA256: candidate.Artifact.SHA256,
	}
	installedID := WindowsInstalledID(identity)
	if !installedIDPattern.MatchString(installedID) {
		return "", errors.New("verified Windows candidate did not derive a canonical installed ID")
	}
	return installedID, nil
}

func WindowsAcceptedStageName(intake VerifiedWindowsIntake) (string, error) {
	if err := intake.Validate(); err != nil {
		return "", err
	}
	installedID, err := WindowsCandidateInstalledID(intake.Candidate)
	if err != nil {
		return "", err
	}
	identity := strings.Join([]string{
		"mesh-windows-accepted-stage-v1", intake.InstallerBootstrapRootSHA256,
		intake.Candidate.TrustedRootSHA256, intake.Candidate.ChannelManifestSHA256,
		intake.Candidate.ReleaseManifestSHA256, intake.Candidate.Artifact.SHA256,
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	name := ".stage-" + installedID + "-" + hex.EncodeToString(digest[:16])
	if !releaseStageNamePattern.MatchString(name) {
		return "", errors.New("verified Windows intake did not derive a canonical stage name")
	}
	return name, nil
}

func (identity AuthenticatedWindowsRelease) Validate() error {
	if identity.ReleaseEpoch == 0 || identity.Sequence == 0 || identity.TrustedRootVersion == 0 {
		return errors.New("Windows release epoch, sequence, and trusted-root version must be positive")
	}
	for label, digest := range map[string]string{
		"trusted root": identity.TrustedRootSHA256, "installer bootstrap": identity.InstallerBootstrapRootSHA256,
		"channel manifest": identity.ChannelManifestSHA256, "release manifest": identity.ReleaseManifestSHA256,
		"artifact": identity.ArtifactSHA256, "package JSON": identity.PackageJSONSHA256,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("Windows %s digest is not canonical", label)
		}
	}
	if identity.MinimumSecurityFloor == 0 || identity.BundleSecurityFloor < identity.MinimumSecurityFloor {
		return errors.New("Windows release security floors are invalid")
	}
	if err := validateWindowsSemVer(identity.Version); err != nil {
		return errors.New("Windows release version is not canonical SemVer")
	}
	if identity.AgentStateReadMin == 0 || identity.AgentStateReadMax == 0 || identity.AgentStateWriteVersion == 0 ||
		identity.AgentStateReadMin > identity.AgentStateWriteVersion || identity.AgentStateWriteVersion > identity.AgentStateReadMax {
		return errors.New("Windows release agent-state compatibility is invalid")
	}
	if !windowsChannelPattern.MatchString(identity.Channel) {
		return errors.New("Windows release channel is not canonical")
	}
	if identity.Arch != "amd64" && identity.Arch != "arm64" {
		return errors.New("Windows release architecture is unsupported")
	}
	if _, err := parseWindowsCanonicalTime(identity.VerifiedAt); err != nil {
		return fmt.Errorf("Windows release verified_at: %w", err)
	}
	if identity.InstalledID != WindowsInstalledID(identity) {
		return errors.New("Windows installed release ID differs from its authenticated authority")
	}
	return nil
}

func (identity AuthenticatedWindowsRelease) CurrentDescriptor() (CurrentDescriptor, error) {
	if err := identity.Validate(); err != nil {
		return CurrentDescriptor{}, err
	}
	descriptor := CurrentDescriptor{
		Schema: CurrentDescriptorSchema, InstalledID: identity.InstalledID,
		ArtifactSHA256: identity.ArtifactSHA256, PackageJSONSHA256: identity.PackageJSONSHA256,
		Architecture: identity.Arch, SecurityFloor: identity.BundleSecurityFloor,
	}
	if err := descriptor.Validate(); err != nil {
		return CurrentDescriptor{}, err
	}
	return descriptor, nil
}

// VerifyWindowsCandidateWithRoots verifies signed release metadata against
// roots already replayed from authenticated history. Candidate bytes cannot
// choose the compiled bootstrap digest, architecture, or supported floor.
func VerifyWindowsCandidateWithRoots(metadata WindowsSignedMetadata, bootstrapTrustSHA256 string, currentRoot, authorityRoot releasetrust.ParsedRoot, prior *WindowsInstallState, now time.Time, supportedSecurityFloor uint64, arch string) (VerifiedWindowsCandidate, error) {
	if !digestPattern.MatchString(bootstrapTrustSHA256) {
		return VerifiedWindowsCandidate{}, errors.New("Windows installer bootstrap digest is not canonical")
	}
	if arch != "amd64" && arch != "arm64" {
		return VerifiedWindowsCandidate{}, errors.New("Windows release verification architecture is unsupported")
	}
	if now.IsZero() || supportedSecurityFloor == 0 {
		return VerifiedWindowsCandidate{}, errors.New("Windows verification time and supported security floor are required")
	}
	current, err := canonicalWindowsRoot(currentRoot)
	if err != nil {
		return VerifiedWindowsCandidate{}, fmt.Errorf("current Windows release root: %w", err)
	}
	authority, err := canonicalWindowsRoot(authorityRoot)
	if err != nil {
		return VerifiedWindowsCandidate{}, fmt.Errorf("Windows release authority: %w", err)
	}
	if authority.Document.Channel != current.Document.Channel || authority.Document.Version > current.Document.Version {
		return VerifiedWindowsCandidate{}, errors.New("Windows release authority is not in the current root history")
	}
	if err := releasetrust.ValidateCurrentRoot(current, now, 0); err != nil {
		return VerifiedWindowsCandidate{}, fmt.Errorf("current Windows release root: %w", err)
	}
	channelDigest, releaseDigest, err := windowsSignedMetadataDigests(metadata)
	if err != nil {
		return VerifiedWindowsCandidate{}, err
	}
	minimumSequence := authority.Document.MinimumReleaseSequence
	minimumFloor := authority.Document.MinimumSecurityFloor
	verificationTime := now.UTC()
	resuming := false
	if prior != nil {
		if err := prior.Validate(); err != nil {
			return VerifiedWindowsCandidate{}, err
		}
		if prior.BootstrapTrustSHA256 != bootstrapTrustSHA256 || prior.Channel != current.Document.Channel || prior.Arch != arch {
			return VerifiedWindowsCandidate{}, errors.New("Windows persisted state differs from compiled trust, channel, or architecture")
		}
		if prior.HighWater.ReleaseEpoch > current.Document.ReleaseEpoch {
			return VerifiedWindowsCandidate{}, errors.New("Windows persisted release epoch is ahead of the trusted root")
		}
		exactAccepted := channelDigest == prior.HighWater.ChannelManifestSHA256 &&
			releaseDigest == prior.HighWater.ReleaseManifestSHA256 &&
			authority.Document.Version == prior.HighWater.TrustedRootVersion && authority.SHA256 == prior.HighWater.TrustedRootSHA256 &&
			authority.Document.ReleaseEpoch == prior.HighWater.ReleaseEpoch
		historical := authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256
		if exactAccepted {
			verificationTime, err = parseWindowsCanonicalTime(prior.HighWater.VerifiedAt)
			if err != nil {
				return VerifiedWindowsCandidate{}, err
			}
			resuming = true
		} else if historical {
			return VerifiedWindowsCandidate{}, errors.New("historical Windows release authority is allowed only for an exact accepted retry")
		}
		if prior.HighWater.ReleaseEpoch == authority.Document.ReleaseEpoch && prior.HighWater.Sequence > minimumSequence {
			minimumSequence = prior.HighWater.Sequence
		}
		if prior.HighWater.MinimumSecurityFloor > minimumFloor {
			minimumFloor = prior.HighWater.MinimumSecurityFloor
		}
	} else if authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256 {
		return VerifiedWindowsCandidate{}, errors.New("historical Windows release authority requires persisted state")
	}
	if err := releasetrust.ValidateCurrentRoot(authority, verificationTime, 0); err != nil {
		return VerifiedWindowsCandidate{}, fmt.Errorf("Windows release authority at verification time: %w", err)
	}
	allowLegacy := current.Document.Version == 1 && current.Document.ReleaseEpoch == 1 &&
		authority.Document.Version == 1 && authority.Document.ReleaseEpoch == 1
	_, verifiedRelease, err := releasetrust.VerifyChannelRelease(
		metadata.ChannelManifest, metadata.ChannelSignatures, metadata.ReleaseManifest, metadata.ReleaseSignatures,
		authority.ReleaseKeys,
		releasetrust.VerificationPolicy{
			Now: verificationTime, Threshold: authority.Document.Roles.Release.Threshold,
			MinimumSequence: minimumSequence, MinimumSecurityFloor: minimumFloor,
			SupportedSecurityFloor: supportedSecurityFloor,
			ExpectedChannel:        authority.Document.Channel, ExpectedReleaseEpoch: authority.Document.ReleaseEpoch,
			MinimumReleaseEpoch: authority.Document.ReleaseEpoch, AllowLegacyEpochOne: allowLegacy,
			PlatformOS: "windows", PlatformArch: arch,
		},
	)
	if err != nil {
		return VerifiedWindowsCandidate{}, err
	}
	if verifiedRelease.SelectedArtifact == nil {
		return VerifiedWindowsCandidate{}, errors.New("verified release did not select a Windows artifact")
	}
	verifiedAt := now.UTC().Truncate(time.Second)
	if resuming {
		verifiedAt = verificationTime
	}
	result := VerifiedWindowsCandidate{
		ReleaseEpoch: verifiedRelease.ReleaseEpoch, TrustedRootVersion: authority.Document.Version,
		TrustedRootSHA256: authority.SHA256, Sequence: verifiedRelease.Release.Sequence,
		Version: verifiedRelease.Release.Version, MinimumSecurityFloor: verifiedRelease.Release.MinimumSecurityFloor,
		Channel: authority.Document.Channel, ChannelManifestSHA256: channelDigest, ReleaseManifestSHA256: releaseDigest,
		Artifact: *verifiedRelease.SelectedArtifact, VerifiedAt: verifiedAt.Format(time.RFC3339),
	}
	if err := result.Validate(); err != nil {
		return VerifiedWindowsCandidate{}, err
	}
	if prior != nil && compareWindowsReleasePosition(
		AuthenticatedWindowsRelease{ReleaseEpoch: result.ReleaseEpoch, Sequence: result.Sequence}, prior.HighWater,
	) == 0 {
		if result.ChannelManifestSHA256 != prior.HighWater.ChannelManifestSHA256 ||
			result.ReleaseManifestSHA256 != prior.HighWater.ReleaseManifestSHA256 ||
			result.Artifact.SHA256 != prior.HighWater.ArtifactSHA256 ||
			result.TrustedRootVersion != prior.HighWater.TrustedRootVersion ||
			result.TrustedRootSHA256 != prior.HighWater.TrustedRootSHA256 || result.VerifiedAt != prior.HighWater.VerifiedAt {
			return VerifiedWindowsCandidate{}, errors.New("same-position Windows candidate differs from its accepted trust decision")
		}
	}
	return result, nil
}

// CompleteWindowsAuthority binds the verified outer release to the exact
// inspected bundle before staging, selection, or activation can gain authority.
func CompleteWindowsAuthority(candidate VerifiedWindowsCandidate, inspection windowsbundle.CandidateInspection, bootstrapTrustSHA256 string) (AuthenticatedWindowsRelease, error) {
	if !digestPattern.MatchString(bootstrapTrustSHA256) {
		return AuthenticatedWindowsRelease{}, errors.New("Windows installer bootstrap digest is not canonical")
	}
	if err := candidate.Validate(); err != nil {
		return AuthenticatedWindowsRelease{}, err
	}
	if err := windowsbundle.ValidateCandidateInspection(inspection); err != nil {
		return AuthenticatedWindowsRelease{}, err
	}
	if candidate.Artifact.OS != "windows" || candidate.Artifact.Arch != inspection.Package.Target.Arch ||
		candidate.Artifact.SHA256 != inspection.ArtifactSHA256 || candidate.Artifact.Size != inspection.ArtifactSize {
		return AuthenticatedWindowsRelease{}, errors.New("verified Windows artifact differs from exact bundle inspection")
	}
	if candidate.Version != inspection.Package.Version {
		return AuthenticatedWindowsRelease{}, errors.New("verified Windows release version differs from bundle version")
	}
	identity := AuthenticatedWindowsRelease{
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
	identity.InstalledID = WindowsInstalledID(identity)
	if err := identity.Validate(); err != nil {
		return AuthenticatedWindowsRelease{}, fmt.Errorf("complete authenticated Windows release: %w", err)
	}
	descriptor, err := identity.CurrentDescriptor()
	if err != nil {
		return AuthenticatedWindowsRelease{}, err
	}
	fromInspection, err := CurrentDescriptorFromInspection(identity.InstalledID, inspection)
	if err != nil || descriptor != fromInspection {
		return AuthenticatedWindowsRelease{}, errors.New("authenticated Windows release does not produce the exact inspected current descriptor")
	}
	return identity, nil
}

func canonicalWindowsRoot(input releasetrust.ParsedRoot) (releasetrust.ParsedRoot, error) {
	raw, err := releasetrust.EncodeRoot(input.Document)
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if input.SHA256 == "" || input.SHA256 != parsed.SHA256 {
		return releasetrust.ParsedRoot{}, errors.New("Windows trusted-root digest differs from its canonical document")
	}
	return parsed, nil
}

func windowsSignedMetadataDigests(metadata WindowsSignedMetadata) (string, string, error) {
	if len(metadata.ChannelManifest) == 0 || len(metadata.ChannelManifest) > releasetrust.MaxManifestSize ||
		len(metadata.ReleaseManifest) == 0 || len(metadata.ReleaseManifest) > releasetrust.MaxManifestSize {
		return "", "", fmt.Errorf("Windows channel and release manifests must each be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	channel := sha256.Sum256(metadata.ChannelManifest)
	release := sha256.Sum256(metadata.ReleaseManifest)
	return hex.EncodeToString(channel[:]), hex.EncodeToString(release[:]), nil
}

func parseWindowsCanonicalTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) != value {
		return time.Time{}, errors.New("must not contain surrounding whitespace")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 without fractional seconds")
	}
	return parsed.UTC(), nil
}

func validateWindowsSemVer(version string) error {
	if version == "" || len(version) > 128 || strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer length or build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validWindowsSemVerIdentifiers(mainAndBuild[1], false) {
		return errors.New("invalid SemVer build metadata")
	}
	mainAndPre := strings.SplitN(mainAndBuild[0], "-", 2)
	core := strings.Split(mainAndPre[0], ".")
	if len(core) != 3 {
		return errors.New("SemVer must contain major.minor.patch")
	}
	for _, number := range core {
		if !validWindowsNumericIdentifier(number) {
			return errors.New("SemVer core is not canonical")
		}
	}
	if len(mainAndPre) == 2 && !validWindowsSemVerIdentifiers(mainAndPre[1], true) {
		return errors.New("invalid SemVer prerelease")
	}
	return nil
}

func validWindowsSemVerIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character != '-' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
		}
		if rejectNumericLeadingZero && allWindowsDigits(part) && !validWindowsNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validWindowsNumericIdentifier(value string) bool {
	return value != "" && allWindowsDigits(value) && (len(value) == 1 || value[0] != '0')
}

func allWindowsDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

//go:build linux

package linuxinstall

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

type SignedMetadata struct {
	ChannelManifest   []byte
	ChannelSignatures [][]byte
	ReleaseManifest   []byte
	ReleaseSignatures [][]byte
}

// CandidateMetadata is the threshold-authenticated metadata identity. It is
// completed with the verified inner bundle digest and supported floor only
// after extraction from the private captured artifact.
type CandidateMetadata struct {
	ReleaseEpoch          uint64
	TrustedRootVersion    uint64
	TrustedRootSHA256     string
	Sequence              uint64
	Version               string
	MinimumSecurityFloor  uint64
	ChannelManifestSHA256 string
	ReleaseManifestSHA256 string
	Artifact              releasetrust.Artifact
	VerifiedAt            string
	ChannelSignerKeyIDs   []string
	ReleaseSignerKeyIDs   []string
}

// VerifySignedCandidate authenticates release metadata exclusively with the
// trust roots and security semantics compiled into this installer binary.
// Neither value can be supplied by a command-line flag, environment variable,
// candidate file, or caller.
func VerifySignedCandidate(metadata SignedMetadata, prior *State) (CandidateMetadata, error) {
	return verifySignedCandidateAt(metadata, prior, time.Now().UTC())
}

func verifySignedCandidateAt(metadata SignedMetadata, prior *State, updateStart time.Time) (CandidateMetadata, error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return CandidateMetadata{}, fmt.Errorf("load compiled installer trust: %w", err)
	}
	identity, err := buildinfo.CurrentProduction()
	if err != nil {
		return CandidateMetadata{}, fmt.Errorf("load compiled installer build identity: %w", err)
	}
	store, err := NewRootStore(productionRootStoreDirectory, uint32(os.Geteuid()), bootstrap.InitialRoot)
	if err != nil {
		return CandidateMetadata{}, fmt.Errorf("configure installer root history: %w", err)
	}
	lock, err := store.Acquire()
	if err != nil {
		return CandidateMetadata{}, fmt.Errorf("load installer root history: %w", err)
	}
	defer lock.Close()
	current := lock.Current()
	authority := current
	channelHex, releaseHex, err := signedMetadataDigests(metadata)
	if err == nil && prior != nil && prior.Schema == StateSchemaV3 && prior.Pending != nil &&
		channelHex == prior.HighWater.ChannelManifestSHA256 && releaseHex == prior.HighWater.ReleaseManifestSHA256 {
		authority, err = lock.RootVersion(prior.HighWater.TrustedRootVersion)
		if err != nil {
			return CandidateMetadata{}, fmt.Errorf("load recorded historical release root: %w", err)
		}
		if authority.SHA256 != prior.HighWater.TrustedRootSHA256 {
			return CandidateMetadata{}, errors.New("recorded historical release root digest differs from root history")
		}
	}
	return verifySignedCandidateWithRoots(metadata, bootstrap, current, authority, prior, updateStart, identity.SecurityFloor)
}

// verifySignedCandidateWithRoots is the deterministic root-aware seam. The
// current and authority roots must originate from one already-verified root
// history. Authority may differ from current only for an exact pending resume.
func verifySignedCandidateWithRoots(metadata SignedMetadata, bootstrap installtrust.Bootstrap, currentRoot, authorityRoot releasetrust.ParsedRoot, prior *State, now time.Time, supportedSecurityFloor uint64) (CandidateMetadata, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return CandidateMetadata{}, errors.New("Mesh Linux installation is supported only on linux/amd64 and linux/arm64")
	}
	if now.IsZero() {
		return CandidateMetadata{}, errors.New("release verification time must be nonzero")
	}
	if supportedSecurityFloor == 0 {
		return CandidateMetadata{}, errors.New("installer supported security floor must be positive")
	}
	trustedBootstrap, current, authority, err := validateRootVerificationInputs(bootstrap, currentRoot, authorityRoot)
	if err != nil {
		return CandidateMetadata{}, err
	}
	if err := releasetrust.ValidateCurrentRoot(current, now, 0); err != nil {
		return CandidateMetadata{}, fmt.Errorf("current trusted release root: %w", err)
	}
	channelHex, releaseHex, err := signedMetadataDigests(metadata)
	if err != nil {
		return CandidateMetadata{}, err
	}

	minimumSequence := authority.Document.MinimumReleaseSequence
	minimumFloor := authority.Document.MinimumSecurityFloor
	verificationTime := now.UTC()
	resuming := false
	if prior != nil {
		if err := prior.Validate(); err != nil {
			return CandidateMetadata{}, err
		}
		if prior.Channel != current.Document.Channel {
			return CandidateMetadata{}, errors.New("trusted root channel differs from persisted installer channel")
		}
		switch prior.Schema {
		case LegacyStateSchema:
			if prior.TrustPolicySHA256 != trustedBootstrap.LegacyPolicySHA256 {
				return CandidateMetadata{}, errors.New("compiled installer legacy policy differs from persisted policy")
			}
			if current.Document.Version != 1 || current.Document.ReleaseEpoch != 1 || current.SHA256 != trustedBootstrap.InitialRootSHA256 {
				return CandidateMetadata{}, errors.New("legacy installer state can be verified only under the immutable initial root")
			}
			if prior.Pending != nil {
				return CandidateMetadata{}, errors.New("legacy pending transaction must be completed by the legacy installer before root-aware migration")
			}
		case StateSchemaV3:
			if prior.BootstrapTrustSHA256 != trustedBootstrap.SHA256 {
				return CandidateMetadata{}, errors.New("compiled installer bootstrap differs from persisted bootstrap identity")
			}
			if prior.HighWater.ReleaseEpoch > current.Document.ReleaseEpoch {
				return CandidateMetadata{}, errors.New("persisted release epoch is ahead of the trusted root")
			}
			exactMetadata := channelHex == prior.HighWater.ChannelManifestSHA256 && releaseHex == prior.HighWater.ReleaseManifestSHA256
			historicalAuthority := authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256
			if exactMetadata && authority.Document.Version == prior.HighWater.TrustedRootVersion &&
				authority.SHA256 == prior.HighWater.TrustedRootSHA256 && authority.Document.ReleaseEpoch == prior.HighWater.ReleaseEpoch {
				if historicalAuthority && prior.Pending == nil {
					return CandidateMetadata{}, errors.New("historical release authority is allowed only for an exact pending resume")
				}
				acceptedAt, err := parseCanonicalTime(prior.HighWater.VerifiedAt)
				if err != nil {
					return CandidateMetadata{}, err
				}
				verificationTime = acceptedAt
				resuming = true
			} else if historicalAuthority {
				return CandidateMetadata{}, errors.New("historical release authority is allowed only for an exact pending resume")
			}
			if prior.Pending != nil && !resuming {
				return CandidateMetadata{}, errors.New("an unfinished installer transaction must be resumed or rolled back before verifying another release")
			}
		default:
			return CandidateMetadata{}, fmt.Errorf("unsupported installer state schema %q", prior.Schema)
		}
		if prior.HighWater.ReleaseEpoch == authority.Document.ReleaseEpoch && prior.HighWater.Sequence > minimumSequence {
			minimumSequence = prior.HighWater.Sequence
		}
		if prior.HighWater.MinimumSecurityFloor > minimumFloor {
			minimumFloor = prior.HighWater.MinimumSecurityFloor
		}
	} else if authority.Document.Version != current.Document.Version || authority.SHA256 != current.SHA256 {
		return CandidateMetadata{}, errors.New("historical release authority requires persisted pending state")
	}
	if err := releasetrust.ValidateCurrentRoot(authority, verificationTime, 0); err != nil {
		return CandidateMetadata{}, fmt.Errorf("release authority at verification time: %w", err)
	}

	allowLegacy := current.Document.Version == 1 && current.Document.ReleaseEpoch == 1 &&
		authority.Document.Version == 1 && authority.Document.ReleaseEpoch == 1 &&
		current.SHA256 == trustedBootstrap.InitialRootSHA256
	verifiedChannel, verifiedRelease, err := releasetrust.VerifyChannelRelease(
		metadata.ChannelManifest, metadata.ChannelSignatures,
		metadata.ReleaseManifest, metadata.ReleaseSignatures,
		authority.ReleaseKeys,
		releasetrust.VerificationPolicy{
			Now: verificationTime, Threshold: authority.Document.Roles.Release.Threshold,
			MinimumSequence: minimumSequence, MinimumSecurityFloor: minimumFloor,
			SupportedSecurityFloor: supportedSecurityFloor,
			ExpectedChannel:        authority.Document.Channel,
			ExpectedReleaseEpoch:   authority.Document.ReleaseEpoch,
			MinimumReleaseEpoch:    authority.Document.ReleaseEpoch,
			AllowLegacyEpochOne:    allowLegacy,
			PlatformOS:             runtime.GOOS,
			PlatformArch:           runtime.GOARCH,
		},
	)
	if err != nil {
		return CandidateMetadata{}, err
	}
	if verifiedRelease.SelectedArtifact == nil {
		return CandidateMetadata{}, errors.New("verified release did not select a Linux installer artifact")
	}
	verifiedAt := now.UTC().Truncate(time.Second)
	if resuming {
		verifiedAt = verificationTime
	}
	result := CandidateMetadata{
		ReleaseEpoch: verifiedRelease.ReleaseEpoch, TrustedRootVersion: authority.Document.Version, TrustedRootSHA256: authority.SHA256,
		Sequence: verifiedRelease.Release.Sequence, Version: verifiedRelease.Release.Version,
		MinimumSecurityFloor:  verifiedRelease.Release.MinimumSecurityFloor,
		ChannelManifestSHA256: channelHex, ReleaseManifestSHA256: releaseHex,
		Artifact: *verifiedRelease.SelectedArtifact, VerifiedAt: verifiedAt.Format(time.RFC3339),
		ChannelSignerKeyIDs: append([]string(nil), verifiedChannel.SignerKeyIDs...),
		ReleaseSignerKeyIDs: append([]string(nil), verifiedRelease.SignerKeyIDs...),
	}
	if prior != nil && compareReleasePosition(ReleaseIdentity{ReleaseEpoch: result.ReleaseEpoch, Sequence: result.Sequence}, prior.HighWater) == 0 {
		if result.ChannelManifestSHA256 != prior.HighWater.ChannelManifestSHA256 ||
			result.ReleaseManifestSHA256 != prior.HighWater.ReleaseManifestSHA256 ||
			result.Artifact.SHA256 != prior.HighWater.ArtifactSHA256 {
			return CandidateMetadata{}, errors.New("same-position metadata or artifact differs from accepted release")
		}
		if prior.Schema == StateSchemaV3 && (result.TrustedRootVersion != prior.HighWater.TrustedRootVersion ||
			result.TrustedRootSHA256 != prior.HighWater.TrustedRootSHA256 || result.VerifiedAt != prior.HighWater.VerifiedAt) {
			return CandidateMetadata{}, errors.New("same-position candidate differs from its accepted trust decision")
		}
	}
	return result, nil
}

func signedMetadataDigests(metadata SignedMetadata) (string, string, error) {
	if len(metadata.ChannelManifest) == 0 || len(metadata.ChannelManifest) > releasetrust.MaxManifestSize ||
		len(metadata.ReleaseManifest) == 0 || len(metadata.ReleaseManifest) > releasetrust.MaxManifestSize {
		return "", "", fmt.Errorf("channel and release manifests must each be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	channelDigest := sha256.Sum256(metadata.ChannelManifest)
	releaseDigest := sha256.Sum256(metadata.ReleaseManifest)
	return hex.EncodeToString(channelDigest[:]), hex.EncodeToString(releaseDigest[:]), nil
}

func validateRootVerificationInputs(bootstrap installtrust.Bootstrap, currentInput, authorityInput releasetrust.ParsedRoot) (installtrust.Bootstrap, releasetrust.ParsedRoot, releasetrust.ParsedRoot, error) {
	_, trusted, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: bootstrap.InitialRootRaw})
	if err != nil {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, fmt.Errorf("compiled installer bootstrap: %w", err)
	}
	providedRaw, err := releasetrust.EncodeRoot(bootstrap.InitialRoot.Document)
	if err != nil || !bytes.Equal(providedRaw, bootstrap.InitialRootRaw) || bootstrap.InitialRoot.SHA256 != trusted.InitialRoot.SHA256 ||
		bootstrap.SHA256 != trusted.SHA256 || bootstrap.InitialRootSHA256 != trusted.InitialRootSHA256 || bootstrap.LegacyPolicySHA256 != trusted.LegacyPolicySHA256 {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, errors.New("compiled installer bootstrap identity is inconsistent")
	}
	canonicalRoot := func(label string, input releasetrust.ParsedRoot) (releasetrust.ParsedRoot, error) {
		raw, err := releasetrust.EncodeRoot(input.Document)
		if err != nil {
			return releasetrust.ParsedRoot{}, fmt.Errorf("%s root: %w", label, err)
		}
		parsed, err := releasetrust.ParseRoot(raw)
		if err != nil || parsed.SHA256 != input.SHA256 {
			return releasetrust.ParsedRoot{}, fmt.Errorf("%s root digest does not match its canonical document", label)
		}
		return parsed, nil
	}
	current, err := canonicalRoot("current", currentInput)
	if err != nil {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, err
	}
	authority, err := canonicalRoot("authority", authorityInput)
	if err != nil {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, err
	}
	if current.Document.Channel != trusted.InitialRoot.Document.Channel || current.Document.Version < 1 ||
		current.Document.ReleaseEpoch < 1 || current.Document.MinimumSecurityFloor < trusted.InitialRoot.Document.MinimumSecurityFloor {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, errors.New("current root is inconsistent with the compiled initial root")
	}
	if authority.Document.Channel != current.Document.Channel || authority.Document.Version > current.Document.Version {
		return installtrust.Bootstrap{}, releasetrust.ParsedRoot{}, releasetrust.ParsedRoot{}, errors.New("release authority is not in the current root history")
	}
	return trusted, current, authority, nil
}

// verifySignedCandidateWithPolicy is the deterministic test seam. Production
// call sites must use VerifySignedCandidate so trust and supported semantics
// always come from the running binary.
func verifySignedCandidateWithPolicy(metadata SignedMetadata, policy installtrust.Policy, prior *State, now time.Time, supportedSecurityFloor uint64) (CandidateMetadata, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return CandidateMetadata{}, errors.New("Mesh Linux installation is supported only on linux/amd64 and linux/arm64")
	}
	if now.IsZero() {
		return CandidateMetadata{}, errors.New("release verification time must be nonzero")
	}
	if supportedSecurityFloor == 0 {
		return CandidateMetadata{}, errors.New("installer supported security floor must be positive")
	}
	if err := validateVerificationPolicy(policy); err != nil {
		return CandidateMetadata{}, errors.New("compiled installer trust policy is invalid")
	}
	if len(metadata.ChannelManifest) == 0 || len(metadata.ChannelManifest) > releasetrust.MaxManifestSize ||
		len(metadata.ReleaseManifest) == 0 || len(metadata.ReleaseManifest) > releasetrust.MaxManifestSize {
		return CandidateMetadata{}, fmt.Errorf("channel and release manifests must each be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	channelDigest := sha256.Sum256(metadata.ChannelManifest)
	releaseDigest := sha256.Sum256(metadata.ReleaseManifest)
	channelHex := hex.EncodeToString(channelDigest[:])
	releaseHex := hex.EncodeToString(releaseDigest[:])
	minimumSequence := policy.MinimumSequence
	minimumFloor := policy.MinimumSecurityFloor
	verificationTime := now.UTC()
	resuming := false
	if prior != nil {
		if err := prior.Validate(); err != nil {
			return CandidateMetadata{}, err
		}
		if prior.TrustPolicySHA256 != policy.SHA256 {
			return CandidateMetadata{}, errors.New("compiled installer trust policy differs from persisted policy")
		}
		if prior.Channel != policy.Channel {
			return CandidateMetadata{}, errors.New("compiled installer channel differs from persisted channel")
		}
		if prior.HighWater.Sequence > minimumSequence {
			minimumSequence = prior.HighWater.Sequence
		}
		if prior.HighWater.MinimumSecurityFloor > minimumFloor {
			minimumFloor = prior.HighWater.MinimumSecurityFloor
		}
		// An exact candidate whose trust decision was already fsynced may be
		// resumed after metadata expiry. Re-run threshold and semantic checks at
		// the original trusted time; different bytes always use the current time.
		if channelHex == prior.HighWater.ChannelManifestSHA256 && releaseHex == prior.HighWater.ReleaseManifestSHA256 {
			acceptedAt, err := parseCanonicalTime(prior.HighWater.VerifiedAt)
			if err != nil {
				return CandidateMetadata{}, err
			}
			verificationTime = acceptedAt
			resuming = true
		}
		if prior.Pending != nil && !resuming {
			return CandidateMetadata{}, errors.New("an unfinished installer transaction must be resumed or rolled back before verifying another release")
		}
	}
	verifiedChannel, verifiedRelease, err := releasetrust.VerifyChannelRelease(
		metadata.ChannelManifest, metadata.ChannelSignatures,
		metadata.ReleaseManifest, metadata.ReleaseSignatures,
		policy.TrustedKeys,
		releasetrust.VerificationPolicy{
			Now: verificationTime, Threshold: policy.SignatureThreshold,
			MinimumSequence: minimumSequence, MinimumSecurityFloor: minimumFloor,
			SupportedSecurityFloor: supportedSecurityFloor,
			ExpectedChannel:        policy.Channel, PlatformOS: runtime.GOOS, PlatformArch: runtime.GOARCH,
		},
	)
	if err != nil {
		return CandidateMetadata{}, err
	}
	if verifiedRelease.SelectedArtifact == nil {
		return CandidateMetadata{}, errors.New("verified release did not select a Linux installer artifact")
	}
	verifiedAt := now.UTC().Truncate(time.Second)
	if resuming {
		verifiedAt = verificationTime
	}
	result := CandidateMetadata{
		Sequence: verifiedRelease.Release.Sequence, Version: verifiedRelease.Release.Version,
		MinimumSecurityFloor:  verifiedRelease.Release.MinimumSecurityFloor,
		ChannelManifestSHA256: channelHex, ReleaseManifestSHA256: releaseHex,
		Artifact: *verifiedRelease.SelectedArtifact, VerifiedAt: verifiedAt.Format(time.RFC3339),
		ChannelSignerKeyIDs: append([]string(nil), verifiedChannel.SignerKeyIDs...),
		ReleaseSignerKeyIDs: append([]string(nil), verifiedRelease.SignerKeyIDs...),
	}
	if prior != nil && result.Sequence == prior.HighWater.Sequence {
		if result.ChannelManifestSHA256 != prior.HighWater.ChannelManifestSHA256 ||
			result.ReleaseManifestSHA256 != prior.HighWater.ReleaseManifestSHA256 ||
			result.Artifact.SHA256 != prior.HighWater.ArtifactSHA256 {
			return CandidateMetadata{}, errors.New("same-sequence metadata or artifact differs from accepted release")
		}
	}
	return result, nil
}

func (candidate CandidateMetadata) releaseIdentity(bundleManifestSHA256, installerBootstrapRootSHA256 string, bundleSupportedSecurityFloor, agentStateReadMin, agentStateReadMax, agentStateWriteVersion uint64) (ReleaseIdentity, error) {
	identity := ReleaseIdentity{
		ReleaseEpoch:                 candidate.ReleaseEpoch,
		TrustedRootVersion:           candidate.TrustedRootVersion,
		TrustedRootSHA256:            candidate.TrustedRootSHA256,
		InstallerBootstrapRootSHA256: installerBootstrapRootSHA256,
		Sequence:                     candidate.Sequence,
		ChannelManifestSHA256:        candidate.ChannelManifestSHA256,
		ReleaseManifestSHA256:        candidate.ReleaseManifestSHA256,
		ArtifactSHA256:               candidate.Artifact.SHA256,
		BundleManifestSHA256:         bundleManifestSHA256,
		Version:                      candidate.Version,
		MinimumSecurityFloor:         candidate.MinimumSecurityFloor,
		BundleSecurityFloor:          bundleSupportedSecurityFloor,
		AgentStateReadMin:            agentStateReadMin,
		AgentStateReadMax:            agentStateReadMax,
		AgentStateWriteVersion:       agentStateWriteVersion,
		VerifiedAt:                   candidate.VerifiedAt,
	}
	if candidate.ReleaseEpoch == 0 {
		identity.InstallerBootstrapRootSHA256 = ""
	}
	identity.InstalledID = InstalledID(identity)
	if err := identity.Validate(); err != nil {
		return ReleaseIdentity{}, fmt.Errorf("complete authenticated release identity: %w", err)
	}
	return identity, nil
}

func validateVerificationPolicy(policy installtrust.Policy) error {
	if !channelPattern.MatchString(policy.Channel) || policy.SignatureThreshold < 2 || len(policy.TrustedKeys) < policy.SignatureThreshold ||
		len(policy.TrustedKeys) > releasetrust.MaxTrustedKeys || policy.MinimumSequence == 0 || policy.MinimumSecurityFloor == 0 ||
		!lowerHex64Pattern.MatchString(policy.SHA256) {
		return errors.New("invalid policy fields")
	}
	seen := make(map[string]struct{}, len(policy.TrustedKeys))
	for _, key := range policy.TrustedKeys {
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return errors.New("invalid trusted public key length")
		}
		derived, err := releasetrust.KeyID(ed25519.PublicKey(key.PublicKey))
		if err != nil || derived != key.KeyID {
			return errors.New("trusted public key ID does not match its bytes")
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return errors.New("duplicate trusted public key")
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

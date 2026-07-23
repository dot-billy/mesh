package darwininstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"

	"mesh/internal/darwinbundle"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const (
	DarwinIntakeRecordSchema      = "mesh-darwin-accepted-intake-v1"
	maximumDarwinIntakeRecordSize = 2 * onlinerelease.MaxEncodedBundleSize
)

// DarwinIntakeRecord is the immutable crash boundary between threshold
// metadata authentication and artifact acquisition. OnlineBundle retains the
// exact canonical signed bytes; Candidate is a cache that must be reproduced
// by verification before the record is used as authority.
type DarwinIntakeRecord struct {
	Schema                       string                  `json:"schema"`
	OnlineBundle                 string                  `json:"online_bundle"`
	Candidate                    VerifiedDarwinCandidate `json:"candidate"`
	InstallerBootstrapRootSHA256 string                  `json:"installer_bootstrap_root_sha256"`
}

func NewDarwinIntakeRecord(bundle onlinerelease.Bundle, intake VerifiedDarwinIntake) (DarwinIntakeRecord, error) {
	raw, err := onlinerelease.Encode(bundle)
	if err != nil {
		return DarwinIntakeRecord{}, fmt.Errorf("encode accepted Darwin online bundle: %w", err)
	}
	record := DarwinIntakeRecord{
		Schema: DarwinIntakeRecordSchema, OnlineBundle: string(raw), Candidate: intake.Candidate,
		InstallerBootstrapRootSHA256: intake.InstallerBootstrapRootSHA256,
	}
	if err := record.Validate(); err != nil {
		return DarwinIntakeRecord{}, err
	}
	return record, nil
}

func (record DarwinIntakeRecord) Validate() error {
	if record.Schema != DarwinIntakeRecordSchema {
		return errors.New("Darwin accepted-intake schema is invalid")
	}
	if !darwinDigestPattern.MatchString(record.InstallerBootstrapRootSHA256) {
		return errors.New("Darwin accepted-intake bootstrap digest is not canonical")
	}
	if err := validateVerifiedDarwinCandidate(record.Candidate); err != nil {
		return fmt.Errorf("Darwin accepted-intake candidate: %w", err)
	}
	bundle, err := onlinerelease.Parse([]byte(record.OnlineBundle))
	if err != nil {
		return fmt.Errorf("Darwin accepted-intake online bundle: %w", err)
	}
	channelDigest, releaseDigest, err := darwinSignedMetadataDigests(darwinMetadataFromOnlineBundle(bundle))
	if err != nil {
		return err
	}
	if channelDigest != record.Candidate.ChannelManifestSHA256 || releaseDigest != record.Candidate.ReleaseManifestSHA256 {
		return errors.New("Darwin accepted-intake metadata digests differ from its verified candidate")
	}
	verifiedAt, _ := parseDarwinCanonicalTime(record.Candidate.VerifiedAt)
	parsedRelease, err := releasetrust.ParseManifest(bundle.ReleaseManifest, releasetrust.VerificationPolicy{
		Now: verifiedAt, MinimumSequence: record.Candidate.Sequence,
		MinimumSecurityFloor: record.Candidate.MinimumSecurityFloor, SupportedSecurityFloor: record.Candidate.MinimumSecurityFloor,
		ExpectedChannel: record.Candidate.Channel, ExpectedReleaseEpoch: record.Candidate.ReleaseEpoch,
		MinimumReleaseEpoch: record.Candidate.ReleaseEpoch, AllowLegacyEpochOne: true,
		PlatformOS: "darwin", PlatformArch: record.Candidate.Artifact.Arch,
	})
	if err != nil || parsedRelease.Release == nil || parsedRelease.SelectedArtifact == nil ||
		parsedRelease.Release.Version != record.Candidate.Version || parsedRelease.Release.Sequence != record.Candidate.Sequence ||
		parsedRelease.Release.MinimumSecurityFloor != record.Candidate.MinimumSecurityFloor ||
		*parsedRelease.SelectedArtifact != record.Candidate.Artifact {
		return errors.Join(err, errors.New("Darwin accepted-intake release manifest differs from its verified candidate"))
	}
	return nil
}

func (record DarwinIntakeRecord) Bundle() (onlinerelease.Bundle, error) {
	if err := record.Validate(); err != nil {
		return onlinerelease.Bundle{}, err
	}
	return onlinerelease.Parse([]byte(record.OnlineBundle))
}

func (record DarwinIntakeRecord) Intake() (VerifiedDarwinIntake, error) {
	if err := record.Validate(); err != nil {
		return VerifiedDarwinIntake{}, err
	}
	return VerifiedDarwinIntake{
		Candidate: record.Candidate, InstallerBootstrapRootSHA256: record.InstallerBootstrapRootSHA256,
	}, nil
}

func validateVerifiedDarwinCandidate(candidate VerifiedDarwinCandidate) error {
	if candidate.ReleaseEpoch == 0 || candidate.TrustedRootVersion == 0 || candidate.Sequence == 0 || candidate.MinimumSecurityFloor == 0 {
		return errors.New("release epoch, trusted-root version, sequence, and security floor must be positive")
	}
	for label, digest := range map[string]string{
		"trusted root": candidate.TrustedRootSHA256, "channel manifest": candidate.ChannelManifestSHA256,
		"release manifest": candidate.ReleaseManifestSHA256,
	} {
		if !darwinDigestPattern.MatchString(digest) {
			return fmt.Errorf("%s digest is not canonical", label)
		}
	}
	if err := validateDarwinSemVer(candidate.Version); err != nil {
		return errors.New("release version is not canonical SemVer")
	}
	if !darwinChannelPattern.MatchString(candidate.Channel) {
		return errors.New("release channel is not canonical")
	}
	if _, err := parseDarwinCanonicalTime(candidate.VerifiedAt); err != nil {
		return fmt.Errorf("verified_at: %w", err)
	}
	if err := releasetrust.ValidateArtifactReference(candidate.Artifact); err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	if candidate.Artifact.OS != "darwin" || candidate.Artifact.Arch != "amd64" && candidate.Artifact.Arch != "arm64" ||
		candidate.Artifact.Size > darwinbundle.MaxArchiveSize {
		return errors.New("artifact is not a bounded supported Darwin bundle")
	}
	return nil
}

func darwinMetadataFromOnlineBundle(bundle onlinerelease.Bundle) DarwinSignedMetadata {
	return DarwinSignedMetadata{
		ChannelManifest: bundle.ChannelManifest, ChannelSignatures: bundle.ChannelSignatures,
		ReleaseManifest: bundle.ReleaseManifest, ReleaseSignatures: bundle.ReleaseSignatures,
	}
}

func encodeDarwinIntakeRecord(record DarwinIntakeRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin accepted intake: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) == 0 || len(raw) > maximumDarwinIntakeRecordSize {
		return nil, errors.New("Darwin accepted intake exceeds its size bound")
	}
	return raw, nil
}

func decodeDarwinIntakeRecord(raw []byte) (DarwinIntakeRecord, error) {
	if len(raw) == 0 || len(raw) > maximumDarwinIntakeRecordSize || !utf8.Valid(raw) {
		return DarwinIntakeRecord{}, errors.New("Darwin accepted-intake bytes are invalid or outside their bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record DarwinIntakeRecord
	if err := decoder.Decode(&record); err != nil {
		return DarwinIntakeRecord{}, fmt.Errorf("decode Darwin accepted intake: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return DarwinIntakeRecord{}, fmt.Errorf("decode Darwin accepted-intake trailing data: %w", err)
		}
		return DarwinIntakeRecord{}, fmt.Errorf("decode Darwin accepted-intake trailing token %v", token)
	}
	canonical, err := encodeDarwinIntakeRecord(record)
	if err != nil {
		return DarwinIntakeRecord{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return DarwinIntakeRecord{}, errors.New("Darwin accepted intake is not canonical")
	}
	return record, nil
}

func sameDarwinIntakeRecord(left, right DarwinIntakeRecord) bool {
	return reflect.DeepEqual(left, right)
}

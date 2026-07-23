package windowsinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const (
	WindowsIntakeRecordSchema = "mesh-windows-accepted-intake-v1"
	maximumWindowsIntakeBytes = 2 * onlinerelease.MaxEncodedBundleSize
)

type WindowsIntakeRecord struct {
	Schema                       string                   `json:"schema"`
	OnlineBundle                 string                   `json:"online_bundle"`
	Candidate                    VerifiedWindowsCandidate `json:"candidate"`
	InstallerBootstrapRootSHA256 string                   `json:"installer_bootstrap_root_sha256"`
}

func NewWindowsIntakeRecord(bundle onlinerelease.Bundle, intake VerifiedWindowsIntake) (WindowsIntakeRecord, error) {
	raw, err := onlinerelease.Encode(bundle)
	if err != nil {
		return WindowsIntakeRecord{}, fmt.Errorf("encode accepted Windows online bundle: %w", err)
	}
	record := WindowsIntakeRecord{
		Schema: WindowsIntakeRecordSchema, OnlineBundle: string(raw), Candidate: intake.Candidate,
		InstallerBootstrapRootSHA256: intake.InstallerBootstrapRootSHA256,
	}
	if err := record.Validate(); err != nil {
		return WindowsIntakeRecord{}, err
	}
	return record, nil
}

func (record WindowsIntakeRecord) Validate() error {
	if record.Schema != WindowsIntakeRecordSchema {
		return errors.New("Windows accepted-intake schema is invalid")
	}
	if !digestPattern.MatchString(record.InstallerBootstrapRootSHA256) {
		return errors.New("Windows accepted-intake bootstrap digest is invalid")
	}
	if err := record.Candidate.Validate(); err != nil {
		return fmt.Errorf("Windows accepted-intake candidate: %w", err)
	}
	bundle, err := onlinerelease.Parse([]byte(record.OnlineBundle))
	if err != nil {
		return fmt.Errorf("Windows accepted-intake online bundle: %w", err)
	}
	metadata := windowsMetadataFromOnlineBundle(bundle)
	channelDigest, releaseDigest, err := windowsSignedMetadataDigests(metadata)
	if err != nil {
		return err
	}
	if channelDigest != record.Candidate.ChannelManifestSHA256 || releaseDigest != record.Candidate.ReleaseManifestSHA256 {
		return errors.New("Windows accepted-intake metadata digests differ from its verified candidate")
	}
	verifiedAt, _ := parseWindowsCanonicalTime(record.Candidate.VerifiedAt)
	parsedRelease, err := releasetrust.ParseManifest(bundle.ReleaseManifest, releasetrust.VerificationPolicy{
		Now: verifiedAt, MinimumSequence: record.Candidate.Sequence,
		MinimumSecurityFloor: record.Candidate.MinimumSecurityFloor, SupportedSecurityFloor: record.Candidate.MinimumSecurityFloor,
		ExpectedChannel: record.Candidate.Channel, ExpectedReleaseEpoch: record.Candidate.ReleaseEpoch,
		MinimumReleaseEpoch: record.Candidate.ReleaseEpoch, AllowLegacyEpochOne: true,
		PlatformOS: "windows", PlatformArch: record.Candidate.Artifact.Arch,
	})
	if err != nil || parsedRelease.Release == nil || parsedRelease.SelectedArtifact == nil ||
		parsedRelease.Release.Version != record.Candidate.Version || parsedRelease.Release.Sequence != record.Candidate.Sequence ||
		parsedRelease.Release.MinimumSecurityFloor != record.Candidate.MinimumSecurityFloor ||
		!reflect.DeepEqual(*parsedRelease.SelectedArtifact, record.Candidate.Artifact) {
		return errors.Join(err, errors.New("Windows accepted-intake release manifest differs from its verified candidate"))
	}
	return nil
}

func (record WindowsIntakeRecord) Bundle() (onlinerelease.Bundle, error) {
	if err := record.Validate(); err != nil {
		return onlinerelease.Bundle{}, err
	}
	return onlinerelease.Parse([]byte(record.OnlineBundle))
}

func windowsMetadataFromOnlineBundle(bundle onlinerelease.Bundle) WindowsSignedMetadata {
	return WindowsSignedMetadata{
		ChannelManifest: bundle.ChannelManifest, ChannelSignatures: bundle.ChannelSignatures,
		ReleaseManifest: bundle.ReleaseManifest, ReleaseSignatures: bundle.ReleaseSignatures,
	}
}

func (record WindowsIntakeRecord) Intake() (VerifiedWindowsIntake, error) {
	if err := record.Validate(); err != nil {
		return VerifiedWindowsIntake{}, err
	}
	return VerifiedWindowsIntake{
		Candidate: record.Candidate, InstallerBootstrapRootSHA256: record.InstallerBootstrapRootSHA256,
	}, nil
}

func MarshalWindowsIntakeRecord(record WindowsIntakeRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode Windows accepted intake: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumWindowsIntakeBytes {
		return nil, errors.New("Windows accepted intake exceeds its size bound")
	}
	return raw, nil
}

func ParseWindowsIntakeRecord(raw []byte) (WindowsIntakeRecord, error) {
	if len(raw) < 2 || len(raw) > maximumWindowsIntakeBytes {
		return WindowsIntakeRecord{}, errors.New("Windows accepted intake is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record WindowsIntakeRecord
	if err := decoder.Decode(&record); err != nil {
		return WindowsIntakeRecord{}, fmt.Errorf("decode Windows accepted intake: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return WindowsIntakeRecord{}, errors.New("Windows accepted intake contains multiple JSON values")
		}
		return WindowsIntakeRecord{}, fmt.Errorf("decode trailing Windows accepted-intake data: %w", err)
	}
	canonical, err := MarshalWindowsIntakeRecord(record)
	if err != nil {
		return WindowsIntakeRecord{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return WindowsIntakeRecord{}, errors.New("Windows accepted intake is not canonical")
	}
	return record, nil
}

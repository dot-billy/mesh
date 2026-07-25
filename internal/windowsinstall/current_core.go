package windowsinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"mesh/internal/windowsbundle"
)

const CurrentDescriptorSchema = "mesh-windows-current-release-v1"

var (
	installedIDPattern      = regexp.MustCompile(`^(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}$`)
	digestPattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	currentTemporaryPattern = regexp.MustCompile(`^\.current-[0-9a-f]{32}\.json$`)
	releaseStageNamePattern = regexp.MustCompile(`^\.stage-(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}-[0-9a-f]{32}$`)
)

// CurrentDescriptor is the complete Windows release-selection authority. It
// uses a protected regular file because creating symbolic links is not a
// generally available service-installation primitive on Windows.
type CurrentDescriptor struct {
	Schema            string `json:"schema"`
	InstalledID       string `json:"installed_id"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	PackageJSONSHA256 string `json:"package_json_sha256"`
	Architecture      string `json:"architecture"`
	SecurityFloor     uint64 `json:"security_floor"`
}

func CurrentDescriptorFromInspection(installedID string, inspection windowsbundle.CandidateInspection) (CurrentDescriptor, error) {
	result := CurrentDescriptor{
		Schema: CurrentDescriptorSchema, InstalledID: installedID,
		ArtifactSHA256: inspection.ArtifactSHA256, PackageJSONSHA256: inspection.PackageJSONSHA256,
		Architecture: inspection.Package.Target.Arch, SecurityFloor: inspection.Package.SecurityFloor,
	}
	if inspection.Schema != windowsbundle.CandidateInspectionSchema {
		return CurrentDescriptor{}, errors.New("Windows candidate inspection schema is invalid")
	}
	if err := result.Validate(); err != nil {
		return CurrentDescriptor{}, err
	}
	if len(result.ArtifactSHA256) != 64 || result.InstalledID[len(result.InstalledID)-18:] != "-a"+result.ArtifactSHA256[:16] {
		return CurrentDescriptor{}, errors.New("Windows installed ID is not bound to the candidate artifact")
	}
	return result, nil
}

func (descriptor CurrentDescriptor) Validate() error {
	if descriptor.Schema != CurrentDescriptorSchema {
		return fmt.Errorf("unsupported Windows current-descriptor schema %q", descriptor.Schema)
	}
	if !installedIDPattern.MatchString(descriptor.InstalledID) {
		return errors.New("Windows current-descriptor installed ID is invalid")
	}
	if !digestPattern.MatchString(descriptor.ArtifactSHA256) || !digestPattern.MatchString(descriptor.PackageJSONSHA256) {
		return errors.New("Windows current-descriptor digests are invalid")
	}
	if descriptor.InstalledID[len(descriptor.InstalledID)-18:] != "-a"+descriptor.ArtifactSHA256[:16] {
		return errors.New("Windows current-descriptor installed ID is not bound to its artifact digest")
	}
	if descriptor.Architecture != "amd64" && descriptor.Architecture != "arm64" {
		return errors.New("Windows current-descriptor architecture is invalid")
	}
	if descriptor.SecurityFloor == 0 {
		return errors.New("Windows current-descriptor security floor must be positive")
	}
	return nil
}

func MarshalCurrentDescriptor(descriptor CurrentDescriptor) ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("encode Windows current descriptor: %w", err)
	}
	return append(raw, '\n'), nil
}

func ParseCurrentDescriptor(raw []byte) (CurrentDescriptor, error) {
	if len(raw) < 2 || len(raw) > 4096 {
		return CurrentDescriptor{}, errors.New("Windows current descriptor is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var descriptor CurrentDescriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return CurrentDescriptor{}, fmt.Errorf("decode Windows current descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return CurrentDescriptor{}, errors.New("Windows current descriptor contains multiple JSON values")
		}
		return CurrentDescriptor{}, fmt.Errorf("decode trailing Windows current-descriptor data: %w", err)
	}
	canonical, err := MarshalCurrentDescriptor(descriptor)
	if err != nil {
		return CurrentDescriptor{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return CurrentDescriptor{}, errors.New("Windows current descriptor is not canonical")
	}
	return descriptor, nil
}

func cloneCurrentDescriptor(value *CurrentDescriptor) *CurrentDescriptor {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
